package approvals_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hollis-labs/libs/core/store"
	"github.com/hollis-labs/libs/core/store/migrate"
	libauth "github.com/hollis-labs/libs/security/auth"

	"github.com/hollis-labs/gatecrasher/internal/approvals"
	"github.com/hollis-labs/gatecrasher/internal/settings"
	"github.com/hollis-labs/gatecrasher/internal/storage"
	"github.com/hollis-labs/gatecrasher/pkg/approvalapi"
)

const class = "approve.credentials"

var (
	warden   = libauth.Principal{Verified: true, ID: "key:warden", Kind: libauth.KindService, Audience: "gatecrasher", Scopes: []string{approvalapi.ScopeSubmit, approvalapi.ScopeRead}}
	other    = libauth.Principal{Verified: true, ID: "key:other", Kind: libauth.KindService, Audience: "gatecrasher", Scopes: []string{approvalapi.ScopeSubmit, approvalapi.ScopeRead}}
	owner    = libauth.Principal{Verified: true, ID: "user:usr_owner", Kind: "user", Audience: "gatecrasher", Scopes: []string{"*"}}
	approver = libauth.Principal{Verified: true, ID: "key:approver", Kind: libauth.KindService, Audience: "gatecrasher", Scopes: []string{approvalapi.ScopeDecide, approvalapi.ScopeRead, class}}
	// A wildcard grant never makes a caller an approver.
	wildcard = libauth.Principal{Verified: true, ID: "key:wild", Kind: libauth.KindService, Audience: "gatecrasher", Scopes: []string{"*"}}
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func cfg(shadow bool) settings.Approvals {
	return settings.Approvals{
		Owner:     settings.Owner{Principal: owner.ID, Sub: "chrispian"},
		Producers: map[string]string{warden.ID: "warden", other.ID: "other"},
		Classes: map[string]settings.Class{class: {
			Agents:  map[string]string{approver.ID: "agt_approver", wildcard.ID: "agt_wild"},
			Ceiling: settings.Ceiling{MaxTTLSeconds: 3600, Audiences: []string{"llm-gateway"}, Scopes: []string{"llm-gateway.decide"}},
			Shadow:  shadow,
		}},
	}
}

func open(t *testing.T, a settings.Approvals) (*approvals.Service, *clock, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	sc := store.Config{Driver: store.DriverSQLite, SQLite: store.SQLiteConfig{Path: filepath.Join(dir, "gatecrasher.db"), Journal: "wal", Synchronous: "FULL", CreateParentDir: true}}
	st, err := store.Open(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fs, root := storage.Migrations()
	if err = migrate.Ensure(context.Background(), sc, st, migrate.Source{FS: fs, Root: root}); err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)}
	svc, err := approvals.New(st, approvals.Config{Settings: a, DataDir: dir, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	return svc, c, st
}

func request(t *testing.T, c *clock, key string, tier approvalapi.Tier) approvalapi.SubmitRequest {
	t.Helper()
	r := approvalapi.SubmitRequest{
		IdempotencyKey: key, Source: "warden", Kind: approvalapi.KindCredentialGrant, Tier: tier,
		Principal: approvalapi.Principal{Sub: "agt_x", Kind: approvalapi.KindAgent},
		Requested: approvalapi.Requested{Audience: "llm-gateway", Scopes: []string{"llm-gateway.decide"}, TTLSeconds: 600},
		Purpose:   "test", ExpiresAt: c.now().Add(time.Hour),
	}
	if tier == approvalapi.TierElevated {
		r.ApproverClass = class
	}
	d, err := r.Digest()
	if err != nil {
		t.Fatal(err)
	}
	r.RequestDigest = d
	return r
}

func code(t *testing.T, err error) (int, string) {
	t.Helper()
	var e *approvals.Error
	if !errors.As(err, &e) {
		t.Fatalf("want an approvals.Error, got %v", err)
	}
	return e.Status, e.Code
}

func verify(t *testing.T, svc *approvals.Service, a approvalapi.Approval, req approvalapi.SubmitRequest, now time.Time) approvalapi.DecisionClaims {
	t.Helper()
	c, err := approvalapi.VerifyDecision(a.Decision, svc.JWKS(), req.Source, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err = c.Check(approvalapi.Expect{RequestID: req.IdempotencyKey, RequestDigest: req.RequestDigest, Tier: req.Tier, Requested: req.Requested, Owner: "chrispian"}); err != nil {
		t.Fatalf("check: %v", err)
	}
	return c
}

func TestSubmitIdempotencyAndDigest(t *testing.T) {
	ctx := context.Background()
	svc, c, _ := open(t, cfg(false))
	req := request(t, c, "r1", approvalapi.TierCritical)
	first, created, err := svc.Submit(ctx, warden, req)
	if err != nil || !created || first.Status != approvalapi.StatusPending {
		t.Fatalf("first submit: %v %v %+v", err, created, first)
	}
	again, created, err := svc.Submit(ctx, warden, req)
	if err != nil || created || again.ApprovalID != first.ApprovalID {
		t.Fatalf("resubmit: %v %v %+v", err, created, again)
	}
	changed := req
	changed.Requested.TTLSeconds = 60
	changed.RequestDigest, _ = changed.Digest()
	if _, _, err = svc.Submit(ctx, warden, changed); err == nil {
		t.Fatal("same key, different digest was accepted")
	} else if s, cd := code(t, err); s != http.StatusConflict || cd != approvalapi.ErrCodeIdempotency {
		t.Fatalf("conflict: %d %s", s, cd)
	}
	bad := request(t, c, "r2", approvalapi.TierCritical)
	bad.RequestDigest = "sha256:00"
	if _, _, err = svc.Submit(ctx, warden, bad); err == nil {
		t.Fatal("bad digest accepted")
	} else if s, cd := code(t, err); s != http.StatusUnprocessableEntity || cd != approvalapi.ErrCodeDigestMismatch {
		t.Fatalf("digest: %d %s", s, cd)
	}
	// Keys are per producer: another producer may reuse one.
	o := request(t, c, "r1", approvalapi.TierCritical)
	o.Source = "other"
	if _, created, err = svc.Submit(ctx, other, o); err != nil || !created {
		t.Fatalf("other producer, same key: %v %v", err, created)
	}
}

func TestSubmitValidation(t *testing.T) {
	ctx := context.Background()
	svc, c, _ := open(t, cfg(false))
	for name, mod := range map[string]func(*approvalapi.SubmitRequest){
		"no key":            func(r *approvalapi.SubmitRequest) { r.IdempotencyKey = "" },
		"bad tier":          func(r *approvalapi.SubmitRequest) { r.Tier = "high" },
		"elevated no class": func(r *approvalapi.SubmitRequest) { r.Tier = approvalapi.TierElevated },
		"critical w/ class": func(r *approvalapi.SubmitRequest) { r.ApproverClass = class },
		"unknown class": func(r *approvalapi.SubmitRequest) {
			r.Tier, r.ApproverClass = approvalapi.TierElevated, "approve.nothing"
		},
		"past expiry": func(r *approvalapi.SubmitRequest) { r.ExpiresAt = c.now().Add(-time.Second) },
		"far expiry":  func(r *approvalapi.SubmitRequest) { r.ExpiresAt = c.now().Add(31 * 24 * time.Hour) },
		"no audience": func(r *approvalapi.SubmitRequest) { r.Requested.Audience = "" },
		"bad kind":    func(r *approvalapi.SubmitRequest) { r.Principal.Kind = "robot" },
	} {
		r := request(t, c, "v-"+name, approvalapi.TierCritical)
		mod(&r)
		r.RequestDigest, _ = r.Digest()
		if _, _, err := svc.Submit(ctx, warden, r); err == nil {
			t.Errorf("%s: accepted", name)
		} else if s, _ := code(t, err); s != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, s)
		}
	}
	// A producer submits as its own source only, and an unknown caller not at all.
	r := request(t, c, "spoof", approvalapi.TierCritical)
	r.Source = "other"
	if _, _, err := svc.Submit(ctx, warden, r); err == nil {
		t.Error("spoofed source accepted")
	}
	if _, _, err := svc.Submit(ctx, approver, request(t, c, "x", approvalapi.TierCritical)); err == nil {
		t.Error("non-producer accepted")
	}
}

func TestGroundIsApprovedOnArrival(t *testing.T) {
	ctx := context.Background()
	svc, c, _ := open(t, cfg(false))
	req := request(t, c, "g1", approvalapi.TierGround)
	out, created, err := svc.Submit(ctx, warden, req)
	if err != nil || !created || out.Status != approvalapi.StatusApproved {
		t.Fatalf("ground: %v %+v", err, out)
	}
	a, err := svc.Get(ctx, warden, out.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	cl := verify(t, svc, a, req, c.now())
	if cl.Outcome != approvalapi.OutcomeApproved || cl.Decider.Kind != approvalapi.KindApp || cl.Aud != "warden" || cl.Jti == "" {
		t.Fatalf("claims: %+v", cl)
	}
	if _, err = svc.Decide(ctx, owner, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeDenied}); err == nil {
		t.Fatal("a decided ground request was decided again")
	}
}

func TestCriticalOwnerOnly(t *testing.T) {
	ctx := context.Background()
	svc, c, _ := open(t, cfg(false))
	req := request(t, c, "c1", approvalapi.TierCritical)
	out, _, err := svc.Submit(ctx, warden, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Decide(ctx, approver, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}); err == nil {
		t.Fatal("an agent decided a critical request")
	}
	// A producer may not decide its own request.
	if _, err = svc.Decide(ctx, warden, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}); err == nil {
		t.Fatal("the producer decided its own request")
	}
	// Another user is not the owner, and neither is an unverified caller carrying the owner's id
	// (auth off). The owner's kind is not part of the match.
	notOwner := owner
	notOwner.ID = "user:usr_someone"
	if _, err = svc.Decide(ctx, notOwner, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}); err == nil {
		t.Fatal("another user decided")
	}
	unverified := owner
	unverified.Verified = false
	if _, err = svc.Decide(ctx, unverified, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}); err == nil {
		t.Fatal("an unverified caller with the owner's id decided")
	}
	d, err := svc.Decide(ctx, owner, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved, Narrowed: &approvalapi.Narrowed{TTLSeconds: 300}})
	if err != nil || d.Status != approvalapi.StatusApproved {
		t.Fatalf("owner decide: %v %+v", err, d)
	}
	cl := verify(t, svc, d.Approval, req, c.now())
	if cl.Decider != (approvalapi.Actor{Sub: "chrispian", Kind: approvalapi.KindHuman}) || cl.Narrowed == nil || cl.Narrowed.TTLSeconds != 300 {
		t.Fatalf("claims: %+v", cl)
	}
	if cl.Exp-cl.Iat > int64(approvalapi.MaxDecisionLifetime/time.Second) {
		t.Fatalf("lifetime %d", cl.Exp-cl.Iat)
	}
	if _, err = svc.Decide(ctx, owner, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeDenied}); err == nil {
		t.Fatal("decided twice")
	} else if s, cd := code(t, err); s != http.StatusConflict || cd != approvalapi.ErrCodeTerminal {
		t.Fatalf("twice: %d %s", s, cd)
	}
	// A decision expires for redemption after ten minutes.
	if _, err = approvalapi.VerifyDecision(d.Decision, svc.JWKS(), "warden", c.now().Add(11*time.Minute)); !errors.Is(err, approvalapi.ErrExpired) {
		t.Fatalf("late verify: %v", err)
	}
}

func TestNarrowingOnlyNarrows(t *testing.T) {
	ctx := context.Background()
	svc, c, _ := open(t, cfg(false))
	out, _, _ := svc.Submit(ctx, warden, request(t, c, "n1", approvalapi.TierCritical))
	for name, n := range map[string]*approvalapi.Narrowed{
		"new scope":  {Scopes: []string{"llm-gateway.admin"}},
		"longer ttl": {TTLSeconds: 6000},
		"repeat":     {Scopes: []string{"llm-gateway.decide", "llm-gateway.decide"}},
	} {
		if _, err := svc.Decide(ctx, owner, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved, Narrowed: n}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestElevatedApproverRules(t *testing.T) {
	ctx := context.Background()
	svc, c, _ := open(t, cfg(false))
	req := request(t, c, "e1", approvalapi.TierElevated)
	out, _, err := svc.Submit(ctx, warden, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Decide(ctx, wildcard, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}); err == nil {
		t.Fatal("a wildcard scope made an approver")
	}
	// Over the ceiling (ttl 600 > 3600 is fine; make a wider one).
	wide := request(t, c, "e2", approvalapi.TierElevated)
	wide.Requested.TTLSeconds = 7200
	wide.RequestDigest, _ = wide.Digest()
	wout, _, _ := svc.Submit(ctx, warden, wide)
	if _, err = svc.Decide(ctx, approver, wout.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}); err == nil {
		t.Fatal("approved over the ceiling")
	} else if _, cd := code(t, err); cd != approvalapi.ErrCodeCeiling {
		t.Fatalf("ceiling code %s", cd)
	}
	// Narrowed into the ceiling, it may.
	if d, derr := svc.Decide(ctx, approver, wout.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved, Narrowed: &approvalapi.Narrowed{TTLSeconds: 1800}}); derr != nil || d.Status != approvalapi.StatusApproved {
		t.Fatalf("narrowed into ceiling: %v", derr)
	}
	d, err := svc.Decide(ctx, approver, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeDenied})
	if err != nil || d.Status != approvalapi.StatusDenied {
		t.Fatalf("agent deny: %v %+v", err, d)
	}
	cl := verify(t, svc, d.Approval, req, c.now())
	if cl.Decider != (approvalapi.Actor{Sub: "agt_approver", Kind: approvalapi.KindAgent}) || cl.Outcome != approvalapi.OutcomeDenied {
		t.Fatalf("claims %+v", cl)
	}
}

func TestShadowLeavesPending(t *testing.T) {
	ctx := context.Background()
	svc, c, _ := open(t, cfg(true))
	out, _, _ := svc.Submit(ctx, warden, request(t, c, "s1", approvalapi.TierElevated))
	d, err := svc.Decide(ctx, approver, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved})
	if err != nil || !d.Shadow || d.Status != approvalapi.StatusPending || d.Decision != "" {
		t.Fatalf("shadow: %v %+v", err, d)
	}
	if d, err = svc.Decide(ctx, owner, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}); err != nil || d.Status != approvalapi.StatusApproved {
		t.Fatalf("owner after shadow: %v %+v", err, d)
	}
	ev, err := svc.Events(ctx, out.ApprovalID)
	if err != nil || len(ev) != 3 || ev[1].Type != "shadow_decided" || ev[2].Type != "decided" {
		t.Fatalf("events: %v %+v", err, ev)
	}
}

func TestWithdraw(t *testing.T) {
	ctx := context.Background()
	svc, c, _ := open(t, cfg(false))
	out, _, _ := svc.Submit(ctx, warden, request(t, c, "w1", approvalapi.TierCritical))
	if _, err := svc.Withdraw(ctx, other, out.ApprovalID); err == nil {
		t.Fatal("another producer withdrew")
	}
	for range 2 {
		a, err := svc.Withdraw(ctx, warden, out.ApprovalID)
		if err != nil || a.Status != approvalapi.StatusWithdrawn {
			t.Fatalf("withdraw: %v %+v", err, a)
		}
	}
	if _, err := svc.Decide(ctx, owner, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}); err == nil {
		t.Fatal("decided a withdrawn request")
	}
	dec, _, _ := svc.Submit(ctx, warden, request(t, c, "w2", approvalapi.TierGround))
	if _, err := svc.Withdraw(ctx, warden, dec.ApprovalID); err == nil {
		t.Fatal("withdrew a decided request")
	} else if s, cd := code(t, err); s != http.StatusConflict || cd != approvalapi.ErrCodeTerminal {
		t.Fatalf("terminal: %d %s", s, cd)
	}
}

func TestExpiryAndAwait(t *testing.T) {
	ctx := context.Background()
	svc, c, _ := open(t, cfg(false))
	out, _, _ := svc.Submit(ctx, warden, request(t, c, "x1", approvalapi.TierCritical))
	// Await times out with the current status.
	a, err := svc.Await(ctx, warden, out.ApprovalID, 20*time.Millisecond)
	if err != nil || a.Status != approvalapi.StatusPending {
		t.Fatalf("await timeout: %v %+v", err, a)
	}
	// Await wakes on a decision.
	done := make(chan approvalapi.Approval, 1)
	go func() {
		got, _ := svc.Await(ctx, warden, out.ApprovalID, 5*time.Second)
		done <- got
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err = svc.Decide(ctx, owner, out.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeDenied}); err != nil {
		t.Fatal(err)
	}
	select {
	case a = <-done:
		if a.Status != approvalapi.StatusDenied || a.Decision == "" {
			t.Fatalf("woken: %+v", a)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("await did not wake on the decision")
	}
	// Expiry: the sweep moves a due request to expired, and it can no longer be decided.
	late, _, _ := svc.Submit(ctx, warden, request(t, c, "x2", approvalapi.TierCritical))
	c.add(2 * time.Hour)
	if n, serr := svc.Sweep(ctx); serr != nil || n != 1 {
		t.Fatalf("sweep: %v %d", serr, n)
	}
	if a, err = svc.Get(ctx, warden, late.ApprovalID); err != nil || a.Status != approvalapi.StatusExpired {
		t.Fatalf("expired: %v %+v", err, a)
	}
	if _, err = svc.Decide(ctx, owner, late.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}); err == nil {
		t.Fatal("decided an expired request")
	}
	// Get expires lazily too.
	lazy, _, _ := svc.Submit(ctx, warden, request(t, c, "x3", approvalapi.TierCritical))
	c.add(2 * time.Hour)
	if a, err = svc.Get(ctx, warden, lazy.ApprovalID); err != nil || a.Status != approvalapi.StatusExpired {
		t.Fatalf("lazy expiry: %v %+v", err, a)
	}
}

func TestReadIsScoped(t *testing.T) {
	ctx := context.Background()
	svc, c, _ := open(t, cfg(false))
	out, _, _ := svc.Submit(ctx, warden, request(t, c, "r1", approvalapi.TierCritical))
	if _, err := svc.Get(ctx, other, out.ApprovalID); err == nil {
		t.Fatal("another producer read the approval")
	} else if s, _ := code(t, err); s != http.StatusNotFound {
		t.Fatalf("status %d", s)
	}
	if _, err := svc.Get(ctx, owner, out.ApprovalID); err != nil {
		t.Fatalf("owner read: %v", err)
	}
}

func TestStoreIsImmutable(t *testing.T) {
	ctx := context.Background()
	svc, c, st := open(t, cfg(false))
	out, _, _ := svc.Submit(ctx, warden, request(t, c, "i1", approvalapi.TierGround))
	for _, q := range []string{
		`UPDATE approvals SET snapshot_json='{}' WHERE approval_id=?`,
		`UPDATE approvals SET status='pending' WHERE approval_id=?`,
		`UPDATE approvals SET status='denied' WHERE approval_id=?`,
		`DELETE FROM approvals WHERE approval_id=?`,
		`UPDATE approval_decisions SET outcome='denied' WHERE approval_id=?`,
		`DELETE FROM approval_events WHERE approval_id=?`,
	} {
		if _, err := st.ExecContext(ctx, q, out.ApprovalID); err == nil {
			t.Errorf("allowed: %s", q)
		}
	}
}

func TestDecisionKeyPersists(t *testing.T) {
	ctx := context.Background()
	svc, _, st := open(t, cfg(false))
	dir := filepath.Dir(st.Config().SQLite.Path)
	again, err := approvals.New(st, approvals.Config{Settings: cfg(false), DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if svc.JWKS().Keys[0].Kid != again.JWKS().Keys[0].Kid {
		t.Fatal("the key changed across restarts")
	}
	key := filepath.Join(dir, "decision-signing.key")
	if fi, serr := os.Stat(key); serr != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode: %v %v", serr, fi)
	}
	if err = os.Chmod(key, 0o644); err != nil { //nolint:gosec // the test makes the key too open on purpose
		t.Fatal(err)
	}
	if _, err = approvals.New(st, approvals.Config{Settings: cfg(false), DataDir: dir}); err == nil {
		t.Fatal("a world-readable key was accepted")
	}
	_ = ctx
}

func TestUnconfigured(t *testing.T) {
	ctx := context.Background()
	a := cfg(false)
	a.Owner = settings.Owner{}
	svc, c, _ := open(t, a)
	if _, _, err := svc.Submit(ctx, warden, request(t, c, "u1", approvalapi.TierCritical)); err == nil {
		t.Fatal("accepted without an owner")
	} else if s, _ := code(t, err); s != http.StatusServiceUnavailable {
		t.Fatalf("status %d", s)
	}
}
