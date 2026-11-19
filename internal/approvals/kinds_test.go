package approvals_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/approvals"
	"github.com/hollis-labs/gatecrasher/internal/settings"
	"github.com/hollis-labs/gatecrasher/pkg/approvalapi"
)

const intakeOrigin = "https://warden.example"

func withIntake(a settings.Approvals) settings.Approvals {
	a.IntakeOrigins = map[string][]string{"warden": {intakeOrigin}}
	return a
}

func digested(t *testing.T, r approvalapi.SubmitRequest) approvalapi.SubmitRequest {
	t.Helper()
	d, err := r.Digest()
	if err != nil {
		t.Fatal(err)
	}
	r.RequestDigest = d
	return r
}

func promptReq(t *testing.T, c *clock, key, kind string, p *approvalapi.Prompt) approvalapi.SubmitRequest {
	return digested(t, approvalapi.SubmitRequest{
		IdempotencyKey: key, Source: "warden", Kind: kind, Tier: approvalapi.TierCritical,
		Principal: approvalapi.Principal{Sub: "agt_x", Kind: approvalapi.KindAgent},
		Purpose:   "pick one", ExpiresAt: c.now().Add(time.Hour), Prompt: p,
	})
}

func secretReq(t *testing.T, c *clock, key, url string) approvalapi.SubmitRequest {
	return digested(t, approvalapi.SubmitRequest{
		IdempotencyKey: key, Source: "warden", Kind: approvalapi.KindSecretRequest, Tier: approvalapi.TierCritical,
		Principal: approvalapi.Principal{Sub: "agt_x", Kind: approvalapi.KindAgent},
		Purpose:   "the API key for x", ExpiresAt: c.now().Add(time.Hour),
		SecretIntake: &approvalapi.SecretIntake{IntakeID: "int_1", IntakeURL: url, ExpiresAt: c.now().Add(30 * time.Minute)},
	})
}

func TestChoiceAndQuestion(t *testing.T) {
	ctx := context.Background()
	svc, c, _ := open(t, cfg(false))
	choices := &approvalapi.Prompt{Question: "Which model?", Choices: []approvalapi.Choice{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}}}
	req := promptReq(t, c, "c1", approvalapi.KindChoice, choices)
	sub, _, err := svc.Submit(ctx, warden, req)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []approvalapi.DecideRequest{
		{Outcome: approvalapi.OutcomeApproved, Choice: "z"},
		{Outcome: approvalapi.OutcomeApproved},
		{Outcome: approvalapi.OutcomeApproved, Choice: "a", Answer: "x"},
	} {
		if _, err = svc.Decide(ctx, owner, sub.ApprovalID, in); err == nil {
			t.Fatalf("bad choice accepted: %+v", in)
		}
	}
	card, err := svc.Card(ctx, owner, sub.ApprovalID)
	if err != nil || card.Type != approvalapi.CardChoose || len(card.Actions) != 2 || card.Actions[0].Decide != approvalapi.PathApprovals+"/"+sub.ApprovalID+"/decide" {
		t.Fatalf("choice card: %v %+v", err, card)
	}
	got, err := svc.Decide(ctx, owner, sub.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved, Choice: "b"})
	if err != nil || got.Status != approvalapi.StatusApproved {
		t.Fatalf("choose: %v %+v", err, got)
	}
	claims, err := approvalapi.VerifyDecision(got.Decision, svc.JWKS(), "warden", c.now())
	if err != nil || claims.Response == nil || claims.Response.Choice != "b" {
		t.Fatalf("choice decision: %v %+v", err, claims)
	}
	if card, _ = svc.Card(ctx, owner, sub.ApprovalID); len(card.Actions) != 0 || card.Outcome == nil || card.Outcome.Response.Choice != "b" {
		t.Fatalf("decided card: %+v", card)
	}

	// Prompts are checked on submit.
	for _, p := range []*approvalapi.Prompt{nil, {Question: "q"}, {Question: "q", Choices: []approvalapi.Choice{{ID: "a", Label: "A"}, {ID: "a", Label: "B"}}}, {Question: "q", Choices: []approvalapi.Choice{{ID: "a b", Label: "A"}, {ID: "c", Label: "C"}}}} {
		if _, _, err = svc.Submit(ctx, warden, promptReq(t, c, "bad", approvalapi.KindChoice, p)); err == nil {
			t.Fatalf("bad prompt accepted: %+v", p)
		}
	}

	q := promptReq(t, c, "q1", approvalapi.KindQuestion, &approvalapi.Prompt{Question: "Why?"})
	qs, _, err := svc.Submit(ctx, warden, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Decide(ctx, owner, qs.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved, Answer: "  "}); err == nil {
		t.Fatal("empty answer accepted")
	}
	qa, err := svc.Decide(ctx, owner, qs.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved, Answer: "Because."})
	if err != nil {
		t.Fatal(err)
	}
	claims, err = approvalapi.VerifyDecision(qa.Decision, svc.JWKS(), "warden", c.now())
	if err != nil || claims.Response == nil || claims.Response.Answer != "Because." {
		t.Fatalf("answer decision: %v %+v", err, claims)
	}
	// A grant takes neither.
	g, _, _ := svc.Submit(ctx, warden, request(t, c, "g1", approvalapi.TierCritical))
	if _, err = svc.Decide(ctx, owner, g.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved, Answer: "x"}); err == nil {
		t.Fatal("answer on a grant accepted")
	}
	if card, _ = svc.Card(ctx, owner, g.ApprovalID); card.Type != approvalapi.CardApprove || card.Requested == nil || card.Actions[0].Kind != approvalapi.ActionApprove {
		t.Fatalf("grant card: %+v", card)
	}
}

func TestSecretRequest(t *testing.T) {
	ctx := context.Background()
	svc, c, st := open(t, withIntake(cfg(false)))

	notCritical := secretReq(t, c, "s0", intakeOrigin+"/intake/int_1")
	notCritical.Tier = approvalapi.TierGround
	notCritical = digested(t, notCritical)
	for name, r := range map[string]approvalapi.SubmitRequest{
		"other origin":   secretReq(t, c, "s0", "https://evil.example/intake"),
		"plain http":     secretReq(t, c, "s0", "http://warden.example/intake"),
		"not critical":   notCritical,
		"other producer": secretReq(t, c, "s0", intakeOrigin+"/intake/int_1"),
	} {
		who := warden
		if name == "other producer" {
			who = other
			r.Source = "other"
		}
		if _, _, err := svc.Submit(ctx, who, r); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}

	req := secretReq(t, c, "s1", intakeOrigin+"/intake/int_1")
	sub, _, err := svc.Submit(ctx, warden, req)
	if err != nil {
		t.Fatal(err)
	}
	card, err := svc.Card(ctx, owner, sub.ApprovalID)
	if err != nil || card.Type != approvalapi.CardRequestSecret || card.Secret == nil || card.Secret.PostURL != req.SecretIntake.IntakeURL || !card.Secret.WriteOnly || card.Actions[0].Decide != "" {
		t.Fatalf("secret card: %v %+v", err, card)
	}
	// Only provided through the producer, never approved by a decide.
	if _, err = svc.Decide(ctx, owner, sub.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}); err == nil {
		t.Fatal("decide approved a secret_request")
	}
	good := approvalapi.SecretProvidedRequest{IntakeID: "int_1", Ref: "warden:secret/sec_123", ProvidedAt: c.now()}
	for name, tc := range map[string]struct {
		who approvalapi.SecretProvidedRequest
		p   bool
	}{
		"wrong intake": {approvalapi.SecretProvidedRequest{IntakeID: "int_2", Ref: good.Ref, ProvidedAt: c.now()}, true},
		"value as ref": {approvalapi.SecretProvidedRequest{IntakeID: "int_1", Ref: "sk live with spaces", ProvidedAt: c.now()}, true},
		"long ref":     {approvalapi.SecretProvidedRequest{IntakeID: "int_1", Ref: strings.Repeat("a", 300), ProvidedAt: c.now()}, true},
		"no time":      {approvalapi.SecretProvidedRequest{IntakeID: "int_1", Ref: good.Ref}, true},
		"not producer": {good, false},
	} {
		caller := warden
		if !tc.p {
			caller = other
		}
		if _, err = svc.SecretProvided(ctx, caller, sub.ApprovalID, tc.who); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	got, err := svc.SecretProvided(ctx, warden, sub.ApprovalID, good)
	if err != nil || got.Status != approvalapi.StatusApproved || got.Secret == nil || got.Secret.Ref != good.Ref {
		t.Fatalf("provided: %v %+v", err, got)
	}
	claims, err := approvalapi.VerifyDecision(got.Decision, svc.JWKS(), "warden", c.now())
	if err != nil || claims.Response == nil || claims.Response.SecretRef != good.Ref || claims.Decider.Kind != approvalapi.KindApp {
		t.Fatalf("secret decision: %v %+v", err, claims)
	}
	exp := approvalapi.Expect{RequestID: req.IdempotencyKey, RequestDigest: req.RequestDigest, Tier: req.Tier, Owner: "chrispian"}
	if claims.Check(exp) == nil {
		t.Fatal("a producer-decided secret_request passed the plain critical check")
	}
	exp.SecretRequest = true
	if err = claims.Check(exp); err != nil {
		t.Fatalf("secret_request check: %v", err)
	}
	if again, rerr := svc.SecretProvided(ctx, warden, sub.ApprovalID, good); rerr != nil || again.Secret.Ref != good.Ref {
		t.Fatalf("repeat: %v", rerr)
	}
	if _, err = svc.SecretProvided(ctx, warden, sub.ApprovalID, approvalapi.SecretProvidedRequest{IntakeID: "int_1", Ref: "other-ref", ProvidedAt: c.now()}); err == nil {
		t.Fatal("a second ref was accepted")
	}
	if card, _ = svc.Card(ctx, owner, sub.ApprovalID); card.Secret != nil || len(card.Actions) != 0 {
		t.Fatalf("closed secret card still has a form: %+v", card)
	}
	// The store holds the reference only: no column anywhere holds a value it never had,
	// and the stored row is exactly the reference.
	var ref string
	if err = st.Reader().QueryRowContext(ctx, `SELECT ref FROM approval_secrets WHERE approval_id=?`, sub.ApprovalID).Scan(&ref); err != nil || ref != good.Ref {
		t.Fatalf("stored ref: %v %q", err, ref)
	}
	// Declining works through decide.
	s2, _, _ := svc.Submit(ctx, warden, secretReq(t, c, "s2", intakeOrigin+"/intake/int_1"))
	if d, err := svc.Decide(ctx, owner, s2.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeDenied}); err != nil || d.Status != approvalapi.StatusDenied {
		t.Fatalf("decline: %v %+v", err, d)
	}
}

func TestFeedIsFilteredByReader(t *testing.T) {
	ctx := context.Background()
	svc, c, _ := open(t, cfg(false))
	mine, _, _ := svc.Submit(ctx, warden, request(t, c, "f1", approvalapi.TierElevated))
	theirs, _, _ := svc.Submit(ctx, other, func() approvalapi.SubmitRequest {
		r := request(t, c, "f2", approvalapi.TierCritical)
		r.Source = "other"
		return r
	}())
	ids := func(evs []approvalapi.FeedEvent) map[string]int {
		out := map[string]int{}
		for _, e := range evs {
			out[e.ApprovalID]++
		}
		return out
	}
	all, last, err := svc.Feed(ctx, owner, 0)
	if err != nil || len(all) != 2 || last != all[1].Seq {
		t.Fatalf("owner feed: %v %d %+v", err, last, all)
	}
	w, _, _ := svc.Feed(ctx, warden, 0)
	if got := ids(w); got[mine.ApprovalID] != 1 || got[theirs.ApprovalID] != 0 {
		t.Fatalf("warden sees: %+v", got)
	}
	a, _, _ := svc.Feed(ctx, approver, 0)
	if got := ids(a); got[mine.ApprovalID] != 1 || got[theirs.ApprovalID] != 0 {
		t.Fatalf("approver sees: %+v", got)
	}
	o, scanned, _ := svc.Feed(ctx, other, all[0].Seq)
	if len(o) != 1 || o[0].ApprovalID != theirs.ApprovalID || scanned != last {
		t.Fatalf("other after first: %+v %d", o, scanned)
	}
	// Resuming after the end gives nothing; a change wakes Changed.
	wake := svc.Changed()
	if _, err = svc.Decide(ctx, owner, mine.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeDenied}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wake:
	case <-time.After(time.Second):
		t.Fatal("a decision did not wake the stream")
	}
	next, _, _ := svc.Feed(ctx, warden, last)
	if len(next) != 1 || next[0].Type != "decided" || next[0].Status != approvalapi.StatusDenied {
		t.Fatalf("after decide: %+v", next)
	}
}

type hookSink struct {
	mu     sync.Mutex
	status int
	got    []approvalapi.WebhookDelivery
	sigs   []string
	bodies [][]byte
}

func (h *hookSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.status != 0 {
		w.WriteHeader(h.status)
		return
	}
	var d approvalapi.WebhookDelivery
	_ = json.Unmarshal(b, &d)
	h.got = append(h.got, d)
	h.sigs = append(h.sigs, r.Header.Get(approvalapi.HeaderWebhookSignature))
	h.bodies = append(h.bodies, b)
}

func TestWebhooks(t *testing.T) {
	ctx := context.Background()
	sink := &hookSink{}
	srv := httptest.NewServer(sink)
	t.Cleanup(srv.Close)
	secret := []byte(strings.Repeat("k", 40))
	a := cfg(false)
	a.Webhooks = []settings.Webhook{{Name: "basalisk", URL: srv.URL, SecretFile: "hook.key", View: "owner"}, {Name: "class", URL: srv.URL, SecretFile: "hook.key", View: class}}
	svc, c, st := open(t, a)
	dir := filepath.Dir(st.Config().SQLite.Path)
	key := filepath.Join(dir, "hook.key")
	if err := os.WriteFile(key, secret, 0o644); err != nil { //nolint:gosec // the point: a readable key is refused
		t.Fatal(err)
	}
	if _, err := svc.Webhooks(dir); err == nil {
		t.Fatal("a world-readable webhook key was accepted")
	}
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	subs, err := svc.Webhooks(dir)
	if err != nil || len(subs) != 2 {
		t.Fatalf("subscribers: %v %d", err, len(subs))
	}
	// What happened before a subscriber first ran is not replayed to it.
	_, _, _ = svc.Submit(ctx, warden, request(t, c, "h0", approvalapi.TierCritical))
	if sent, derr := svc.DeliverOnce(ctx, subs[0], srv.Client()); derr != nil || sent {
		t.Fatalf("first run: %v %v", derr, sent)
	}
	crit, _, _ := svc.Submit(ctx, warden, request(t, c, "h1", approvalapi.TierCritical))
	if sent, derr := svc.DeliverOnce(ctx, subs[0], srv.Client()); derr != nil || !sent {
		t.Fatalf("deliver: %v %v", derr, sent)
	}
	if len(sink.got) != 1 || len(sink.got[0].Events) != 1 || sink.got[0].Events[0].ApprovalID != crit.ApprovalID {
		t.Fatalf("delivered: %+v", sink.got)
	}
	if err = approvalapi.VerifyWebhook(secret, sink.bodies[0], sink.sigs[0], c.now()); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if approvalapi.VerifyWebhook([]byte("wrong-key-wrong-key-wrong-key-wrong"), sink.bodies[0], sink.sigs[0], c.now()) == nil {
		t.Fatal("a wrong key verified")
	}
	// Nothing new: nothing sent. A failing subscriber is retried from the same place.
	if sent, _ := svc.DeliverOnce(ctx, subs[0], srv.Client()); sent {
		t.Fatal("sent with nothing new")
	}
	_, _ = svc.Decide(ctx, owner, crit.ApprovalID, approvalapi.DecideRequest{Outcome: approvalapi.OutcomeDenied})
	sink.status = http.StatusInternalServerError
	if _, err = svc.DeliverOnce(ctx, subs[0], srv.Client()); err == nil {
		t.Fatal("a 500 was taken as delivered")
	}
	sink.status = 0
	if sent, err := svc.DeliverOnce(ctx, subs[0], srv.Client()); err != nil || !sent || sink.got[1].Events[0].Type != "decided" {
		t.Fatalf("redeliver: %v %v %+v", err, sent, sink.got)
	}
	// The class subscriber sees no critical request.
	if sent, err := svc.DeliverOnce(ctx, subs[1], srv.Client()); err != nil || sent {
		t.Fatalf("class subscriber first run: %v %v", err, sent)
	}
	_, _, _ = svc.Submit(ctx, warden, request(t, c, "h2", approvalapi.TierCritical))
	if sent, err := svc.DeliverOnce(ctx, subs[1], srv.Client()); err != nil || sent {
		t.Fatalf("class subscriber got a critical request: %v %v", err, sent)
	}
	el, _, _ := svc.Submit(ctx, warden, request(t, c, "h3", approvalapi.TierElevated))
	if sent, err := svc.DeliverOnce(ctx, subs[1], srv.Client()); err != nil || !sent || sink.got[len(sink.got)-1].Events[0].ApprovalID != el.ApprovalID {
		t.Fatalf("class subscriber: %v %v", err, sent)
	}
}

var _ = approvals.FeedLimit
