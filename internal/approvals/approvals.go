// Package approvals is Gatecrasher's approval inbox and decision store (gate v1): it
// records producers' requests as immutable snapshots, applies the tier rules to
// decisions, signs them and answers status. The HTTP adapter is internal/api.
package approvals

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hollis-labs/libs/core/store"
	libauth "github.com/hollis-labs/libs/security/auth"

	"github.com/hollis-labs/gatecrasher/internal/settings"
	"github.com/hollis-labs/gatecrasher/pkg/approvalapi"
)

// Limits on what a submit may carry.
const (
	MaxBody        = 64 << 10
	maxKey         = 128
	maxShort       = 64
	maxPurpose     = 2000
	maxScopes      = 64
	maxApprovalAge = 30 * 24 * time.Hour
	sweepEvery     = 15 * time.Second
)

// gatecrasherSub is the decider of ground requests, which are approved on arrival.
const gatecrasherSub = "gatecrasher"

// ts is the stored time format: fixed width, so stored times compare as strings.
const ts = "2006-01-02T15:04:05.000000000Z"

// Error is a refusal with the HTTP status and contract code it maps to.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func fail(status int, code, msg string) *Error { return &Error{status, code, msg} }

var errUnavailable = fail(http.StatusServiceUnavailable, approvalapi.ErrCodeUnavailable, "Approvals are not configured")

// Config is trusted operator configuration.
type Config struct {
	Settings settings.Approvals
	// DataDir resolves a relative DecisionKeyFile.
	DataDir string
	Now     func() time.Time
}

// Service is the approval inbox. Create it with New and run Sweep in the background.
type Service struct {
	st  *store.Store
	cfg settings.Approvals
	now func() time.Time
	key ed25519.PrivateKey
	kid string

	mu      sync.Mutex
	waiters map[string][]chan struct{}
}

// New opens the inbox on st and loads (or creates) the decision signing key.
func New(st *store.Store, cfg Config) (*Service, error) {
	if st == nil {
		return nil, errors.New("approvals: no store")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	path := cfg.Settings.DecisionKeyFile
	if path == "" {
		path = "decision-signing.key"
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cfg.DataDir, path)
	}
	key, err := loadOrCreateKey(path)
	if err != nil {
		return nil, err
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	return &Service{st: st, cfg: cfg.Settings, now: func() time.Time { return now().UTC() }, key: key, kid: keyID(pub), waiters: map[string][]chan struct{}{}}, nil
}

// JWKS is the public key set decisions verify against.
func (s *Service) JWKS() approvalapi.JWKS {
	pub, _ := s.key.Public().(ed25519.PublicKey)
	return approvalapi.JWKS{Keys: []approvalapi.JWK{approvalapi.PublicJWK(s.kid, pub)}}
}

// configured reports whether the owner is set; without one nothing can be decided.
func (s *Service) configured() bool { return s.cfg.Owner.Principal != "" }

// row is a stored approval.
type row struct {
	ID, Submitter, Key, Digest, Source, Tier, Class, Snapshot, Expires, Status string
	JWS                                                                        sql.NullString
}

func (r row) answer() approvalapi.Approval {
	return approvalapi.Approval{ApprovalID: r.ID, Status: approvalapi.Status(r.Status), Decision: r.JWS.String}
}

func (r row) request() (approvalapi.SubmitRequest, error) {
	var req approvalapi.SubmitRequest
	err := json.Unmarshal([]byte(r.Snapshot), &req)
	return req, err
}

const selectRow = `SELECT a.approval_id, a.submitter, a.idempotency_key, a.request_digest, a.source, a.tier, a.approver_class, a.snapshot_json, a.expires_at, a.status, d.jws
 FROM approvals a LEFT JOIN approval_decisions d ON d.approval_id = a.approval_id `

func scan(sc interface{ Scan(...any) error }) (row, error) {
	var r row
	err := sc.Scan(&r.ID, &r.Submitter, &r.Key, &r.Digest, &r.Source, &r.Tier, &r.Class, &r.Snapshot, &r.Expires, &r.Status, &r.JWS)
	return r, err
}

func (s *Service) load(ctx context.Context, q store.Querier, id string) (row, error) {
	r, err := scan(q.QueryRowContext(ctx, selectRow+`WHERE a.approval_id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, fail(http.StatusNotFound, approvalapi.ErrCodeNotFound, "No such approval")
	}
	return r, err
}

// Submit records a producer's request. created is false when the same key and digest
// were submitted before; the earlier approval is returned.
func (s *Service) Submit(ctx context.Context, caller libauth.Principal, req approvalapi.SubmitRequest) (approvalapi.SubmitResponse, bool, error) {
	var out approvalapi.SubmitResponse
	source, ok := s.cfg.Producers[caller.ID]
	if !ok {
		return out, false, fail(http.StatusForbidden, approvalapi.ErrCodeForbidden, "Not a configured producer")
	}
	if !s.configured() {
		return out, false, errUnavailable
	}
	now := s.now()
	if err := s.validate(req, source, now); err != nil {
		return out, false, err
	}
	digest, err := req.Digest()
	if err != nil {
		return out, false, fail(http.StatusBadRequest, approvalapi.ErrCodeInvalid, "The request cannot be digested")
	}
	if digest != req.RequestDigest {
		return out, false, fail(http.StatusUnprocessableEntity, approvalapi.ErrCodeDigestMismatch, "request_digest does not match principal, requested and tier")
	}
	snap, err := json.Marshal(req)
	if err != nil {
		return out, false, err
	}
	created := false
	err = s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		prev, qerr := scan(tx.QueryRowContext(ctx, selectRow+`WHERE a.submitter = ? AND a.idempotency_key = ?`, caller.ID, req.IdempotencyKey))
		switch {
		case qerr == nil:
			if prev.Digest != digest {
				return fail(http.StatusConflict, approvalapi.ErrCodeIdempotency, "This idempotency_key was submitted with a different request")
			}
			out = approvalapi.SubmitResponse{ApprovalID: prev.ID, Status: approvalapi.Status(prev.Status)}
			return nil
		case !errors.Is(qerr, sql.ErrNoRows):
			return qerr
		}
		created = true
		id := newID("apr")
		at := now.Format(ts)
		if _, err = tx.ExecContext(ctx, `INSERT INTO approvals(approval_id, submitter, idempotency_key, request_digest, source, kind, tier, approver_class, snapshot_json, expires_at, created_at, status, status_at)
 VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending',?)`, id, caller.ID, req.IdempotencyKey, digest, req.Source, req.Kind, string(req.Tier), req.ApproverClass, string(snap), req.ExpiresAt.UTC().Format(ts), at, at); err != nil {
			return err
		}
		if err = event(ctx, tx, id, "submitted", caller.ID, map[string]any{"tier": req.Tier, "source": req.Source, "kind": req.Kind}, now); err != nil {
			return err
		}
		out = approvalapi.SubmitResponse{ApprovalID: id, Status: approvalapi.StatusPending}
		if req.Tier != approvalapi.TierGround {
			return nil
		}
		// Ground is recorded and approved on arrival, by Gatecrasher itself.
		r := row{ID: id, Key: req.IdempotencyKey, Digest: digest, Source: req.Source, Tier: string(req.Tier)}
		d := approvalapi.Actor{Sub: gatecrasherSub, Kind: approvalapi.KindApp}
		if err = s.decide(ctx, tx, r, d, gatecrasherSub, approvalapi.OutcomeApproved, nil, "ground", now); err != nil {
			return err
		}
		out.Status = approvalapi.StatusApproved
		return nil
	})
	if err != nil {
		return approvalapi.SubmitResponse{}, false, err
	}
	if created && out.Status != approvalapi.StatusPending {
		s.notify(out.ApprovalID)
	}
	return out, created, nil
}

func (s *Service) validate(req approvalapi.SubmitRequest, source string, now time.Time) error {
	bad := func(msg string) error { return fail(http.StatusBadRequest, approvalapi.ErrCodeInvalid, msg) }
	switch {
	case req.IdempotencyKey == "" || len(req.IdempotencyKey) > maxKey:
		return bad("idempotency_key is required (at most 128 bytes)")
	case req.Source != source:
		return fail(http.StatusForbidden, approvalapi.ErrCodeForbidden, "source does not match the caller")
	case req.Kind == "" || len(req.Kind) > maxShort:
		return bad("kind is required")
	case !req.Tier.Valid():
		return bad("tier must be ground, elevated or critical")
	case req.Tier == approvalapi.TierElevated && req.ApproverClass == "":
		return bad("approver_class is required for elevated")
	case req.Tier != approvalapi.TierElevated && req.ApproverClass != "":
		return bad("approver_class is only for elevated")
	case req.Principal.Sub == "" || !validKind(req.Principal.Kind):
		return bad("principal needs sub and a known kind")
	case req.Requested.Audience == "" || req.Requested.TTLSeconds <= 0 || len(req.Requested.Scopes) > maxScopes:
		return bad("requested needs audience and a positive ttl_seconds")
	case len(req.Purpose) > maxPurpose:
		return bad("purpose is too long")
	case req.RequestDigest == "":
		return bad("request_digest is required")
	case !req.ExpiresAt.After(now) || req.ExpiresAt.Sub(now) > maxApprovalAge:
		return bad("expires_at must be in the future and within 30 days")
	}
	if req.Tier == approvalapi.TierElevated {
		if _, ok := s.cfg.Classes[req.ApproverClass]; !ok {
			return bad("approver_class is not a configured class")
		}
	}
	for _, a := range req.Principal.Act {
		if a.Sub == "" || !validKind(a.Kind) {
			return bad("every act entry needs sub and a known kind")
		}
	}
	for _, sc := range req.Requested.Scopes {
		if sc == "" {
			return bad("empty scope")
		}
	}
	return nil
}

func validKind(k approvalapi.PrincipalKind) bool {
	switch k {
	case approvalapi.KindAgent, approvalapi.KindSession, approvalapi.KindMachine, approvalapi.KindApp, approvalapi.KindHuman:
		return true
	}
	return false
}

// mayRead: the submitter, the owner, and the class's approver agents.
func (s *Service) mayRead(caller libauth.Principal, r row) bool {
	if caller.ID == r.Submitter || s.isOwner(caller) {
		return true
	}
	c, ok := s.cfg.Classes[r.Class]
	_, agent := c.Agents[caller.ID]
	return ok && agent && hasExact(caller, r.Class)
}

func (s *Service) isOwner(p libauth.Principal) bool {
	return s.cfg.Owner.Principal != "" && p.ID == s.cfg.Owner.Principal && p.Kind == libauth.KindOperator
}

// hasExact: approver classes are never granted by a wildcard scope.
func hasExact(p libauth.Principal, scope string) bool { return slices.Contains(p.Scopes, scope) }

// Get answers an approval's status, expiring it first when its time has passed.
func (s *Service) Get(ctx context.Context, caller libauth.Principal, id string) (approvalapi.Approval, error) {
	r, err := s.load(ctx, s.st.Reader(), id)
	if err != nil {
		return approvalapi.Approval{}, err
	}
	if !s.mayRead(caller, r) {
		// Same answer as a missing id, so ids cannot be probed.
		return approvalapi.Approval{}, fail(http.StatusNotFound, approvalapi.ErrCodeNotFound, "No such approval")
	}
	if r.Status == string(approvalapi.StatusPending) && r.Expires <= s.now().Format(ts) {
		if _, err = s.Sweep(ctx); err != nil {
			return approvalapi.Approval{}, err
		}
		if r, err = s.load(ctx, s.st.Reader(), id); err != nil {
			return approvalapi.Approval{}, err
		}
	}
	return r.answer(), nil
}

// Await answers as soon as the approval is no longer pending, or after timeout (capped
// at approvalapi.MaxAwait) with its current status.
func (s *Service) Await(ctx context.Context, caller libauth.Principal, id string, timeout time.Duration) (approvalapi.Approval, error) {
	timeout = min(timeout, approvalapi.MaxAwait)
	ch := s.subscribe(id)
	defer s.unsubscribe(id, ch)
	a, err := s.Get(ctx, caller, id)
	if err != nil || a.Status.Terminal() || timeout <= 0 {
		return a, err
	}
	r, err := s.load(ctx, s.st.Reader(), id)
	if err != nil {
		return approvalapi.Approval{}, err
	}
	// Wake at the approval's own expiry too, so a waiter sees it expire.
	until := timeout
	if exp, perr := time.Parse(ts, r.Expires); perr == nil {
		until = min(until, max(exp.Sub(s.now()), 0)+time.Millisecond)
	}
	t := time.NewTimer(until)
	defer t.Stop()
	select {
	case <-ch:
	case <-t.C:
	case <-ctx.Done():
		return approvalapi.Approval{}, ctx.Err()
	}
	return s.Get(ctx, caller, id)
}

// Withdraw takes back a pending request. Only its submitter may; withdrawing twice
// answers the same; withdrawing a decided or expired request is refused.
func (s *Service) Withdraw(ctx context.Context, caller libauth.Principal, id string) (approvalapi.Approval, error) {
	now := s.now()
	var out approvalapi.Approval
	changed := false
	err := s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		r, err := s.load(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.Submitter != caller.ID {
			return fail(http.StatusNotFound, approvalapi.ErrCodeNotFound, "No such approval")
		}
		switch approvalapi.Status(r.Status) {
		case approvalapi.StatusWithdrawn:
			out = r.answer()
			return nil
		case approvalapi.StatusPending:
		default:
			return fail(http.StatusConflict, approvalapi.ErrCodeTerminal, "The approval is already "+r.Status)
		}
		if err = setStatus(ctx, tx, id, approvalapi.StatusWithdrawn, now); err != nil {
			return err
		}
		changed = true
		r.Status = string(approvalapi.StatusWithdrawn)
		out = r.answer()
		return event(ctx, tx, id, "withdrawn", caller.ID, map[string]any{}, now)
	})
	if err != nil {
		return approvalapi.Approval{}, err
	}
	if changed {
		s.notify(id)
	}
	return out, nil
}

// Decide applies a decision from a surface (the owner) or an approver agent.
//
//   - ground: already decided on arrival.
//   - elevated: the owner, or an agent configured for the class that holds the class as a
//     scope. An agent's approval must stay within the class ceiling; in shadow mode the
//     agent's decision is recorded only and the request stays pending.
//   - critical: the owner only.
func (s *Service) Decide(ctx context.Context, caller libauth.Principal, id string, in approvalapi.DecideRequest) (approvalapi.DecideResponse, error) {
	var out approvalapi.DecideResponse
	if !s.configured() {
		return out, errUnavailable
	}
	if in.Outcome != approvalapi.OutcomeApproved && in.Outcome != approvalapi.OutcomeDenied {
		return out, fail(http.StatusBadRequest, approvalapi.ErrCodeInvalid, "outcome must be approved or denied")
	}
	if len(in.Note) > maxPurpose {
		return out, fail(http.StatusBadRequest, approvalapi.ErrCodeInvalid, "note is too long")
	}
	// Expire what is due first, so a late decision meets an expired approval.
	if _, err := s.Sweep(ctx); err != nil {
		return out, err
	}
	now := s.now()
	decided := false
	err := s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		r, err := s.load(ctx, tx, id)
		if err != nil {
			return err
		}
		if !s.mayRead(caller, r) {
			return fail(http.StatusNotFound, approvalapi.ErrCodeNotFound, "No such approval")
		}
		if r.Status == string(approvalapi.StatusPending) && r.Expires <= now.Format(ts) {
			// The sweep before this transaction expires it; nothing is written here.
			return fail(http.StatusConflict, approvalapi.ErrCodeTerminal, "The approval has expired")
		}
		if r.Status != string(approvalapi.StatusPending) {
			return fail(http.StatusConflict, approvalapi.ErrCodeTerminal, "The approval is already "+r.Status)
		}
		req, err := r.request()
		if err != nil {
			return err
		}
		narrowed, err := checkNarrowing(req.Requested, in.Narrowed)
		if err != nil {
			return err
		}
		var who approvalapi.Actor
		switch {
		case s.isOwner(caller):
			who = approvalapi.Actor{Sub: s.cfg.Owner.Sub, Kind: approvalapi.KindHuman}
		case approvalapi.Tier(r.Tier) == approvalapi.TierElevated:
			c := s.cfg.Classes[r.Class]
			sub, ok := c.Agents[caller.ID]
			if !ok || !hasExact(caller, r.Class) {
				return fail(http.StatusForbidden, approvalapi.ErrCodeNotDecider, "Not an approver for "+r.Class)
			}
			if in.Outcome == approvalapi.OutcomeApproved && !withinCeiling(c.Ceiling, req.Requested, narrowed) {
				return fail(http.StatusForbidden, approvalapi.ErrCodeCeiling, "Approving this exceeds the class ceiling; it waits for the owner")
			}
			who = approvalapi.Actor{Sub: sub, Kind: approvalapi.KindAgent}
			if c.Shadow {
				nj, _ := json.Marshal(narrowedOrEmpty(narrowed))
				if _, err = tx.ExecContext(ctx, `INSERT INTO approval_shadow_decisions(approval_id, outcome, decider_sub, decider_principal, narrowed_json, decided_at) VALUES(?,?,?,?,?,?)`,
					r.ID, string(in.Outcome), sub, caller.ID, string(nj), now.Format(ts)); err != nil {
					return err
				}
				out = approvalapi.DecideResponse{Approval: r.answer(), Shadow: true}
				return event(ctx, tx, r.ID, "shadow_decided", caller.ID, map[string]any{"outcome": in.Outcome, "decider": sub, "note": in.Note}, now)
			}
		default:
			return fail(http.StatusForbidden, approvalapi.ErrCodeNotDecider, "Only the owner decides "+r.Tier+" requests")
		}
		if err = s.decide(ctx, tx, r, who, caller.ID, in.Outcome, narrowed, in.Note, now); err != nil {
			return err
		}
		decided = true
		got, err := s.load(ctx, tx, r.ID)
		out = approvalapi.DecideResponse{Approval: got.answer()}
		return err
	})
	if decided {
		s.notify(id)
	}
	if err != nil {
		return approvalapi.DecideResponse{}, err
	}
	return out, nil
}

// decide moves a pending approval to its outcome and stores the signed decision.
func (s *Service) decide(ctx context.Context, tx store.Tx, r row, who approvalapi.Actor, principal string, outcome approvalapi.Outcome, narrowed *approvalapi.Narrowed, note string, now time.Time) error {
	jti := newID("dec")
	claims := approvalapi.DecisionClaims{
		Iss: approvalapi.Issuer, Aud: r.Source, Jti: jti,
		Iat: now.Unix(), Exp: now.Add(approvalapi.MaxDecisionLifetime).Unix(),
		ApprovalID: r.ID, RequestID: r.Key, RequestDigest: r.Digest,
		Outcome: outcome, Tier: approvalapi.Tier(r.Tier), Decider: who,
		DecidedAt: now.Truncate(time.Second), Narrowed: narrowed,
	}
	jws, err := approvalapi.SignDecision(s.key, s.kid, claims)
	if err != nil {
		return err
	}
	status := approvalapi.StatusApproved
	if outcome == approvalapi.OutcomeDenied {
		status = approvalapi.StatusDenied
	}
	if err = setStatus(ctx, tx, r.ID, status, now); err != nil {
		return err
	}
	nj, _ := json.Marshal(narrowedOrEmpty(narrowed))
	if _, err = tx.ExecContext(ctx, `INSERT INTO approval_decisions(approval_id, jti, outcome, decider_sub, decider_kind, decider_principal, narrowed_json, decided_at, kid, jws) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		r.ID, jti, string(outcome), who.Sub, string(who.Kind), principal, string(nj), now.Format(ts), s.kid, jws); err != nil {
		return err
	}
	return event(ctx, tx, r.ID, "decided", principal, map[string]any{"outcome": outcome, "decider": who, "jti": jti, "note": note}, now)
}

func narrowedOrEmpty(n *approvalapi.Narrowed) any {
	if n == nil {
		return map[string]any{}
	}
	return n
}

// checkNarrowing refuses a narrowing that widens: scopes must be requested ones, without
// repeats, and the TTL no longer than requested. An empty narrowing is none.
func checkNarrowing(req approvalapi.Requested, n *approvalapi.Narrowed) (*approvalapi.Narrowed, error) {
	if n == nil || (len(n.Scopes) == 0 && n.TTLSeconds == 0) {
		return nil, nil
	}
	bad := fail(http.StatusBadRequest, approvalapi.ErrCodeInvalid, "narrowed may only drop requested scopes or shorten the TTL")
	seen := map[string]bool{}
	for _, sc := range n.Scopes {
		if seen[sc] || !slices.Contains(req.Scopes, sc) {
			return nil, bad
		}
		seen[sc] = true
	}
	if n.TTLSeconds < 0 || n.TTLSeconds > req.TTLSeconds {
		return nil, bad
	}
	return n, nil
}

// withinCeiling: what the agent would grant (after narrowing) fits the class ceiling.
func withinCeiling(c settings.Ceiling, req approvalapi.Requested, n *approvalapi.Narrowed) bool {
	scopes, ttl := req.Scopes, req.TTLSeconds
	if n != nil {
		if len(n.Scopes) > 0 {
			scopes = n.Scopes
		}
		if n.TTLSeconds > 0 {
			ttl = n.TTLSeconds
		}
	}
	if c.MaxTTLSeconds <= 0 || ttl > c.MaxTTLSeconds || !slices.Contains(c.Audiences, req.Audience) {
		return false
	}
	for _, sc := range scopes {
		if !slices.Contains(c.Scopes, sc) {
			return false
		}
	}
	return true
}

// Sweep expires every pending approval whose time has passed and wakes its waiters.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	now := s.now()
	var ids []string
	err := s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		ids = ids[:0]
		rows, err := tx.QueryContext(ctx, `SELECT approval_id FROM approvals WHERE status='pending' AND expires_at <= ?`, now.Format(ts))
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err = rows.Close(); err != nil {
			return err
		}
		for _, id := range ids {
			if err = expire(ctx, tx, id, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		s.notify(id)
	}
	return len(ids), nil
}

// Run sweeps until ctx ends.
func (s *Service) Run(ctx context.Context, errs func(error)) {
	t := time.NewTicker(sweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.Sweep(ctx); err != nil && errs != nil && ctx.Err() == nil {
				errs(err)
			}
		}
	}
}

func expire(ctx context.Context, tx store.Tx, id string, now time.Time) error {
	if err := setStatus(ctx, tx, id, approvalapi.StatusExpired, now); err != nil {
		return err
	}
	return event(ctx, tx, id, "expired", gatecrasherSub, map[string]any{}, now)
}

func setStatus(ctx context.Context, tx store.Tx, id string, st approvalapi.Status, now time.Time) error {
	res, err := tx.ExecContext(ctx, `UPDATE approvals SET status=?, status_at=? WHERE approval_id=? AND status='pending'`, string(st), now.Format(ts), id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return fail(http.StatusConflict, approvalapi.ErrCodeTerminal, "The approval is no longer pending")
	}
	return nil
}

func event(ctx context.Context, tx store.Tx, id, typ, actor string, detail any, now time.Time) error {
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO approval_events(approval_id, type, actor, detail_json, at) VALUES(?,?,?,?,?)`, id, typ, actor, string(b), now.Format(ts))
	return err
}

// Event is one entry of an approval's log.
type Event struct {
	Seq    int64           `json:"seq"`
	Type   string          `json:"type"`
	Actor  string          `json:"actor"`
	Detail json.RawMessage `json:"detail"`
	At     string          `json:"at"`
}

// Events is an approval's append-only log, oldest first (for the runbook and tests).
func (s *Service) Events(ctx context.Context, id string) ([]Event, error) {
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT seq, type, actor, detail_json, at FROM approval_events WHERE approval_id=? ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Event
	for rows.Next() {
		var e Event
		var d string
		if err = rows.Scan(&e.Seq, &e.Type, &e.Actor, &d, &e.At); err != nil {
			return nil, err
		}
		e.Detail = json.RawMessage(d)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Service) subscribe(id string) chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.waiters[id] = append(s.waiters[id], ch)
	s.mu.Unlock()
	return ch
}

func (s *Service) unsubscribe(id string, ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws := slices.DeleteFunc(s.waiters[id], func(c chan struct{}) bool { return c == ch })
	if len(ws) == 0 {
		delete(s.waiters, id)
	} else {
		s.waiters[id] = ws
	}
}

func (s *Service) notify(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.waiters[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

var idEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

func newID(prefix string) string {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("approvals: random: %v", err))
	}
	return prefix + "_" + strings.ToLower(idEnc.EncodeToString(b))
}
