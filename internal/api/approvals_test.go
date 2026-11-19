package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/hollis-labs/libs/core/store"
	"github.com/hollis-labs/libs/core/store/migrate"
	libauth "github.com/hollis-labs/libs/security/auth"

	"github.com/hollis-labs/gatecrasher/internal/api"
	"github.com/hollis-labs/gatecrasher/internal/approvals"
	"github.com/hollis-labs/gatecrasher/internal/settings"
	"github.com/hollis-labs/gatecrasher/internal/storage"
	"github.com/hollis-labs/gatecrasher/pkg/approvalapi"
)

type tokens map[string]libauth.Principal

func (t tokens) Verify(_ context.Context, tok string) (libauth.Principal, error) {
	if p, ok := t[tok]; ok {
		return p, nil
	}
	return libauth.Principal{}, errors.New("unknown token")
}

const cls = "approve.credentials"

func server(t *testing.T, shadow bool) *httptest.Server {
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
	svc, err := approvals.New(st, approvals.Config{DataDir: dir, Settings: settings.Approvals{
		Owner:     settings.Owner{Principal: "user:usr_owner", Sub: "chrispian"},
		Producers: map[string]string{"key:warden": "warden"},
		Classes: map[string]settings.Class{cls: {
			Agents:  map[string]string{"key:approver": "agt_approver"},
			Ceiling: settings.Ceiling{MaxTTLSeconds: 3600, Audiences: []string{"llm-gateway"}, Scopes: []string{"llm-gateway.decide"}},
			Shadow:  shadow,
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	g := "gatecrasher"
	v := tokens{
		"warden":    {Verified: true, ID: "key:warden", Kind: libauth.KindService, Audience: g, Scopes: []string{approvalapi.ScopeSubmit, approvalapi.ScopeRead}},
		"reader":    {Verified: true, ID: "key:reader", Kind: libauth.KindService, Audience: g, Scopes: []string{approvalapi.ScopeRead}},
		"owner":     {Verified: true, ID: "user:usr_owner", Kind: "user", Audience: g, Scopes: []string{"*"}},
		"approver":  {Verified: true, ID: "key:approver", Kind: libauth.KindService, Audience: g, Scopes: []string{approvalapi.ScopeDecide, approvalapi.ScopeRead, cls}},
		"elsewhere": {Verified: true, ID: "key:warden", Kind: libauth.KindService, Audience: "tachyon", Scopes: []string{"*"}},
	}
	srv := httptest.NewServer(api.New(nil, v).WithApprovals(svc).Mux())
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, srv *httptest.Server, method, path, token string, body any, out any) int {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if out != nil {
		_ = json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

func submitBody(t *testing.T, key string, tier approvalapi.Tier, ttl int64) approvalapi.SubmitRequest {
	t.Helper()
	r := approvalapi.SubmitRequest{
		IdempotencyKey: key, Source: "warden", Kind: approvalapi.KindCredentialGrant, Tier: tier,
		Principal: approvalapi.Principal{Sub: "agt_x", Kind: approvalapi.KindAgent},
		Requested: approvalapi.Requested{Audience: "llm-gateway", Scopes: []string{"llm-gateway.decide"}, TTLSeconds: ttl},
		Purpose:   "http test", ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
	if tier == approvalapi.TierElevated {
		r.ApproverClass = cls
	}
	r.RequestDigest, _ = r.Digest()
	return r
}

func TestApprovalHTTPContract(t *testing.T) {
	srv := server(t, false)
	p := approvalapi.PathApprovals
	body := submitBody(t, "req-1", approvalapi.TierCritical, 600)

	if c := call(t, srv, "POST", p, "", body, nil); c != 401 {
		t.Fatalf("no token: %d", c)
	}
	if c := call(t, srv, "POST", p, "reader", body, nil); c != 403 {
		t.Fatalf("read-only submit: %d", c)
	}
	if c := call(t, srv, "POST", p, "elsewhere", body, nil); c != 403 {
		t.Fatalf("wrong audience: %d", c)
	}
	var sub approvalapi.SubmitResponse
	if c := call(t, srv, "POST", p, "warden", body, &sub); c != 201 || sub.Status != approvalapi.StatusPending {
		t.Fatalf("submit: %d %+v", c, sub)
	}
	var again approvalapi.SubmitResponse
	if c := call(t, srv, "POST", p, "warden", body, &again); c != 200 || again.ApprovalID != sub.ApprovalID {
		t.Fatalf("resubmit: %d %+v", c, again)
	}
	changed := submitBody(t, "req-1", approvalapi.TierCritical, 60)
	var e approvalapi.Error
	if c := call(t, srv, "POST", p, "warden", changed, &e); c != 409 || e.Code != approvalapi.ErrCodeIdempotency {
		t.Fatalf("conflict: %d %+v", c, e)
	}
	bad := submitBody(t, "req-2", approvalapi.TierCritical, 600)
	bad.RequestDigest = "sha256:00"
	if c := call(t, srv, "POST", p, "warden", bad, &e); c != 422 || e.Code != approvalapi.ErrCodeDigestMismatch {
		t.Fatalf("digest: %d %+v", c, e)
	}
	if c := call(t, srv, "POST", p, "warden", map[string]any{"nope": 1}, &e); c != 400 || e.Code != approvalapi.ErrCodeInvalid {
		t.Fatalf("unknown field: %d %+v", c, e)
	}

	var a approvalapi.Approval
	if c := call(t, srv, "GET", p+"/"+sub.ApprovalID, "warden", nil, &a); c != 200 || a.Status != approvalapi.StatusPending {
		t.Fatalf("get: %d %+v", c, a)
	}
	if c := call(t, srv, "GET", p+"/apr_missing", "warden", nil, &e); c != 404 || e.Code != approvalapi.ErrCodeNotFound {
		t.Fatalf("missing: %d", c)
	}
	start := time.Now()
	if c := call(t, srv, "GET", p+"/"+sub.ApprovalID+"/await?timeout=50ms", "warden", nil, &a); c != 200 || a.Status != approvalapi.StatusPending || time.Since(start) < 40*time.Millisecond {
		t.Fatalf("await timeout: %d %+v", c, a)
	}
	if c := call(t, srv, "GET", p+"/"+sub.ApprovalID+"/await?timeout=soon", "warden", nil, &e); c != 400 {
		t.Fatalf("bad timeout: %d", c)
	}

	// An approver agent cannot see a critical request, let alone decide it; the owner may.
	if c := call(t, srv, "POST", p+"/"+sub.ApprovalID+"/decide", "approver", approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}, &e); c != 404 || e.Code != approvalapi.ErrCodeNotFound {
		t.Fatalf("agent on critical: %d %+v", c, e)
	}
	var d approvalapi.DecideResponse
	if c := call(t, srv, "POST", p+"/"+sub.ApprovalID+"/decide", "owner", approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}, &d); c != 200 || d.Status != approvalapi.StatusApproved {
		t.Fatalf("owner decide: %d %+v", c, d)
	}
	// Withdrawing a decided approval is terminal.
	if c := call(t, srv, "POST", p+"/"+sub.ApprovalID+"/withdraw", "warden", nil, &e); c != 409 || e.Code != approvalapi.ErrCodeTerminal {
		t.Fatalf("withdraw decided: %d %+v", c, e)
	}

	// The decision verifies against the published key set.
	var keys approvalapi.JWKS
	if c := call(t, srv, "GET", approvalapi.PathJWKS, "warden", nil, &keys); c != 200 || len(keys.Keys) != 1 {
		t.Fatalf("jwks: %d %+v", c, keys)
	}
	if c := call(t, srv, "GET", p+"/"+sub.ApprovalID, "warden", nil, &a); c != 200 || a.Decision == "" {
		t.Fatalf("get decided: %d %+v", c, a)
	}
	cl, err := approvalapi.VerifyDecision(a.Decision, keys, "warden", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = cl.Check(approvalapi.Expect{RequestID: "req-1", RequestDigest: body.RequestDigest, Tier: approvalapi.TierCritical, Requested: body.Requested, Owner: "chrispian"}); err != nil {
		t.Fatal(err)
	}

	// Withdraw a pending one, twice.
	w := submitBody(t, "req-3", approvalapi.TierCritical, 600)
	_ = call(t, srv, "POST", p, "warden", w, &sub)
	for range 2 {
		if c := call(t, srv, "POST", p+"/"+sub.ApprovalID+"/withdraw", "warden", nil, &a); c != 200 || a.Status != approvalapi.StatusWithdrawn {
			t.Fatalf("withdraw: %d %+v", c, a)
		}
	}
}

func TestApprovalHTTPShadow(t *testing.T) {
	srv := server(t, true)
	var sub approvalapi.SubmitResponse
	if c := call(t, srv, "POST", approvalapi.PathApprovals, "warden", submitBody(t, "s-1", approvalapi.TierElevated, 600), &sub); c != 201 {
		t.Fatalf("submit: %d", c)
	}
	var d approvalapi.DecideResponse
	if c := call(t, srv, "POST", approvalapi.PathApprovals+"/"+sub.ApprovalID+"/decide", "approver", approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}, &d); c != 202 || !d.Shadow || d.Status != approvalapi.StatusPending {
		t.Fatalf("shadow: %d %+v", c, d)
	}
}

func TestApprovalRoutesUnconfigured(t *testing.T) {
	v := tokens{"warden": {Verified: true, ID: "key:warden", Audience: "gatecrasher", Scopes: []string{approvalapi.ScopeSubmit}}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", approvalapi.PathApprovals, bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer warden")
	req.Header.Set("Content-Type", "application/json")
	api.New(nil, v).Mux().ServeHTTP(rec, req)
	if rec.Code != 503 {
		t.Fatalf("status %d", rec.Code)
	}
}
