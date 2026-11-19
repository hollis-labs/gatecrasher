package api_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

const intake = "https://warden.example/intake/int_1"

// fullServer is server() with intake origins and, when trusted is set, a trusted issuer.
func fullServer(t *testing.T, trusted libauth.Verifier) (*httptest.Server, string) {
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
		Owner:         settings.Owner{Principal: "usr_owner", Sub: "chrispian"},
		Producers:     map[string]string{"key:warden": "warden", api.WardenPrefix + "wdn_service": "warden-jwt"},
		IntakeOrigins: map[string][]string{"warden": {"https://warden.example"}},
		Classes: map[string]settings.Class{cls: {
			Agents:  map[string]string{"key:approver": "agt_approver"},
			Ceiling: settings.Ceiling{MaxTTLSeconds: 3600, Audiences: []string{"llm-gateway"}, Scopes: []string{"llm-gateway.decide"}},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	g := "gatecrasher"
	v := tokens{
		"warden":   {Verified: true, ID: "key:warden", Kind: libauth.KindService, Audience: g, Scopes: []string{approvalapi.ScopeSubmit, approvalapi.ScopeRead}},
		"owner":    {Verified: true, ID: "usr_owner", Kind: libauth.KindOperator, Audience: g, Scopes: []string{"*"}},
		"approver": {Verified: true, ID: "key:approver", Kind: libauth.KindService, Audience: g, Scopes: []string{approvalapi.ScopeDecide, approvalapi.ScopeRead, cls}},
	}
	h := api.New(nil, v).WithApprovals(svc)
	if trusted != nil {
		h.WithTrusted(trusted)
	}
	srv := httptest.NewServer(h.Mux())
	t.Cleanup(srv.Close)
	return srv, dir
}

func TestCardAndSecretProvidedRoutes(t *testing.T) {
	srv, _ := fullServer(t, nil)
	p := approvalapi.PathApprovals
	body := submitBody(t, "sec-1", approvalapi.TierCritical, 0)
	body.Kind = approvalapi.KindSecretRequest
	body.Requested = approvalapi.Requested{}
	body.SecretIntake = &approvalapi.SecretIntake{IntakeID: "int_1", IntakeURL: intake, ExpiresAt: time.Now().Add(10 * time.Minute).UTC()}
	body.RequestDigest, _ = body.Digest()
	var sub approvalapi.SubmitResponse
	if c := call(t, srv, "POST", p, "warden", body, &sub); c != 201 {
		t.Fatalf("submit secret_request: %d", c)
	}
	var card approvalapi.Card
	if c := call(t, srv, "GET", p+"/"+sub.ApprovalID+"/card", "owner", nil, &card); c != 200 || card.Secret == nil || card.Secret.PostURL != intake {
		t.Fatalf("card: %d %+v", c, card)
	}
	if c := call(t, srv, "GET", p+"/"+sub.ApprovalID+"/card", "approver", nil, nil); c != 404 {
		t.Fatalf("approver read a critical card: %d", c)
	}
	in := approvalapi.SecretProvidedRequest{IntakeID: "int_1", Ref: "warden:sec_1", ProvidedAt: time.Now().UTC()}
	// Only the submitter reports a secret provided, not even the owner.
	if c := call(t, srv, "POST", p+"/"+sub.ApprovalID+"/secret-provided", "owner", in, nil); c != 404 {
		t.Fatalf("owner reported a secret provided: %d", c)
	}
	var got approvalapi.Approval
	if c := call(t, srv, "POST", p+"/"+sub.ApprovalID+"/secret-provided", "warden", in, &got); c != 200 || got.Status != approvalapi.StatusApproved || got.Secret == nil {
		t.Fatalf("secret-provided: %d %+v", c, got)
	}
}

func readEvents(t *testing.T, srv *httptest.Server, token, lastID string, want int) []approvalapi.FeedEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+approvalapi.PathEvents, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("events: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	var out []approvalapi.FeedEvent
	sc := bufio.NewScanner(res.Body)
	var id string
	for len(out) < want && sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "id: "):
			id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "data: "):
			var e approvalapi.FeedEvent
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e); err != nil {
				t.Fatal(err)
			}
			if id == "" {
				t.Fatal("an event without an id")
			}
			out = append(out, e)
		}
	}
	if len(out) < want {
		t.Fatalf("got %d of %d events: %v", len(out), want, sc.Err())
	}
	return out
}

func TestEventStream(t *testing.T) {
	srv, _ := fullServer(t, nil)
	p := approvalapi.PathApprovals
	var a approvalapi.SubmitResponse
	call(t, srv, "POST", p, "warden", submitBody(t, "e1", approvalapi.TierCritical, 600), &a)
	first := readEvents(t, srv, "owner", "", 1)
	if first[0].ApprovalID != a.ApprovalID || first[0].Type != "submitted" {
		t.Fatalf("first: %+v", first)
	}
	// Live: a decision made while the stream is open arrives on it.
	done := make(chan []approvalapi.FeedEvent, 1)
	go func() { done <- readEvents(t, srv, "warden", strings.TrimSpace(itoa(first[0].Seq)), 1) }()
	time.Sleep(100 * time.Millisecond)
	if c := call(t, srv, "POST", p+"/"+a.ApprovalID+"/decide", "owner", approvalapi.DecideRequest{Outcome: approvalapi.OutcomeDenied}, nil); c != 200 {
		t.Fatalf("decide: %d", c)
	}
	select {
	case evs := <-done:
		if evs[0].Type != "decided" || evs[0].Status != approvalapi.StatusDenied || evs[0].Seq <= first[0].Seq {
			t.Fatalf("live: %+v", evs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the live event did not arrive")
	}
	// The approver may not see a critical request's events.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+approvalapi.PathEvents, nil)
	req.Header.Set("Authorization", "Bearer approver")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(res.Body)
	_ = res.Body.Close()
	if strings.Contains(buf.String(), a.ApprovalID) {
		t.Fatal("the approver saw a critical request")
	}
	if c := call(t, srv, "GET", approvalapi.PathEvents+"?after=x", "owner", nil, nil); c != 400 {
		t.Fatalf("bad after: %d", c)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// Warden-issued JWTs are accepted when trusted, as warden:-prefixed service principals
// that can never be the owner.
func TestWardenTrust(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	jwks := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"w1","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}]}`
	keyFile := filepath.Join(dir, "warden.jwks.json")
	if err := os.WriteFile(keyFile, []byte(jwks), 0o600); err != nil {
		t.Fatal(err)
	}
	jv, err := libauth.NewJWTVerifier(libauth.JWTConfig{Issuer: "warden", Audience: "gatecrasher", BootstrapKeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	mint := func(sub, aud, kind string) string {
		h, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "w1", "typ": "JWT"})
		c, _ := json.Marshal(map[string]any{"iss": "warden", "sub": sub, "aud": aud, "kind": kind, "exp": time.Now().Add(time.Hour).Unix(), "scope": approvalapi.ScopeSubmit + " " + approvalapi.ScopeRead + " " + approvalapi.ScopeDecide})
		in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
		return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(in)))
	}
	body := submitBody(t, "w1", approvalapi.TierCritical, 600)
	body.Source = "warden-jwt"
	body.RequestDigest, _ = body.Digest()

	untrusted, _ := fullServer(t, nil)
	if c := call(t, untrusted, "POST", approvalapi.PathApprovals, mint("wdn_service", "gatecrasher", "service"), body, nil); c != 401 {
		t.Fatalf("standalone accepted a Warden token: %d", c)
	}
	srv, _ := fullServer(t, api.WardenVerifier(jv))
	var sub approvalapi.SubmitResponse
	if c := call(t, srv, "POST", approvalapi.PathApprovals, mint("wdn_service", "gatecrasher", "service"), body, &sub); c != 201 {
		t.Fatalf("trusted Warden submit: %d", c)
	}
	if c := call(t, srv, "POST", approvalapi.PathApprovals, mint("wdn_service", "tachyon", "service"), body, nil); c != 401 {
		t.Fatalf("wrong audience: %d", c)
	}
	// A Warden subject named like the owner, claiming operator, is not the owner.
	var e approvalapi.Error
	if c := call(t, srv, "POST", approvalapi.PathApprovals+"/"+sub.ApprovalID+"/decide", mint("usr_owner", "gatecrasher", "operator"), approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}, &e); c != 404 {
		t.Fatalf("impersonated owner: %d %+v", c, e)
	}
}

// No Gatecrasher route takes a secret value: a body carrying one is refused, and the
// value reaches neither the log nor the database.
func TestSecretValuesAreRefusedAndNeverLogged(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	srv, dir := fullServer(t, nil)
	p := approvalapi.PathApprovals
	var a approvalapi.SubmitResponse
	sr := submitBody(t, "canary-req", approvalapi.TierCritical, 0)
	sr.Kind, sr.Requested = approvalapi.KindSecretRequest, approvalapi.Requested{}
	sr.SecretIntake = &approvalapi.SecretIntake{IntakeID: "int_1", IntakeURL: intake, ExpiresAt: time.Now().Add(10 * time.Minute).UTC()}
	sr.RequestDigest, _ = sr.Digest()
	if c := call(t, srv, "POST", p, "warden", sr, &a); c != 201 {
		t.Fatalf("submit: %d", c)
	}
	const canary = "sk-CANARY-7f3a9c1e5b2d"
	routes := []string{p, p + "/" + a.ApprovalID + "/decide", p + "/" + a.ApprovalID + "/secret-provided", p + "/" + a.ApprovalID + "/withdraw", "/api/gate/v1/authorize-response", "/api/gate/v1/recipes/fingerprint"}
	bodies := []map[string]any{
		{"value": canary},
		{"secret": canary, "intake_id": "int_1"},
		{"outcome": "approved", "value": canary},
		{"intake_id": "int_1", "ref": "warden:x", "provided_at": time.Now().UTC(), "value": canary},
		{"intake_id": "int_1", "ref": canary + " with spaces", "provided_at": time.Now().UTC()},
	}
	for _, route := range routes {
		for _, b := range bodies {
			for _, tok := range []string{"warden", "owner"} {
				c := call(t, srv, "POST", route, tok, b, nil)
				if c < 400 && !(strings.HasSuffix(route, "/withdraw")) {
					t.Fatalf("%s accepted a secret-shaped body: %d %v", route, c, b)
				}
			}
		}
	}
	if strings.Contains(logs.String(), canary) {
		t.Fatal("the secret value reached the log")
	}
	for _, f := range []string{"gatecrasher.db", "gatecrasher.db-wal"} {
		b, err := os.ReadFile(filepath.Join(dir, f)) // #nosec G304 -- test temp dir
		if err == nil && bytes.Contains(b, []byte(canary)) {
			t.Fatalf("the secret value reached %s", f)
		}
	}
}
