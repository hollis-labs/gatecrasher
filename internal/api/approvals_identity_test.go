package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/hollis-labs/substrate/boot"
	"github.com/hollis-labs/substrate/modules/auth"
	"github.com/hollis-labs/substrate/modules/database"
	"github.com/hollis-labs/substrate/modules/httphost"
	"github.com/hollis-labs/substrate/modules/identity"

	"github.com/hollis-labs/gatecrasher/internal/api"
	"github.com/hollis-labs/gatecrasher/internal/approvals"
	"github.com/hollis-labs/gatecrasher/internal/settings"
	"github.com/hollis-labs/gatecrasher/internal/storage"
	"github.com/hollis-labs/gatecrasher/pkg/approvalapi"
)

// The owner is matched through the real identity module, as serve wires it: a session
// (principal user:…, kind "user") and an owner key (key:…, kind "service") can each read and
// decide a critical request, and another verified key cannot. All identities live under
// t.TempDir.
func TestApprovalOwnerThroughRealIdentity(t *testing.T) {
	for _, via := range []string{"session", "key"} {
		t.Run(via, func(t *testing.T) { ownerThroughIdentity(t, via) })
	}
}

func ownerThroughIdentity(t *testing.T, via string) {
	dir := t.TempDir()
	raw, _ := json.Marshal(map[string]any{
		"database": map[string]any{"sqlite": map[string]any{"path": filepath.Join(dir, "host.db"), "journal": "wal", "synchronous": "FULL"}},
		"auth":     map[string]any{"mode": "enforce"},
		"identity": map[string]any{"key_file": filepath.Join(dir, "issuer.key"), "setup": "offline", "bcrypt_cost": 4},
	})
	database.UseMigrationFS(storage.Migrations())
	running, err := boot.Start(t.Context(), "gatecrasher", []string{"logging", "health", "auth", "database", "httphost", "identity"}, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = running.Stop(context.Background()) })
	id := identity.From(running.App)
	password := rand.Text()
	user, err := id.SetupOwner(t.Context(), identity.OwnerInput{Username: "isolated-owner", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	key := func(name string, scopes ...string) (string, string) {
		token, cred, kerr := id.CreateKey(t.Context(), identity.KeyInput{Name: name, Scopes: scopes})
		if kerr != nil {
			t.Fatal(kerr)
		}
		return token, "key:" + cred.ID
	}
	producer, producerID := key("isolated-warden", approvalapi.ScopeSubmit, approvalapi.ScopeRead)
	ownerKey, ownerKeyID := key("isolated-owner-key", approvalapi.ScopeRead, approvalapi.ScopeDecide)
	other, _ := key("isolated-other", approvalapi.ScopeRead, approvalapi.ScopeDecide)

	ownerPrincipal := "user:" + user.ID
	if via == "key" {
		ownerPrincipal = ownerKeyID
	}
	inbox, err := approvals.New(database.From(running.App), approvals.Config{DataDir: dir, Settings: settings.Approvals{
		Owner:     settings.Owner{Principal: ownerPrincipal, Sub: "chrispian"},
		Producers: map[string]string{producerID: "warden"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	api.RegisterScopes(auth.ScopeTable(running.App))
	h, err := httphost.Handler(running.App, httphost.Options{Routes: api.New(nil, id).WithApprovals(inbox).Mux()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(id.Middleware(h))
	t.Cleanup(srv.Close)

	// The owner's client: a logged-in session (cookie), or the owner key.
	jar, _ := cookiejar.New(nil)
	ownerClient := &http.Client{Jar: jar}
	ownerToken := ownerKey
	if via == "session" {
		ownerToken = ""
		b, _ := json.Marshal(map[string]string{"username": "isolated-owner", "password": password})
		res, lerr := ownerClient.Post(srv.URL+"/api/login", "application/json", bytes.NewReader(b))
		if lerr != nil {
			t.Fatal(lerr)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("login: %d", res.StatusCode)
		}
	}
	do := func(c *http.Client, method, path, token string, body, out any) int {
		t.Helper()
		var rd bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = *bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, srv.URL+path, &rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		} else {
			req.Header.Set("X-Requested-With", "test")
		}
		res, derr := c.Do(req)
		if derr != nil {
			t.Fatal(derr)
		}
		defer func() { _ = res.Body.Close() }()
		if out != nil {
			_ = json.NewDecoder(res.Body).Decode(out)
		}
		return res.StatusCode
	}

	p := approvalapi.PathApprovals
	var sub approvalapi.SubmitResponse
	if c := do(http.DefaultClient, "POST", p, producer, submitBody(t, "req-"+via, approvalapi.TierCritical, 600), &sub); c != 201 {
		t.Fatalf("submit: %d %+v", c, sub)
	}
	one := p + "/" + sub.ApprovalID
	approve := approvalapi.DecideRequest{Outcome: approvalapi.OutcomeApproved}

	// Another verified key sees nothing and cannot decide.
	if c := do(http.DefaultClient, "GET", one, other, nil, nil); c != 404 {
		t.Fatalf("other key get: %d", c)
	}
	if c := do(http.DefaultClient, "POST", one+"/decide", other, approve, nil); c != 404 && c != 403 {
		t.Fatalf("other key decide: %d", c)
	}
	// The owner reads and decides it.
	var a approvalapi.Approval
	if c := do(ownerClient, "GET", one, ownerToken, nil, &a); c != 200 || a.Status != approvalapi.StatusPending {
		t.Fatalf("owner get: %d %+v", c, a)
	}
	var d approvalapi.DecideResponse
	if c := do(ownerClient, "POST", one+"/decide", ownerToken, approve, &d); c != 200 || d.Status != approvalapi.StatusApproved {
		t.Fatalf("owner decide: %d %+v", c, d)
	}
	claims, err := approvalapi.VerifyDecision(d.Decision, inbox.JWKS(), "warden", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Decider.Kind != approvalapi.KindHuman || claims.Decider.Sub != "chrispian" {
		t.Fatalf("decider: %+v", claims.Decider)
	}
}
