package api_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/api"
	"github.com/hollis-labs/gatecrasher/internal/ownerwire"
	"github.com/hollis-labs/gatecrasher/internal/recipewire"
	"github.com/hollis-labs/gatecrasher/internal/service"
	"github.com/hollis-labs/gatecrasher/internal/storage"
	"github.com/hollis-labs/libs/core/store"
	"github.com/hollis-labs/libs/llm/core/llmcontracts"
	"github.com/hollis-labs/libs/llm/core/llmtypes"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/core/hitl/memstore"
	"github.com/hollis-labs/substrate/boot"
	"github.com/hollis-labs/substrate/modules/auth"
	"github.com/hollis-labs/substrate/modules/database"
	"github.com/hollis-labs/substrate/modules/httphost"
	"github.com/hollis-labs/substrate/modules/identity"
)

type recipeModel struct {
	calls atomic.Int32
	fail  atomic.Bool
}

func (*recipeModel) Capabilities() llmtypes.ProviderCapabilities {
	return isolatedModel{}.Capabilities()
}
func (*recipeModel) Complete(context.Context, llmtypes.ChatRequest) (string, error) {
	return isolatedModel{}.Complete(context.Background(), llmtypes.ChatRequest{})
}
func (m *recipeModel) StreamChat(ctx context.Context, q llmtypes.ChatRequest) (<-chan llmtypes.StreamEvent, error) {
	m.calls.Add(1)
	if m.fail.Load() {
		return nil, errors.New("private model diagnostic; never expose raw input")
	}
	return isolatedModel{}.StreamChat(ctx, q)
}

type recipeFixture struct {
	config                                    string
	hostConfig                                service.Config
	owner                                     *contractOwner
	model                                     *recipeModel
	st                                        *store.Store
	host                                      *service.Service
	identity                                  *identity.Service
	token, alias, noGrant, unmapped, callback string
	stop                                      func()
	server                                    *httptest.Server
	handler                                   http.Handler
}

func (f *recipeFixture) start(t *testing.T, initialize bool) {
	t.Helper()
	database.UseMigrationFS(storage.Migrations())
	running, err := boot.Start(t.Context(), "gatecrasher", []string{"logging", "health", "auth", "database", "httphost", "identity"}, f.config)
	if err != nil {
		t.Fatal(err)
	}
	id := identity.From(running.App)
	if initialize {
		if _, err = id.SetupOwner(t.Context(), identity.OwnerInput{Username: "fixture-owner", Password: rand.Text()}); err != nil {
			t.Fatal(err)
		}
		token, cred, e := id.CreateKey(t.Context(), identity.KeyInput{Name: "recipe", Scopes: []string{service.RecipeScope}})
		if e != nil {
			t.Fatal(e)
		}
		f.token = token
		alias, aliasCred, e := id.CreateKey(t.Context(), identity.KeyInput{Name: "recipe-rotated-alias", Scopes: []string{service.RecipeScope}})
		if e != nil {
			t.Fatal(e)
		}
		f.alias = alias
		f.noGrant, _, e = id.CreateKey(t.Context(), identity.KeyInput{Name: "no-recipe-grant", Scopes: []string{"gatecrasher.health"}})
		if e != nil {
			t.Fatal(e)
		}
		f.unmapped, _, e = id.CreateKey(t.Context(), identity.KeyInput{Name: "no-actor-mapping", Scopes: []string{service.RecipeScope}})
		if e != nil {
			t.Fatal(e)
		}
		callback, callbackCred, e := id.CreateKey(t.Context(), identity.KeyInput{Name: "callback", Scopes: []string{service.CallbackScope}})
		if e != nil {
			t.Fatal(e)
		}
		f.callback = callback
		f.hostConfig = service.Config{OwnerRef: "tachyon-contract-fixture", CallerScope: "gatecrasher", CallbackSubject: "key:" + callbackCred.ID, ActorMap: map[string]string{"gatecrasher/key:" + cred.ID: "person:requester", "gatecrasher/key:" + aliasCred.ID: "person:requester", "tachyon/user:reviewer": "person:reviewer"}}
	}
	host, err := service.New(t.Context(), database.From(running.App), f.hostConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err = host.Wire(f.owner); err != nil {
		t.Fatal(err)
	}
	api.RegisterScopes(auth.ScopeTable(running.App))
	makeHandler := func(provider llmcontracts.Provider) http.Handler {
		handler, e := httphost.Handler(running.App, httphost.Options{Routes: api.New(host, id, service.RecipeRunner{Host: host, Provider: provider}).Mux()})
		if e != nil {
			t.Fatal(e)
		}
		return id.Middleware(handler)
	}
	f.st = database.From(running.App)
	f.handler = makeHandler(f.model)
	f.server, f.host, f.identity = httptest.NewServer(f.handler), host, id
	f.stop = func() { f.server.Close(); _ = host.Close(); _ = running.Stop(context.Background()) }
	// Each activation has a separate idempotent cleanup closure, even after restart.
	stop := f.stop
	var stopped atomic.Bool
	f.stop = func() {
		if stopped.CompareAndSwap(false, true) {
			stop()
		}
	}
	t.Cleanup(f.stop)
	// Missing model config is tested through the same own-identity middleware.
	missing := httptest.NewServer(makeHandler(nil))
	t.Cleanup(missing.Close)
	status, body := httpJSON(t, missing.URL+"/api/gate/v1/recipes/fingerprint", f.token, map[string]string{"run_id": "unconfigured", "text": "never execute"})
	var unavailable recipewire.Response
	if status != 503 || json.Unmarshal(body, &unavailable) != nil || unavailable.State != "unavailable" {
		t.Fatal("missing model did not refuse", status, string(body))
	}
	missing.Close()
}

func newRecipeFixture(t *testing.T) *recipeFixture {
	t.Helper()
	dir := t.TempDir()
	config, err := json.Marshal(map[string]any{"database": map[string]any{"sqlite": map[string]any{"path": filepath.Join(dir, "host.db"), "journal": "wal", "synchronous": "FULL"}}, "auth": map[string]any{"mode": "enforce"}, "identity": map[string]any{"key_file": filepath.Join(dir, "issuer.key"), "setup": "offline", "bcrypt_cost": 4}})
	if err != nil {
		t.Fatal(err)
	}
	f := &recipeFixture{config: string(config), owner: &contractOwner{Service: hitl.NewService(memstore.New(), hitl.Options{PollInterval: time.Millisecond}), enqueued: make(chan hitl.EnqueueRequest, 4), handles: make(chan hitl.Handle, 4), awaiting: make(chan struct{}, 1)}, model: &recipeModel{}}
	f.start(t, true)
	return f
}

func TestRecipeHTTPConcurrentReplayRestartAndCredentialRotation(t *testing.T) {
	// All keys, identity state and SQLite live under t.TempDir. The HITL owner is
	// an isolated contract fixture, not actual Tachyon integration acceptance.
	f := newRecipeFixture(t)
	endpoint := f.server.URL + "/api/gate/v1/recipes/fingerprint"
	for _, token := range []string{"", f.noGrant, f.unmapped} {
		status, _ := httpJSON(t, endpoint, token, map[string]string{"run_id": "no-grant", "text": "never execute"})
		if status != 401 && status != 403 {
			t.Fatal("missing grant/mapping accepted", status)
		}
	}
	for _, field := range []string{"launch", "provider", "tool", "identity", "conversation_id", "environment"} {
		status, _ := httpJSON(t, endpoint, f.token, map[string]string{"run_id": "invalid", "text": "never execute", field: "caller-selected"})
		if status != 400 {
			t.Fatal("caller selected host binding", field, status)
		}
	}
	if f.model.calls.Load() != 0 {
		t.Fatal("model effect occurred before config/grant validation")
	}
	done := make(chan struct {
		status int
		body   []byte
	}, 1)
	go func() {
		status, body := httpJSON(t, endpoint, f.token, map[string]string{"run_id": "durable-http-run", "text": "isolated"})
		done <- struct {
			status int
			body   []byte
		}{status, body}
	}()
	var request hitl.EnqueueRequest
	select {
	case request = <-f.owner.enqueued:
	case <-time.After(5 * time.Second):
		t.Fatal("no actual SDK approval request")
	}
	handle := <-f.owner.handles
	// The first HTTP request is blocked on its real SDK approval; overlapping
	// same-ID/changed-input and same-canonical rotated-key requests must conflict.
	before := f.model.calls.Load()
	for _, token := range []string{f.token, f.alias} {
		for _, text := range []string{"isolated", "changed input"} {
			status, body := httpJSON(t, endpoint, token, map[string]string{"run_id": "durable-http-run", "text": text})
			var receipt recipewire.Response
			if status != 409 || json.Unmarshal(body, &receipt) != nil || receipt.State != "conflict" || receipt.ReplayAllowed || receipt.ResumeAvailable {
				t.Fatal("concurrent replay accepted", status, string(body))
			}
		}
	}
	if f.model.calls.Load() != before {
		t.Fatal("concurrent replay made model effects")
	}
	var sealed string
	var native gate.Request
	if json.Unmarshal(request.Extra["gate_request"], &sealed) != nil || json.Unmarshal([]byte(sealed), &native) != nil {
		t.Fatal("missing immutable request")
	}
	digest, err := native.Digest()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	proposal := service.ProposedResponse{ContractVersion: "1", OwnerRef: f.hostConfig.OwnerRef, IdempotencyKey: native.IdempotencyKey, ItemID: handle.ItemID, RequestDigest: digest, OperationDigest: native.OperationDigest, Binding: native.Binding, NativeRequestID: native.NativeRequestID, ExpectedRevision: handle.Revision, PresentedRevision: handle.Revision, OptionID: "allow-once", Participant: hitl.Participant{PrincipalRef: "user:reviewer", Authority: "tachyon/identity", Assurance: "operator-token"}, ActorScopes: []string{"tachyon.operator", "tachyon.approvals.resolve"}, AssessedAt: now, ExpiresAt: now.Add(ownerwire.AssessmentTTL)}
	if status, body := httpJSON(t, f.server.URL+"/api/gate/v1/authorize-response", f.callback, proposal); status != 200 {
		t.Fatal("own-key callback refused", status, string(body))
	}
	if _, err = f.owner.Respond(t.Context(), hitl.RespondCommand{ItemID: handle.ItemID, ExpectedRevision: &handle.Revision, Response: hitl.Response{Kind: "gate_native_v1", Decision: "allow-once"}, Participant: proposal.Participant}); err != nil {
		t.Fatal(err)
	}
	select {
	case completed := <-done:
		var receipt recipewire.Response
		if completed.status != 200 || json.Unmarshal(completed.body, &receipt) != nil || receipt.State != "completed" || receipt.Result == nil || receipt.ReplayAllowed || receipt.ResumeAvailable {
			t.Fatal("recipe did not complete", completed.status, string(completed.body))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("recipe did not finish")
	}
	// The SDK event log contains references/outcomes, not submitted text or secrets.
	rows, err := databaseRows(f, t)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range rows {
		if strings.Contains(raw, "isolated") || strings.Contains(raw, f.token) || strings.Contains(raw, f.callback) {
			t.Fatal("sensitive input entered event telemetry")
		}
	}
	before = f.model.calls.Load()
	f.stop()
	f.start(t, false) // real own identity + same file SQLite reopened, no seeded terminal row
	endpoint = f.server.URL + "/api/gate/v1/recipes/fingerprint"
	for _, token := range []string{f.token, f.alias} {
		for _, text := range []string{"isolated", "changed input"} {
			status, body := httpJSON(t, endpoint, token, map[string]string{"run_id": "durable-http-run", "text": text})
			var receipt recipewire.Response
			if status != 409 || json.Unmarshal(body, &receipt) != nil || receipt.State != "conflict" {
				t.Fatal("restart replay accepted", status, string(body))
			}
		}
	}
	if f.model.calls.Load() != before {
		t.Fatal("restart replay executed model work")
	}
}

func databaseRows(f *recipeFixture, t *testing.T) ([]string, error) {
	rows, err := f.st.Reader().QueryContext(t.Context(), `SELECT event_json FROM host_events`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

func TestRecipeHTTPCancelIsStoppedRunNotWithdrawalOrResume(t *testing.T) {
	f := newRecipeFixture(t)
	cancels := make(chan context.CancelFunc, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		cancels <- cancel
		f.handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer server.Close()
	done := make(chan struct {
		status int
		body   []byte
	}, 1)
	go func() {
		status, body := httpJSON(t, server.URL+"/api/gate/v1/recipes/fingerprint", f.token, map[string]string{"run_id": "canceled-run", "text": "isolated"})
		done <- struct {
			status int
			body   []byte
		}{status, body}
	}()
	select {
	case <-f.owner.enqueued:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not reach approval")
	}
	handle := <-f.owner.handles
	cancel := <-cancels
	select {
	case <-f.owner.awaiting:
	case <-time.After(5 * time.Second):
		t.Fatal("SDK did not attach its wait ticket")
	}
	cancel()
	select {
	case reply := <-done:
		var receipt recipewire.Response
		if reply.status != 200 || json.Unmarshal(reply.body, &receipt) != nil || receipt.State != "canceled" || receipt.Result == nil || receipt.Result.PendingTicket == nil || receipt.ReplayAllowed || receipt.ResumeAvailable || !receipt.ReconciliationRequired {
			t.Fatal("ambiguous cancellation receipt", reply.status, string(reply.body))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled run did not stop")
	}
	view, err := f.owner.Get(t.Context(), hitl.GetCommand{ContractVersion: hitl.ContractVersion, ItemID: handle.ItemID, Caller: hitl.CallerAssertion{ApplicationID: "gatecrasher"}})
	if err != nil || view.Item.State.IsTerminal() {
		t.Fatal("run cancellation silently withdrew approval", view, err)
	}
	before := f.model.calls.Load()
	if status, _ := httpJSON(t, f.server.URL+"/api/gate/v1/recipes/fingerprint", f.token, map[string]string{"run_id": "canceled-run", "text": "isolated"}); status != 409 {
		t.Fatal("canceled run replayed", status)
	}
	if f.model.calls.Load() != before {
		t.Fatal("canceled run resumed model work")
	}
}

func TestRecipeHTTPPendingIsRetainedReceiptWithoutAutomaticResume(t *testing.T) {
	f := newRecipeFixture(t)
	// Exercise the production SDK wait bound, not a seeded pending result.
	status, body := httpJSON(t, f.server.URL+"/api/gate/v1/recipes/fingerprint", f.token, map[string]string{"run_id": "pending-run", "text": "isolated"})
	var receipt recipewire.Response
	if status != 202 || json.Unmarshal(body, &receipt) != nil || receipt.State != "pending" || receipt.Result == nil || receipt.Result.PendingTicket == nil || receipt.ReplayAllowed || receipt.ResumeAvailable || !receipt.ReconciliationRequired {
		t.Fatal("ambiguous pending receipt", status, string(body))
	}
	ticket := receipt.Result.PendingTicket
	if ticket.Validate() != nil {
		t.Fatal("pending ticket lost binding")
	}
	before := f.model.calls.Load()
	// A later owner outcome is not SDK continuation authority. Its original
	// environment was detached when the bounded run returned.
	view, err := f.owner.Get(t.Context(), hitl.GetCommand{ContractVersion: hitl.ContractVersion, ItemID: ticket.Handle.ItemID, Caller: hitl.CallerAssertion{ApplicationID: "gatecrasher"}})
	if err != nil || view.Item.State.IsTerminal() {
		t.Fatal(view, err)
	}
	revision := view.Item.Revision
	if _, err = f.owner.Respond(t.Context(), hitl.RespondCommand{ItemID: ticket.Handle.ItemID, ExpectedRevision: &revision, Response: hitl.Response{Kind: "gate_native_v1", Decision: "allow-once"}, Participant: hitl.Participant{PrincipalRef: "user:reviewer", Authority: "tachyon/identity", Assurance: "operator-token"}}); err != nil {
		t.Fatal(err)
	}
	if status, _ = httpJSON(t, f.server.URL+"/api/gate/v1/recipes/fingerprint", f.token, map[string]string{"run_id": "pending-run", "text": "isolated"}); status != 409 {
		t.Fatal("pending run replayed after owner decision", status)
	}
	if f.model.calls.Load() != before {
		t.Fatal("later decision silently resumed SDK")
	}
}

func TestRecipeHTTPUnknownDoesNotEchoDiagnosticsOrReplay(t *testing.T) {
	f := newRecipeFixture(t)
	f.model.fail.Store(true)
	status, body := httpJSON(t, f.server.URL+"/api/gate/v1/recipes/fingerprint", f.token, map[string]string{"run_id": "unknown-run", "text": "private supplied input"})
	var receipt recipewire.Response
	if status != 503 || json.Unmarshal(body, &receipt) != nil || receipt.State != "unknown" || !receipt.ReconciliationRequired || receipt.ReplayAllowed || receipt.ResumeAvailable {
		t.Fatal("uncertain model failure misclassified", status, string(body))
	}
	if strings.Contains(string(body), "private model diagnostic") || strings.Contains(string(body), "private supplied input") {
		t.Fatal("raw diagnostic/input exposed")
	}
	before := f.model.calls.Load()
	if status, _ = httpJSON(t, f.server.URL+"/api/gate/v1/recipes/fingerprint", f.token, map[string]string{"run_id": "unknown-run", "text": "changed input"}); status != 409 {
		t.Fatal("unknown run replayed", status)
	}
	if f.model.calls.Load() != before {
		t.Fatal("unknown run retried effect")
	}
}
