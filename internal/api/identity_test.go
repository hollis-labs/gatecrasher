package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/api"
	"github.com/hollis-labs/gatecrasher/internal/ownerwire"
	"github.com/hollis-labs/gatecrasher/internal/recipewire"
	"github.com/hollis-labs/gatecrasher/internal/service"
	"github.com/hollis-labs/gatecrasher/internal/storage"
	"github.com/hollis-labs/libs/agent/sdk"
	"github.com/hollis-labs/libs/llm/core/llmtypes"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/core/hitl/memstore"
	"github.com/hollis-labs/substrate/boot"
	"github.com/hollis-labs/substrate/modules/auth"
	"github.com/hollis-labs/substrate/modules/database"
	_ "github.com/hollis-labs/substrate/modules/health"
	"github.com/hollis-labs/substrate/modules/httphost"
	"github.com/hollis-labs/substrate/modules/identity"
	_ "github.com/hollis-labs/substrate/modules/logging"
)

type contractOwner struct {
	*hitl.Service
	enqueued chan hitl.EnqueueRequest
	handles  chan hitl.Handle
	awaiting chan struct{}
}

func (o *contractOwner) Await(ctx context.Context, q hitl.AwaitCommand) (hitl.RetrievalResult, error) {
	if o.awaiting != nil {
		select {
		case o.awaiting <- struct{}{}:
		default:
		}
	}
	return o.Service.Await(ctx, q)
}

func (o *contractOwner) Enqueue(ctx context.Context, r hitl.EnqueueRequest) (hitl.Handle, error) {
	h, err := o.Service.Enqueue(ctx, r)
	if err == nil {
		o.enqueued <- r
		o.handles <- h
	}
	return h, err
}

type isolatedModel struct{}

func (isolatedModel) Capabilities() llmtypes.ProviderCapabilities {
	return llmtypes.ProviderCapabilities{SupportsToolCalling: true, ContextWindowSize: 65536}
}
func (isolatedModel) Complete(context.Context, llmtypes.ChatRequest) (string, error) {
	return "", errors.New("stream only")
}
func (isolatedModel) StreamChat(_ context.Context, q llmtypes.ChatRequest) (<-chan llmtypes.StreamEvent, error) {
	c := make(chan llmtypes.StreamEvent, 2)
	if len(q.Messages) > 2 {
		c <- llmtypes.StreamEvent{Type: llmtypes.EventDelta, Content: "done"}
	} else {
		c <- llmtypes.StreamEvent{Type: llmtypes.EventToolUse, ToolUse: &llmtypes.ToolUseBlock{ID: "one", Name: "fingerprint", Input: map[string]any{"text": "isolated"}}}
	}
	c <- llmtypes.StreamEvent{Type: llmtypes.EventDone}
	close(c)
	return c, nil
}
func httpJSON(t testing.TB, url, token string, value any) (int, []byte) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, raw
}

func TestOwnIdentityHTTPCallbackWithActualSDKAndSQLite(t *testing.T) {
	// These identities/credentials exist only under t.TempDir. They establish
	// isolated code behavior, never production identity or Tachyon acceptance.
	dir := t.TempDir()
	raw, _ := json.Marshal(map[string]any{"database": map[string]any{"sqlite": map[string]any{"path": filepath.Join(dir, "host.db"), "journal": "wal", "synchronous": "FULL"}}, "auth": map[string]any{"mode": "enforce"}, "identity": map[string]any{"key_file": filepath.Join(dir, "issuer.key"), "setup": "offline", "bcrypt_cost": 4}})
	database.UseMigrationFS(storage.Migrations())
	running, err := boot.Start(t.Context(), "gatecrasher", []string{"logging", "health", "auth", "database", "httphost", "identity"}, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer running.Stop(context.Background())
	id := identity.From(running.App)
	if _, err = id.SetupOwner(t.Context(), identity.OwnerInput{Username: "isolated-owner", Password: rand.Text()}); err != nil {
		t.Fatal(err)
	}
	callback, credential, err := id.CreateKey(t.Context(), identity.KeyInput{Name: "isolated-tachyon", Scopes: []string{service.CallbackScope}, Audiences: []string{"gatecrasher", "another-audience"}})
	if err != nil {
		t.Fatal(err)
	}
	producer, producerCredential, err := id.CreateKey(t.Context(), identity.KeyInput{Name: "isolated-recipe", Scopes: []string{service.RecipeScope}})
	if err != nil {
		t.Fatal(err)
	}
	host, err := service.New(t.Context(), database.From(running.App), service.Config{OwnerRef: "tachyon-contract-fixture", CallerScope: "gatecrasher", CallbackSubject: "key:" + credential.ID, ActorMap: map[string]string{"gatecrasher/key:" + producerCredential.ID: "person:requester", "tachyon/user:reviewer": "person:reviewer"}})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	owner := &contractOwner{Service: hitl.NewService(memstore.New(), hitl.Options{}), enqueued: make(chan hitl.EnqueueRequest, 1), handles: make(chan hitl.Handle, 1)}
	if err = host.Wire(owner); err != nil {
		t.Fatal(err)
	}
	api.RegisterScopes(auth.ScopeTable(running.App))
	handler, err := httphost.Handler(running.App, httphost.Options{Routes: api.New(host, id, service.RecipeRunner{Host: host, Provider: isolatedModel{}}).Mux()})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(id.Middleware(handler))
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		status, body := httpJSON(t, server.URL+"/api/gate/v1/recipes/fingerprint", producer, map[string]string{"run_id": "actual-sdk-over-callback", "text": "isolated"})
		var result recipewire.Response
		if status != 200 || json.Unmarshal(body, &result) != nil || result.State != "completed" || result.Result == nil || result.Result.Status != sdk.Succeeded {
			done <- errors.New("authenticated recipe HTTP run did not succeed")
			return
		}
		done <- nil
	}()
	var request hitl.EnqueueRequest
	select {
	case request = <-owner.enqueued:
	case completedErr := <-done:
		t.Fatal("recipe stopped", completedErr)
	case <-time.After(5 * time.Second):
		t.Fatal("no SDK approval")
	}
	handle := <-owner.handles
	var sealed string
	if err = json.Unmarshal(request.Extra["gate_request"], &sealed); err != nil {
		t.Fatal(err)
	}
	var gr gate.Request
	if err = json.Unmarshal([]byte(sealed), &gr); err != nil {
		t.Fatal(err)
	}
	digest, err := gr.Digest()
	if err != nil {
		t.Fatal(err)
	}
	assessedAt := time.Now().UTC()
	proposal := service.ProposedResponse{ContractVersion: "1", OwnerRef: "tachyon-contract-fixture", IdempotencyKey: gr.IdempotencyKey, ItemID: handle.ItemID, RequestDigest: digest, OperationDigest: gr.OperationDigest, Binding: gr.Binding, NativeRequestID: gr.NativeRequestID, AssessedAt: assessedAt, ExpiresAt: assessedAt.Add(ownerwire.AssessmentTTL), ExpectedRevision: handle.Revision, PresentedRevision: handle.Revision, OptionID: "allow-once", Participant: hitl.Participant{PrincipalRef: "user:reviewer", Authority: "tachyon/identity", Assurance: "operator-token"}, ActorScopes: []string{"tachyon.operator", "tachyon.approvals.resolve"}}
	endpoint := server.URL + "/api/gate/v1/authorize-response"
	wrongVersion := proposal
	wrongVersion.ContractVersion = hitl.ContractVersion
	if code, _ := httpJSON(t, endpoint, callback, wrongVersion); code != 403 {
		t.Fatal("HITL version accepted at own-key gate callback", code)
	}
	for _, bearer := range []string{"", producer, "key_not-from-this-issuer"} {
		code, _ := httpJSON(t, endpoint, bearer, proposal)
		if code == 200 {
			t.Fatal("unrelated credential authorized callback")
		}
	}
	other, _, err := id.CreateKey(t.Context(), identity.KeyInput{Name: "same-scope-wrong-subject", Scopes: []string{service.CallbackScope}})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := httpJSON(t, endpoint, other, proposal); code != 403 {
		t.Fatal("unpinned subject accepted", code)
	}
	// Even an authentic own-issued key-derived JWT is intentionally unsupported:
	// the raw key must be checked live on every callback for immediate revocation.
	for _, aud := range []string{"gatecrasher", "another-audience"} {
		code, body := httpJSON(t, server.URL+"/api/token", callback, map[string]any{"audience": aud, "scopes": []string{service.CallbackScope}})
		if code != 200 {
			t.Fatal("test token mint failed", code, string(body))
		}
		var token struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(body, &token) != nil || token.Token == "" {
			t.Fatal("no isolated token")
		}
		if code, _ = httpJSON(t, endpoint, token.Token, proposal); code == 200 {
			t.Fatal("JWT callback accepted", aud)
		}
	}
	if code, body := httpJSON(t, endpoint, callback, proposal); code != 200 {
		t.Fatal("real own-key callback refused", code, string(body))
	} else {
		var out service.Authorization
		if json.Unmarshal(body, &out) != nil || !out.Authorized {
			t.Fatal("missing callback authorization")
		}
		got, _ := json.Marshal(out.ProposedResponse)
		want, _ := json.Marshal(proposal)
		if !bytes.Equal(got, want) {
			t.Fatal("callback did not bind complete proposal")
		}
	}
	// The callback has not made a human decision. The owner still has to win CAS.
	view, err := owner.Get(t.Context(), hitl.GetCommand{ContractVersion: hitl.ContractVersion, ItemID: handle.ItemID, Caller: hitl.CallerAssertion{ApplicationID: "gatecrasher"}})
	if err != nil || view.Item.State.IsTerminal() {
		t.Fatal("authorization wrote a decision", view, err)
	}
	if _, err = owner.Respond(t.Context(), hitl.RespondCommand{ItemID: handle.ItemID, ExpectedRevision: &handle.Revision, Response: hitl.Response{Kind: "gate_native_v1", Decision: "allow-once"}, Participant: proposal.Participant}); err != nil {
		t.Fatal(err)
	}
	select {
	case completedErr := <-done:
		if completedErr != nil {
			t.Fatal(completedErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SDK did not finish")
	}
	if err = id.RevokeKey(t.Context(), credential.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := httpJSON(t, endpoint, callback, proposal); code == 200 {
		t.Fatal("revoked callback key accepted")
	}
	if strings.Contains(sealed, callback) || strings.Contains(sealed, producer) {
		t.Fatal("credential entered request snapshot")
	}
}
