package tachyon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/ownerwire"

	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/gate/gatetest"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/core/hitl/memstore"
	libauth "github.com/hollis-labs/libs/security/auth"
)

// This is a PROVISIONAL transport contract fixture with real bearer verification
// and HITL lifecycle calls. It is not Tachyon's mapped-service implementation.
func TestProvisionalAgentVerbsPreserveSnapshotConflictsAndTimeout(t *testing.T) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(secret[:])
	tokenPath := filepath.Join(t.TempDir(), "producer-token")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	scopes := libauth.NewScopeTable()
	for _, v := range []string{"enqueue", "get", "await", "withdraw"} {
		method := http.MethodGet
		if v == "enqueue" || v == "withdraw" {
			method = http.MethodPost
		}
		scopes.Route(method, "/api/agent/v1/data/providers/tachyon/verbs/gate."+v, "tachyon.gate."+v)
	}
	guard, err := libauth.New(libauth.Config{Mode: libauth.ModeEnforce, Scopes: scopes, Verifier: libauth.NewAPIKeyVerifier(libauth.APIKey{ID: "mapped-producer", Hash: libauth.HashKey(token), Scopes: []string{"tachyon.gate.*"}})})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := hitl.NewService(memstore.New(), hitl.Options{PollInterval: time.Millisecond})
	var active atomic.Bool
	active.Store(true)
	var loseReply atomic.Bool
	loseReply.Store(true)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := libauth.FromContext(r.Context())
		if !ok || p.ID != "mapped-producer" || !active.Load() {
			w.WriteHeader(403)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "unauthorized"})
			return
		}
		verb := strings.TrimPrefix(r.URL.Path, "/api/agent/v1/data/providers/tachyon/verbs/")
		raw := []byte(r.URL.Query().Get("input"))
		if r.Method == http.MethodPost {
			var data json.RawMessage
			if json.NewDecoder(r.Body).Decode(&data) != nil {
				w.WriteHeader(400)
				return
			}
			raw = data
		}
		var result any
		var callErr error
		switch verb {
		case "gate.enqueue":
			var q hitl.EnqueueRequest
			if json.Unmarshal(raw, &q) != nil || q.Source.ApplicationID != "gatecrasher" || q.Kind != "gate_native_v1" {
				callErr = hitl.ErrUnauthorized
			} else {
				result, callErr = lifecycle.Enqueue(r.Context(), q)
			}
		case "gate.get":
			var q hitl.GetCommand
			callErr = json.Unmarshal(raw, &q)
			if callErr == nil && q.Caller.ApplicationID != "gatecrasher" {
				callErr = hitl.ErrUnauthorized
			}
			if callErr == nil {
				result, callErr = lifecycle.Get(r.Context(), q)
			}
		case "gate.await":
			var q hitl.AwaitCommand
			callErr = json.Unmarshal(raw, &q)
			if callErr == nil && q.Caller.ApplicationID != "gatecrasher" {
				callErr = hitl.ErrUnauthorized
			}
			if callErr == nil {
				result, callErr = lifecycle.Await(r.Context(), q)
			}
		case "gate.withdraw":
			var q hitl.WithdrawCommand
			callErr = json.Unmarshal(raw, &q)
			if callErr == nil && q.Caller.ApplicationID != "gatecrasher" {
				callErr = hitl.ErrUnauthorized
			}
			if callErr == nil {
				result, callErr = lifecycle.Withdraw(r.Context(), q)
			}
		default:
			callErr = hitl.ErrUnauthorized
		}
		if callErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(409)
			// #nosec G705 -- application/json HITL error encoding in an isolated contract fixture, never HTML.
			_, _ = w.Write(hitl.EncodeError(callErr))
			return
		}
		if verb == "gate.enqueue" && loseReply.Swap(false) {
			h, ok := w.(http.Hijacker)
			if !ok {
				t.Error("cannot simulate lost enqueue")
				return
			}
			c, _, e := h.Hijack()
			if e == nil {
				_ = c.Close()
			}
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "provider": "tachyon", "verb": verb, "data": result})
	})
	server := httptest.NewServer(guard.Middleware(handler))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL, TokenFile: tokenPath, CallerScope: "gatecrasher", AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	r := gatetest.Request(time.Now().UTC())
	sealed, _ := json.Marshal(r)
	opaque, _ := json.Marshal(string(sealed))
	request := hitl.EnqueueRequest{ContractVersion: hitl.ContractVersion, Kind: "gate_native_v1", IdempotencyKey: r.IdempotencyKey, Source: hitl.SourceAssertion{ApplicationID: "gatecrasher", AgentID: "fixture"}, ExpiresAt: &r.ExpiresAt, Extra: map[string]json.RawMessage{"gate_request": opaque}}
	if _, err = client.Enqueue(t.Context(), request); !errors.Is(err, ErrTransport) {
		t.Fatal("ambiguous enqueue did not fail", err)
	}
	ticket, err := client.Enqueue(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	same, err := client.Enqueue(t.Context(), request)
	if err != nil || same.ItemID != ticket.ItemID {
		t.Fatal(same, err)
	}
	changed := request
	changed.Extra = map[string]json.RawMessage{"gate_request": json.RawMessage(`"changed"`)}
	if _, err = client.Enqueue(t.Context(), changed); !errors.Is(err, hitl.ErrIdempotencyConflict) {
		t.Fatal("typed conflict lost", err)
	}
	zero := 0
	pending, err := client.Await(t.Context(), hitl.AwaitCommand{ContractVersion: hitl.ContractVersion, ItemID: ticket.ItemID, Caller: hitl.CallerAssertion{ApplicationID: "gatecrasher"}, WaitMs: &zero})
	if err != nil || pending.Item.State.IsTerminal() {
		t.Fatal(pending, err)
	}
	view, err := client.Get(t.Context(), hitl.GetCommand{ContractVersion: hitl.ContractVersion, ItemID: ticket.ItemID, Caller: hitl.CallerAssertion{ApplicationID: "gatecrasher"}})
	if err != nil {
		t.Fatal(err)
	}
	var echoed hitl.EnqueueRequest
	if json.Unmarshal(view.Item.RequestSnapshot, &echoed) != nil {
		t.Fatal("snapshot decode")
	}
	var text string
	if json.Unmarshal(echoed.Extra["gate_request"], &text) != nil {
		t.Fatal("sealed payload lost")
	}
	var snapshot gate.Request
	if json.Unmarshal([]byte(text), &snapshot) != nil || !snapshot.NativeRequestID.Equal(r.NativeRequestID) {
		t.Fatal("large numeric native ID changed")
	}
	if _, err = client.Respond(t.Context(), hitl.RespondCommand{}); !errors.Is(err, hitl.ErrUnauthorized) {
		t.Fatal("producer gained decision authority")
	}
	wrong := int64(99)
	if _, err = client.Withdraw(t.Context(), hitl.WithdrawCommand{ContractVersion: hitl.ContractVersion, ItemID: ticket.ItemID, Caller: hitl.CallerAssertion{ApplicationID: "gatecrasher"}, ExpectedRevision: &wrong}); !errors.Is(err, hitl.ErrStaleRevision) {
		t.Fatal("typed revision conflict lost", err)
	}
	out, err := client.Withdraw(t.Context(), hitl.WithdrawCommand{ContractVersion: hitl.ContractVersion, ItemID: ticket.ItemID, Caller: hitl.CallerAssertion{ApplicationID: "gatecrasher"}})
	if err != nil || out.OutcomeState() != hitl.StateCanceled {
		t.Fatal(out, err)
	}
	active.Store(false)
	if _, err = client.Get(t.Context(), hitl.GetCommand{ContractVersion: hitl.ContractVersion, ItemID: ticket.ItemID, Caller: hitl.CallerAssertion{ApplicationID: "gatecrasher"}}); err == nil {
		t.Fatal("inactive mapping accepted")
	}
	active.Store(true)
	if err = os.WriteFile(tokenPath, []byte("rotated-unknown-credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Get(t.Context(), hitl.GetCommand{ContractVersion: hitl.ContractVersion, ItemID: ticket.ItemID, Caller: hitl.CallerAssertion{ApplicationID: "gatecrasher"}}); err == nil {
		t.Fatal("rotated unknown credential accepted")
	}
}
func TestClientRejectsUnsafeOriginAndPermissiveTokenCustody(t *testing.T) {
	// Build invalid URL userinfo without embedding a static credential in source.
	userinfo := url.URL{Scheme: "https", Host: "example.test", User: url.UserPassword("fixture", rand.Text())}
	for _, base := range []string{"http://example.test", userinfo.String(), "https://example.test/path", "https://example.test?token=x"} {
		if _, err := New(Config{BaseURL: base, TokenFile: "external", CallerScope: "gatecrasher", AllowLoopbackHTTP: true}); err == nil {
			t.Fatal("unsafe owner URL accepted", base)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c, err := New(Config{BaseURL: "https://example.test", TokenFile: filepath.Join(t.TempDir(), "missing"), CallerScope: "gatecrasher"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Get(ctx, hitl.GetCommand{ContractVersion: hitl.ContractVersion, ItemID: "item", Caller: hitl.CallerAssertion{ApplicationID: "gatecrasher"}}); err == nil {
		t.Fatal("missing credential accepted")
	}
}

// Wire-only fixture: verifies the approved minimal GET and explicit scope. This
// test does not implement or establish Tachyon's current-user authority checks.
func TestAssessmentUsesScopedMinimalGETAndSeparateGrant(t *testing.T) {
	token := rand.Text()
	tokenPath := filepath.Join(t.TempDir(), "producer")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	scopes := libauth.NewScopeTable()
	const path = "/api/agent/v1/data/providers/tachyon/verbs/gate.assess-response"
	scopes.Route(http.MethodGet, path, "tachyon.gate.assess-response")
	guard, err := libauth.New(libauth.Config{Mode: libauth.ModeEnforce, Scopes: scopes, Verifier: libauth.NewAPIKeyVerifier(libauth.APIKey{ID: "mapped-producer", Hash: libauth.HashKey(token), Scopes: []string{"tachyon.gate.assess-response"}})})
	if err != nil {
		t.Fatal(err)
	}
	var unavailable atomic.Bool
	var corrupt atomic.Value
	corrupt.Store(func(map[string]json.RawMessage) {})
	server := httptest.NewServer(guard.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != path {
			t.Error("incorrect assessment method/path")
			w.WriteHeader(405)
			return
		}
		// A strict minimal owner decoder will reject caller-selected digests/actor/option.
		var q struct {
			ContractVersion          string               `json:"contract_version"`
			ItemID                   string               `json:"item_id"`
			Caller                   hitl.CallerAssertion `json:"caller"`
			ExpectedTerminalRevision int64                `json:"expected_terminal_revision"`
		}
		decoder := json.NewDecoder(strings.NewReader(r.URL.Query().Get("input")))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&q) != nil || q.ContractVersion != hitl.ContractVersion || q.ItemID != "retained-item" || q.Caller.ApplicationID != "gatecrasher" || q.ExpectedTerminalRevision != 2 {
			t.Error("incorrect assessment lookup")
			w.WriteHeader(400)
			return
		}
		if unavailable.Load() {
			w.WriteHeader(403)
			_, _ = w.Write(hitl.EncodeError(hitl.ErrUnauthorized))
			return
		}
		now := time.Now().UTC()
		native := gatetest.Request(now)
		requestDigest, digestErr := native.Digest()
		if digestErr != nil {
			t.Error(digestErr)
			w.WriteHeader(500)
			return
		}
		data := ownerwire.ResponseAssessment{IdempotencyKey: native.IdempotencyKey, Binding: native.Binding, NativeRequestID: native.NativeRequestID, ContractVersion: "1", OwnerRef: "owner-fixture", ItemID: q.ItemID, RequestDigest: requestDigest, OperationDigest: native.OperationDigest, OptionID: native.Options[0].ID, TerminalRevision: q.ExpectedTerminalRevision, Participant: hitl.Participant{PrincipalRef: "user:reviewer-fixture", Authority: "tachyon/identity", Assurance: "operator-token"}, AssessedAt: now, ExpiresAt: now.Add(ownerwire.AssessmentTTL)}
		encoded, encodeErr := json.Marshal(data)
		var fields map[string]json.RawMessage
		if encodeErr != nil || json.Unmarshal(encoded, &fields) != nil {
			t.Error("invalid fixture observation")
			w.WriteHeader(500)
			return
		}
		corrupt.Load().(func(map[string]json.RawMessage))(fields)
		_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "provider": "tachyon", "verb": "gate.assess-response", "data": fields})
	})))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL, TokenFile: tokenPath, CallerScope: "gatecrasher", AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	q := ownerwire.AssessResponseCommand{GetCommand: hitl.GetCommand{ContractVersion: hitl.ContractVersion, ItemID: "retained-item", Caller: hitl.CallerAssertion{ApplicationID: "gatecrasher"}}, ExpectedTerminalRevision: 2}
	out, err := client.AssessResponse(t.Context(), q)
	if err != nil || out.OwnerRef != "owner-fixture" || out.TerminalRevision != 2 {
		t.Fatal(out, err)
	}
	t.Run("gate-version-refused-in-hitl-input", func(t *testing.T) {
		wrong := q
		wrong.ContractVersion = gate.ContractVersion
		if _, assessmentErr := client.AssessResponse(t.Context(), wrong); !errors.Is(assessmentErr, hitl.ErrUnauthorized) {
			t.Fatal("gate version accepted as native HITL input", assessmentErr)
		}
	})
	t.Run("hitl-version-refused-in-gate-output", func(t *testing.T) {
		corrupt.Store(func(fields map[string]json.RawMessage) { fields["contract_version"] = json.RawMessage(`"1.0"`) })
		if _, assessmentErr := client.AssessResponse(t.Context(), q); !errors.Is(assessmentErr, ErrTransport) {
			t.Fatal("HITL version accepted as gate assessment output", assessmentErr)
		}
	})
	for _, field := range []string{"idempotency_key", "binding", "native_request_id"} {
		t.Run("missing-"+field, func(t *testing.T) {
			corrupt.Store(func(fields map[string]json.RawMessage) { delete(fields, field) })
			if _, assessmentErr := client.AssessResponse(t.Context(), q); !errors.Is(assessmentErr, ErrTransport) {
				t.Fatal("omitted derived field accepted", field, assessmentErr)
			}
		})
		t.Run("null-"+field, func(t *testing.T) {
			corrupt.Store(func(fields map[string]json.RawMessage) { fields[field] = json.RawMessage(`null`) })
			if _, assessmentErr := client.AssessResponse(t.Context(), q); !errors.Is(assessmentErr, ErrTransport) {
				t.Fatal("null derived field accepted", field, assessmentErr)
			}
		})
	}
	for _, mutate := range []func(map[string]json.RawMessage){
		func(fields map[string]json.RawMessage) { fields["idempotency_key"] = json.RawMessage(`""`) },
		func(fields map[string]json.RawMessage) { fields["binding"] = json.RawMessage(`{}`) },
		func(fields map[string]json.RawMessage) { fields["native_request_id"] = json.RawMessage(`{}`) },
		func(fields map[string]json.RawMessage) {
			fields["NativeRequestID"] = fields["native_request_id"]
			delete(fields, "native_request_id")
		},
	} {
		corrupt.Store(mutate)
		if _, err = client.AssessResponse(t.Context(), q); !errors.Is(err, ErrTransport) {
			t.Fatal("invalid or aliased derived field accepted", err)
		}
	}
	corrupt.Store(func(map[string]json.RawMessage) {})
	unavailable.Store(true)
	if _, err = client.AssessResponse(t.Context(), q); !errors.Is(err, hitl.ErrUnauthorized) {
		t.Fatal("owner refusal lost", err)
	}
	q.Caller.ApplicationID = "another-producer"
	if _, err = client.AssessResponse(t.Context(), q); !errors.Is(err, hitl.ErrUnauthorized) {
		t.Fatal("caller namespace accepted", err)
	}
}

func TestClientRefusesMalformedEnvelopesAndBoundsReadInput(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "producer")
	if err := os.WriteFile(tokenPath, []byte(rand.Text()), 0o600); err != nil {
		t.Fatal(err)
	}
	const payload = `{"native_request_id":900719925474099312345,"opaque":{"number":900719925474099312346}}`
	const valid = `{"version":1,"provider":"tachyon","verb":"gate.get","data":` + payload + `}`
	var response atomic.Value
	response.Store(valid)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()
		if r.Method != http.MethodGet || len(values) != 1 || len(values["input"]) != 1 || len(values.Get("input")) > 16<<10 {
			t.Error("read transport violated single bounded input")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, response.Load().(string))
	}))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL, TokenFile: tokenPath, CallerScope: "gatecrasher", AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	var out json.RawMessage
	if err = client.call(t.Context(), "gate.get", false, map[string]string{"item_id": "item"}, &out); err != nil || string(out) != payload {
		t.Fatal("opaque payload changed", string(out), err)
	}
	for _, body := range []string{
		`{"version":2,"provider":"tachyon","verb":"gate.get","data":{}}`,
		`{"version":1,"provider":"another","verb":"gate.get","data":{}}`,
		`{"version":1,"provider":"tachyon","verb":"gate.await","data":{}}`,
		`{"version":1,"provider":"tachyon","verb":"gate.get","data":null}`,
		`{"version":1,"provider":"tachyon","verb":"gate.get"}`,
		`{"version":1,"provider":"tachyon","verb":"gate.get","data":{},"unknown":true}`,
		`{"version":2,"version":1,"provider":"tachyon","verb":"gate.get","data":{}}`,
		`{"version":1,"provider":"other","provider":"tachyon","verb":"gate.get","data":{}}`,
		valid + `{}`,
		`[]`,
	} {
		response.Store(body)
		if err = client.call(t.Context(), "gate.get", false, map[string]string{"item_id": "item"}, &out); !errors.Is(err, ErrTransport) {
			t.Fatal("malformed wrapper accepted", body, err)
		}
	}
	response.Store(valid)
	atLimit := json.RawMessage(`{"value":"` + strings.Repeat("x", (16<<10)-len(`{"value":""}`)) + `"}`)
	if err = client.call(t.Context(), "gate.get", false, atLimit, &out); err != nil {
		t.Fatal("valid read boundary refused", err)
	}
	tooLarge := map[string]string{"value": strings.Repeat("x", 16<<10)}
	if err = client.call(t.Context(), "gate.get", false, tooLarge, &out); !errors.Is(err, ErrTransport) {
		t.Fatal("oversized read accepted", err)
	}
}

func TestProvisionalErrorsNeverInventMissingConflictEvidence(t *testing.T) {
	if err := decodeError([]byte(`{"code":"unauthorized","message":"refused"}`)); !errors.Is(err, hitl.ErrUnauthorized) {
		t.Fatal("baseline flat refusal lost", err)
	}
	for _, raw := range []string{
		`{"code":"stale_revision","message":"details dropped by baseline"}`,
		`{"code":"idempotency_conflict","message":"details dropped by baseline"}`,
		`{"code":"terminal_conflict"}`,
		`{"contract_version":"other","code":"unauthorized"}`,
		`{"code":"unknown"}`,
		`{"code":"unauthorized","new_field":true}`,
		`{"code":"unauthorized","code":"not_found"}`,
		`{"code":"unauthorized","message":null}`,
		`{"version":1,"provider":"tachyon","verb":"gate.get","data":{}}`,
		`null`, `not JSON`,
		`{"contract_version":"1.0","code":"idempotency_conflict","idempotency_key":"key","existing_item_id":"item","actual_revision":7}`,
	} {
		if err := decodeError([]byte(raw)); !errors.Is(err, ErrTransport) {
			t.Fatal("malformed or incomplete error gained evidence", raw, err)
		}
	}
}
