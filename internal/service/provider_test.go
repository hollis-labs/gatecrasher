package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/ownerwire"
	"github.com/hollis-labs/libs/harness/core/adapters/agentsessions"
	"github.com/hollis-labs/libs/harness/core/adapters/turn"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/gatecrasher"
)

func preparedNative(t testing.TB, s *Service, o *observedOwner, id string, choices ...string) (*agentsessions.JsonRpcPreparedReply, agentsessions.JsonRpcServerRequest, gate.Request) {
	return preparedNativeWithFacts(t, s, o, id, runtimeFixture(s), choices...)
}

func preparedNativeWithFacts(t testing.TB, s *Service, o *observedOwner, id string, f RuntimeFacts, choices ...string) (*agentsessions.JsonRpcPreparedReply, agentsessions.JsonRpcServerRequest, gate.Request) {
	t.Helper()
	if err := s.Enroll(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	native := agentsessions.JsonRpcServerRequest{ID: json.RawMessage(id), Method: turn.CodexCommandApprovalMethod, Binding: f.Binding, Params: json.RawMessage(`{"threadId":"thread","turnId":"turn","itemId":"item","command":"echo fixture","cwd":"/fixture","availableDecisions":["accept","decline","cancel"]}`)}
	expiry := s.cfg.Now().Add(time.Minute)
	base := gate.Request{ContractVersion: gate.ContractVersion, IdempotencyKey: "native-request", Binding: f.Binding, Adapter: CodexScope, Environment: &f.Environment, EnforcementPoint: "gatecrasher/codex-admission", OperationID: "native-operation", ResourceVersions: f.Resources, ExpiresAt: expiry, Policy: f.Policy, Provenance: policyProjection(f).Provenance, Obligations: policyProjection(f).Obligations}
	respond := s.ProviderResponder(func(context.Context, agentsessions.JsonRpcServerRequest) (turn.CodexGateFacts, error) {
		return turn.CodexGateFacts{Request: base, MaxScope: gate.Once, Descriptor: json.RawMessage(`{"version":1,"effect":"process","resourceVersion":"1","environment":"fixture"}`), ThreadID: "thread", TurnID: "turn", ItemID: "item", Command: "echo fixture", CWD: "/fixture"}, nil
	})
	type result struct {
		v   any
		err *agentsessions.JsonRpcError
	}
	done := make(chan result, 1)
	go func() { v, e := respond(context.Background(), native); done <- result{v, e} }()
	var h hitl.Handle
	select {
	case h = <-o.queued:
	case out := <-done:
		t.Fatalf("responder ended early: %v", out.err)
	case <-time.After(3 * time.Second):
		t.Fatal("native request not queued")
	}
	req := <-o.request
	var sealed string
	if json.Unmarshal(req.Extra["gate_request"], &sealed) != nil {
		t.Fatal("no sealed request")
	}
	var r gate.Request
	if json.Unmarshal([]byte(sealed), &r) != nil {
		t.Fatal("invalid gate request")
	}
	choice := "accept"
	if len(choices) == 1 {
		choice = choices[0]
	}
	decide(t, s, o, r, h, choice)
	select {
	case out := <-done:
		if out.err != nil {
			t.Fatal(out.err)
		}
		p, ok := out.v.(*agentsessions.JsonRpcPreparedReply)
		if !ok {
			t.Fatalf("not prepared: %T", out.v)
		}
		return p, native, r
	case <-time.After(3 * time.Second):
		t.Fatal("native approval did not prepare")
	}
	return nil, native, r
}
func TestProviderWrapperClaimsAtActualPreparedWriteAndRetainsFence(t *testing.T) {
	for _, id := range []string{`9007199254740993`, `"9007199254740993"`} {
		t.Run(id, func(t *testing.T) {
			s, o, _ := newHost(t)
			p, native, r := preparedNative(t, s, o, id)
			var calls atomic.Int32
			reader, writer := io.Pipe()
			wire := make(chan string, 1)
			go func() { raw, _ := io.ReadAll(reader); wire <- string(raw) }()
			if err := p.Deliver(t.Context(), func(c context.Context, result any, rpcErr *agentsessions.JsonRpcError) error {
				if c.Err() != nil || rpcErr != nil {
					t.Fatal(c.Err(), rpcErr)
				}
				// A different goroutine cannot take the host's revocation fence while the
				// original prepared callback is physically writing.
				blocked := make(chan struct{})
				release := make(chan struct{})
				go func() { s.mu.Lock(); close(blocked); <-release; s.mu.Unlock() }()
				select {
				case <-blocked:
					t.Fatal("fence released before physical write")
				case <-time.After(10 * time.Millisecond):
				}
				body, err := json.Marshal(struct {
					ID     json.RawMessage `json:"id"`
					Result any             `json:"result"`
				}{native.ID, result})
				if err != nil {
					return err
				}
				calls.Add(1)
				_, err = writer.Write(body)
				if e := writer.Close(); err == nil {
					err = e
				}
				close(release)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			raw := <-wire
			var frame struct {
				ID     json.RawMessage `json:"id"`
				Result json.RawMessage `json:"result"`
			}
			if json.Unmarshal([]byte(raw), &frame) != nil || !gate.NativeRequestID(frame.ID).Equal(gate.NativeRequestID(native.ID)) || string(frame.Result) != `{"decision":"accept"}` {
				t.Fatal(raw)
			}
			route, err := s.Journal.Load(t.Context(), r.IdempotencyKey)
			if err != nil || route.Delivery.Status != gate.DeliverySent {
				t.Fatal(route, err)
			}
			if err = s.ObserveProviderReply(t.Context(), native, agentsessions.JsonRpcReplySent); err != nil {
				t.Fatal(err)
			}
			if err = p.Deliver(t.Context(), func(context.Context, any, *agentsessions.JsonRpcError) error { calls.Add(1); return nil }); !errors.Is(err, gatecrasher.ErrUnknown) || calls.Load() != 1 {
				t.Fatal("unknown physical send replayed", err, calls.Load())
			}
		})
	}
}
func TestQueuedNativeExpiryOrRevocationEmitsNoAllow(t *testing.T) {
	for _, kind := range []string{"expiry", "revocation"} {
		t.Run(kind, func(t *testing.T) {
			s, o, _ := newHost(t)
			p, _, r := preparedNative(t, s, o, `7`)
			if kind == "revocation" {
				if err := s.Revoke(t.Context(), r.Binding); err != nil {
					t.Fatal(err)
				}
			} else {
				clock := s.cfg.Now
				s.cfg.Now = func() time.Time { return clock().Add(2 * time.Minute) }
			}
			calls := 0
			if err := p.Deliver(t.Context(), func(context.Context, any, *agentsessions.JsonRpcError) error { calls++; return nil }); err == nil || calls != 0 {
				t.Fatal("queued stale allow emitted", err, calls)
			}
		})
	}
}

func TestNativeCancelAndDenyRemainExactChoicesWithoutClaim(t *testing.T) {
	for _, choice := range []string{"cancel", "decline"} {
		t.Run(choice, func(t *testing.T) {
			s, o, _ := newHost(t)
			p, _, _ := preparedNative(t, s, o, `"native-choice"`, choice)
			var payload string
			if err := p.Deliver(t.Context(), func(_ context.Context, value any, _ *agentsessions.JsonRpcError) error {
				raw, err := json.Marshal(value)
				payload = string(raw)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if payload != `{"decision":"`+choice+`"}` {
				t.Fatal("native choice was coerced", payload)
			}
			var key string
			err := s.st.Reader().QueryRowContext(t.Context(), `SELECT claim_key FROM operation_claims LIMIT 1`).Scan(&key)
			if !isNoRows(err) {
				t.Fatal("refusal consumed an allow grant", key, err)
			}
		})
	}
}

func TestProviderEnvironmentExpiryBoundsDelayedPhysicalSendAndRetainsClaim(t *testing.T) {
	s, o, _ := newHost(t)
	facts := runtimeFixture(s)
	facts.Environment.ExpiresAt = s.cfg.Now().Add(2 * time.Second)
	prepared, _, request := preparedNativeWithFacts(t, s, o, `9007199254740993`, facts)
	if !request.ExpiresAt.After(facts.Environment.ExpiresAt) {
		t.Fatal("regression requires unequal request/environment expiry")
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	wire := make(chan []byte, 1)
	go func() { raw, _ := io.ReadAll(reader); wire <- raw }()
	err := prepared.Deliver(t.Context(), func(ctx context.Context, result any, rpcErr *agentsessions.JsonRpcError) error {
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(facts.Environment.ExpiresAt) {
			t.Error("physical send outlives authoritative environment")
		}
		delay := time.NewTimer(time.Until(facts.Environment.ExpiresAt.Add(25 * time.Millisecond)))
		defer delay.Stop()
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-delay.C:
		}
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		body, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = writer.Write(body)
		return err
	})
	if err == nil {
		t.Fatal("delayed expired send reported success")
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if payload := <-wire; len(payload) != 0 {
		t.Fatal("allow physically written after environment expiry", string(payload))
	}
	var claim string
	if err = s.st.Reader().QueryRowContext(t.Context(), `SELECT descriptor_json FROM operation_claims WHERE binding_key=?`, bindingKey(request.Binding)).Scan(&claim); err != nil || claim == "" {
		t.Fatal("expiry released the consumed claim", err)
	}
	if err = prepared.Deliver(t.Context(), func(context.Context, any, *agentsessions.JsonRpcError) error {
		t.Error("expired uncertain send replayed")
		return nil
	}); err == nil {
		t.Fatal("expired send replay reported success")
	}
}

func TestAssessmentNativeNumberAndStringIdentityMismatchRefusesBeforeSend(t *testing.T) {
	for _, pair := range []struct{ native, other string }{
		{`9007199254740993`, `"9007199254740993"`},
		{`"9007199254740993"`, `9007199254740993`},
	} {
		t.Run(pair.native, func(t *testing.T) {
			s, o, _ := newHost(t)
			prepared, _, request := preparedNative(t, s, o, pair.native)
			o.assessmentHook = func(a *ownerwire.ResponseAssessment) error {
				a.NativeRequestID = gate.NativeRequestID(pair.other)
				return nil
			}
			sent := false
			err := prepared.Deliver(t.Context(), func(context.Context, any, *agentsessions.JsonRpcError) error { sent = true; return nil })
			if err == nil || sent {
				t.Fatal("same digits with different native ID kind admitted", err, sent)
			}
			var claim string
			if err = s.st.Reader().QueryRowContext(t.Context(), `SELECT claim_key FROM operation_claims WHERE binding_key=?`, bindingKey(request.Binding)).Scan(&claim); !isNoRows(err) {
				t.Fatal("mismatched native identity reached grant consumption", claim, err)
			}
		})
	}
}
