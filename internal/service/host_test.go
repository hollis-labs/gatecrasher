package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/ownerwire"

	"github.com/hollis-labs/libs/agent/sdk"
	"github.com/hollis-labs/libs/llm/core/llmtypes"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/core/hitl/memstore"
	"github.com/hollis-labs/libs/mesh/core/runtimecontract"
	libauth "github.com/hollis-labs/libs/security/auth"
)

type observedOwner struct {
	*hitl.Service
	queued         chan hitl.Handle
	request        chan hitl.EnqueueRequest
	assessmentHook func(*ownerwire.ResponseAssessment) error
}

func (o *observedOwner) Enqueue(ctx context.Context, r hitl.EnqueueRequest) (hitl.Handle, error) {
	h, err := o.Service.Enqueue(ctx, r)
	if err == nil {
		select {
		case o.queued <- h:
		default:
		}
		select {
		case o.request <- r:
		default:
		}
	}
	return h, err
}
func newHost(t testing.TB) (*Service, *observedOwner, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host.db")
	st := openStore(t, path)
	s, err := New(context.Background(), st, Config{OwnerRef: "tachyon-fixture", CallerScope: "gatecrasher", CallbackSubject: "key:callback-fixture", ActorMap: map[string]string{"tachyon/user:reviewer": "person:reviewer", "tachyon/user:self": "person:requester", "gatecrasher/key:recipe-fixture": "person:requester"}})
	if err != nil {
		t.Fatal(err)
	}
	owner := &observedOwner{Service: hitl.NewService(memstore.New(), hitl.Options{Clock: s.cfg.Now, PollInterval: time.Millisecond}), queued: make(chan hitl.Handle, 20), request: make(chan hitl.EnqueueRequest, 20)}
	if err = s.Wire(owner); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(); _ = st.Close() })
	return s, owner, path
}
func runtimeFixture(s *Service) RuntimeFacts {
	now := s.cfg.Now()
	owner := runtimecontract.OwnerID("owner-fixture")
	b := runtimecontract.Binding{OwnerID: owner, OperativeID: "operative", ConversationID: "conversation", AttemptID: "attempt-7", Generation: 7}
	env := runtimecontract.EnvironmentRef{Receipt: reference(owner, "environment"), Workspace: reference(owner, "workspace"), Lease: reference(owner, "lease"), Grants: reference(owner, "grants"), Capabilities: []string{"tool.execute", sdk.CapabilityApproval}, ExpiresAt: now.Add(5 * time.Minute)}
	return RuntimeFacts{Binding: b, Environment: env, Requester: "person:requester", Resources: FingerprintTool(owner).Versions, Policy: reference(owner, PolicyID)}
}
func reservationFixture(f RuntimeFacts) sdk.RunReservation {
	return sdk.RunReservation{RunID: "run", Binding: f.Binding, Environment: f.Environment, DefinitionDigest: RecipeDefinitionDigest(), Route: "model", Model: "fixture", InputDigest: digest("sdk-run-v1", "exact input")}
}
func prepareSDK(t testing.TB, s *Service) (RuntimeFacts, sdk.RunReservation, sdk.Operation, gate.Request) {
	t.Helper()
	f := runtimeFixture(s)
	if err := s.Enroll(context.Background(), f); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	rr := reservationFixture(f)
	if err := s.ReserveRun(context.Background(), rr); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	op := sdk.Operation{RunID: rr.RunID, InputDigest: rr.InputDigest, Version: "sdk-tool-v1", ID: "turn/tool/call", Binding: f.Binding, Environment: f.Environment, DefinitionDigest: rr.DefinitionDigest, PermissionProfile: PolicyID, TurnID: "turn", ToolCallID: "call", Tool: "fingerprint", Arguments: json.RawMessage(`{"text":"hello"}`), Versions: f.Resources}
	p, err := s.Evaluate(context.Background(), op)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	d, err := op.Digest()
	if err != nil {
		t.Fatal(err)
	}
	scope := gate.Scope{Kind: gate.Once, Target: op.ID, MaxUses: 1, ExpiresAt: s.cfg.Now().Add(time.Minute)}
	r := gate.Request{ContractVersion: gate.ContractVersion, IdempotencyKey: "sdk-request", Binding: f.Binding, Adapter: sdk.NativeAdapterScope(), Environment: &f.Environment, EnforcementPoint: "tradecraft/tool-admission", OperationID: op.ID, OperationClass: "tool", OperationDigest: d, ResourceVersions: f.Resources, TurnID: op.TurnID, ToolCallID: op.ToolCallID, NativeRequestID: gate.NativeRequestID(`"turn/tool/call"`), Options: []gate.NativeOption{{ID: "allow-once", Kind: gate.Allow, Scope: scope}, {ID: "deny", Kind: gate.Deny, Scope: scope}}, ExpiresAt: scope.ExpiresAt, Policy: p.Reference, Provenance: p.Provenance, Obligations: p.Obligations}
	return f, rr, op, r
}
func callbackPrincipal() libauth.Principal {
	return libauth.Principal{Verified: true, Kind: libauth.KindService, ID: "key:callback-fixture", TokenID: "callback-fixture", Audience: "gatecrasher", Scopes: []string{CallbackScope}}
}
func proposed(r gate.Request, h hitl.Handle) ProposedResponse {
	d, _ := r.Digest()
	until := time.Now().UTC().Add(ownerwire.AssessmentTTL)
	if r.ExpiresAt.Before(until) {
		until = r.ExpiresAt
	}
	return ProposedResponse{ContractVersion: "1", OwnerRef: "tachyon-fixture", IdempotencyKey: r.IdempotencyKey, ItemID: h.ItemID, RequestDigest: d, OperationDigest: r.OperationDigest, Binding: r.Binding, NativeRequestID: r.NativeRequestID, ExpectedRevision: h.Revision, PresentedRevision: h.Revision, OptionID: "allow-once", Participant: hitl.Participant{PrincipalRef: "user:reviewer", Authority: "tachyon/identity", Assurance: "operator-token"}, ActorScopes: []string{"tachyon.operator", "tachyon.approvals.resolve"}, AssessedAt: time.Now().UTC(), ExpiresAt: until}
}
func decide(t testing.TB, s *Service, o *observedOwner, r gate.Request, h hitl.Handle, option string) {
	t.Helper()
	in := proposed(r, h)
	in.OptionID = option
	if _, err := s.AuthorizeResponse(context.Background(), callbackPrincipal(), in); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Respond(context.Background(), hitl.RespondCommand{ItemID: h.ItemID, ExpectedRevision: &h.Revision, Response: hitl.Response{Kind: "gate_native_v1", Decision: option}, Participant: in.Participant}); err != nil {
		t.Fatal(err)
	}
}
func TestRunReservationAndUnknownOnceClaimSurviveReopen(t *testing.T) {
	s, o, path := newHost(t)
	f, rr, op, r := prepareSDK(t, s)
	ticket, err := s.coordinator.Request(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	decide(t, s, o, r, ticket.Handle, "allow-once")
	res, err := SDKGate{Host: s}.Await(t.Context(), ticket, gate.WaitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := policyProjection(f)
	a := sdk.Admission{Run: rr, Kind: "tool", Binding: f.Binding, Environment: f.Environment, DefinitionDigest: rr.DefinitionDigest, Operation: &op, Request: &r, Decision: res.Decision, Policy: &p}
	effects := 0
	if err = s.Admit(t.Context(), a, func(context.Context) error { effects++; return errors.New("uncertain external effect") }); err == nil {
		t.Fatal("uncertain callback became success")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = s.st.Close(); err != nil {
		t.Fatal(err)
	}
	st := openStore(t, path)
	defer st.Close()
	next, err := New(t.Context(), st, s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err = next.Wire(o); err != nil {
		t.Fatal(err)
	}
	if err = next.VerifyEnvironment(t.Context(), f.Binding, f.Environment, nil); err == nil {
		t.Fatal("reopened host retained a dead runtime writer")
	}
	successor := f
	successor.Binding.Generation++
	successor.Binding.AttemptID = "attempt-8"
	if err = next.Enroll(t.Context(), successor); err != nil {
		t.Fatal(err)
	}
	rr.Binding = successor.Binding
	if err = next.ReserveRun(t.Context(), rr); !errors.Is(err, sdk.ErrRunUsed) {
		t.Fatal("logical run replayed after generation replacement", err)
	}
	// Inspect the durable one-use admission record rather than trying to resume
	// an old runtime. There is no release/retry method on uncertain claims.
	var descriptor string
	if err = st.Reader().QueryRowContext(t.Context(), `SELECT descriptor_json FROM operation_claims WHERE claim_key=?`, logicalKey(f.Binding, res.Decision.Resolution.ResolutionID+"/"+r.OperationID)).Scan(&descriptor); err != nil || descriptor == "" {
		t.Fatal(err)
	}
	if effects != 1 {
		t.Fatal("unexpected callback count", effects)
	}
}
func TestAuthorityCallbackRefusesSpoofSelfRevisionChoiceAndStrongerProof(t *testing.T) {
	s, o, _ := newHost(t)
	_, _, _, r := prepareSDK(t, s)
	ticket, err := s.coordinator.Request(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	base := proposed(r, ticket.Handle)
	for _, mutate := range []func(*ProposedResponse){func(q *ProposedResponse) { q.OwnerRef = "wrong" }, func(q *ProposedResponse) { q.RequestDigest.Value = strings.Repeat("0", 64) }, func(q *ProposedResponse) { q.ExpectedRevision++ }, func(q *ProposedResponse) { q.PresentedRevision++ }, func(q *ProposedResponse) { q.OptionID = "Always" }, func(q *ProposedResponse) { q.Participant.PrincipalRef = "user:self" }, func(q *ProposedResponse) { q.Participant.PrincipalRef = "key:agent" }, func(q *ProposedResponse) { q.Participant.Assurance = "passkey" }, func(q *ProposedResponse) { q.ActorScopes = nil }} {
		q, _ := detached(base)
		mutate(&q)
		if _, err = s.AuthorizeResponse(t.Context(), callbackPrincipal(), q); err == nil {
			t.Fatal("forged proposal authorized", q)
		}
	}
	for _, mutate := range []func(*libauth.Principal){func(p *libauth.Principal) { p.Verified = false }, func(p *libauth.Principal) { p.ID = "key:producer" }, func(p *libauth.Principal) { p.Kind = "user" }, func(p *libauth.Principal) { p.Audience = "tachyon" }, func(p *libauth.Principal) { p.Scopes = nil }, func(p *libauth.Principal) { p.ExpiresAt = time.Now().Add(-time.Second) }} {
		p := callbackPrincipal()
		mutate(&p)
		if _, err = s.AuthorizeResponse(t.Context(), p, base); err == nil {
			t.Fatal("wrong callback credential authorized")
		}
	}
	decide(t, s, o, r, ticket.Handle, "deny")
	res, err := SDKGate{Host: s}.Await(t.Context(), ticket, gate.WaitOptions{})
	if err != nil || res.Decision.OptionID != "deny" {
		t.Fatal(res, err)
	}
}
func TestConcurrentOnceAdmissionAndRevocationFence(t *testing.T) {
	s, o, _ := newHost(t)
	f, rr, op, r := prepareSDK(t, s)
	ticket, err := s.coordinator.Request(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	decide(t, s, o, r, ticket.Handle, "allow-once")
	res, err := SDKGate{Host: s}.Await(t.Context(), ticket, gate.WaitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := policyProjection(f)
	a := sdk.Admission{Run: rr, Kind: "tool", Binding: f.Binding, Environment: f.Environment, DefinitionDigest: rr.DefinitionDigest, Operation: &op, Request: &r, Decision: res.Decision, Policy: &p}
	var effects atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			admitErr := s.Admit(t.Context(), a, func(context.Context) error { effects.Add(1); return nil })
			if admitErr != nil && !errors.Is(admitErr, ErrClaimed) {
				t.Error(admitErr)
			}
		}()
	}
	close(start)
	wg.Wait()
	if effects.Load() != 1 {
		t.Fatal(effects.Load())
	}
	if err = s.Revoke(t.Context(), f.Binding); err != nil {
		t.Fatal(err)
	}
	if err = s.Admit(t.Context(), a, func(context.Context) error { effects.Add(1); return nil }); err == nil || effects.Load() != 1 {
		t.Fatal("revoked callback started", err)
	}
}

type recipeModel struct{ calls atomic.Int32 }

func (*recipeModel) Capabilities() llmtypes.ProviderCapabilities {
	return llmtypes.ProviderCapabilities{SupportsToolCalling: true, ContextWindowSize: 65536}
}
func (*recipeModel) Complete(context.Context, llmtypes.ChatRequest) (string, error) {
	return "", errors.New("stream only")
}
func (m *recipeModel) StreamChat(ctx context.Context, q llmtypes.ChatRequest) (<-chan llmtypes.StreamEvent, error) {
	m.calls.Add(1)
	out := make(chan llmtypes.StreamEvent, 2)
	if len(q.Messages) > 2 {
		out <- llmtypes.StreamEvent{Type: llmtypes.EventDelta, Content: "fingerprint complete"}
	} else {
		out <- llmtypes.StreamEvent{Type: llmtypes.EventToolUse, ToolUse: &llmtypes.ToolUseBlock{ID: "call-1", Name: "fingerprint", Input: map[string]any{"text": "hello"}}}
	}
	out <- llmtypes.StreamEvent{Type: llmtypes.EventDone}
	close(out)
	return out, ctx.Err()
}
func TestActualSDKRecipeAndReceiptCorrelation(t *testing.T) {
	s, o, _ := newHost(t)
	model := &recipeModel{}
	p := libauth.Principal{Verified: true, ID: "key:recipe-fixture", Kind: libauth.KindService, Audience: "gatecrasher", Scopes: []string{RecipeScope}}
	type result struct {
		r   sdk.Result
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := s.RunRecipe(t.Context(), p, "logical-recipe", "hello", model)
		done <- result{r, err}
	}()
	var h hitl.Handle
	select {
	case h = <-o.queued:
	case early := <-done:
		t.Fatal("recipe stopped before approval", early.r, early.err)
	case <-time.After(5 * time.Second):
		t.Fatal("real SDK did not request approval")
	}
	req := <-o.request
	var raw string
	if err := json.Unmarshal(req.Extra["gate_request"], &raw); err != nil {
		t.Fatal(err)
	}
	var r gate.Request
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	decide(t, s, o, r, h, "allow-once")
	select {
	case out := <-done:
		if out.err != nil || out.r.Status != sdk.Succeeded {
			t.Fatal(out.r, out.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SDK did not finish")
	}
	route, err := s.Journal.Load(t.Context(), r.IdempotencyKey)
	if err != nil || route.Delivery == nil || route.Delivery.Status != gate.DeliveryAcknowledged || route.DecisionRef == "" || len(route.Executions) != 1 || route.Executions[0].State != gate.ExecutionSucceeded {
		t.Fatal(route, err)
	}
	if model.calls.Load() != 2 {
		t.Fatal("unexpected model loop", model.calls.Load())
	}
	if _, err = s.RunRecipe(t.Context(), p, "logical-recipe", "hello", model); !errors.Is(err, sdk.ErrRunUsed) || model.calls.Load() != 2 {
		t.Fatal("duplicate logical run reached model", err)
	}
	sum := sha256.Sum256([]byte("hello"))
	toolResult, err := FingerprintTool(r.Binding.OwnerID).Execute(t.Context(), map[string]any{"text": "hello"})
	if err != nil || toolResult.Content != hex.EncodeToString(sum[:]) {
		t.Fatal(toolResult, err)
	}
}
func TestMutationAfterApprovalRefusesUnregisteredOperation(t *testing.T) {
	s, o, _ := newHost(t)
	f, rr, op, r := prepareSDK(t, s)
	ticket, err := s.coordinator.Request(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	decide(t, s, o, r, ticket.Handle, "allow-once")
	res, err := SDKGate{Host: s}.Await(t.Context(), ticket, gate.WaitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := policyProjection(f)
	a := sdk.Admission{Run: rr, Kind: "tool", Binding: f.Binding, Environment: f.Environment, DefinitionDigest: rr.DefinitionDigest, Operation: &op, Request: &r, Decision: res.Decision, Policy: &p}
	op.Arguments = json.RawMessage(`{"text":"edited"}`)
	called := false
	if err = s.Admit(t.Context(), a, func(context.Context) error { called = true; return nil }); err == nil || called {
		t.Fatal("changed descriptor admitted", err)
	}
	snapshot, _ := detached(r)
	snapshot.ResourceVersions[0].Revision = "changed"
	if err = s.Verify(t.Context(), snapshot, *res.Decision); err == nil {
		t.Fatal("changed resource accepted")
	}
	if !reflect.DeepEqual(r.ResourceVersions, f.Resources) {
		t.Fatal("test mutated original facts")
	}
}

type ambiguousEnqueue struct {
	*observedOwner
	lose atomic.Bool
}

func (o *ambiguousEnqueue) Enqueue(ctx context.Context, r hitl.EnqueueRequest) (hitl.Handle, error) {
	h, err := o.observedOwner.Enqueue(ctx, r)
	if err == nil && o.lose.Swap(false) {
		return hitl.Handle{}, errors.New("lost reply after owner commit")
	}
	return h, err
}
func TestAmbiguousEnqueueRecoversSameOwnerAfterHostReopen(t *testing.T) {
	s, o, path := newHost(t)
	_, _, _, request := prepareSDK(t, s)
	ambiguous := &ambiguousEnqueue{observedOwner: o}
	ambiguous.lose.Store(true)
	if err := s.Wire(ambiguous); err != nil {
		t.Fatal(err)
	}
	if _, err := s.coordinator.Request(t.Context(), request); err == nil {
		t.Fatal("ambiguous enqueue did not fail")
	}
	h := <-o.queued
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.st.Close(); err != nil {
		t.Fatal(err)
	}
	st := openStore(t, path)
	defer st.Close()
	next, err := New(t.Context(), st, s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err = next.Wire(ambiguous); err != nil {
		t.Fatal(err)
	}
	tickets, cursor, err := next.RecoverRoutes(t.Context(), "", 10)
	if err != nil || len(tickets) != 1 || cursor != "" || tickets[0].Handle.ItemID != h.ItemID {
		t.Fatal(tickets, cursor, err)
	}
	if _, err = next.coordinator.Deliver(t.Context(), tickets[0]); err == nil {
		t.Fatal("recovery auto-granted a decision")
	}
}
