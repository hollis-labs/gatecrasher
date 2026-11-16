package service

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/ownerwire"

	"github.com/hollis-labs/libs/agent/sdk"
	"github.com/hollis-labs/libs/mesh/core/agentdef"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/core/runtimecontract"
	"github.com/hollis-labs/libs/mesh/gatecrasher"
	libauth "github.com/hollis-labs/libs/security/auth"
	"github.com/hollis-labs/libs/security/policy"
)

func policyDecision() policy.Decision {
	return policy.Decision{Effect: policy.Ask, MatchedPolicies: []policy.PolicyMatch{{ID: PolicyID, Source: "gatecrasher", Reason: "explicit operator once approval"}}, Obligations: []policy.Obligation{{Kind: policy.Approval, PolicyID: PolicyID, Reference: PolicyID}}}
}
func policyProjection(f RuntimeFacts) sdk.PolicyResult {
	return sdk.PolicyResult{Decision: policyDecision(), Reference: f.Policy, Provenance: []runtimecontract.Reference{f.Policy}, Obligations: []gate.ObligationRef{{Kind: "approval", Ref: f.Policy}}}
}
func (s *Service) CheckDefinition(ctx context.Context, d agentdef.Definition, b runtimecontract.Binding, e runtimecontract.EnvironmentRef) error {
	if err := s.VerifyEnvironment(ctx, b, e, []string{"tool.execute"}); err != nil {
		return err
	}
	actual, err := agentdef.Digest(&d)
	if err != nil || actual != RecipeDefinitionDigest() {
		return gate.ErrUnsupported
	}
	if d.DefinitionID != "gatecrasher-fingerprint" || len(d.Requirements.Tools) != 1 || d.Requirements.Tools[0] != "fingerprint" || d.HarnessProfile.Permissions.Profile != PolicyID {
		return gate.ErrUnsupported
	}
	return nil
}
func (s *Service) Evaluate(ctx context.Context, op sdk.Operation) (sdk.PolicyResult, error) {
	f, err := s.facts(ctx, op.Binding)
	if err != nil {
		return sdk.PolicyResult{}, err
	}
	if op.Version != "sdk-tool-v1" || op.Tool != "fingerprint" || op.PermissionProfile != PolicyID || !same(op.Environment, f.Environment) || !slices.Equal(op.Versions, f.Resources) {
		return sdk.PolicyResult{}, gate.ErrBinding
	}
	if op.DefinitionDigest != RecipeDefinitionDigest() || op.RunID == "" || op.ID == "" || op.InputDigest.Validate() != nil {
		return sdk.PolicyResult{}, ErrRefused
	}
	var args struct {
		Text string `json:"text"`
	}
	if strictJSON(op.Arguments, &args) != nil || len(args.Text) > 4096 {
		return sdk.PolicyResult{}, ErrRefused
	}
	var raw string
	if err = s.st.Reader().QueryRowContext(ctx, `SELECT reservation_json FROM run_reservations WHERE logical_key=?`, logicalKey(op.Binding, op.RunID)).Scan(&raw); err != nil {
		return sdk.PolicyResult{}, ErrRefused
	}
	var reserved sdk.RunReservation
	if decode(raw, &reserved) != nil || reserved.Binding != op.Binding || reserved.InputDigest != op.InputDigest || reserved.DefinitionDigest != op.DefinitionDigest {
		return sdk.PolicyResult{}, ErrRefused
	}
	descriptor, err := encode(op)
	if err != nil {
		return sdk.PolicyResult{}, err
	}
	d, err := op.Digest()
	if err != nil {
		return sdk.PolicyResult{}, err
	}
	res, err := s.st.ExecContext(ctx, `INSERT INTO operation_facts(operation_key,binding_key,descriptor_json,digest) VALUES(?,?,?,?) ON CONFLICT(operation_key) DO NOTHING`, logicalKey(op.Binding, op.ID), bindingKey(op.Binding), descriptor, d.Value)
	if err != nil {
		return sdk.PolicyResult{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return sdk.PolicyResult{}, err
	}
	if n == 0 {
		if err := s.checkOperation(ctx, op); err != nil {
			return sdk.PolicyResult{}, err
		}
	}
	return policyProjection(f), nil
}
func (s *Service) checkOperation(ctx context.Context, op sdk.Operation) error {
	var raw, digest string
	err := s.st.Reader().QueryRowContext(ctx, `SELECT descriptor_json,digest FROM operation_facts WHERE operation_key=? AND binding_key=?`, logicalKey(op.Binding, op.ID), bindingKey(op.Binding)).Scan(&raw, &digest)
	if err != nil {
		return ErrRefused
	}
	expected, err := encode(op)
	if err != nil {
		return err
	}
	d, err := op.Digest()
	if err != nil {
		return err
	}
	f, err := s.facts(ctx, op.Binding)
	if err != nil {
		return err
	}
	if raw != expected || digest != d.Value || !slices.Equal(op.Versions, f.Resources) || !same(op.Environment, f.Environment) {
		return gate.ErrBinding
	}
	return nil
}

// RegisterNativeRequest is called only by the per-invocation provider wrapper
// after the reviewed native adapter derives the descriptor from trusted runtime
// facts. There is no HTTP registration or caller-provided operation registry.
func (s *Service) registerNativeRequest(ctx context.Context, r gate.Request) error {
	f, err := s.facts(ctx, r.Binding)
	if err != nil {
		return err
	}
	if r.Environment == nil || !same(*r.Environment, f.Environment) || !slices.Equal(r.ResourceVersions, f.Resources) || r.Policy != f.Policy || r.Adapter != CodexScope {
		return gate.ErrBinding
	}
	raw, err := encode(r)
	if err != nil {
		return err
	}
	_, err = s.st.ExecContext(ctx, `INSERT INTO operation_facts(operation_key,binding_key,descriptor_json,digest) VALUES(?,?,?,?) ON CONFLICT(operation_key) DO NOTHING`, logicalKey(r.Binding, r.OperationID), bindingKey(r.Binding), raw, r.OperationDigest.Value)
	if err != nil {
		return err
	}
	return s.checkRequest(ctx, r)
}
func (s *Service) checkRequest(ctx context.Context, r gate.Request) error {
	if r.Validate() != nil {
		return ErrRefused
	}
	f, err := s.facts(ctx, r.Binding)
	if err != nil {
		return err
	}
	if r.Environment == nil || !same(*r.Environment, f.Environment) || !slices.Equal(r.ResourceVersions, f.Resources) || r.Policy != f.Policy {
		return gate.ErrBinding
	}
	var raw, d string
	if err := s.st.Reader().QueryRowContext(ctx, `SELECT descriptor_json,digest FROM operation_facts WHERE operation_key=? AND binding_key=?`, logicalKey(r.Binding, r.OperationID), bindingKey(r.Binding)).Scan(&raw, &d); err != nil {
		return ErrRefused
	}
	if d != r.OperationDigest.Value {
		return gate.ErrBinding
	}
	if r.Adapter == sdk.NativeAdapterScope() {
		var op sdk.Operation
		if decode(raw, &op) != nil {
			return ErrRefused
		}
		if err := s.checkOperation(ctx, op); err != nil {
			return err
		}
		digest, err := op.Digest()
		if err != nil || digest != r.OperationDigest || op.ID != r.OperationID || op.TurnID != r.TurnID || op.ToolCallID != r.ToolCallID {
			return gate.ErrBinding
		}
	} else {
		var original gate.Request
		if decode(raw, &original) != nil {
			return ErrRefused
		}
		a, _ := original.Digest()
		b, _ := r.Digest()
		if a != b {
			return gate.ErrBinding
		}
	}
	for _, o := range r.Options {
		if o.Scope.Kind != gate.Once || o.Scope.MaxUses != 1 || o.Scope.Target != r.OperationID {
			return gate.ErrUnsupported
		}
	}
	return nil
}
func (s *Service) checkIntent(ctx context.Context, r gate.Request, d policy.Decision) error {
	if err := s.checkRequest(ctx, r); err != nil {
		return err
	}
	f, err := s.facts(ctx, r.Binding)
	if err != nil {
		return err
	}
	want := policyProjection(f)
	if !same(d, want.Decision) || !slices.Equal(r.Provenance, want.Provenance) || !slices.Equal(r.Obligations, want.Obligations) {
		return ErrRefused
	}
	return nil
}

type PolicyBinding struct{ Host *Service }

func (b PolicyBinding) Facts(ctx context.Context, r gate.Request) (policy.Request, error) {
	if err := b.Host.checkRequest(ctx, r); err != nil {
		return policy.Request{}, err
	}
	f, err := b.Host.facts(ctx, r.Binding)
	if err != nil {
		return policy.Request{}, err
	}
	return policy.Request{RequestID: r.IdempotencyKey, Principal: policy.Principal{URN: "urn:gatecrasher:operative:" + string(f.Binding.OperativeID), Kind: "operative"}, Action: "operation.request", Resource: policy.Resource{Type: r.OperationClass, ID: r.OperationID}, Scope: r.EnforcementPoint}, nil
}
func (b PolicyBinding) CheckIntent(ctx context.Context, r gate.Request, d policy.Decision) error {
	return b.Host.checkIntent(ctx, r, d)
}

type hostPDP struct{}

func (hostPDP) Evaluate(context.Context, policy.Request) (policy.Decision, error) {
	return policyDecision(), nil
}

type auditSink struct{ Host *Service }

func (a auditSink) Record(ctx context.Context, e policy.AuditEvent) error {
	raw, err := encode(e)
	if err != nil {
		return err
	}
	_, err = a.Host.st.ExecContext(ctx, `INSERT INTO host_events(event_json) VALUES(?)`, raw)
	return err
}

type refuseResponse struct{}

func (refuseResponse) Authorize(context.Context, gate.Request, gate.Ticket, gatecrasher.ResponseAttempt) (hitl.Participant, error) {
	return hitl.Participant{}, ErrRefused
}

func (s *Service) Wire(owner gatecrasher.InteractionPort) error {
	if owner == nil {
		return ErrUnconfigured
	}
	s.owner = owner
	s.origin = newDeliveryHub(s)
	c, err := gatecrasher.New(gatecrasher.Config{OwnerRef: s.cfg.OwnerRef, CallerScope: s.cfg.CallerScope, Interactions: owner, Journal: s.Journal,
		Policy:    gatecrasher.PolicyPort{Evaluator: policy.Evaluator{PDP: hostPDP{}, Audit: auditSink{Host: s}}, Options: policy.Options{Mode: policy.Enforce, FailMode: policy.FailClosed}, Binding: PolicyBinding{Host: s}},
		Responses: refuseResponse{}, Verifier: s, Origin: s.origin, Clock: s.cfg.Now, LeaseDuration: 5e9})
	if err != nil {
		return err
	}
	s.coordinator = c
	return nil
}
func (s *Service) ownerItem(ctx context.Context, r gate.Request, item string) (hitl.ItemView, error) {
	if s.owner == nil {
		return hitl.ItemView{}, ErrUnconfigured
	}
	v, err := s.owner.Get(ctx, hitl.GetCommand{ContractVersion: hitl.ContractVersion, ItemID: item, Caller: hitl.CallerAssertion{ApplicationID: s.cfg.CallerScope}})
	if err != nil {
		return hitl.ItemView{}, err
	}
	if v.Item.ItemID != item || v.Item.ContractVersion != hitl.ContractVersion {
		return hitl.ItemView{}, ErrRefused
	}
	var req hitl.EnqueueRequest
	if json.Unmarshal(v.Item.RequestSnapshot, &req) != nil || req.Source.ApplicationID != s.cfg.CallerScope || req.IdempotencyKey != r.IdempotencyKey || req.Kind != gatecrasher.InteractionKind || req.Source.AgentID != string(r.Binding.OperativeID) || req.ExpiresAt == nil || !req.ExpiresAt.Equal(r.ExpiresAt) {
		return hitl.ItemView{}, ErrRefused
	}
	sealed, err := json.Marshal(r)
	if err != nil {
		return hitl.ItemView{}, err
	}
	opaque, err := json.Marshal(string(sealed))
	if err != nil {
		return hitl.ItemView{}, err
	}
	expected := hitl.EnqueueRequest{ContractVersion: hitl.ContractVersion, Kind: gatecrasher.InteractionKind, IdempotencyKey: r.IdempotencyKey, Source: hitl.SourceAssertion{ApplicationID: s.cfg.CallerScope, AgentID: string(r.Binding.OperativeID)}, ExpiresAt: &r.ExpiresAt, Extra: map[string]json.RawMessage{"gate_request": opaque}}
	if !same(req, expected) {
		return hitl.ItemView{}, gate.ErrBinding
	}
	var snapshot string
	if json.Unmarshal(req.Extra["gate_request"], &snapshot) != nil {
		return hitl.ItemView{}, ErrRefused
	}
	var actual gate.Request
	if decode(snapshot, &actual) != nil {
		return hitl.ItemView{}, ErrRefused
	}
	a, _ := actual.Digest()
	b, _ := r.Digest()
	if a != b {
		return hitl.ItemView{}, gate.ErrBinding
	}
	return v.Item, nil
}
func (s *Service) actor(f RuntimeFacts, p hitl.Participant) error {
	if p.Validate() != nil || p.Authority != "tachyon/identity" || !strings.HasPrefix(p.PrincipalRef, "user:") || p.Assurance != "operator-token" {
		return ErrRefused
	}
	canonical := s.cfg.ActorMap["tachyon/"+p.PrincipalRef]
	if canonical == "" || canonical == f.Requester {
		return ErrRefused
	}
	return nil
}
func (s *Service) Verify(ctx context.Context, r gate.Request, d gate.Decision) error {
	if d.AuthorityRef != s.cfg.OwnerRef || d.Ticket.AuthorityRef != s.cfg.OwnerRef || d.Ticket.Binding != r.Binding {
		return ErrRefused
	}
	digest, err := r.Digest()
	if err != nil || d.Ticket.RequestDigest != digest || d.OperationDigest != r.OperationDigest {
		return gate.ErrBinding
	}
	if err = s.checkIntent(ctx, r, policyDecision()); err != nil {
		return err
	}
	f, err := s.facts(ctx, r.Binding)
	if err != nil {
		return err
	}
	if err = s.actor(f, d.Resolution.Participant); err != nil {
		return err
	}
	v, err := s.ownerItem(ctx, r, d.Ticket.Handle.ItemID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(v.TerminalOutcome)
	if err != nil {
		return err
	}
	outcome, err := hitl.UnmarshalOutcome(raw)
	if err != nil {
		return ErrRefused
	}
	resolved, ok := outcome.(hitl.Resolved)
	if !ok || v.State != hitl.StateResolved || v.Revision != d.Resolution.InteractionRevision || v.Revision < d.Ticket.Handle.Revision || !same(resolved.Resolution, d.Resolution) || resolved.Resolution.Response.Decision != d.OptionID || resolved.Resolution.Response.Kind != gatecrasher.InteractionKind {
		return ErrRefused
	}
	for _, o := range r.Options {
		if o.ID == d.OptionID {
			if !same(o.Scope, d.Scope) || !s.cfg.Now().Before(o.Scope.ExpiresAt) || !d.Resolution.ResolvedAt.Before(o.Scope.ExpiresAt) {
				return gate.ErrExpired
			}
			return s.assessResponse(ctx, r, d)
		}
	}
	return gate.ErrUnsupported
}

type responseAssessor interface {
	AssessResponse(context.Context, ownerwire.AssessResponseCommand) (ownerwire.ResponseAssessment, error)
}

// Fresh owner role evidence is fetched for each verification, including inside
// the admission fence. It is never cached or accepted as a reusable grant.
func (s *Service) assessResponse(ctx context.Context, r gate.Request, d gate.Decision) error {
	owner, ok := s.owner.(responseAssessor)
	if !ok {
		return ErrUnconfigured
	}
	started := s.cfg.Now()
	a, err := owner.AssessResponse(ctx, ownerwire.AssessResponseCommand{GetCommand: hitl.GetCommand{ContractVersion: hitl.ContractVersion, ItemID: d.Ticket.Handle.ItemID, Caller: hitl.CallerAssertion{ApplicationID: s.cfg.CallerScope}}, ExpectedTerminalRevision: d.Resolution.InteractionRevision})
	if err != nil {
		return err
	}
	digest, err := r.Digest()
	if err != nil || a.ContractVersion != gate.ContractVersion || a.OwnerRef != s.cfg.OwnerRef || a.ItemID != d.Ticket.Handle.ItemID || a.IdempotencyKey != r.IdempotencyKey || a.Binding != r.Binding || !a.NativeRequestID.Equal(r.NativeRequestID) || a.RequestDigest != digest || a.OperationDigest != r.OperationDigest || a.OptionID != d.OptionID || a.TerminalRevision != d.Resolution.InteractionRevision || !same(a.Participant, d.Resolution.Participant) {
		return ErrRefused
	}
	if !validObservation(started, s.cfg.Now(), a.AssessedAt, a.ExpiresAt) || a.ExpiresAt.After(r.ExpiresAt) || a.ExpiresAt.After(d.Scope.ExpiresAt) {
		return ErrRefused
	}
	return ctx.Err()
}

// A one-second inter-host clock allowance does not extend the five-second TTL.
// Deployments need clocks within that bound; failure remains closed.
func validObservation(started, now, at, until time.Time) bool {
	return !at.IsZero() && !at.Before(started.Add(-time.Second)) && !at.After(now.Add(time.Second)) && until.After(at) && until.Sub(at) <= ownerwire.AssessmentTTL && now.Before(until)
}

// ProposedResponse is provisional owner transport v1. It requests an assessment before
// owner CAS, never a stored decision, transferable grant or effect admission.
type ProposedResponse struct {
	ContractVersion   string                  `json:"contract_version"`
	OwnerRef          string                  `json:"owner_ref"`
	IdempotencyKey    string                  `json:"idempotency_key"`
	ItemID            string                  `json:"item_id"`
	RequestDigest     runtimecontract.Digest  `json:"request_digest"`
	OperationDigest   runtimecontract.Digest  `json:"operation_digest"`
	Binding           runtimecontract.Binding `json:"binding"`
	NativeRequestID   gate.NativeRequestID    `json:"native_request_id"`
	ExpectedRevision  int64                   `json:"expected_revision"`
	PresentedRevision int64                   `json:"presented_projection_revision"`
	OptionID          string                  `json:"option_id"`
	Participant       hitl.Participant        `json:"participant"`
	ActorScopes       []string                `json:"actor_scopes"`
	AssessedAt        time.Time               `json:"assessed_at"`
	ExpiresAt         time.Time               `json:"expires_at"`
}
type Authorization struct {
	ProposedResponse
	Authorized bool `json:"authorized"`
}

const CallbackScope = "gatecrasher.gate.authorize-response"

func (s *Service) AuthorizeResponse(ctx context.Context, p libauth.Principal, in ProposedResponse) (Authorization, error) {
	if !p.Verified || p.Kind != libauth.KindService || p.Audience != "gatecrasher" || p.ID != s.cfg.CallbackSubject || p.TokenID != strings.TrimPrefix(p.ID, "key:") || !strings.HasPrefix(p.ID, "key:") || !p.HasScope(CallbackScope) || (!p.ExpiresAt.IsZero() && !s.cfg.Now().Before(p.ExpiresAt)) {
		return Authorization{}, ErrRefused
	}
	if in.ContractVersion != gate.ContractVersion || in.OwnerRef != s.cfg.OwnerRef || in.ExpectedRevision < 1 || in.PresentedRevision != in.ExpectedRevision {
		return Authorization{}, ErrRefused
	}
	route, err := s.Journal.Load(ctx, in.IdempotencyKey)
	if err != nil {
		return Authorization{}, ErrRefused
	}
	r := route.Request
	d, err := r.Digest()
	if err != nil || d != in.RequestDigest || r.OperationDigest != in.OperationDigest || r.Binding != in.Binding || !r.NativeRequestID.Equal(in.NativeRequestID) || route.OwnerRef != in.OwnerRef || route.CallerScope != s.cfg.CallerScope {
		return Authorization{}, ErrRefused
	}
	if route.Ticket != nil && route.Ticket.Handle.ItemID != in.ItemID {
		return Authorization{}, ErrRefused
	}
	if err = s.checkIntent(ctx, r, policyDecision()); err != nil {
		return Authorization{}, err
	}
	f, err := s.facts(ctx, r.Binding)
	if err != nil {
		return Authorization{}, err
	}
	if err = s.actor(f, in.Participant); err != nil {
		return Authorization{}, err
	}
	if !slices.Contains(in.ActorScopes, "tachyon.operator") || !slices.Contains(in.ActorScopes, "tachyon.approvals.resolve") {
		return Authorization{}, ErrRefused
	}
	v, err := s.ownerItem(ctx, r, in.ItemID)
	if err != nil {
		return Authorization{}, err
	}
	if v.State.IsTerminal() {
		return Authorization{}, &hitl.TerminalConflictError{Outcome: v.TerminalOutcome}
	}
	if v.Revision != in.ExpectedRevision {
		return Authorization{}, &hitl.StaleRevisionError{ItemID: in.ItemID, Operation: "resolve", RevisionKind: "interaction", Expected: in.ExpectedRevision, Actual: v.Revision, CurrentState: v.State}
	}
	if !s.cfg.Now().Before(r.ExpiresAt) {
		return Authorization{}, gate.ErrExpired
	}
	for _, o := range r.Options {
		if o.ID == in.OptionID {
			now := s.cfg.Now()
			if !now.Before(o.Scope.ExpiresAt) || !validObservation(in.AssessedAt, now, in.AssessedAt, in.ExpiresAt) || in.ExpiresAt.After(r.ExpiresAt) || in.ExpiresAt.After(o.Scope.ExpiresAt) {
				return Authorization{}, gate.ErrExpired
			}
			return Authorization{ProposedResponse: in, Authorized: true}, nil
		}
	}
	return Authorization{}, gate.ErrUnsupported
}

var _ gate.AuthorityVerifier = (*Service)(nil)
var _ sdk.AdmissionPort = (*Service)(nil)
var _ sdk.PolicyPort = (*Service)(nil)
