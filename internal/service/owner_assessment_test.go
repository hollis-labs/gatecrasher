package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/ownerwire"
	"github.com/hollis-labs/libs/agent/sdk"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/core/runtimecontract"
)

// This derives observation bindings from the real HITL fixture's retained
// resolution. Role/mapping mutation hooks test refusal, not real Tachyon roles.
func (o *observedOwner) AssessResponse(ctx context.Context, q ownerwire.AssessResponseCommand) (ownerwire.ResponseAssessment, error) {
	v, err := o.Get(ctx, q.GetCommand)
	if err != nil {
		return ownerwire.ResponseAssessment{}, err
	}
	if v.Item.Revision != q.ExpectedTerminalRevision {
		return ownerwire.ResponseAssessment{}, hitl.ErrStaleRevision
	}
	raw, err := json.Marshal(v.Item.TerminalOutcome)
	if err != nil {
		return ownerwire.ResponseAssessment{}, err
	}
	out, err := hitl.UnmarshalOutcome(raw)
	if err != nil {
		return ownerwire.ResponseAssessment{}, err
	}
	resolved, ok := out.(hitl.Resolved)
	if !ok {
		return ownerwire.ResponseAssessment{}, ErrRefused
	}
	var enq hitl.EnqueueRequest
	var text string
	var req gate.Request
	if json.Unmarshal(v.Item.RequestSnapshot, &enq) != nil || json.Unmarshal(enq.Extra["gate_request"], &text) != nil || json.Unmarshal([]byte(text), &req) != nil {
		return ownerwire.ResponseAssessment{}, ErrRefused
	}
	d, err := req.Digest()
	if err != nil {
		return ownerwire.ResponseAssessment{}, err
	}
	now := time.Now().UTC()
	until := now.Add(ownerwire.AssessmentTTL)
	for _, option := range req.Options {
		if option.ID == resolved.Resolution.Response.Decision && option.Scope.ExpiresAt.Before(until) {
			until = option.Scope.ExpiresAt
		}
	}
	if req.ExpiresAt.Before(until) {
		until = req.ExpiresAt
	}
	a := ownerwire.ResponseAssessment{IdempotencyKey: req.IdempotencyKey, Binding: req.Binding, NativeRequestID: req.NativeRequestID, ContractVersion: "1", OwnerRef: "tachyon-fixture", ItemID: v.Item.ItemID, RequestDigest: d, OperationDigest: req.OperationDigest, OptionID: resolved.Resolution.Response.Decision, TerminalRevision: v.Item.Revision, Participant: resolved.Resolution.Participant, AssessedAt: now, ExpiresAt: until}
	if o.assessmentHook != nil {
		err = o.assessmentHook(&a)
	}
	return a, err
}

func TestFreshOwnerAssessmentRefusesRevocationAndMismatchedEvidenceBeforeEffect(t *testing.T) {
	s, o, _ := newHost(t)
	f, run, op, request := prepareSDK(t, s)
	ticket, err := s.coordinator.Request(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	decide(t, s, o, request, ticket.Handle, "allow-once")
	resolution, err := (SDKGate{Host: s}).Await(t.Context(), ticket, gate.WaitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := policyProjection(f)
	a := sdk.Admission{Run: run, Kind: "tool", Binding: f.Binding, Environment: f.Environment, DefinitionDigest: run.DefinitionDigest, Operation: &op, Request: &request, Decision: resolution.Decision, Policy: &p}
	effects := 0
	for _, mutate := range []func(*ownerwire.ResponseAssessment) error{
		func(a *ownerwire.ResponseAssessment) error { a.ContractVersion = hitl.ContractVersion; return nil },
		func(*ownerwire.ResponseAssessment) error { return hitl.ErrUnauthorized }, // roles removed or user disabled
		func(*ownerwire.ResponseAssessment) error { return errors.New("owner unavailable") },
		func(a *ownerwire.ResponseAssessment) error { a.OwnerRef = "different-owner"; return nil },
		func(a *ownerwire.ResponseAssessment) error { a.IdempotencyKey = "different-key"; return nil },
		func(a *ownerwire.ResponseAssessment) error { a.IdempotencyKey = ""; return nil },
		func(a *ownerwire.ResponseAssessment) error { a.Binding.Generation++; return nil },
		func(a *ownerwire.ResponseAssessment) error { a.Binding = runtimecontract.Binding{}; return nil },
		func(a *ownerwire.ResponseAssessment) error { a.NativeRequestID = nil; return nil },
		func(a *ownerwire.ResponseAssessment) error {
			a.NativeRequestID = gate.NativeRequestID(`"foreign"`)
			return nil
		},
		func(a *ownerwire.ResponseAssessment) error { a.ItemID = "different-item"; return nil },
		func(a *ownerwire.ResponseAssessment) error { a.TerminalRevision++; return nil },
		func(a *ownerwire.ResponseAssessment) error { a.OptionID = "deny"; return nil },
		func(a *ownerwire.ResponseAssessment) error { a.OperationDigest.Value = "different"; return nil },
		func(a *ownerwire.ResponseAssessment) error { a.RequestDigest.Value = "different"; return nil },
		func(a *ownerwire.ResponseAssessment) error { a.Participant.PrincipalRef = "user:self"; return nil },
		func(a *ownerwire.ResponseAssessment) error { a.ExpiresAt = time.Now().Add(-time.Second); return nil },
		func(a *ownerwire.ResponseAssessment) error { a.AssessedAt = time.Now().Add(-time.Minute); return nil },
		func(a *ownerwire.ResponseAssessment) error { a.AssessedAt = time.Now().Add(time.Minute); return nil },
		func(a *ownerwire.ResponseAssessment) error { a.ExpiresAt = a.AssessedAt.Add(time.Minute); return nil },
	} {
		o.assessmentHook = mutate
		if err = s.Admit(t.Context(), a, func(context.Context) error { effects++; return nil }); err == nil {
			t.Fatal("stale/unavailable/mismatched owner authority admitted")
		}
	}
	if effects != 0 {
		t.Fatal("effect ran after authority changed", effects)
	}
	checks := 0
	o.assessmentHook = func(*ownerwire.ResponseAssessment) error {
		checks++
		if checks > 1 {
			return hitl.ErrUnauthorized
		}
		return nil
	}
	if err = s.Admit(t.Context(), a, func(context.Context) error { effects++; return nil }); err == nil || checks < 2 || effects != 0 {
		t.Fatal("role loss after durable claim was not fenced", err, checks, effects)
	}
	o.assessmentHook = nil
	if err = s.Admit(t.Context(), a, func(context.Context) error { effects++; return nil }); !errors.Is(err, ErrClaimed) || effects != 0 {
		t.Fatal("role restoration released an uncertain claim", err, effects)
	}
}

func TestCallbackBindsNativeIdentityAndBoundedObservation(t *testing.T) {
	s, _, _ := newHost(t)
	_, _, _, r := prepareSDK(t, s)
	ticket, err := s.coordinator.Request(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	base := proposed(r, ticket.Handle)
	for _, mutate := range []func(*ProposedResponse){
		func(p *ProposedResponse) { p.ContractVersion = hitl.ContractVersion },
		func(p *ProposedResponse) { p.Binding.Generation++ },
		func(p *ProposedResponse) { p.NativeRequestID = gate.NativeRequestID(`"another"`) },
		func(p *ProposedResponse) { p.AssessedAt = time.Now().Add(time.Minute) },
		func(p *ProposedResponse) { p.ExpiresAt = time.Now().Add(-time.Second) },
		func(p *ProposedResponse) { p.ExpiresAt = p.AssessedAt.Add(time.Minute) },
		func(p *ProposedResponse) { p.ExpiresAt = r.ExpiresAt.Add(time.Second) },
	} {
		p, err := detached(base)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&p)
		if _, err = s.AuthorizeResponse(t.Context(), callbackPrincipal(), p); err == nil {
			t.Fatal("mismatched callback observation authorized")
		}
	}
}
