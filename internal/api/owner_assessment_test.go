package api_test

import (
	"context"
	"encoding/json"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/ownerwire"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/hitl"
)

// Contract fixture only; real Tachyon role storage remains a separate acceptance gate.
func (o *contractOwner) AssessResponse(ctx context.Context, q ownerwire.AssessResponseCommand) (ownerwire.ResponseAssessment, error) {
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
		return ownerwire.ResponseAssessment{}, hitl.ErrUnauthorized
	}
	var enq hitl.EnqueueRequest
	var text string
	var req gate.Request
	if json.Unmarshal(v.Item.RequestSnapshot, &enq) != nil || json.Unmarshal(enq.Extra["gate_request"], &text) != nil || json.Unmarshal([]byte(text), &req) != nil {
		return ownerwire.ResponseAssessment{}, hitl.ErrUnauthorized
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
	a := ownerwire.ResponseAssessment{IdempotencyKey: req.IdempotencyKey, Binding: req.Binding, NativeRequestID: req.NativeRequestID, ContractVersion: "1", OwnerRef: "tachyon-contract-fixture", ItemID: v.Item.ItemID, RequestDigest: d, OperationDigest: req.OperationDigest, OptionID: resolved.Resolution.Response.Decision, TerminalRevision: v.Item.Revision, Participant: resolved.Resolution.Participant, AssessedAt: now, ExpiresAt: until}
	return a, err
}
