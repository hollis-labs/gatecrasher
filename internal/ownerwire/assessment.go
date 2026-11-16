// Package ownerwire describes the provisional Tachyon observation transport.
// These DTOs carry evidence, never a decision-writing or admission capability.
package ownerwire

import (
	"time"

	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/core/runtimecontract"
)

const AssessmentTTL = 5 * time.Second

// AssessResponseCommand contains only a scoped lookup and the retained revision.
// The owner derives the actor, selected option and all digests from its own record.
type AssessResponseCommand struct {
	hitl.GetCommand
	ExpectedTerminalRevision int64 `json:"expected_terminal_revision"`
}

// ResponseAssessment requires every named field, including explicit key,
// binding and native identity. Digests do not replace any of these wire facts.
type ResponseAssessment struct {
	IdempotencyKey   string                  `json:"idempotency_key"`
	Binding          runtimecontract.Binding `json:"binding"`
	NativeRequestID  gate.NativeRequestID    `json:"native_request_id"`
	ContractVersion  string                  `json:"contract_version"`
	OwnerRef         string                  `json:"owner_ref"`
	ItemID           string                  `json:"item_id"`
	RequestDigest    runtimecontract.Digest  `json:"request_digest"`
	OperationDigest  runtimecontract.Digest  `json:"operation_digest"`
	OptionID         string                  `json:"option_id"`
	TerminalRevision int64                   `json:"terminal_revision"`
	Participant      hitl.Participant        `json:"participant"`
	AssessedAt       time.Time               `json:"assessed_at"`
	ExpiresAt        time.Time               `json:"expires_at"`
}
