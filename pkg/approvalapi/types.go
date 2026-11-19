package approvalapi

import "time"

// Paths and scopes of the approval API.
const (
	PathApprovals = "/api/gate/v1/approvals"
	PathJWKS      = "/api/gate/v1/jwks.json"

	ScopeSubmit = "gatecrasher.approval.submit"
	ScopeRead   = "gatecrasher.approval.read"

	// MaxAwait is the longest wait the await route honors; a longer timeout is capped.
	MaxAwait = 60 * time.Second
)

// Tier is how much authority a decision needs.
type Tier string

// Tiers. Ground is recorded and returned already approved; elevated goes to approver
// agents holding approve.<class>; critical goes to the owner, a human, only.
const (
	TierGround   Tier = "ground"
	TierElevated Tier = "elevated"
	TierCritical Tier = "critical"
)

// Valid reports whether t is a known tier.
func (t Tier) Valid() bool {
	switch t {
	case TierGround, TierElevated, TierCritical:
		return true
	}
	return false
}

// Status is where an approval stands.
type Status string

// Statuses. Pending is the only non-terminal one.
const (
	StatusPending   Status = "pending"
	StatusApproved  Status = "approved"
	StatusDenied    Status = "denied"
	StatusExpired   Status = "expired"
	StatusWithdrawn Status = "withdrawn"
)

// Terminal reports whether the approval can no longer change.
func (s Status) Terminal() bool { return s != StatusPending && s != "" }

// Outcome is what a signed decision says.
type Outcome string

// Outcomes.
const (
	OutcomeApproved Outcome = "approved"
	OutcomeDenied   Outcome = "denied"
)

// PrincipalKind is what sort of party a principal or actor is.
type PrincipalKind string

// Principal kinds.
const (
	KindAgent   PrincipalKind = "agent"
	KindSession PrincipalKind = "session"
	KindMachine PrincipalKind = "machine"
	KindApp     PrincipalKind = "app"
	KindHuman   PrincipalKind = "human"
)

// Request kinds.
const (
	KindCredentialGrant = "credential_grant" //nolint:gosec // a request kind, not a credential
)

// Actor is one party: a registry id and its kind.
type Actor struct {
	Sub  string        `json:"sub"`
	Kind PrincipalKind `json:"kind"`
}

// Principal is who the grant is for, with the chain acting on its behalf (outermost
// first). Act is omitted when empty.
type Principal struct {
	Sub  string        `json:"sub"`
	Kind PrincipalKind `json:"kind"`
	Act  []Actor       `json:"act,omitempty"`
}

// Requested is the exact grant asked for. Constraints is always an object; nil is
// treated as {} (also by the digest).
type Requested struct {
	Audience    string         `json:"audience"`
	Scopes      []string       `json:"scopes"`
	TTLSeconds  int64          `json:"ttl_seconds"`
	Constraints map[string]any `json:"constraints"`
}

// Evidence links the request to what prompted it.
type Evidence struct {
	TaskID     string `json:"task_id,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	PolicyRule string `json:"policy_rule,omitempty"`
}

// SubmitRequest is the body of POST /api/gate/v1/approvals (scope gatecrasher.approval.submit).
//
// IdempotencyKey is the producer's request id. Submitting the same key with the same
// digest returns the same approval; the same key with a different digest is a 409.
// RequestDigest must equal RequestDigest(Principal, Requested, Tier) or the request is
// refused with 422. ApproverClass is required for elevated and refused otherwise.
type SubmitRequest struct {
	IdempotencyKey string    `json:"idempotency_key"`
	Source         string    `json:"source"`
	Kind           string    `json:"kind"`
	Tier           Tier      `json:"tier"`
	ApproverClass  string    `json:"approver_class,omitempty"`
	Principal      Principal `json:"principal"`
	Requested      Requested `json:"requested"`
	Purpose        string    `json:"purpose"`
	Evidence       Evidence  `json:"evidence"`
	RequestDigest  string    `json:"request_digest"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// SubmitResponse is the 201 (new) or 200 (same key, same digest) answer to a submit.
type SubmitResponse struct {
	ApprovalID string `json:"approval_id"`
	Status     Status `json:"status"`
}

// Approval is the answer to get, await and withdraw. Decision is the compact JWS and is
// present when Status is approved or denied.
type Approval struct {
	ApprovalID string `json:"approval_id"`
	Status     Status `json:"status"`
	Decision   string `json:"decision,omitempty"`
}

// Error is the body of every non-2xx answer.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error codes.
const (
	ErrCodeInvalid        = "invalid"              // 400: malformed or missing fields
	ErrCodeUnauthorized   = "unauthorized"         // 401
	ErrCodeForbidden      = "forbidden"            // 403: scope missing
	ErrCodeNotFound       = "not_found"            // 404
	ErrCodeIdempotency    = "idempotency_conflict" // 409: same key, different digest
	ErrCodeTerminal       = "terminal"             // 409: withdraw on a decided approval
	ErrCodeDigestMismatch = "digest_mismatch"      // 422
)

// Narrowed is a decider's narrowing of the grant. It can only narrow: scopes are a
// subset of those requested and the TTL is no longer.
type Narrowed struct {
	Scopes     []string `json:"scopes,omitempty"`
	TTLSeconds int64    `json:"ttl_seconds,omitempty"`
}

// DecisionClaims are the claims of a signed decision (compact JWS, alg EdDSA, kid in the
// header, keys at /api/gate/v1/jwks.json). Times are NumericDate seconds, except
// DecidedAt (RFC 3339). A decision is valid for redemption until Exp, at most ten
// minutes after it was issued.
type DecisionClaims struct {
	Iss           string    `json:"iss"` // "gatecrasher"
	Aud           string    `json:"aud"` // the producer, e.g. "warden"
	Jti           string    `json:"jti"` // decision id
	Iat           int64     `json:"iat"`
	Exp           int64     `json:"exp"`
	ApprovalID    string    `json:"approval_id"`
	RequestID     string    `json:"request_id"` // the submit's idempotency_key
	RequestDigest string    `json:"request_digest"`
	Outcome       Outcome   `json:"outcome"`
	Tier          Tier      `json:"tier"`
	Decider       Actor     `json:"decider"`
	DecidedAt     time.Time `json:"decided_at"`
	Narrowed      *Narrowed `json:"narrowed,omitempty"`
}

// Issuer is the iss of every decision.
const Issuer = "gatecrasher"

// MaxDecisionLifetime bounds exp - iat.
const MaxDecisionLifetime = 10 * time.Minute

// SecretIntake is the producer's one-use intake for request_secret (milestone 2). The
// card form posts the value write-only to IntakeURL; Gatecrasher never receives,
// stores or logs it.
type SecretIntake struct {
	IntakeID  string    `json:"intake_id"`
	IntakeURL string    `json:"intake_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SecretProvided is all Gatecrasher records of a provided secret: when, and the
// reference the producer returned.
type SecretProvided struct {
	IntakeID   string    `json:"intake_id"`
	Ref        string    `json:"ref"`
	ProvidedAt time.Time `json:"provided_at"`
}

// The decide route, for surfaces and approver agents (scope gatecrasher.approval.decide).
// Elevated requests also need the caller to hold the request's approver class as a scope
// and to be configured for it; critical requests are decided by the owner only.
const (
	PathDecideSuffix = "/decide"
	ScopeDecide      = "gatecrasher.approval.decide"
)

// DecideRequest is the body of POST /api/gate/v1/approvals/{id}/decide.
type DecideRequest struct {
	Outcome  Outcome   `json:"outcome"`
	Narrowed *Narrowed `json:"narrowed,omitempty"`
	Note     string    `json:"note,omitempty"`
}

// DecideResponse is the answer to a decide. Shadow is true when the decision was only
// recorded (shadow mode); the approval then stays pending.
type DecideResponse struct {
	Approval
	Shadow bool `json:"shadow,omitempty"`
}

// More error codes, for the decide route.
const (
	ErrCodeNotDecider  = "not_decider" // 403: the caller may not decide this approval
	ErrCodeCeiling     = "ceiling"     // 403: an approver agent's approval would exceed its class ceiling
	ErrCodeUnavailable = "unavailable" // 503: approvals are not configured
)
