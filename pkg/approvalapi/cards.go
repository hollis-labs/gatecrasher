package approvalapi

import "time"

// Request kinds beyond credential_grant. Any other kind is an approve/deny request for
// the grant in Requested.
const (
	// KindChoice asks the owner to pick one of Prompt.Choices.
	KindChoice = "choice"
	// KindQuestion asks the owner for a short free-text answer to Prompt.Question.
	KindQuestion = "question"
	// KindSecretRequest asks the owner for a secret, which the card posts write-only to the
	// producer's SecretIntake. It is always tier critical.
	KindSecretRequest = "secret_request" //nolint:gosec // a request kind, not a credential
)

// Limits on prompts and answers.
const (
	MaxQuestion    = 2000
	MaxChoices     = 20
	MaxChoiceLabel = 200
	MaxAnswer      = 4000
	MaxSecretRef   = 256
)

// Prompt is the question a choice or question request puts to the owner.
type Prompt struct {
	Question string   `json:"question"`
	Choices  []Choice `json:"choices,omitempty"`
}

// Choice is one option of a choice request.
type Choice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Response is what a decision carries besides its outcome.
type Response struct {
	Choice    string `json:"choice,omitempty"`
	Answer    string `json:"answer,omitempty"`
	SecretRef string `json:"secret_ref,omitempty"`
}

// PathSecretProvidedSuffix is the secret-provided route: the producer reports that the
// owner provided the secret to its intake. Gatecrasher records the reference only (scope
// gatecrasher.approval.submit, submitter only).
const PathSecretProvidedSuffix = "/secret-provided"

// SecretProvidedRequest is the body of POST /api/gate/v1/approvals/{id}/secret-provided.
// Ref is the producer's reference to the stored secret (never the secret itself).
type SecretProvidedRequest struct {
	IntakeID   string    `json:"intake_id"`
	Ref        string    `json:"ref"`
	ProvidedAt time.Time `json:"provided_at"`
}

// Paths of the card and the event stream.
const (
	PathCardSuffix = "/card"
	PathEvents     = "/api/gate/v1/events"
)

// CardVersion is the version every card carries.
const CardVersion = "gatecrasher.card/v1"

// CardType is the interaction a card asks for.
type CardType string

// Card types.
const (
	CardApprove       CardType = "approve" // approve or deny a grant
	CardChoose        CardType = "choose"  // pick one choice (or decline)
	CardAnswer        CardType = "answer"  // answer a question (or decline)
	CardRequestSecret CardType = "request_secret"
)

// ActionKind is one button or submit on a card.
type ActionKind string

// Card actions. Each maps to a decide call except provide_secret, which is the write-only
// form post to the producer's intake.
const (
	ActionApprove       ActionKind = "approve"
	ActionDeny          ActionKind = "deny"
	ActionChoose        ActionKind = "choose"
	ActionAnswer        ActionKind = "answer"
	ActionProvideSecret ActionKind = "provide_secret"
)

// Card is a transport-neutral rendering of one approval: what a surface (an app, a chat,
// an MCP UI) shows and the calls its actions make. Gatecrasher owns the content and the
// decide endpoint; how a card is drawn is the surface's (or the MCP UI work's) concern.
type Card struct {
	Version    string       `json:"version"`
	ApprovalID string       `json:"approval_id"`
	Type       CardType     `json:"type"`
	Status     Status       `json:"status"`
	Tier       Tier         `json:"tier"`
	Kind       string       `json:"kind"`
	Source     string       `json:"source"`
	Title      string       `json:"title"`
	Summary    string       `json:"summary,omitempty"`
	Principal  Principal    `json:"principal"`
	Requested  *Requested   `json:"requested,omitempty"`
	Evidence   Evidence     `json:"evidence"`
	Prompt     *Prompt      `json:"prompt,omitempty"`
	ExpiresAt  time.Time    `json:"expires_at"`
	Deciders   string       `json:"deciders"` // "owner" or "owner, approve.<class>"
	Actions    []CardAction `json:"actions"`
	Secret     *SecretForm  `json:"secret,omitempty"`
	Outcome    *CardOutcome `json:"outcome,omitempty"`
}

// CardAction is one thing the viewer can do. Decide is the call it makes (POST, JSON body
// a DecideRequest with Outcome set as here); provide_secret has no Decide.
type CardAction struct {
	Kind    ActionKind `json:"kind"`
	Label   string     `json:"label"`
	Outcome Outcome    `json:"outcome,omitempty"`
	Decide  string     `json:"decide,omitempty"`
}

// SecretForm is the request_secret form: one field, posted write-only straight to the
// producer's intake. Gatecrasher never sees the value, and a surface must not put it in
// any model transcript, log or store.
type SecretForm struct {
	IntakeID  string    `json:"intake_id"`
	PostURL   string    `json:"post_url"`
	Field     string    `json:"field"` // the form field name the intake reads: "value"
	ExpiresAt time.Time `json:"expires_at"`
	WriteOnly bool      `json:"write_only"`
}

// CardOutcome is the outcome of a decided card.
type CardOutcome struct {
	Status   Status    `json:"status"`
	Decider  *Actor    `json:"decider,omitempty"`
	Response *Response `json:"response,omitempty"`
}

// FeedEvent is one entry of the event stream (GET /api/gate/v1/events) and of webhook
// deliveries. Seq orders the whole log and resumes the stream (Last-Event-ID).
type FeedEvent struct {
	Seq        int64  `json:"seq"`
	ApprovalID string `json:"approval_id"`
	Type       string `json:"type"` // submitted, decided, shadow_decided, withdrawn, expired, secret_provided
	At         string `json:"at"`
	Status     Status `json:"status"` // the approval's status now
	Tier       Tier   `json:"tier"`
	Kind       string `json:"kind"`
	Source     string `json:"source"`
}

// WebhookDelivery is the body of a webhook POST. It is signed: the Gatecrasher-Signature
// header is "t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>" under the subscriber's
// secret>".
type WebhookDelivery struct {
	Subscriber string      `json:"subscriber"`
	Events     []FeedEvent `json:"events"`
}

// Webhook headers.
const (
	HeaderWebhookSignature = "Gatecrasher-Signature"
	HeaderWebhookName      = "Gatecrasher-Webhook"
)
