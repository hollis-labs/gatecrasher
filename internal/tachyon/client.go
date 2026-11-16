// Package tachyon is the provisional mapped-service agent-verb client. It owns
// no decision store and cannot respond. Reconcile this wire with Tachyon's
// substrate-port executor before claiming existing-owner integration.
package tachyon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/ownerwire"

	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/gatecrasher"
)

var ErrTransport = errors.New("gatecrasher: Tachyon owner transport unavailable")

type Config struct {
	BaseURL, TokenFile, CallerScope string
	AllowLoopbackHTTP               bool
}
type Client struct {
	cfg  Config
	base *url.URL
	http *http.Client
}

func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" || cfg.TokenFile == "" || cfg.CallerScope == "" {
		return nil, ErrTransport
	}
	loopback := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && (u.Scheme != "http" || !cfg.AllowLoopbackHTTP || loopback == nil || !loopback.IsLoopback()) {
		return nil, ErrTransport
	}
	return &Client{cfg: cfg, base: u, http: &http.Client{Timeout: 55 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) token() (string, error) {
	info, err := os.Stat(c.cfg.TokenFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 4096 {
		return "", ErrTransport
	}
	b, err := os.ReadFile(c.cfg.TokenFile)
	if err != nil {
		return "", ErrTransport
	}
	token := strings.TrimSpace(string(b))
	if token == "" || strings.ContainsAny(token, " \r\n\t") {
		return "", ErrTransport
	}
	return token, nil
}
func (c *Client) call(ctx context.Context, verb string, write bool, input, out any) error {
	token, err := c.token()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return ErrTransport
	}
	u := *c.base
	u.Path = "/api/agent/v1/data/providers/tachyon/verbs/" + verb
	method := http.MethodGet
	var body io.Reader
	if write {
		method = http.MethodPost
		body = bytes.NewReader(raw)
	} else {
		if len(raw) > 16<<10 {
			return ErrTransport
		}
		q := url.Values{}
		q.Set("input", string(raw))
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return ErrTransport
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if write {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		return ErrTransport
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return ErrTransport
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return decodeError(data)
	}
	var envelope struct {
		Version  int             `json:"version"`
		Provider string          `json:"provider"`
		Verb     string          `json:"verb"`
		Data     json.RawMessage `json:"data"`
	}
	if _, err = exactObject(data, "version", "provider", "verb", "data"); err != nil || json.Unmarshal(data, &envelope) != nil || envelope.Version != 1 || envelope.Provider != "tachyon" || envelope.Verb != verb || len(envelope.Data) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
		return ErrTransport
	}
	if err = json.Unmarshal(envelope.Data, out); err != nil {
		return ErrTransport
	}
	return nil
}

// Reject ambiguous discriminants without decoding opaque data through float64.
func exactObject(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrTransport
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, ErrTransport
		}
		if !slices.Contains(allowed, key) || fields[key] != nil {
			return nil, ErrTransport
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrTransport
		}
		fields[key] = value
	}
	if _, err = d.Token(); err != nil {
		return nil, ErrTransport
	}
	if !errors.Is(d.Decode(new(any)), io.EOF) {
		return nil, ErrTransport
	}
	return fields, nil
}

// Typed HITL errors are a PROVISIONAL gate-family addition, not the baseline
// Tachyon writeError contract. Never manufacture revision/terminal evidence
// from its existing code/message-only errors.
func decodeError(raw []byte) error {
	fields, err := exactObject(raw, "contract_version", "code", "message", "operation", "item_id", "revision_kind", "expected_revision", "actual_revision", "current_state", "idempotency_key", "existing_item_id", "terminal_outcome")
	if err != nil {
		return ErrTransport
	}
	var code, version, message string
	if json.Unmarshal(fields["code"], &code) != nil || code == "" {
		return ErrTransport
	}
	if v, ok := fields["message"]; ok && (bytes.Equal(bytes.TrimSpace(v), []byte("null")) || json.Unmarshal(v, &message) != nil) {
		return ErrTransport
	}
	if v, ok := fields["contract_version"]; ok && (json.Unmarshal(v, &version) != nil || version != hitl.ContractVersion) {
		return ErrTransport
	}
	allowed := []string{"contract_version", "code", "message"}
	switch code {
	case "stale_revision":
		allowed = append(allowed, "operation", "item_id", "revision_kind", "expected_revision", "actual_revision", "current_state", "terminal_outcome")
	case "idempotency_conflict":
		allowed = append(allowed, "idempotency_key", "existing_item_id")
	case "terminal_conflict":
		allowed = append(allowed, "terminal_outcome")
	}
	for key := range fields {
		if !slices.Contains(allowed, key) {
			return ErrTransport
		}
	}
	decoded := hitl.DecodeError(raw)
	switch code {
	case "stale_revision":
		var e *hitl.StaleRevisionError
		if !errors.As(decoded, &e) || version != hitl.ContractVersion || e.ItemID == "" || e.Expected < 1 || e.Actual < 1 || e.Expected == e.Actual || !e.CurrentState.Valid() || (e.Operation != "resolve" && e.Operation != "withdraw" && e.Operation != "assess-response") || (e.RevisionKind != "interaction" && e.RevisionKind != "presented_projection") {
			return ErrTransport
		}
		if e.CurrentState.IsTerminal() && e.Outcome == nil {
			return ErrTransport
		}
		if e.Outcome != nil && (e.Outcome.OutcomeItemID() != e.ItemID || e.Outcome.OutcomeRevision() != e.Actual || e.Outcome.OutcomeState() != e.CurrentState) {
			return ErrTransport
		}
	case "idempotency_conflict":
		var e *hitl.IdempotencyConflictError
		if !errors.As(decoded, &e) || version != hitl.ContractVersion || e.IdempotencyKey == "" || e.ExistingItemID == "" {
			return ErrTransport
		}
	case "terminal_conflict":
		var e *hitl.TerminalConflictError
		if !errors.As(decoded, &e) || version != hitl.ContractVersion || e.Outcome == nil {
			return ErrTransport
		}
	case "unauthorized", "not_found", "validation_failed", "wait_canceled", "await_timeout", "hitl_error", "unavailable", "method_not_allowed":
		for key := range fields {
			if key != "code" && key != "message" && key != "contract_version" {
				return ErrTransport
			}
		}
	default:
		return ErrTransport
	}
	return decoded
}
func (c *Client) Enqueue(ctx context.Context, r hitl.EnqueueRequest) (hitl.Handle, error) {
	if r.Validate() != nil || r.Source.ApplicationID != c.cfg.CallerScope || r.Kind != gatecrasher.InteractionKind {
		return hitl.Handle{}, hitl.ErrUnauthorized
	}
	var h hitl.Handle
	err := c.call(ctx, "gate.enqueue", true, r, &h)
	if err == nil && (h.ContractVersion != hitl.ContractVersion || h.ItemID == "" || h.Revision < 1 || !h.State.Valid()) {
		err = ErrTransport
	}
	return h, err
}
func (c *Client) Get(ctx context.Context, q hitl.GetCommand) (hitl.RetrievalResult, error) {
	if q.Validate() != nil || q.Caller.ApplicationID != c.cfg.CallerScope {
		return hitl.RetrievalResult{}, hitl.ErrUnauthorized
	}
	var r hitl.RetrievalResult
	err := c.call(ctx, "gate.get", false, q, &r)
	if err == nil {
		err = r.Validate()
	}
	return r, err
}
func (c *Client) Await(ctx context.Context, q hitl.AwaitCommand) (hitl.RetrievalResult, error) {
	if q.Validate() != nil || q.Caller.ApplicationID != c.cfg.CallerScope {
		return hitl.RetrievalResult{}, hitl.ErrUnauthorized
	}
	var r hitl.RetrievalResult
	err := c.call(ctx, "gate.await", false, q, &r)
	if err == nil {
		err = r.Validate()
	}
	return r, err
}
func (c *Client) Withdraw(ctx context.Context, q hitl.WithdrawCommand) (hitl.Outcome, error) {
	if q.Validate() != nil || q.Caller.ApplicationID != c.cfg.CallerScope {
		return nil, hitl.ErrUnauthorized
	}
	var raw json.RawMessage
	if err := c.call(ctx, "gate.withdraw", true, q, &raw); err != nil {
		return nil, err
	}
	return hitl.UnmarshalOutcome(raw)
}
func (*Client) Respond(context.Context, hitl.RespondCommand) (hitl.Outcome, error) {
	return nil, hitl.ErrUnauthorized
}

func (c *Client) AssessResponse(ctx context.Context, q ownerwire.AssessResponseCommand) (ownerwire.ResponseAssessment, error) {
	if q.Validate() != nil || q.Caller.ApplicationID != c.cfg.CallerScope || q.ExpectedTerminalRevision < 1 {
		return ownerwire.ResponseAssessment{}, hitl.ErrUnauthorized
	}
	var raw json.RawMessage
	if err := c.call(ctx, "gate.assess-response", false, q, &raw); err != nil {
		return ownerwire.ResponseAssessment{}, err
	}
	return decodeAssessment(raw, q)
}

// Every derived field must be present under its exact wire name. Omitted facts
// are never reconstructed from request digests or caller expectations.
func decodeAssessment(raw json.RawMessage, q ownerwire.AssessResponseCommand) (ownerwire.ResponseAssessment, error) {
	required := []string{"idempotency_key", "binding", "native_request_id", "contract_version", "owner_ref", "item_id", "request_digest", "operation_digest", "option_id", "terminal_revision", "participant", "assessed_at", "expires_at"}
	fields, err := exactObject(raw, required...)
	if err != nil {
		return ownerwire.ResponseAssessment{}, ErrTransport
	}
	for _, name := range required {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ownerwire.ResponseAssessment{}, ErrTransport
		}
	}
	var r ownerwire.ResponseAssessment
	if json.Unmarshal(raw, &r) != nil || r.ContractVersion != gate.ContractVersion || strings.TrimSpace(r.OwnerRef) == "" || r.ItemID != q.ItemID || r.TerminalRevision != q.ExpectedTerminalRevision || strings.TrimSpace(r.IdempotencyKey) == "" || r.Binding.Validate() != nil || r.NativeRequestID.Validate() != nil || r.RequestDigest.Validate() != nil || r.OperationDigest.Validate() != nil || r.OptionID == "" || r.Participant.Validate() != nil || r.AssessedAt.IsZero() || !r.ExpiresAt.After(r.AssessedAt) || r.ExpiresAt.Sub(r.AssessedAt) > ownerwire.AssessmentTTL {
		return ownerwire.ResponseAssessment{}, ErrTransport
	}
	return r, nil
}

var _ gatecrasher.InteractionPort = (*Client)(nil)
