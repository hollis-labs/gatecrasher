package approvals

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/hollis-labs/libs/core/store"
	libauth "github.com/hollis-labs/libs/security/auth"

	"github.com/hollis-labs/gatecrasher/internal/settings"
	"github.com/hollis-labs/gatecrasher/pkg/approvalapi"
)

// grantKind: every kind but choice, question and secret_request is an approve/deny
// request for the grant in Requested.
func grantKind(kind string) bool {
	switch kind {
	case approvalapi.KindChoice, approvalapi.KindQuestion, approvalapi.KindSecretRequest:
		return false
	}
	return true
}

var (
	choiceID  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	secretRef = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,256}$`)
)

// validateKind checks what a kind needs: a prompt for choice and question, an intake on
// an allowed origin for secret_request, and nothing extra for a grant.
func (s *Service) validateKind(req approvalapi.SubmitRequest, now time.Time) error {
	bad := func(msg string) error { return fail(http.StatusBadRequest, approvalapi.ErrCodeInvalid, msg) }
	p := req.Prompt
	switch req.Kind {
	case approvalapi.KindChoice, approvalapi.KindQuestion:
		if req.SecretIntake != nil {
			return bad("secret_intake is only for secret_request")
		}
		if p == nil || strings.TrimSpace(p.Question) == "" || len(p.Question) > approvalapi.MaxQuestion {
			return bad("prompt.question is required (at most 2000 bytes)")
		}
		if req.Kind == approvalapi.KindQuestion {
			if len(p.Choices) > 0 {
				return bad("a question has no choices")
			}
			return nil
		}
		if len(p.Choices) < 2 || len(p.Choices) > approvalapi.MaxChoices {
			return bad("a choice needs 2 to 20 choices")
		}
		seen := map[string]bool{}
		for _, c := range p.Choices {
			if !choiceID.MatchString(c.ID) || seen[c.ID] || strings.TrimSpace(c.Label) == "" || len(c.Label) > approvalapi.MaxChoiceLabel {
				return bad("every choice needs a unique id ([A-Za-z0-9._-]) and a label")
			}
			seen[c.ID] = true
		}
		return nil
	case approvalapi.KindSecretRequest:
		in := req.SecretIntake
		switch {
		case p != nil && len(p.Choices) > 0:
			return bad("a secret_request has no choices")
		case p != nil && len(p.Question) > approvalapi.MaxQuestion:
			return bad("prompt.question is too long")
		case req.Tier != approvalapi.TierCritical:
			return bad("a secret_request is always tier critical")
		case in == nil || in.IntakeID == "" || len(in.IntakeID) > maxKey || in.IntakeURL == "":
			return bad("secret_intake needs intake_id and intake_url")
		case !in.ExpiresAt.After(now):
			return bad("secret_intake.expires_at must be in the future")
		case !settings.SafeURL(in.IntakeURL):
			return bad("secret_intake.intake_url must be https (or http on loopback)")
		case !slices.Contains(s.originsFor(req.Source), settings.Origin(in.IntakeURL)):
			return fail(http.StatusForbidden, approvalapi.ErrCodeForbidden, "secret_intake.intake_url is not an allowed intake origin for "+req.Source)
		}
		return nil
	}
	if p != nil || req.SecretIntake != nil {
		return bad("prompt and secret_intake are only for choice, question and secret_request")
	}
	return nil
}

func (s *Service) originsFor(source string) []string {
	var out []string
	for _, o := range s.cfg.IntakeOrigins[source] {
		out = append(out, strings.ToLower(strings.TrimSuffix(o, "/")))
	}
	return out
}

// checkResponse is what a decision on req carries besides its outcome: the choice or the
// answer when approving those kinds. A secret_request is only declined by a decide; it is
// approved when the producer reports the secret provided.
func checkResponse(req approvalapi.SubmitRequest, in approvalapi.DecideRequest) (*approvalapi.Response, error) {
	bad := func(msg string) error { return fail(http.StatusBadRequest, approvalapi.ErrCodeInvalid, msg) }
	approve := in.Outcome == approvalapi.OutcomeApproved
	switch req.Kind {
	case approvalapi.KindChoice:
		if in.Answer != "" {
			return nil, bad("a choice takes choice, not answer")
		}
		if !approve {
			return nil, nil
		}
		if !slices.ContainsFunc(req.Prompt.Choices, func(c approvalapi.Choice) bool { return c.ID == in.Choice }) {
			return nil, bad("choice must be one of the request's choice ids")
		}
		return &approvalapi.Response{Choice: in.Choice}, nil
	case approvalapi.KindQuestion:
		if in.Choice != "" {
			return nil, bad("a question takes answer, not choice")
		}
		if !approve {
			return nil, nil
		}
		if strings.TrimSpace(in.Answer) == "" || len(in.Answer) > approvalapi.MaxAnswer {
			return nil, bad("answer is required (at most 4000 bytes)")
		}
		return &approvalapi.Response{Answer: in.Answer}, nil
	case approvalapi.KindSecretRequest:
		if approve {
			return nil, fail(http.StatusConflict, approvalapi.ErrCodeTerminal, "A secret_request is approved when the producer reports the secret provided; decide can only decline it")
		}
	}
	if in.Choice != "" || in.Answer != "" {
		return nil, bad("choice and answer are only for choice and question requests")
	}
	return nil, nil
}

// SecretProvided records that the owner gave the secret to the producer's intake. Only
// the submitter reports it, for the intake it submitted; Gatecrasher stores the
// reference and time, never the value, and closes the request approved with the
// producer as decider (its intake is the proof).
func (s *Service) SecretProvided(ctx context.Context, caller libauth.Principal, id string, in approvalapi.SecretProvidedRequest) (approvalapi.Approval, error) {
	if !s.configured() {
		return approvalapi.Approval{}, errUnavailable
	}
	if !secretRef.MatchString(in.Ref) {
		return approvalapi.Approval{}, fail(http.StatusBadRequest, approvalapi.ErrCodeInvalid, "ref must be a reference ([A-Za-z0-9._:/@-], at most 256 bytes), never a value")
	}
	if _, err := s.Sweep(ctx); err != nil {
		return approvalapi.Approval{}, err
	}
	now := s.now()
	if in.ProvidedAt.IsZero() || in.ProvidedAt.After(now.Add(time.Minute)) {
		return approvalapi.Approval{}, fail(http.StatusBadRequest, approvalapi.ErrCodeInvalid, "provided_at is required and not in the future")
	}
	var out approvalapi.Approval
	changed := false
	err := s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		r, err := s.load(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.Submitter != caller.ID {
			return fail(http.StatusNotFound, approvalapi.ErrCodeNotFound, "No such approval")
		}
		if r.Kind != approvalapi.KindSecretRequest {
			return fail(http.StatusBadRequest, approvalapi.ErrCodeInvalid, "Not a secret_request")
		}
		req, err := r.request()
		if err != nil {
			return err
		}
		if req.SecretIntake == nil || req.SecretIntake.IntakeID != in.IntakeID {
			return fail(http.StatusBadRequest, approvalapi.ErrCodeInvalid, "intake_id does not match the request")
		}
		if r.SecretRef.Valid {
			if r.SecretRef.String != in.Ref {
				return fail(http.StatusConflict, approvalapi.ErrCodeTerminal, "A different secret reference was already recorded")
			}
			out = r.answer()
			return nil
		}
		if r.Status != string(approvalapi.StatusPending) {
			return fail(http.StatusConflict, approvalapi.ErrCodeTerminal, "The approval is already "+r.Status)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO approval_secrets(approval_id, intake_id, ref, provided_at, reported_by, recorded_at) VALUES(?,?,?,?,?,?)`,
			r.ID, in.IntakeID, in.Ref, in.ProvidedAt.UTC().Format(ts), caller.ID, now.Format(ts)); err != nil {
			return err
		}
		if err = event(ctx, tx, r.ID, "secret_provided", caller.ID, map[string]any{"intake_id": in.IntakeID, "ref": in.Ref}, now); err != nil {
			return err
		}
		who := approvalapi.Actor{Sub: r.Source, Kind: approvalapi.KindApp}
		if err = s.decide(ctx, tx, r, who, caller.ID, approvalapi.OutcomeApproved, nil, &approvalapi.Response{SecretRef: in.Ref}, "secret provided", now); err != nil {
			return err
		}
		changed = true
		got, err := s.load(ctx, tx, r.ID)
		out = got.answer()
		return err
	})
	if changed {
		s.notify(id)
	}
	if err != nil {
		return approvalapi.Approval{}, err
	}
	return out, nil
}

// Card renders an approval for a surface, for a caller who may read it.
func (s *Service) Card(ctx context.Context, caller libauth.Principal, id string) (approvalapi.Card, error) {
	if _, err := s.Get(ctx, caller, id); err != nil {
		return approvalapi.Card{}, err
	}
	r, err := s.load(ctx, s.st.Reader(), id)
	if err != nil {
		return approvalapi.Card{}, err
	}
	req, err := r.request()
	if err != nil {
		return approvalapi.Card{}, err
	}
	var d decisionRow
	if r.JWS.Valid {
		if d, err = s.loadDecision(ctx, id); err != nil {
			return approvalapi.Card{}, err
		}
	}
	return buildCard(r, req, d), nil
}

type decisionRow struct {
	Sub, Kind string
	Response  *approvalapi.Response
}

func (s *Service) loadDecision(ctx context.Context, id string) (decisionRow, error) {
	var d decisionRow
	var rj string
	err := s.st.Reader().QueryRowContext(ctx, `SELECT decider_sub, decider_kind, response_json FROM approval_decisions WHERE approval_id=?`, id).Scan(&d.Sub, &d.Kind, &rj)
	if err != nil {
		return d, err
	}
	var resp approvalapi.Response
	if json.Unmarshal([]byte(rj), &resp) == nil && resp != (approvalapi.Response{}) {
		d.Response = &resp
	}
	return d, nil
}

func buildCard(r row, req approvalapi.SubmitRequest, d decisionRow) approvalapi.Card {
	decide := approvalapi.PathApprovals + "/" + r.ID + approvalapi.PathDecideSuffix
	c := approvalapi.Card{
		Version: approvalapi.CardVersion, ApprovalID: r.ID, Status: approvalapi.Status(r.Status),
		Tier: req.Tier, Kind: req.Kind, Source: req.Source, Summary: req.Purpose,
		Principal: req.Principal, Evidence: req.Evidence, Prompt: req.Prompt, ExpiresAt: req.ExpiresAt,
		Deciders: "owner", Actions: []approvalapi.CardAction{},
	}
	if req.Tier == approvalapi.TierElevated {
		c.Deciders = "owner, " + req.ApproverClass
	}
	if req.Requested.Audience != "" {
		rq := req.Requested
		c.Requested = &rq
	}
	deny := approvalapi.CardAction{Kind: approvalapi.ActionDeny, Label: "Deny", Outcome: approvalapi.OutcomeDenied, Decide: decide}
	switch req.Kind {
	case approvalapi.KindChoice:
		c.Type, c.Title = approvalapi.CardChoose, req.Prompt.Question
		deny.Label = "Decline"
		c.Actions = append(c.Actions, approvalapi.CardAction{Kind: approvalapi.ActionChoose, Label: "Choose", Outcome: approvalapi.OutcomeApproved, Decide: decide}, deny)
	case approvalapi.KindQuestion:
		c.Type, c.Title = approvalapi.CardAnswer, req.Prompt.Question
		deny.Label = "Decline"
		c.Actions = append(c.Actions, approvalapi.CardAction{Kind: approvalapi.ActionAnswer, Label: "Answer", Outcome: approvalapi.OutcomeApproved, Decide: decide}, deny)
	case approvalapi.KindSecretRequest:
		c.Type, c.Title = approvalapi.CardRequestSecret, fmt.Sprintf("%s asks for a secret", req.Source)
		if req.Prompt != nil && req.Prompt.Question != "" {
			c.Title = req.Prompt.Question
		}
		in := req.SecretIntake
		c.Secret = &approvalapi.SecretForm{IntakeID: in.IntakeID, PostURL: in.IntakeURL, Field: "value", ExpiresAt: in.ExpiresAt, WriteOnly: true}
		deny.Label = "Decline"
		c.Actions = append(c.Actions, approvalapi.CardAction{Kind: approvalapi.ActionProvideSecret, Label: "Provide secret"}, deny)
	default:
		c.Type = approvalapi.CardApprove
		c.Title = fmt.Sprintf("%s: %s for %s", req.Kind, req.Requested.Audience, req.Principal.Sub)
		c.Actions = append(c.Actions, approvalapi.CardAction{Kind: approvalapi.ActionApprove, Label: "Approve", Outcome: approvalapi.OutcomeApproved, Decide: decide}, deny)
	}
	if c.Status.Terminal() {
		c.Actions = []approvalapi.CardAction{}
		c.Outcome = &approvalapi.CardOutcome{Status: c.Status, Response: d.Response}
		if d.Sub != "" {
			c.Outcome.Decider = &approvalapi.Actor{Sub: d.Sub, Kind: approvalapi.PrincipalKind(d.Kind)}
		}
		if c.Secret != nil {
			c.Secret = nil // the form is gone once the request is closed
		}
	}
	return c
}

// FeedLimit bounds one page of the event log.
const FeedLimit = 200

// Feed is the event log after seq, oldest first, holding only what caller may read.
// The second result is the last seq read, which a caller resumes after even when none of
// the events it skipped were for it.
func (s *Service) Feed(ctx context.Context, caller libauth.Principal, after int64) ([]approvalapi.FeedEvent, int64, error) {
	return s.feed(ctx, s.viewerOf(caller), after)
}

func (s *Service) feed(ctx context.Context, v viewer, after int64) ([]approvalapi.FeedEvent, int64, error) {
	out := []approvalapi.FeedEvent{}
	for {
		rows, err := s.st.Reader().QueryContext(ctx, `SELECT e.seq, e.approval_id, e.type, e.at, a.status, a.tier, a.kind, a.source, a.submitter, a.approver_class
 FROM approval_events e JOIN approvals a ON a.approval_id = e.approval_id WHERE e.seq > ? ORDER BY e.seq LIMIT ?`, after, FeedLimit)
		if err != nil {
			return nil, after, err
		}
		n := 0
		for rows.Next() {
			var e approvalapi.FeedEvent
			var submitter, class string
			if err = rows.Scan(&e.Seq, &e.ApprovalID, &e.Type, &e.At, &e.Status, &e.Tier, &e.Kind, &e.Source, &submitter, &class); err != nil {
				_ = rows.Close()
				return nil, after, err
			}
			n++
			after = e.Seq
			if v.can(submitter, class) {
				out = append(out, e)
			}
		}
		if err = rows.Close(); err != nil {
			return nil, after, err
		}
		// Stop at a full page for this reader, or at the end of the log.
		if len(out) >= FeedLimit || n < FeedLimit {
			return out, after, nil
		}
	}
}
