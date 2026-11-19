package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	libauth "github.com/hollis-labs/libs/security/auth"

	"github.com/hollis-labs/gatecrasher/internal/approvals"
	"github.com/hollis-labs/gatecrasher/pkg/approvalapi"
)

// Approvals is the approval inbox the gate v1 routes serve.
type Approvals interface {
	Submit(context.Context, libauth.Principal, approvalapi.SubmitRequest) (approvalapi.SubmitResponse, bool, error)
	Get(context.Context, libauth.Principal, string) (approvalapi.Approval, error)
	Await(context.Context, libauth.Principal, string, time.Duration) (approvalapi.Approval, error)
	Withdraw(context.Context, libauth.Principal, string) (approvalapi.Approval, error)
	Decide(context.Context, libauth.Principal, string, approvalapi.DecideRequest) (approvalapi.DecideResponse, error)
	JWKS() approvalapi.JWKS
}

const defaultAwait = 30 * time.Second

func approvalRoutes() []Route {
	p := approvalapi.PathApprovals
	return []Route{
		{http.MethodPost, p, approvalapi.ScopeSubmit},
		{http.MethodGet, p + "/{id}", approvalapi.ScopeRead},
		{http.MethodGet, p + "/{id}/await", approvalapi.ScopeRead},
		{http.MethodPost, p + "/{id}/withdraw", approvalapi.ScopeSubmit},
		{http.MethodPost, p + "/{id}" + approvalapi.PathDecideSuffix, approvalapi.ScopeDecide},
		{http.MethodGet, approvalapi.PathJWKS, approvalapi.ScopeRead},
	}
}

func (h *Handler) mountApprovals(m *http.ServeMux) {
	p := approvalapi.PathApprovals
	m.HandleFunc("POST "+p, h.guarded(approvalapi.ScopeSubmit, h.submit))
	m.HandleFunc("GET "+p+"/{id}", h.guarded(approvalapi.ScopeRead, h.getApproval))
	m.HandleFunc("GET "+p+"/{id}/await", h.guarded(approvalapi.ScopeRead, h.awaitApproval))
	m.HandleFunc("POST "+p+"/{id}/withdraw", h.guarded(approvalapi.ScopeSubmit, h.withdraw))
	m.HandleFunc("POST "+p+"/{id}"+approvalapi.PathDecideSuffix, h.guarded(approvalapi.ScopeDecide, h.decide))
	m.HandleFunc("GET "+approvalapi.PathJWKS, h.guarded(approvalapi.ScopeRead, h.jwks))
}

type approvalHandler func(http.ResponseWriter, *http.Request, libauth.Principal)

// guarded reverifies the bearer with Gatecrasher's own identity (no implicit trust of
// another issuer) and requires the route's scope, as the other routes do.
func (h *Handler) guarded(scope string, next approvalHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		token, state := libauth.ParseBearer(r.Header.Values("Authorization"))
		if state != "" || h.own == nil {
			writeErr(w, http.StatusUnauthorized, approvalapi.ErrCodeUnauthorized, "Own credential required")
			return
		}
		p, err := h.own.Verify(r.Context(), token)
		if err != nil || !p.Verified {
			writeErr(w, http.StatusUnauthorized, approvalapi.ErrCodeUnauthorized, "Credential refused")
			return
		}
		if p.Audience != "gatecrasher" || !p.HasScope(scope) {
			writeErr(w, http.StatusForbidden, approvalapi.ErrCodeForbidden, "Missing scope "+scope)
			return
		}
		if h.approvals == nil {
			writeErr(w, http.StatusServiceUnavailable, approvalapi.ErrCodeUnavailable, "Approvals are not configured")
			return
		}
		next(w, r, p)
	}
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request, p libauth.Principal) {
	var in approvalapi.SubmitRequest
	if !decodeBody(w, r, &in) {
		return
	}
	out, created, err := h.approvals.Submit(r.Context(), p, in)
	if err != nil {
		writeApprovalErr(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, out)
}

func (h *Handler) getApproval(w http.ResponseWriter, r *http.Request, p libauth.Principal) {
	if r.URL.RawQuery != "" {
		writeErr(w, http.StatusBadRequest, approvalapi.ErrCodeInvalid, "No query is accepted")
		return
	}
	out, err := h.approvals.Get(r.Context(), p, r.PathValue("id"))
	if err != nil {
		writeApprovalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) awaitApproval(w http.ResponseWriter, r *http.Request, p libauth.Principal) {
	q := r.URL.Query()
	timeout := defaultAwait
	for k := range q {
		if k != "timeout" {
			writeErr(w, http.StatusBadRequest, approvalapi.ErrCodeInvalid, "Only timeout is accepted")
			return
		}
	}
	if v := q.Get("timeout"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			writeErr(w, http.StatusBadRequest, approvalapi.ErrCodeInvalid, "timeout must be a duration such as 30s")
			return
		}
		timeout = d
	}
	out, err := h.approvals.Await(r.Context(), p, r.PathValue("id"), timeout)
	if err != nil {
		writeApprovalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) withdraw(w http.ResponseWriter, r *http.Request, p libauth.Principal) {
	out, err := h.approvals.Withdraw(r.Context(), p, r.PathValue("id"))
	if err != nil {
		writeApprovalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) decide(w http.ResponseWriter, r *http.Request, p libauth.Principal) {
	var in approvalapi.DecideRequest
	if !decodeBody(w, r, &in) {
		return
	}
	out, err := h.approvals.Decide(r.Context(), p, r.PathValue("id"), in)
	if err != nil {
		writeApprovalErr(w, err)
		return
	}
	status := http.StatusOK
	if out.Shadow {
		status = http.StatusAccepted
	}
	writeJSON(w, status, out)
}

func (h *Handler) jwks(w http.ResponseWriter, _ *http.Request, _ libauth.Principal) {
	writeJSON(w, http.StatusOK, h.approvals.JWKS())
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		writeErr(w, http.StatusBadRequest, approvalapi.ErrCodeInvalid, "A JSON body is required")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, approvals.MaxBody))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		writeErr(w, http.StatusBadRequest, approvalapi.ErrCodeInvalid, "Invalid body")
		return false
	}
	return true
}

func writeApprovalErr(w http.ResponseWriter, err error) {
	var e *approvals.Error
	if errors.As(err, &e) {
		writeErr(w, e.Status, e.Code, e.Message)
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		writeErr(w, http.StatusServiceUnavailable, approvalapi.ErrCodeUnavailable, "Request ended")
		return
	}
	writeErr(w, http.StatusInternalServerError, "internal", "Approval store error")
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, approvalapi.Error{Code: code, Message: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
