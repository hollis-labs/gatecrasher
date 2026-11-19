// Package api exposes the gate v1 routes: narrowly scoped host assessments and the
// approval inbox (approvals.go).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	libauth "github.com/hollis-labs/libs/security/auth"
	"github.com/hollis-labs/substrate/apierr"

	"github.com/hollis-labs/gatecrasher/internal/service"
	"github.com/hollis-labs/libs/agent/sdk"
)

type Route struct{ Method, Pattern, Scope string }

func Routes() []Route {
	return append([]Route{{http.MethodPost, "/api/gate/v1/authorize-response", service.CallbackScope}, {http.MethodPost, "/api/gate/v1/recipes/fingerprint", service.RecipeScope}}, approvalRoutes()...)
}
func RegisterScopes(t *libauth.ScopeTable) {
	for _, r := range Routes() {
		t.Route(r.Method, r.Pattern, r.Scope)
	}
}

type Assessor interface {
	AuthorizeResponse(context.Context, libauth.Principal, service.ProposedResponse) (service.Authorization, error)
}
type RecipeRunner interface {
	Run(context.Context, libauth.Principal, string, string) (sdk.Result, error)
}
type Handler struct {
	assessor  Assessor
	own       libauth.Verifier
	recipe    RecipeRunner
	approvals Approvals
	trusted   libauth.Verifier
}

// WithTrusted also accepts credentials v verifies on the approval routes (auth.trust:
// warden). The Tachyon callback and recipe routes keep accepting only Gatecrasher's own.
func (h *Handler) WithTrusted(v libauth.Verifier) *Handler {
	h.trusted = v
	return h
}

// WithApprovals serves the approval inbox; without it those routes answer 503.
func (h *Handler) WithApprovals(a Approvals) *Handler {
	h.approvals = a
	return h
}

func New(a Assessor, own libauth.Verifier, recipes ...RecipeRunner) *Handler {
	h := &Handler{assessor: a, own: own}
	if len(recipes) == 1 {
		h.recipe = recipes[0]
	}
	return h
}
func (h *Handler) Mux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("POST /api/gate/v1/authorize-response", h.authorize)
	m.HandleFunc("POST /api/gate/v1/recipes/fingerprint", h.runRecipe)
	h.mountApprovals(m)
	return m
}
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// Reverify with the app's OWN identity service, even if another configured
	// outer guard verifier accepted the bearer. No implicit external issuer trust.
	token, state := libauth.ParseBearer(r.Header.Values("Authorization"))
	if state != "" || h.own == nil {
		apierr.Write(w, 401, "unauthorized", "Own service credential required", nil)
		return
	}
	p, err := h.own.Verify(r.Context(), token)
	if err != nil || !p.Verified || p.Kind != libauth.KindService || p.Audience != "gatecrasher" || !p.HasScope(service.CallbackScope) || !strings.HasPrefix(p.ID, "key:") || p.TokenID != strings.TrimPrefix(p.ID, "key:") {
		apierr.Write(w, 403, "forbidden", "Callback credential refused", nil)
		return
	}
	if r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		apierr.Write(w, 400, "invalid_request", "A JSON command body is required", nil)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		apierr.Write(w, 400, "invalid_request", "Invalid command", nil)
		return
	}
	var in service.ProposedResponse
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	d.UseNumber()
	if d.Decode(&in) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		apierr.Write(w, 400, "invalid_request", "Invalid command", nil)
		return
	}
	if h.assessor == nil {
		apierr.Write(w, 503, "unavailable", "The Tachyon binding is not configured", nil)
		return
	}
	out, err := h.assessor.AuthorizeResponse(r.Context(), p, in)
	if err != nil {
		apierr.Write(w, 403, "forbidden", "Response authorization refused", nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (h *Handler) runRecipe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token, state := libauth.ParseBearer(r.Header.Values("Authorization"))
	if state != "" || h.own == nil {
		apierr.Write(w, 401, "unauthorized", "Own credential required", nil)
		return
	}
	p, err := h.own.Verify(r.Context(), token)
	if err != nil || !p.Verified || p.Audience != "gatecrasher" || !p.HasScope(service.RecipeScope) {
		apierr.Write(w, 403, "forbidden", "Recipe credential refused", nil)
		return
	}
	if r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		apierr.Write(w, 400, "invalid_request", "A JSON command is required", nil)
		return
	}
	var in struct {
		RunID string `json:"run_id"`
		Text  string `json:"text"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || !errors.Is(d.Decode(new(any)), io.EOF) || len(in.RunID) > 128 || in.RunID == "" || len(in.Text) > 4096 || strings.TrimSpace(in.Text) == "" {
		apierr.Write(w, 400, "invalid_request", "Invalid bounded recipe input", nil)
		return
	}
	if h.recipe == nil {
		writeRecipeResponse(w, in.RunID, sdk.Result{}, service.ErrUnconfigured)
		return
	}
	out, err := h.recipe.Run(r.Context(), p, in.RunID, in.Text)
	writeRecipeResponse(w, in.RunID, out, err)
}
