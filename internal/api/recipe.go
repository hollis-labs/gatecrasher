package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/hollis-labs/gatecrasher/internal/recipewire"
	"github.com/hollis-labs/gatecrasher/internal/service"
	"github.com/hollis-labs/libs/agent/sdk"
	"github.com/hollis-labs/libs/mesh/core/gate"
)

func writeRecipeResponse(w http.ResponseWriter, id string, result sdk.Result, err error) {
	out := recipewire.Response{ContractVersion: recipewire.Version, RunID: id, State: "unknown", ReconciliationRequired: true}
	if result.RunID == id {
		out.Result = &result
	}
	switch {
	case errors.Is(err, service.ErrCleanup):
		out.State = "unknown"
	case err == nil && result.RunID == id && result.Status == sdk.Succeeded:
		out.State, out.ReconciliationRequired = "completed", false
	case errors.Is(err, sdk.ErrRunUsed), errors.Is(err, sdk.ErrBusy):
		out.State = "conflict"
	case errors.Is(err, sdk.ErrPending) && result.Status == sdk.Pending && result.PendingTicket != nil:
		out.State = "pending"
	case result.Status == sdk.Cancelled && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)): //nolint:misspell // SDK API uses this spelling.
		// Stopping the run does not undo an admitted effect or withdraw the owner item.
		out.State = "canceled"
	case errors.Is(err, service.ErrUnconfigured):
		out.State = "unavailable"
	case errors.Is(err, service.ErrRefused), errors.Is(err, gate.ErrDenied), errors.Is(err, gate.ErrExpired):
		out.State = "refused"
	}
	if out.State != "completed" && out.Result != nil {
		out.Result.Text = "" // retain evidence references, never partial model text on failure
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(recipewire.HTTPStatus(out.State))
	_ = json.NewEncoder(w).Encode(out)
}
