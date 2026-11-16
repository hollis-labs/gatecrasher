package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/hollis-labs/gatecrasher/internal/recipewire"
	"github.com/hollis-labs/gatecrasher/internal/service"
	"github.com/hollis-labs/libs/agent/sdk"
)

func TestCleanupFailureMapsToUnknownReceipt(t *testing.T) {
	// Response mapping only; the service fixture separately faults real SQLite
	// cleanup after actual SDK completion.
	recorder := httptest.NewRecorder()
	writeRecipeResponse(recorder, "run", sdk.Result{RunID: "run", Status: sdk.Succeeded, Text: "private partial output"}, service.ErrCleanup)
	var reply recipewire.Response
	if recorder.Code != 503 || json.Unmarshal(recorder.Body.Bytes(), &reply) != nil || reply.State != "unknown" || reply.Result == nil || reply.Result.Text != "" || !reply.ReconciliationRequired || reply.ReplayAllowed || reply.ResumeAvailable {
		t.Fatal("cleanup failure became successful or resumable receipt")
	}
}
