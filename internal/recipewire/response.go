// Package recipewire defines bounded recipe receipts, not resumable sessions.
package recipewire

import "github.com/hollis-labs/libs/agent/sdk"

const Version = "1"

type Response struct {
	ContractVersion        string      `json:"contract_version"`
	RunID                  string      `json:"run_id"`
	State                  string      `json:"state"`
	Result                 *sdk.Result `json:"result,omitempty"`
	ReplayAllowed          bool        `json:"replay_allowed"`
	ResumeAvailable        bool        `json:"resume_available"`
	ReconciliationRequired bool        `json:"reconciliation_required"`
}

// HTTPStatus also defines the closed state vocabulary used by the thin client.
func HTTPStatus(state string) int {
	switch state {
	case "completed", "canceled":
		return 200
	case "pending":
		return 202
	case "conflict":
		return 409
	case "refused":
		return 403
	case "unknown", "unavailable":
		return 503
	default:
		return 0
	}
}
