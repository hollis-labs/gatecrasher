package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/recipewire"
	"github.com/hollis-labs/libs/agent/sdk"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/gate/gatetest"
	"github.com/hollis-labs/libs/mesh/core/hitl"
)

func TestFixedRecipeCLIUsesDaemonWithoutRuntimeSelection(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "recipe-credential")
	if err := os.WriteFile(tokenFile, []byte("isolated-credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/gate/v1/recipes/fingerprint" || r.Header.Get("Authorization") != "Bearer isolated-credential" {
			t.Error("wrong fixed route/auth")
		}
		var input map[string]string
		if json.NewDecoder(r.Body).Decode(&input) != nil || len(input) != 2 || input["run_id"] != "logical-1" || input["text"] != "hello" {
			t.Error(input)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"contract_version":"1","run_id":"logical-1","state":"completed","replay_allowed":false,"resume_available":false,"reconciliation_required":false,"result":{"RunID":"logical-1","Status":"succeeded"}}`))
	}))
	defer server.Close()
	cmd := recipeCmd()
	cmd.SetArgs([]string{"fingerprint", "--url", server.URL, "--token-file", tokenFile, "--run-id", "logical-1"})
	cmd.SetIn(strings.NewReader("hello"))
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil || calls != 1 || !strings.Contains(out.String(), "succeeded") {
		t.Fatal(err, calls)
	}
	cmd = recipeCmd()
	cmd.SetArgs([]string{"fingerprint", "--runtime", "arbitrary"})
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err == nil || calls != 1 {
		t.Fatal("arbitrary runtime option was accepted")
	}
	if plan([]string{"recipe", "fingerprint"}).prepare {
		t.Fatal("recipe CLI opened local state")
	}
}

func TestRecipeCLIKeepsPendingCancelledAndUnknownExplicitWithoutRetry(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "recipe-credential")
	token := rand.Text()
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	native := gatetest.Request(time.Now().UTC())
	digest, err := native.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ticket := gate.Ticket{AuthorityRef: "owner-fixture", RequestDigest: digest, Binding: native.Binding, Handle: hitl.Handle{ContractVersion: hitl.ContractVersion, ItemID: "item", State: hitl.StateSubmitted, Revision: 1}}
	for _, state := range []string{"pending", "canceled", "unknown", "unavailable", "conflict", "refused"} {
		t.Run(state, func(t *testing.T) {
			var calls atomic.Int32
			receipt := recipewire.Response{ContractVersion: "1", RunID: "run", State: state, ReconciliationRequired: true}
			if state == "pending" {
				receipt.Result = &sdk.Result{RunID: "run", Status: sdk.Pending, PendingTicket: &ticket}
			}
			if state == "canceled" {
				receipt.Result = &sdk.Result{RunID: "run", Status: sdk.Cancelled} //nolint:misspell // SDK API uses this spelling.
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("credential lost")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(recipewire.HTTPStatus(state))
				_ = json.NewEncoder(w).Encode(receipt)
			}))
			defer server.Close()
			cmd := recipeCmd()
			cmd.SetArgs([]string{"fingerprint", "--url", server.URL, "--token-file", tokenFile, "--run-id", "run"})
			cmd.SetIn(strings.NewReader("private supplied text"))
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			if err := cmd.Execute(); err == nil || calls.Load() != 1 {
				t.Fatal("nonterminal/uncertain result retried or reported success", err, calls.Load())
			}
			if !strings.Contains(out.String(), `"state":"`+state+`"`) || strings.Contains(out.String(), "private supplied text") || strings.Contains(out.String(), token) {
				t.Fatal("receipt lost state or leaked request custody")
			}
		})
	}
}
