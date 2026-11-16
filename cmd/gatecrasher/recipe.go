package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/recipewire"
	"github.com/hollis-labs/libs/agent/sdk"
	"github.com/spf13/cobra"
)

func recipeCmd() *cobra.Command {
	root := &cobra.Command{Use: "recipe", Short: "Run the fixed fingerprint recipe on the authenticated daemon"}
	var origin, file, runID string
	cmd := &cobra.Command{Use: "fingerprint", Short: "Submit bounded text from stdin; never choose a runtime or tool", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
			return errors.New("a daemon origin is required")
		}
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "https" && (u.Scheme != "http" || ip == nil || !ip.IsLoopback()) {
			return errors.New("HTTPS or a numeric loopback daemon is required")
		}
		if file == "" || runID == "" || len(runID) > 128 {
			return errors.New("--token-file and --run-id are required")
		}
		info, err := os.Stat(file)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 4096 {
			return errors.New("private token file required")
		}
		// #nosec G304 -- explicit local CLI credential path; private regular file checked above.
		credential, err := os.ReadFile(file)
		if err != nil {
			return errors.New("cannot read token file")
		}
		token := strings.TrimSpace(string(credential))
		if token == "" || strings.ContainsAny(token, " \r\n\t") {
			return errors.New("invalid token file")
		}
		text, err := io.ReadAll(io.LimitReader(c.InOrStdin(), 4097))
		if err != nil || len(text) > 4096 || strings.TrimSpace(string(text)) == "" {
			return errors.New("stdin must contain 1 to 4096 bytes of text")
		}
		body, err := json.Marshal(struct {
			RunID string `json:"run_id"`
			Text  string `json:"text"`
		}{runID, string(text)})
		if err != nil {
			return err
		}
		u.Path = "/api/gate/v1/recipes/fingerprint"
		request, err := http.NewRequestWithContext(c.Context(), http.MethodPost, u.String(), bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Do(request)
		if err != nil {
			return errors.New("recipe transport unavailable; do not replay uncertain work")
		}
		defer func() { _ = response.Body.Close() }()
		raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
		if err != nil || len(raw) > 64<<10 {
			return errors.New("invalid bounded recipe response")
		}
		var receipt recipewire.Response
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&receipt) != nil || !errors.Is(d.Decode(new(any)), io.EOF) || receipt.ContractVersion != recipewire.Version || receipt.RunID != runID || receipt.ReplayAllowed || receipt.ResumeAvailable || recipewire.HTTPStatus(receipt.State) == 0 || recipewire.HTTPStatus(receipt.State) != response.StatusCode {
			return errors.New("unknown recipe response; reconcile retained work without replay")
		}
		if receipt.State == "completed" && (receipt.Result == nil || receipt.Result.RunID != runID || receipt.Result.Status != sdk.Succeeded || receipt.ReconciliationRequired) {
			return errors.New("invalid completion evidence; reconcile without replay")
		}
		if receipt.State != "completed" && !receipt.ReconciliationRequired {
			return errors.New("invalid recipe outcome; reconcile without replay")
		}
		if receipt.State == "pending" && (receipt.Result == nil || receipt.Result.RunID != runID || receipt.Result.Status != sdk.Pending || receipt.Result.PendingTicket == nil || receipt.Result.PendingTicket.Validate() != nil) {
			return errors.New("invalid pending receipt; reconcile without replay")
		}
		if receipt.State == "canceled" && (receipt.Result == nil || receipt.Result.RunID != runID || receipt.Result.Status != sdk.Cancelled) { //nolint:misspell // SDK API uses this spelling.
			return errors.New("invalid cancellation receipt; reconcile without replay")
		}
		if _, err = c.OutOrStdout().Write(raw); err != nil {
			return err
		}
		switch receipt.State {
		case "completed":
			return nil
		case "pending":
			return errors.New("approval pending; this SDK run stopped and cannot resume; reconcile without replay")
		case "canceled":
			return errors.New("run canceled; effects and owner approvals may need reconciliation; do not replay")
		case "unknown":
			return errors.New("run outcome unknown; reconcile retained work without replay")
		default:
			return errors.New("recipe refused, unavailable or already reserved; reconcile retained work without replay")
		}
	}}
	cmd.Flags().StringVar(&origin, "url", "", "Gatecrasher daemon origin")
	cmd.Flags().StringVar(&file, "token-file", "", "Own-identity scoped recipe credential file")
	cmd.Flags().StringVar(&runID, "run-id", "", "Unique logical run identity; never reused")
	root.AddCommand(cmd)
	return root
}
