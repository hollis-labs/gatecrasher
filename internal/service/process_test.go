package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/hollis-labs/libs/agent/sdk"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/core/hitl/memstore"
)

const processFixtureEnv = "GATECRASHER_TEST_CRASH_DIR"

func TestProcessCrashHelper(t *testing.T) {
	dir := os.Getenv(processFixtureEnv)
	if dir == "" {
		return
	}
	st := openStore(t, filepath.Join(dir, "host.db"))
	s, err := New(context.Background(), st, Config{OwnerRef: "tachyon-fixture", CallerScope: "gatecrasher", CallbackSubject: "key:callback-fixture", ActorMap: map[string]string{"tachyon/user:reviewer": "person:reviewer"}})
	if err != nil {
		t.Fatal(err)
	}
	o := &observedOwner{Service: hitl.NewService(memstore.New(), hitl.Options{}), queued: make(chan hitl.Handle, 2), request: make(chan hitl.EnqueueRequest, 2)}
	if err = s.Wire(o); err != nil {
		t.Fatal(err)
	}
	f, rr, op, r := prepareSDK(t, s)
	ticket, err := s.coordinator.Request(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	decide(t, s, o, r, ticket.Handle, "allow-once")
	res, err := SDKGate{Host: s}.Await(t.Context(), ticket, gate.WaitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := policyProjection(f)
	err = s.Admit(t.Context(), sdk.Admission{Run: rr, Kind: "tool", Binding: f.Binding, Environment: f.Environment, DefinitionDigest: rr.DefinitionDigest, Operation: &op, Request: &r, Decision: res.Decision, Policy: &p}, func(context.Context) error {
		// #nosec G304 G703 -- isolated test helper receives only the parent t.TempDir.
		marker, markerErr := os.OpenFile(filepath.Join(dir, "effect-marker"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if markerErr != nil {
			return markerErr
		}
		if markerErr = marker.Close(); markerErr != nil {
			return markerErr
		}
		// Model an abrupt runtime death AFTER the observable effect, before result
		// recording, rollback, Close or any deferred cleanup can run.
		os.Exit(23)
		return nil
	})
	t.Fatal("crash callback returned", err)
}
func TestFileClaimsAndReservationsSurviveAbruptProcessReplacement(t *testing.T) {
	dir := t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- the current test executable, with fixed helper-test arguments.
	child := exec.Command(binary, "-test.run=^TestProcessCrashHelper$")
	child.Env = append(os.Environ(), processFixtureEnv+"="+dir)
	out, err := child.CombinedOutput()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 23 {
		t.Fatal("child did not reach effect crash", err, string(out))
	}
	if _, err = os.Stat(filepath.Join(dir, "effect-marker")); err != nil {
		t.Fatal("effect did not occur", err)
	}
	st := openStore(t, filepath.Join(dir, "host.db"))
	defer st.Close()
	host, err := New(t.Context(), st, Config{OwnerRef: "tachyon-fixture", CallerScope: "gatecrasher", CallbackSubject: "key:callback-fixture"})
	if err != nil {
		t.Fatal("OS did not release old admission ownership", err)
	}
	defer host.Close()
	var reservation string
	if err = st.Reader().QueryRowContext(t.Context(), `SELECT reservation_json FROM run_reservations`).Scan(&reservation); err != nil {
		t.Fatal(err)
	}
	var rr sdk.RunReservation
	if err = decode(reservation, &rr); err != nil {
		t.Fatal(err)
	}
	f := runtimeFixture(host)
	f.Binding = rr.Binding
	f.Binding.Generation++
	f.Binding.AttemptID = "replacement"
	if err = host.Enroll(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	rr.Binding = f.Binding
	rr.Environment = f.Environment
	if err = host.ReserveRun(t.Context(), rr); !errors.Is(err, sdk.ErrRunUsed) {
		t.Fatal("replacement replayed uncertain logical run", err)
	}
	var state string
	if err = st.Reader().QueryRowContext(t.Context(), `SELECT state FROM effect_observations ORDER BY seq DESC LIMIT 1`).Scan(&state); err != nil || state != "unknown" {
		t.Fatal("crashed effect was not uncertain", state, err)
	}
}
