package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hollis-labs/libs/agent/sdk"
	"github.com/hollis-labs/libs/llm/core/llmtypes"
	"github.com/hollis-labs/libs/mesh/core/gate"
	libauth "github.com/hollis-labs/libs/security/auth"
)

// Controlled authority clock reaches environment expiry during an actual SDK
// model effect, without a two-minute wall wait or fabricated terminal SQL row.
type expiringRecipeModel struct {
	offset *atomic.Int64
	calls  atomic.Int32
}

func (*expiringRecipeModel) Capabilities() llmtypes.ProviderCapabilities {
	return llmtypes.ProviderCapabilities{SupportsToolCalling: true, ContextWindowSize: 65536}
}
func (*expiringRecipeModel) Complete(context.Context, llmtypes.ChatRequest) (string, error) {
	return "", errors.New("stream only")
}
func (m *expiringRecipeModel) StreamChat(context.Context, llmtypes.ChatRequest) (<-chan llmtypes.StreamEvent, error) {
	m.calls.Add(1)
	m.offset.Add(int64(3 * time.Minute))
	return nil, context.DeadlineExceeded
}

func TestExpiredRecipeCleanupAllowsNewIDButRetainsConsumedOldRun(t *testing.T) {
	s, _, _ := newHost(t)
	var offset atomic.Int64
	s.cfg.Now = func() time.Time { return time.Now().UTC().Add(time.Duration(offset.Load())) }
	p := libauth.Principal{Verified: true, ID: "key:recipe-fixture", Kind: libauth.KindService, Audience: "gatecrasher", Scopes: []string{RecipeScope}}
	model := &expiringRecipeModel{offset: &offset}
	result, err := s.RunRecipe(t.Context(), p, "expired-run", "bounded input", model)
	if result.Status != sdk.Cancelled || !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrCleanup) { //nolint:misspell // SDK API spelling.
		t.Fatal("did not clean actual expired SDK run", result.Status, err)
	}
	var active int
	if err = s.st.Reader().QueryRowContext(t.Context(), `SELECT active FROM runtime_facts WHERE slot_key=?`, logicalKey(result.Binding, "")).Scan(&active); err != nil || active != 0 {
		t.Fatal("expired returned run retained active slot", active, err)
	}
	if _, err = s.RunRecipe(t.Context(), p, "expired-run", "changed input", model); !errors.Is(err, sdk.ErrRunUsed) {
		t.Fatal("old logical run was released", err)
	}
	before := model.calls.Load()
	next, err := s.RunRecipe(t.Context(), p, "distinct-new-run", "bounded input", model)
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, sdk.ErrBusy) || model.calls.Load() != before+1 {
		t.Fatal("fresh run remained blocked by expired predecessor", next.Status, err)
	}
	if next.Binding.Generation <= result.Binding.Generation || next.Binding.ConversationID != result.Binding.ConversationID || next.Binding.OwnerID != result.Binding.OwnerID {
		t.Fatal("new run lost stable namespace/generation")
	}
	if err = s.VerifyEnvironment(t.Context(), result.Binding, runtimeFixture(s).Environment, nil); err == nil {
		t.Fatal("old expired binding became admissible")
	}
}

func TestExpiredCleanupCannotDeactivateReplacementBinding(t *testing.T) {
	s, _, _ := newHost(t)
	old := runtimeFixture(s)
	if err := s.Enroll(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	clock := s.cfg.Now
	s.cfg.Now = func() time.Time { return clock().Add(6 * time.Minute) }
	if err := s.Revoke(t.Context(), old.Binding); err != nil {
		t.Fatal("expired exact-binding cleanup refused", err)
	}
	replacement := runtimeFixture(s)
	replacement.Binding = old.Binding
	replacement.Binding.Generation++
	replacement.Binding.AttemptID = "replacement"
	if err := s.Enroll(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(t.Context(), old.Binding); !errors.Is(err, gate.ErrBinding) {
		t.Fatal("stale cleanup did not match exact generation", err)
	}
	if err := s.VerifyEnvironment(t.Context(), replacement.Binding, replacement.Environment, nil); err != nil {
		t.Fatal("stale cleanup deactivated replacement", err)
	}
}

type completingRecipeModel struct{}

func (completingRecipeModel) Capabilities() llmtypes.ProviderCapabilities {
	return llmtypes.ProviderCapabilities{SupportsToolCalling: true, ContextWindowSize: 65536}
}
func (completingRecipeModel) Complete(context.Context, llmtypes.ChatRequest) (string, error) {
	return "", errors.New("stream only")
}
func (completingRecipeModel) StreamChat(context.Context, llmtypes.ChatRequest) (<-chan llmtypes.StreamEvent, error) {
	c := make(chan llmtypes.StreamEvent, 2)
	c <- llmtypes.StreamEvent{Type: llmtypes.EventDelta, Content: "done"}
	c <- llmtypes.StreamEvent{Type: llmtypes.EventDone}
	close(c)
	return c, nil
}

func TestRecipeCleanupStorageFailureCannotReportSuccessfulCompletion(t *testing.T) {
	s, _, _ := newHost(t)
	// Fault only lifecycle deactivation, after real SDK events/reservation/model
	// completion. This trigger is isolated to this disposable SQLite fixture.
	if _, err := s.st.ExecContext(t.Context(), `CREATE TRIGGER test_cleanup_failure BEFORE UPDATE OF active ON runtime_facts WHEN NEW.active=0 BEGIN SELECT RAISE(ABORT,'isolated cleanup failure'); END`); err != nil {
		t.Fatal(err)
	}
	p := libauth.Principal{Verified: true, ID: "key:recipe-fixture", Kind: libauth.KindService, Audience: "gatecrasher", Scopes: []string{RecipeScope}}
	result, err := s.RunRecipe(t.Context(), p, "cleanup-write-failure", "bounded input", completingRecipeModel{})
	if !errors.Is(err, ErrCleanup) || result.Status == sdk.Succeeded {
		t.Fatal("cleanup failure hidden as success", result.Status, err)
	}
	if _, err = s.RunRecipe(t.Context(), p, "cleanup-write-failure", "bounded input", completingRecipeModel{}); !errors.Is(err, sdk.ErrRunUsed) {
		t.Fatal("cleanup failure released reservation", err)
	}
}
