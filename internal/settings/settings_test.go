package settings_test

import (
	"strings"
	"testing"

	"github.com/hollis-labs/gatecrasher/internal/settings"
)

func TestParse(t *testing.T) {
	if _, err := settings.Parse(nil); err != nil {
		t.Fatalf("nil block: %v", err)
	}
	s, err := settings.Parse(map[string]any{"allowed_hosts": []any{"app.example.test"}})
	if err != nil || len(s.AllowedHosts) != 1 {
		t.Fatalf("good block: %v %+v", err, s)
	}
	for name, raw := range map[string]any{
		"unknown key": map[string]any{"allowed_host": []any{}},
		"not a list":  map[string]any{"allowed_hosts": "a"},
		"empty entry": map[string]any{"allowed_hosts": []any{" "}},
	} {
		if _, err := settings.Parse(raw); err == nil || !strings.Contains(err.Error(), "gatecrasher") {
			t.Errorf("%s: want an error naming the block, got %v", name, err)
		}
	}
}

func TestParseApprovals(t *testing.T) {
	good := map[string]any{"approvals": map[string]any{
		"owner":     map[string]any{"principal": "usr_1", "sub": "owner"},
		"producers": map[string]any{"key:w": "warden"},
		"classes":   map[string]any{"approve.credentials": map[string]any{"agents": map[string]any{"key:a": "agt_a"}, "ceiling": map[string]any{"max_ttl_seconds": 60}, "shadow": true}},
	}}
	if s, err := settings.Parse(good); err != nil || !s.Approvals.Classes["approve.credentials"].Shadow {
		t.Fatalf("good: %v %+v", err, s)
	}
	for name, raw := range map[string]any{
		"half owner":    map[string]any{"owner": map[string]any{"principal": "usr_1"}},
		"bad class":     map[string]any{"classes": map[string]any{"credentials": map[string]any{}}},
		"empty source":  map[string]any{"producers": map[string]any{"key:w": ""}},
		"neg ceiling":   map[string]any{"classes": map[string]any{"approve.x": map[string]any{"ceiling": map[string]any{"max_ttl_seconds": -1}}}},
		"unknown field": map[string]any{"approver": 1},
	} {
		if _, err := settings.Parse(map[string]any{"approvals": raw}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
