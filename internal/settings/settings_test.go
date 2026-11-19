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

func TestParseFanoutAndTrust(t *testing.T) {
	good := map[string]any{
		"approvals": map[string]any{
			"owner":          map[string]any{"principal": "usr_1", "sub": "owner"},
			"classes":        map[string]any{"approve.credentials": map[string]any{}},
			"intake_origins": map[string]any{"warden": []any{"https://warden.example", "http://127.0.0.1:9000"}},
			"webhooks": []any{
				map[string]any{"name": "basalisk", "url": "http://127.0.0.1:8085/hooks/gate", "secret_file": "basalisk.key", "view": "owner"}, //nolint:gosec // a file name, not a credential
				map[string]any{"name": "bot", "url": "https://bot.example/hook", "secret_file": "bot.key", "view": "approve.credentials"},
			},
		},
		"auth": map[string]any{"trust": "warden", "warden": map[string]any{"issuer": "warden", "jwks_url": "https://warden.example/.well-known/jwks.json"}},
	}
	s, err := settings.Parse(good)
	if err != nil || s.Auth.Trust != settings.TrustWarden || len(s.Approvals.Webhooks) != 2 || !s.ApprovalsConfigured() || s.TachyonConfigured() {
		t.Fatalf("good: %v %+v", err, s)
	}
	hook := func(m map[string]any) map[string]any {
		return map[string]any{"approvals": map[string]any{"classes": map[string]any{"approve.credentials": map[string]any{}}, "webhooks": []any{m}}}
	}
	for name, raw := range map[string]any{
		"http hook":        hook(map[string]any{"name": "a", "url": "http://hooks.example/x", "secret_file": "k", "view": "owner"}),
		"no secret":        hook(map[string]any{"name": "a", "url": "https://hooks.example/x", "view": "owner"}),
		"unknown view":     hook(map[string]any{"name": "a", "url": "https://hooks.example/x", "secret_file": "k", "view": "approve.other"}),
		"userinfo":         hook(map[string]any{"name": "a", "url": "https://u:p@hooks.example/x", "secret_file": "k", "view": "owner"}), //nolint:gosec // the refused case
		"origin with path": map[string]any{"approvals": map[string]any{"intake_origins": map[string]any{"warden": []any{"https://warden.example/intake"}}}},
		"origin http":      map[string]any{"approvals": map[string]any{"intake_origins": map[string]any{"warden": []any{"http://warden.example"}}}},
		"bad trust":        map[string]any{"auth": map[string]any{"trust": "everyone"}},
		"warden no keys":   map[string]any{"auth": map[string]any{"trust": "warden", "warden": map[string]any{"issuer": "warden"}}},
		"warden no iss":    map[string]any{"auth": map[string]any{"trust": "warden", "warden": map[string]any{"jwks_url": "https://warden.example/jwks"}}},
		"warden http jwks": map[string]any{"auth": map[string]any{"trust": "warden", "warden": map[string]any{"issuer": "w", "jwks_url": "http://warden.example/jwks"}}},
	} {
		if _, err := settings.Parse(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if s, err := settings.Parse(map[string]any{"tachyon_url": "https://t.example"}); err != nil || !s.TachyonConfigured() {
		t.Fatalf("tachyon configured: %v", err)
	}
}
