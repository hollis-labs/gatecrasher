package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startServe boots the serve module set with config (YAML for the XDG config file) and
// runs serve. It returns the bound address, or the error serve stopped with.
func startServe(t *testing.T, config string) (string, string, error) {
	t.Helper()
	t.Setenv("SUBSTRATE_CONFIG", "")
	configHome := t.TempDir()
	data := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv(dataDirEnv, data)
	dir := filepath.Join(configHome, substrateApp)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("httphost: {addr: \"127.0.0.1:0\"}\n"+config), 0o600); err != nil {
		t.Fatal(err)
	}
	restore, err := useConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	started, err := start(t.Context(), plan([]string{"serve"}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	addr := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- serve(ctx, started.App, func(a net.Addr) { addr <- a.String() }) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = started.Stop(context.Background())
	})
	select {
	case a := <-addr:
		return a, data, nil
	case err = <-done:
		done <- err
		return "", data, err
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not start")
	}
	return "", data, nil
}

// Approvals run on their own, without the Tachyon binding, and only then is the decision
// key created.
func TestServeApprovalsWithoutTachyon(t *testing.T) {
	addr, data, err := startServe(t, "gatecrasher:\n  allowed_hosts: [\"127.0.0.1\"]\n  approvals:\n    owner: {principal: usr_owner, sub: chrispian}\n")
	if err != nil {
		t.Fatalf("serve refused approvals-only config: %v", err)
	}
	res, err := http.Get("http://" + addr + "/api/gate/v1/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("jwks without a credential: %d", res.StatusCode)
	}
	if _, err = os.Stat(filepath.Join(data, "decision-signing.key")); err != nil {
		t.Fatalf("decision key not created: %v", err)
	}
}

func TestServeRefusesNothingConfigured(t *testing.T) {
	_, data, err := startServe(t, "gatecrasher:\n  allowed_hosts: [\"127.0.0.1\"]\n")
	if err == nil || !strings.Contains(err.Error(), "nothing to serve") {
		t.Fatalf("want nothing to serve, got %v", err)
	}
	if _, err = os.Stat(filepath.Join(data, "decision-signing.key")); !os.IsNotExist(err) {
		t.Fatalf("decision key created without approvals: %v", err)
	}
}
