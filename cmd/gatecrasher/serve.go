package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"path/filepath"

	"github.com/spf13/cobra"

	libauth "github.com/hollis-labs/libs/security/auth"
	"github.com/hollis-labs/substrate/module"
	"github.com/hollis-labs/substrate/modules/auth"
	"github.com/hollis-labs/substrate/modules/database"
	"github.com/hollis-labs/substrate/modules/httphost"
	"github.com/hollis-labs/substrate/modules/identity"

	"github.com/hollis-labs/gatecrasher/internal/api"
	"github.com/hollis-labs/gatecrasher/internal/approvals"
	"github.com/hollis-labs/gatecrasher/internal/hostguard"
	"github.com/hollis-labs/gatecrasher/internal/service"
	"github.com/hollis-labs/gatecrasher/internal/settings"
	"github.com/hollis-labs/gatecrasher/internal/tachyon"
)

func serveCmd(ctx context.Context, app *module.App) *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use: "serve", Short: "Serve the API and the UI", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if addr != "" {
				cfg, _ := app.Config["httphost"].(map[string]any)
				if cfg == nil {
					cfg = map[string]any{}
					app.Config["httphost"] = cfg
				}
				cfg["addr"] = addr
			}
			return serve(ctx, app, nil)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "", "Listener address (overrides httphost.addr)")
	cmd.Flags().Bool("managed", false, "Supervised run; class 1 auth is always enforced")
	return cmd
}

// serve runs the HTTP host until ctx ends. ready, when set, learns the bound address.
func serve(ctx context.Context, app *module.App, ready func(net.Addr)) error {
	if guard := auth.Guard(app); guard == nil || string(guard.Mode()) != "enforce" {
		return errors.New("class 1 applications require enforced auth")
	}
	id := identity.From(app)
	if id == nil {
		return errors.New("the identity module must be started")
	}
	st := database.From(app)
	if st == nil {
		return errors.New("the database module must be started")
	}
	cfg, err := settings.Parse(app.Config[settings.Key])
	if err != nil {
		return err
	}
	api.RegisterScopes(auth.ScopeTable(app))
	if !cfg.TachyonConfigured() && !cfg.ApprovalsConfigured() {
		return errors.New("gatecrasher: nothing to serve: configure gatecrasher.approvals.owner, the Tachyon binding, or both")
	}
	h := api.New(nil, id)
	// The Tachyon response binding is optional: without it Gatecrasher serves approvals only.
	if cfg.TachyonConfigured() {
		owner, terr := tachyon.New(tachyon.Config{BaseURL: cfg.TachyonURL, TokenFile: cfg.ProducerTokenFile, CallerScope: cfg.CallerScope})
		if terr != nil {
			return terr
		}
		host, terr := service.New(ctx, st, service.Config{OwnerRef: cfg.OwnerRef, CallerScope: cfg.CallerScope, CallbackSubject: cfg.CallbackSubject, ActorMap: cfg.ActorMap})
		if terr != nil {
			return terr
		}
		defer func() { _ = host.Close() }()
		if terr = host.Wire(owner); terr != nil {
			return terr
		}
		h = api.New(host, id, service.RecipeRunner{Host: host})
	}
	// The inbox (and its decision key) exists only when approvals are configured;
	// otherwise its routes answer 503.
	if cfg.ApprovalsConfigured() {
		dataDir := filepath.Dir(st.Config().SQLite.Path)
		inbox, aerr := approvals.New(st, approvals.Config{Settings: cfg.Approvals, DataDir: dataDir})
		if aerr != nil {
			return aerr
		}
		subs, aerr := inbox.Webhooks(dataDir)
		if aerr != nil {
			return aerr
		}
		go inbox.Run(ctx, func(err error) { slog.Warn("approvals: sweep failed", "err", err) })
		go inbox.RunWebhooks(ctx, subs, nil, func(name string, err error) {
			slog.Warn("approvals: webhook delivery failed", "webhook", name, "err", err)
		})
		h.WithApprovals(inbox)
	}
	if cfg.Auth.Trust == settings.TrustWarden {
		w := cfg.Auth.Warden
		jv, jerr := libauth.NewJWTVerifier(libauth.JWTConfig{Issuer: w.Issuer, Audience: "gatecrasher", JWKSURL: w.JWKSURL, BootstrapKeyFile: w.BootstrapKeyFile})
		if jerr != nil {
			return jerr
		}
		go jv.Run(ctx)
		trusted := api.WardenVerifier(jv)
		// The outer guard must accept Warden's tokens too; the routes reverify them.
		if jerr = auth.AddVerifier(app, trusted); jerr != nil {
			return jerr
		}
		h.WithTrusted(trusted)
	}
	handler, err := httphost.Handler(app, httphost.Options{
		Routes: h.Mux(),
	})
	if err != nil {
		return err
	}
	// Outermost first: the Host check (DNS rebinding) and forwarding-header hygiene, then the
	// session cookie becomes the bearer the guard verifies, then the host (guard, routes, SPA).
	handler = hostguard.Handler(cfg.AllowedHosts, id.Middleware(handler))
	return httphost.Serve(ctx, app, handler, httphost.ServeOptions{
		Ready: func(addr net.Addr) {
			slog.Info("gatecrasher listening", "addr", addr.String())
			if ready != nil {
				ready(addr)
			}
		},
	})
}
