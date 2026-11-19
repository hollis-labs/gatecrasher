package approvals

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hollis-labs/libs/core/store"

	"github.com/hollis-labs/gatecrasher/internal/settings"
	"github.com/hollis-labs/gatecrasher/pkg/approvalapi"
)

// Webhook delivery timing.
const (
	webhookIdle    = 30 * time.Second
	webhookTimeout = 10 * time.Second
	webhookMaxWait = time.Minute
	minWebhookKey  = 32
)

// Subscriber is one configured webhook with its key loaded.
type Subscriber struct {
	cfg    settings.Webhook
	secret []byte
	view   viewer
}

// Webhooks loads the configured subscribers' keys. A key file readable by group or
// others, or shorter than 32 bytes, is refused.
func (s *Service) Webhooks(dataDir string) ([]Subscriber, error) {
	var out []Subscriber
	for _, w := range s.cfg.Webhooks {
		path := w.SecretFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(dataDir, path)
		}
		fi, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("approvals: webhook %s: %w", w.Name, err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("approvals: webhook %s key must not be readable by others", w.Name)
		}
		// #nosec G304 -- path is operator configuration, never request input.
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		b = bytes.TrimSpace(b)
		if len(b) < minWebhookKey {
			return nil, fmt.Errorf("approvals: webhook %s key must be at least 32 bytes", w.Name)
		}
		v := viewer{all: w.View == "owner"}
		if !v.all {
			v.classes = []string{w.View}
		}
		out = append(out, Subscriber{cfg: w, secret: b, view: v})
	}
	return out, nil
}

// RunWebhooks delivers the event log to every subscriber until ctx ends: at least once,
// in order, resuming from a stored cursor, retrying with backoff. A subscriber that is
// new starts at the current end of the log.
func (s *Service) RunWebhooks(ctx context.Context, subs []Subscriber, client *http.Client, errs func(string, error)) {
	if client == nil {
		client = &http.Client{Timeout: webhookTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	done := make(chan struct{}, len(subs))
	for _, sub := range subs {
		go func() {
			defer func() { done <- struct{}{} }()
			s.runWebhook(ctx, sub, client, errs)
		}()
	}
	for range subs {
		<-done
	}
}

func (s *Service) runWebhook(ctx context.Context, sub Subscriber, client *http.Client, errs func(string, error)) {
	backoff := time.Second
	for ctx.Err() == nil {
		wake := s.Changed()
		sent, err := s.deliverOnce(ctx, sub, client)
		if err != nil {
			if errs != nil && ctx.Err() == nil {
				errs(sub.cfg.Name, err)
			}
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, webhookMaxWait)
			continue
		}
		backoff = time.Second
		if sent {
			continue
		}
		t := time.NewTimer(webhookIdle)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-wake:
		case <-t.C:
		}
		t.Stop()
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// DeliverOnce sends one batch to sub when there is one, and reports whether it sent.
func (s *Service) DeliverOnce(ctx context.Context, sub Subscriber, client *http.Client) (bool, error) {
	return s.deliverOnce(ctx, sub, client)
}

func (s *Service) deliverOnce(ctx context.Context, sub Subscriber, client *http.Client) (bool, error) {
	cursor, err := s.cursor(ctx, sub.cfg.Name)
	if err != nil {
		return false, err
	}
	events, scanned, err := s.feed(ctx, sub.view, cursor)
	if err != nil {
		return false, err
	}
	if len(events) == 0 {
		// Skip what this subscriber may not see, so the next read starts later.
		if scanned > cursor {
			return false, s.setCursor(ctx, sub.cfg.Name, scanned)
		}
		return false, nil
	}
	body, err := json.Marshal(approvalapi.WebhookDelivery{Subscriber: sub.cfg.Name, Events: events})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(approvalapi.HeaderWebhookName, sub.cfg.Name)
	req.Header.Set(approvalapi.HeaderWebhookSignature, approvalapi.SignWebhook(sub.secret, body, s.now()))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	_ = res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return false, fmt.Errorf("webhook answered %d", res.StatusCode)
	}
	return true, s.setCursor(ctx, sub.cfg.Name, events[len(events)-1].Seq)
}

// cursor is the last seq delivered to name; a new subscriber starts at the end of the log.
func (s *Service) cursor(ctx context.Context, name string) (int64, error) {
	var seq int64
	err := s.st.Reader().QueryRowContext(ctx, `SELECT seq FROM webhook_cursors WHERE name=?`, name).Scan(&seq)
	if err == nil {
		return seq, nil
	}
	if !errNoRow(err) {
		return 0, err
	}
	if err = s.st.Reader().QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0) FROM approval_events`).Scan(&seq); err != nil {
		return 0, err
	}
	return seq, s.setCursor(ctx, name, seq)
}

func (s *Service) setCursor(ctx context.Context, name string, seq int64) error {
	return s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO webhook_cursors(name, seq, updated_at) VALUES(?,?,?)
 ON CONFLICT(name) DO UPDATE SET seq=excluded.seq, updated_at=excluded.updated_at WHERE excluded.seq > webhook_cursors.seq`, name, seq, s.now().Format(ts))
		return err
	})
}

func errNoRow(err error) bool { return errors.Is(err, sql.ErrNoRows) }
