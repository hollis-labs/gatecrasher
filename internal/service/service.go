// Package service owns host policy, routing persistence and effect admission.
// HTTP/CLI adapters do not open databases or write human decisions.
package service

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hollis-labs/libs/core/store"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/runtimecontract"
	"github.com/hollis-labs/libs/mesh/gatecrasher"
	"golang.org/x/sys/unix"
)

var (
	ErrUnconfigured = errors.New("gatecrasher: host binding unavailable")
	ErrRefused      = errors.New("gatecrasher: authority refused")
	ErrClaimed      = errors.New("gatecrasher: operation already claimed; reconcile")
	ErrCleanup      = errors.New("gatecrasher: binding cleanup incomplete; reconcile")
)

const PolicyID = "operator-once-v1"

// Config contains trusted operator configuration, never values from API bodies.
// CallbackSubject is a separately provisioned Gatecrasher-issued service key
// identity for Tachyon. It is unrelated to the outbound Tachyon producer key.
type Config struct {
	OwnerRef        string
	CallerScope     string
	CallbackSubject string
	ActorMap        map[string]string // issuer-qualified actor -> canonical person
	Now             func() time.Time
}

type Service struct {
	st          *store.Store
	Journal     *Journal
	cfg         Config
	mu          sync.Mutex
	recipeMu    sync.Mutex // serialize binding enrollment, never held during SDK execution
	lock        *os.File
	ctx         context.Context
	stop        context.CancelFunc
	coordinator *gatecrasher.Coordinator
	owner       gatecrasher.InteractionPort
	origin      *DeliveryHub
}

// New takes exclusive local admission ownership. A crashed prior process loses
// its runtime attachments; reservations and uncertain claims remain consumed.
func New(ctx context.Context, st *store.Store, cfg Config) (*Service, error) {
	if st == nil || st.Config().Driver != store.DriverSQLite || cfg.OwnerRef == "" || cfg.CallerScope == "" || cfg.CallbackSubject == "" {
		return nil, ErrUnconfigured
	}
	path := st.Config().SQLite.Path
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil, ErrUnconfigured
	}
	clock := cfg.Now
	if clock == nil {
		clock = time.Now
	}
	// The existing HITL owner normalizes the outer request deadline to UTC.
	// Issue canonical host timestamps before sealing the immutable snapshot.
	cfg.Now = func() time.Time { return clock().UTC() }
	actors := map[string]string{}
	for k, v := range cfg.ActorMap {
		if k == "" || v == "" {
			return nil, ErrUnconfigured
		}
		actors[k] = v
	}
	cfg.ActorMap = actors
	var journal string
	var synchronous int
	if err := st.Reader().QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journal); err != nil {
		return nil, err
	}
	if err := st.DB().QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&synchronous); err != nil {
		return nil, err
	}
	if journal != "wal" || synchronous != 2 {
		return nil, errors.New("gatecrasher: SQLite WAL and FULL synchronous required")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	// #nosec G304 -- path is the trusted Substrate SQLite path, never request input.
	f, err := os.OpenFile(path+".admission.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- the OS-issued live descriptor fits the platform int used by flock.
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("gatecrasher: another host owns admission")
	}
	if err = st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		if _, e := tx.ExecContext(ctx, `UPDATE runtime_facts SET active=0`); e != nil {
			return e
		}
		// A former process's reserved/started work is uncertain. Append evidence;
		// never delete a reservation, release a claim or invent a completed effect.
		_, e := tx.ExecContext(ctx, `INSERT INTO effect_observations(claim_key,state,evidence,observed_at)
   SELECT c.claim_key,'unknown','host-restart:reconcile',? FROM operation_claims c
   LEFT JOIN effect_observations e ON e.seq=(SELECT MAX(last.seq) FROM effect_observations last WHERE last.claim_key=c.claim_key)
   WHERE e.state IS NULL OR e.state IN ('start_intent','started','callback_returned')`, cfg.Now().UTC().Format(time.RFC3339Nano))
		return e
	}); err != nil {
		_ = f.Close()
		return nil, err
	}
	life, stop := context.WithCancel(ctx)
	return &Service{st: st, Journal: NewJournal(st), cfg: cfg, lock: f, ctx: life, stop: stop}, nil
}
func (s *Service) Close() error {
	s.stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}
func (s *Service) alive() error {
	if s.ctx.Err() != nil {
		return ErrRefused
	}
	return nil
}

// RuntimeFacts are enrolled by trusted composition code. They are NOT accepted
// from a producer Request or callback, and do not provision an environment.
type RuntimeFacts struct {
	Binding     runtimecontract.Binding
	Environment runtimecontract.EnvironmentRef
	Requester   string // canonical requester/delegator from authenticated host facts
	Resources   []runtimecontract.Reference
	Policy      runtimecontract.Reference
}

func (s *Service) Enroll(ctx context.Context, f RuntimeFacts) error {
	if f.Binding.Validate() != nil || f.Environment.ValidateAt(s.cfg.Now(), []string{"tool.execute"}) != nil || f.Environment.Receipt.OwnerID != f.Binding.OwnerID || f.Requester == "" || f.Policy.ID != PolicyID || f.Policy.Validate() != nil || len(f.Resources) == 0 {
		return ErrRefused
	}
	for _, r := range f.Resources {
		if r.Validate() != nil || r.OwnerID != f.Binding.OwnerID {
			return ErrRefused
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.alive(); err != nil {
		return err
	}
	raw, err := encode(f)
	if err != nil {
		return err
	}
	return s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		var prev string
		err := tx.QueryRowContext(ctx, `SELECT facts_json FROM runtime_facts WHERE slot_key=?`, logicalKey(f.Binding, "")).Scan(&prev)
		if err == nil {
			var p RuntimeFacts
			if err = decode(prev, &p); err != nil {
				return err
			}
			if f.Binding.Generation <= p.Binding.Generation {
				return gate.ErrBinding
			}
		} else if !isNoRows(err) {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO runtime_facts(slot_key,facts_json,active) VALUES(?,?,1) ON CONFLICT(slot_key) DO UPDATE SET facts_json=excluded.facts_json,active=1`, logicalKey(f.Binding, ""), raw)
		return err
	})
}

// Revoke deactivates only this exact enrolled attempt under the admission fence.
// Cleanup needs no live environment authority; it cannot revive or replace facts.
func (s *Service) Revoke(ctx context.Context, b runtimecontract.Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b.Validate() != nil {
		return gate.ErrBinding
	}
	return s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		var raw string
		if err := tx.QueryRowContext(ctx, `SELECT facts_json FROM runtime_facts WHERE slot_key=?`, logicalKey(b, "")).Scan(&raw); err != nil {
			return err
		}
		var f RuntimeFacts
		if decode(raw, &f) != nil || f.Binding != b {
			return gate.ErrBinding
		}
		_, err := tx.ExecContext(ctx, `UPDATE runtime_facts SET active=0 WHERE slot_key=?`, logicalKey(b, ""))
		return err
	})
}
func (s *Service) facts(ctx context.Context, b runtimecontract.Binding) (RuntimeFacts, error) {
	if err := s.alive(); err != nil {
		return RuntimeFacts{}, err
	}
	var raw string
	var active int
	err := s.st.Reader().QueryRowContext(ctx, `SELECT facts_json,active FROM runtime_facts WHERE slot_key=?`, logicalKey(b, "")).Scan(&raw, &active)
	if err != nil {
		return RuntimeFacts{}, ErrRefused
	}
	var f RuntimeFacts
	if decode(raw, &f) != nil || active != 1 || f.Binding != b || f.Environment.ValidateAt(s.cfg.Now(), nil) != nil {
		return RuntimeFacts{}, ErrRefused
	}
	return f, nil
}
func (s *Service) WithFence(ctx context.Context, r gate.Request, d gate.Decision, action func(context.Context) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.Verify(ctx, r, d); err != nil {
		return err
	}
	facts, err := s.facts(ctx, r.Binding)
	if err != nil {
		return err
	}
	deadline := r.ExpiresAt
	if facts.Environment.ExpiresAt.Before(deadline) {
		deadline = facts.Environment.ExpiresAt
	}
	if d.ExpiresAt.Before(deadline) {
		deadline = d.ExpiresAt
	}
	if d.Scope.ExpiresAt.Before(deadline) {
		deadline = d.Scope.ExpiresAt
	}
	c, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	if c.Err() != nil {
		return context.Cause(c)
	}
	return action(c)
}

// RecoverRoutes recovers only pinned-owner enqueue/mapping windows. It never
// reconstructs a runtime sender, restarts a run or replays an uncertain effect.
func (s *Service) RecoverRoutes(ctx context.Context, cursor string, limit int) ([]gate.Ticket, string, error) {
	if s.coordinator == nil {
		return nil, "", ErrUnconfigured
	}
	return s.coordinator.Recover(ctx, cursor, limit)
}
