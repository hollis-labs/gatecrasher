package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/hollis-labs/libs/agent/sdk"
	"github.com/hollis-labs/libs/core/store"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/runtimecontract"
)

func decode(raw string, v any) error { return json.Unmarshal([]byte(raw), v) }
func isNoRows(err error) bool        { return errors.Is(err, sql.ErrNoRows) }
func (s *Service) VerifyEnvironment(ctx context.Context, b runtimecontract.Binding, e runtimecontract.EnvironmentRef, required []string) error {
	f, err := s.facts(ctx, b)
	if err != nil {
		return err
	}
	if !same(f.Environment, e) {
		return gate.ErrBinding
	}
	return e.ValidateAt(s.cfg.Now(), required)
}

type Environment struct{ Host *Service }

func (e Environment) Verify(ctx context.Context, b runtimecontract.Binding, r runtimecontract.EnvironmentRef, c []string) error {
	return e.Host.VerifyEnvironment(ctx, b, r, c)
}

func (s *Service) ReserveRun(ctx context.Context, r sdk.RunReservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.RunID == "" || r.DefinitionDigest != RecipeDefinitionDigest() || r.InputDigest.Validate() != nil || r.InputDigest.DescriptorVersion == "" || r.Route == "" || r.Model == "" {
		return ErrRefused
	}
	if err := s.VerifyEnvironment(ctx, r.Binding, r.Environment, nil); err != nil {
		return err
	}
	raw, err := encode(r)
	if err != nil {
		return err
	}
	return s.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO run_reservations(logical_key,reservation_json,reserved_at) VALUES(?,?,?) ON CONFLICT(logical_key) DO NOTHING`, logicalKey(r.Binding, r.RunID), raw, s.cfg.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return sdk.ErrRunUsed
		}
		return nil
	})
}
func (s *Service) reservation(ctx context.Context, r sdk.RunReservation) error {
	var raw string
	if err := s.st.Reader().QueryRowContext(ctx, `SELECT reservation_json FROM run_reservations WHERE logical_key=?`, logicalKey(r.Binding, r.RunID)).Scan(&raw); err != nil {
		return ErrRefused
	}
	var old sdk.RunReservation
	if decode(raw, &old) != nil || !same(old, r) {
		return ErrRefused
	}
	return nil
}

// Claim is the provider's one-use claim. It does not execute, send, or release
// uncertain work. Call only inside WithFence at the serialized physical boundary.
func (s *Service) Claim(ctx context.Context, r gate.Request, d gate.Decision) error {
	if err := gate.ValidateAdmission(ctx, r, d, gate.Admission{Binding: r.Binding, Adapter: r.Adapter, EnforcementPoint: r.EnforcementPoint, OperationDigest: r.OperationDigest, Now: s.cfg.Now()}, s); err != nil {
		return err
	}
	raw, err := encode(struct {
		Request  gate.Request
		Decision gate.Decision
	}{r, d})
	if err != nil {
		return err
	}
	key := logicalKey(r.Binding, d.Resolution.ResolutionID+"/"+r.OperationID)
	return s.claim(ctx, key, r.Binding, raw)
}
func (s *Service) claim(ctx context.Context, key string, b runtimecontract.Binding, raw string) error {
	res, err := s.st.ExecContext(ctx, `INSERT INTO operation_claims(claim_key,binding_key,descriptor_json,claimed_at) VALUES(?,?,?,?) ON CONFLICT(claim_key) DO NOTHING`, key, bindingKey(b), raw, s.cfg.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrClaimed
	}
	return nil
}
func (s *Service) Admit(ctx context.Context, a sdk.Admission, start func(context.Context) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if start == nil || a.Binding != a.Run.Binding || a.DefinitionDigest != a.Run.DefinitionDigest || !same(a.Environment, a.Run.Environment) {
		return ErrRefused
	}
	if err := s.reservation(ctx, a.Run); err != nil {
		return err
	}
	if err := s.VerifyEnvironment(ctx, a.Binding, a.Environment, nil); err != nil {
		return err
	}
	if a.Kind == "model" && a.Route != a.Run.Route {
		return ErrRefused
	}
	if a.Kind != "model" && a.Kind != "tool" {
		return gate.ErrUnsupported
	}
	var claim string
	if a.Kind == "tool" {
		if a.Operation == nil || a.Policy == nil || a.Request == nil || a.Decision == nil {
			return ErrRefused
		}
		if a.Operation.Binding != a.Binding || a.Operation.RunID != a.Run.RunID || a.Operation.InputDigest != a.Run.InputDigest || a.Operation.DefinitionDigest != a.Run.DefinitionDigest {
			return ErrRefused
		}
		d, err := a.Operation.Digest()
		if err != nil || d != a.Request.OperationDigest || a.Request.OperationID != a.Operation.ID || a.Request.Binding != a.Binding {
			return ErrRefused
		}
		if err := s.checkOperation(ctx, *a.Operation); err != nil {
			return err
		}
		if err := s.checkIntent(ctx, *a.Request, a.Policy.Decision); err != nil {
			return err
		}
		if err := s.Claim(ctx, *a.Request, *a.Decision); err != nil {
			return err
		}
		claim = logicalKey(a.Binding, a.Decision.Resolution.ResolutionID+"/"+a.Request.OperationID)
	}
	bounded, cancel := context.WithDeadline(ctx, a.Environment.ExpiresAt)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	if a.Request != nil {
		deadline := a.Decision.ExpiresAt
		if a.Decision.Scope.ExpiresAt.Before(deadline) {
			deadline = a.Decision.Scope.ExpiresAt
		}
		var c context.CancelFunc
		bounded, c = context.WithDeadline(bounded, deadline)
		defer c()
		if err := s.Verify(ctx, *a.Request, *a.Decision); err != nil {
			return err
		}
	}
	if bounded.Err() != nil {
		return context.Cause(bounded)
	}
	if claim != "" {
		if err := s.effect(ctx, claim, "start_intent", ""); err != nil {
			return err
		}
	}
	// Persisted start intent is not proof a callback began. Revalidate after
	// the claim/intent commits and immediately before invoking it; failed or
	// uncertain claims are deliberately retained.
	if err := s.VerifyEnvironment(bounded, a.Binding, a.Environment, nil); err != nil {
		return err
	}
	if a.Request != nil {
		if err := s.Verify(bounded, *a.Request, *a.Decision); err != nil {
			return err
		}
	}
	if bounded.Err() != nil {
		return context.Cause(bounded)
	}
	result := invokeEffect(bounded, start)
	if claim != "" {
		state := "callback_returned"
		if result != nil {
			state = "unknown"
		}
		reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		result = errors.Join(result, s.effect(reportCtx, claim, state, "host-callback-return"))
	}
	return result
}
func invokeEffect(ctx context.Context, fn func(context.Context) error) (err error) {
	defer func() {
		if recover() != nil {
			err = sdk.ErrEffectPanic
		}
	}()
	return fn(ctx)
}
func (s *Service) effect(ctx context.Context, key, state, evidence string) error {
	_, err := s.st.ExecContext(ctx, `INSERT INTO effect_observations(claim_key,state,evidence,observed_at) VALUES(?,?,?,?)`, key, state, evidence, s.cfg.Now().UTC().Format(time.RFC3339Nano))
	return err
}
