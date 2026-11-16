package service

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/hollis-labs/libs/core/store"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/runtimecontract"
	"github.com/hollis-labs/libs/mesh/gatecrasher"
)

// Journal is a file-backed routing journal over the host's Substrate store.
// It never contains an independently writable human decision.
type Journal struct{ st *store.Store }

func NewJournal(st *store.Store) *Journal { return &Journal{st: st} }

var _ gatecrasher.Journal = (*Journal)(nil)

func encode(v any) (string, error) { b, err := json.Marshal(v); return string(b), err }
func same(a, b any) bool {
	x, err := encode(a)
	if err != nil {
		return false
	}
	y, err := encode(b)
	return err == nil && x == y
}
func detached[T any](v T) (T, error) {
	var out T
	b, err := json.Marshal(v)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}
func bindingKey(b runtimecontract.Binding) string { s, _ := encode(b); return s }
func logicalKey(b runtimecontract.Binding, id string) string {
	s, _ := encode([]string{string(b.OwnerID), string(b.OperativeID), string(b.ConversationID), id})
	return s
}
func loadRoute(ctx context.Context, q store.Querier, key string) (gatecrasher.Route, error) {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT route_json FROM routes WHERE route_key=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return gatecrasher.Route{}, gatecrasher.ErrNotFound
	}
	if err != nil {
		return gatecrasher.Route{}, err
	}
	var r gatecrasher.Route
	err = json.Unmarshal([]byte(raw), &r)
	return r, err
}
func (j *Journal) Reserve(ctx context.Context, intent gatecrasher.Route) (gatecrasher.Route, error) {
	var out gatecrasher.Route
	req, err := intent.Request.Snapshot()
	if err != nil {
		return out, err
	}
	if strings.TrimSpace(intent.OwnerRef) == "" || strings.TrimSpace(intent.CallerScope) == "" {
		return out, gate.ErrInvalid
	}
	digest, err := req.Digest()
	if err != nil {
		return out, err
	}
	err = j.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		old, e := loadRoute(ctx, tx, req.IdempotencyKey)
		if e == nil {
			d, _ := old.Request.Digest()
			if d != digest || old.OwnerRef != intent.OwnerRef || old.CallerScope != intent.CallerScope {
				return gatecrasher.ErrConflict
			}
			out = old
			return nil
		}
		if !errors.Is(e, gatecrasher.ErrNotFound) {
			return e
		}
		out = gatecrasher.Route{Version: 1, Request: req, OwnerRef: intent.OwnerRef, CallerScope: intent.CallerScope}
		raw, e := encode(out)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO routes(route_key,owner_ref,caller_scope,request_digest,version,binding_key,route_json) VALUES(?,?,?,?,?,?,?)`, req.IdempotencyKey, out.OwnerRef, out.CallerScope, digest.Value, out.Version, bindingKey(req.Binding), raw)
		return e
	})
	if err != nil {
		return gatecrasher.Route{}, err
	}
	return detached(out)
}
func (j *Journal) Load(ctx context.Context, key string) (gatecrasher.Route, error) {
	return loadRoute(ctx, j.st.Reader(), key)
}
func (j *Journal) Find(ctx context.Context, t gate.Ticket) (gatecrasher.Route, error) {
	if err := t.Validate(); err != nil {
		return gatecrasher.Route{}, err
	}
	raw, err := encode(t)
	if err != nil {
		return gatecrasher.Route{}, err
	}
	var key string
	err = j.st.Reader().QueryRowContext(ctx, `SELECT route_key FROM routes WHERE owner_ref=? AND ticket_json=?`, t.AuthorityRef, raw).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return gatecrasher.Route{}, gatecrasher.ErrNotFound
	}
	if err != nil {
		return gatecrasher.Route{}, err
	}
	return j.Load(ctx, key)
}
func (j *Journal) FindDecision(ctx context.Context, ref string, b runtimecontract.Binding) (gatecrasher.Route, error) {
	var key string
	err := j.st.Reader().QueryRowContext(ctx, `SELECT route_key FROM routes WHERE decision_ref=? AND binding_key=?`, ref, bindingKey(b)).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return gatecrasher.Route{}, gatecrasher.ErrNotFound
	}
	if err != nil {
		return gatecrasher.Route{}, err
	}
	return j.Load(ctx, key)
}
func (j *Journal) Swap(ctx context.Context, key string, version uint64, next gatecrasher.Route) (gatecrasher.Route, error) {
	var out gatecrasher.Route
	err := j.st.WriteTx(ctx, func(ctx context.Context, tx store.Tx) error {
		old, err := loadRoute(ctx, tx, key)
		if err != nil {
			return err
		}
		if old.Version != version {
			return gatecrasher.ErrCAS
		}
		d, err := next.Request.Digest()
		if err != nil {
			return err
		}
		od, _ := old.Request.Digest()
		if version == ^uint64(0) || next.Version != version || d != od || next.OwnerRef != old.OwnerRef || next.CallerScope != old.CallerScope || (old.Ticket != nil && !reflect.DeepEqual(old.Ticket, next.Ticket)) || (old.DecisionRef != "" && old.DecisionRef != next.DecisionRef) {
			return gatecrasher.ErrConflict
		}
		if next.Ticket != nil && (next.Ticket.Validate() != nil || next.Ticket.RequestDigest != d || next.Ticket.AuthorityRef != old.OwnerRef || next.Ticket.Binding != old.Request.Binding) {
			return gate.ErrBinding
		}
		if len(next.Executions) < len(old.Executions) || !slices.Equal(old.Executions, next.Executions[:len(old.Executions)]) {
			return gatecrasher.ErrConflict
		}
		if next.Attempts < old.Attempts {
			return gatecrasher.ErrConflict
		}
		if next.Delivery != nil {
			if err = next.Delivery.Validate(); err != nil {
				return err
			}
			if next.Ticket == nil || next.Delivery.DecisionRef != next.DecisionRef || next.Delivery.Binding != next.Request.Binding || next.Delivery.AdapterID != next.Request.Adapter.AdapterID || !next.Delivery.NativeRequestID.Equal(next.Request.NativeRequestID) {
				return gate.ErrBinding
			}
		}
		if old.Delivery != nil && (old.Delivery.Status == gate.DeliveryAcknowledged || old.Delivery.Status == gate.DeliveryRejected) && !reflect.DeepEqual(old.Delivery, next.Delivery) {
			return gatecrasher.ErrConflict
		}
		next.Version = version + 1
		raw, err := encode(next)
		if err != nil {
			return err
		}
		var ticket, ref any
		if next.Ticket != nil {
			ticket, err = encode(next.Ticket)
			if err != nil {
				return err
			}
		}
		if next.DecisionRef != "" {
			ref = next.DecisionRef
		}
		res, err := tx.ExecContext(ctx, `UPDATE routes SET version=?,ticket_json=?,decision_ref=?,route_json=? WHERE route_key=? AND version=?`, next.Version, ticket, ref, raw, key, version)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return gatecrasher.ErrCAS
		}
		appendObservation := func(kind string, v any) error {
			p, e := encode(v)
			if e != nil {
				return e
			}
			_, e = tx.ExecContext(ctx, `INSERT INTO observations(route_key,kind,payload,observed_at) VALUES(?,?,?,?)`, key, kind, p, time.Now().UTC().Format(time.RFC3339Nano))
			return e
		}
		if !reflect.DeepEqual(old.Delivery, next.Delivery) && next.Delivery != nil {
			if err := appendObservation("delivery", next.Delivery); err != nil {
				return err
			}
		}
		for _, p := range next.Executions[len(old.Executions):] {
			if err := p.Validate(); err != nil {
				return err
			}
			if p.DecisionRef != next.DecisionRef || p.Binding != next.Request.Binding || p.OperationID != next.Request.OperationID {
				return gate.ErrBinding
			}
			if err := appendObservation("execution", p); err != nil {
				return err
			}
		}
		out = next
		return nil
	})
	if err != nil {
		return gatecrasher.Route{}, err
	}
	return detached(out)
}
func (j *Journal) List(ctx context.Context, cursor string, limit int) ([]gatecrasher.Route, string, error) {
	if limit < 1 || limit > 1000 {
		return nil, "", gate.ErrInvalid
	}
	after := ""
	if cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || len(b) == 0 || len(b) > 200 {
			return nil, "", gate.ErrInvalid
		}
		after = string(b)
	}
	rows, err := j.st.Reader().QueryContext(ctx, `SELECT route_key,route_json FROM routes WHERE route_key>? ORDER BY route_key LIMIT ?`, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()
	var out []gatecrasher.Route
	var last string
	next := ""
	for rows.Next() {
		var key, raw string
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, "", err
		}
		if len(out) == limit {
			next = base64.RawURLEncoding.EncodeToString([]byte(last))
			break
		}
		var r gatecrasher.Route
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, "", err
		}
		out = append(out, r)
		last = key
	}
	return out, next, rows.Err()
}
