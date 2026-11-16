package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/hollis-labs/libs/harness/core/adapters/agentsessions"
	"github.com/hollis-labs/libs/harness/core/adapters/turn"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/core/runtimecontract"
	"github.com/hollis-labs/libs/mesh/gatecrasher"
)

type nativeGate struct {
	host    *Service
	ticket  *gate.Ticket
	request *gate.Request
}

func (g nativeGate) Capabilities(ctx context.Context, a gate.AdapterScope) (gate.Capabilities, error) {
	return g.host.coordinator.Capabilities(ctx, a)
}
func (g nativeGate) Request(ctx context.Context, r gate.Request) (gate.Ticket, error) {
	if err := g.host.registerNativeRequest(ctx, r); err != nil {
		return gate.Ticket{}, err
	}
	t, err := g.host.coordinator.Request(ctx, r)
	if err == nil {
		*g.ticket = t
		*g.request = r
	}
	return t, err
}
func (g nativeGate) Await(ctx context.Context, t gate.Ticket, w gate.WaitOptions) (gate.Resolution, error) {
	return g.host.coordinator.Await(ctx, t, w)
}
func (g nativeGate) Cancel(ctx context.Context, t gate.Ticket, c hitl.CancelCause) (gate.Resolution, error) {
	return g.host.coordinator.Cancel(ctx, t, c)
}

// ProviderResponder assembles the reviewed Codex adapter with this host's
// durable claims/fence. Resolve must join authoritative runtime operation facts;
// no display-only/provider-launch API is exposed by this host.
func (s *Service) ProviderResponder(resolve func(context.Context, agentsessions.JsonRpcServerRequest) (turn.CodexGateFacts, error)) func(context.Context, agentsessions.JsonRpcServerRequest) (any, *agentsessions.JsonRpcError) {
	return func(ctx context.Context, native agentsessions.JsonRpcServerRequest) (any, *agentsessions.JsonRpcError) {
		if resolve == nil || s.coordinator == nil {
			return nil, &agentsessions.JsonRpcError{Code: -32000, Message: "gate host unavailable"}
		}
		var t gate.Ticket
		var request gate.Request
		adapter := turn.CodexGateResponder{Gate: nativeGate{host: s, ticket: &t, request: &request}, Authority: s, Resolve: func(c context.Context, n agentsessions.JsonRpcServerRequest) (turn.CodexGateFacts, error) {
			facts, err := resolve(c, n)
			facts.Request.ExpiresAt = facts.Request.ExpiresAt.UTC()
			return facts, err
		}, Claim: s.Claim, WithFence: s.WithFence, Now: s.cfg.Now}
		result, rpcErr := adapter.Respond(ctx, native)
		if rpcErr != nil || t.Handle.ItemID == "" {
			return result, rpcErr
		}
		if _, err := s.st.ExecContext(ctx, `INSERT INTO provider_correlations(rpc_key,route_key) VALUES(?,?) ON CONFLICT(rpc_key) DO NOTHING`, nativeKey(native), request.IdempotencyKey); err != nil {
			return nil, &agentsessions.JsonRpcError{Code: -32000, Message: "gate correlation unavailable"}
		}

		var existing string
		if err := s.st.Reader().QueryRowContext(ctx, `SELECT route_key FROM provider_correlations WHERE rpc_key=?`, nativeKey(native)).Scan(&existing); err != nil || existing != request.IdempotencyKey {
			return nil, &agentsessions.JsonRpcError{Code: -32000, Message: "gate correlation conflict"}
		}

		// The runtime invokes this wrapper only AFTER serializing its writer. Do not
		// call the original admission callback here in the protocol-reader turn.
		return &agentsessions.JsonRpcPreparedReply{Deliver: func(c context.Context, send agentsessions.JsonRpcReplySender) error {
			unregister, err := s.origin.register(request, false, func(c context.Context, _ gate.Resolution) (gate.DeliveryStatus, error) {
				if prepared, ok := result.(*agentsessions.JsonRpcPreparedReply); ok {
					if prepared == nil || prepared.Deliver == nil {
						return gate.DeliveryUnknown, ErrRefused
					}
					err := prepared.Deliver(c, send)
					if err != nil {
						return gate.DeliveryUnknown, err
					}
					return gate.DeliverySent, nil
				}
				// A native cancellation/expiry is a refusal, not a grant. The captured
				// runtime sender still fences the exact original transport generation.
				if err := send(c, result, nil); err != nil {
					return gate.DeliveryUnknown, err
				}
				return gate.DeliverySent, nil
			})
			if err != nil {
				return err
			}
			defer unregister()
			p, err := s.coordinator.Deliver(c, t)
			if errors.Is(err, gatecrasher.ErrUnknown) && p.Status == gate.DeliverySent {
				return nil
			}
			return err
		}}, nil
	}
}

func nativeKey(n agentsessions.JsonRpcServerRequest) string {
	raw, _ := json.Marshal(n)
	return digest("native-rpc-v1", string(raw)).Value
}

// ObserveProviderReply persists a transport observation after the serialized
// callback. Sent never becomes native acknowledgement or execution success.
// A held/abandoned lease leaves the journal unknown and retains this observation
// for explicit reconciliation, rather than racing a receipt write or resending.
func (s *Service) ObserveProviderReply(ctx context.Context, n agentsessions.JsonRpcServerRequest, status agentsessions.JsonRpcReplyStatus) error {
	var key string
	if err := s.st.Reader().QueryRowContext(ctx, `SELECT route_key FROM provider_correlations WHERE rpc_key=?`, nativeKey(n)).Scan(&key); err != nil {
		return ErrRefused
	}
	route, err := s.Journal.Load(ctx, key)
	if err != nil {
		return err
	}
	raw, err := encode(struct {
		Binding  runtimecontract.Binding
		NativeID gate.NativeRequestID
		Status   agentsessions.JsonRpcReplyStatus
	}{n.Binding, gate.NativeRequestID(n.ID), status})
	if err != nil {
		return err
	}
	if _, err = s.st.ExecContext(ctx, `INSERT INTO observations(route_key,kind,payload,observed_at) VALUES(?,?,?,?)`, key, "provider-transport", raw, s.cfg.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if route.DecisionRef == "" {
		return nil
	}
	p := gate.DeliveryReceipt{DecisionRef: route.DecisionRef, Binding: n.Binding, AdapterID: route.Request.Adapter.AdapterID, NativeRequestID: gate.NativeRequestID(n.ID), Status: gate.DeliveryUnknown, EvidenceRef: "runtime-transport-observer"}
	switch status {
	case agentsessions.JsonRpcReplySent:
		p.Status = gate.DeliverySent
	case agentsessions.JsonRpcReplyUnknown:
	case agentsessions.JsonRpcReplyDiscarded:
		p.Status = gate.DeliveryRejected
	default:
		return gate.ErrUnsupported
	}
	err = s.coordinator.RecordDelivery(ctx, p)
	if errors.Is(err, gatecrasher.ErrBusy) {
		return nil
	}
	return err
}
