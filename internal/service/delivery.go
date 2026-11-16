package service

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/hollis-labs/libs/harness/core/adapters/runtimeevents"

	"github.com/hollis-labs/libs/agent/sdk"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/gatecrasher"
)

var CodexScope = gate.AdapterScope{AdapterID: "codex", Protocol: "app-server-v2", LaunchMode: "on-request"}

type receiver struct {
	mu        sync.Mutex
	request   gate.Request
	send      func(context.Context, gate.Resolution) (gate.DeliveryStatus, error)
	attempted bool
	closed    bool
	sdk       bool
}

// DeliveryHub retains only live, exact request callbacks. Durable historical
// observations are in SQLite; callbacks are never reconstructed after restart.
type DeliveryHub struct {
	host      *Service
	mu        sync.Mutex
	receivers map[string]*receiver
}

func newDeliveryHub(s *Service) *DeliveryHub {
	return &DeliveryHub{host: s, receivers: map[string]*receiver{}}
}
func (h *DeliveryHub) register(r gate.Request, sdkReceiver bool, send func(context.Context, gate.Resolution) (gate.DeliveryStatus, error)) (func(), error) {
	d, err := r.Digest()
	if err != nil {
		return nil, err
	}
	snapshot, err := r.Snapshot()
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.receivers[d.Value]; ok {
		return nil, gatecrasher.ErrBusy
	}
	entry := &receiver{request: snapshot, send: send, sdk: sdkReceiver}
	h.receivers[d.Value] = entry
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.receivers[d.Value] == entry {
			entry.mu.Lock()
			entry.closed = true
			entry.mu.Unlock()
			delete(h.receivers, d.Value)
		}
	}, nil
}
func (h *DeliveryHub) receiver(r gate.Request) *receiver {
	d, _ := r.Digest()
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.receivers[d.Value]
}
func (h *DeliveryHub) Capabilities(_ context.Context, a gate.AdapterScope) (gate.Capabilities, error) {
	classes := []string{"tool"}
	if a == CodexScope {
		classes = []string{"command", "mcp_tool_call"}
	} else if a != sdk.NativeAdapterScope() {
		return gate.Capabilities{}, gate.ErrUnsupported
	}
	return gate.Capabilities{Adapter: a, OperationClasses: classes, DecisionKinds: []gate.DecisionKind{gate.Allow, gate.Deny, gate.Cancel}, ScopeKinds: []gate.ScopeKind{gate.Once}, ObligationKinds: []string{"approval"}}, nil
}
func (h *DeliveryHub) Validate(ctx context.Context, r gate.Request) error {
	return h.host.checkRequest(ctx, r)
}
func deliveryReceipt(r gate.Request, res gate.Resolution, status gate.DeliveryStatus) gate.DeliveryReceipt {
	ref := ""
	if res.Decision != nil {
		ref = res.Decision.Resolution.ResolutionID
	} else if res.Outcome != nil {
		ref = res.Ticket.AuthorityRef + "/" + res.Ticket.Handle.ItemID + "/" + strconv.FormatInt(res.Outcome.OutcomeRevision(), 10)
	}
	return gate.DeliveryReceipt{DecisionRef: ref, Binding: r.Binding, AdapterID: r.Adapter.AdapterID, NativeRequestID: r.NativeRequestID, Status: status}
}
func (h *DeliveryHub) Send(ctx context.Context, r gate.Request, res gate.Resolution) (gate.DeliveryReceipt, error) {
	entry := h.receiver(r)
	if entry == nil {
		return gate.DeliveryReceipt{}, gatecrasher.ErrUnknown
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.closed || entry.attempted {
		return gate.DeliveryReceipt{}, gatecrasher.ErrUnknown
	}
	entry.attempted = true
	var status gate.DeliveryStatus
	send := func(c context.Context) error { var err error; status, err = entry.send(c, res); return err }
	var err error
	if entry.sdk && res.Decision != nil {
		err = h.host.WithFence(ctx, r, *res.Decision, send)
	} else {
		err = send(ctx)
	}
	if err != nil {
		return gate.DeliveryReceipt{}, err
	}
	p := deliveryReceipt(r, res, status)
	if status == gate.DeliveryAcknowledged {
		// This is actual synchronous SDK adapter acceptance, not a transport write.
		// Persist evidence AFTER acceptance. Any write ambiguity remains unknown.
		p.EvidenceRef = "sdk-adapter-accepted:" + p.DecisionRef
		raw, e := encode(p)
		if e != nil {
			return gate.DeliveryReceipt{}, e
		}
		_, e = h.host.st.ExecContext(ctx, `INSERT INTO observations(route_key,kind,payload,observed_at) VALUES(?,?,?,?)`, r.IdempotencyKey, "native-accepted", raw, h.host.cfg.Now().UTC().Format(time.RFC3339Nano))
		if e != nil {
			return gate.DeliveryReceipt{}, e
		}
	}
	return p, nil
}
func (h *DeliveryHub) Reconcile(ctx context.Context, r gate.Request, res gate.Resolution) (gate.DeliveryReceipt, error) {
	var raw string
	err := h.host.st.Reader().QueryRowContext(ctx, `SELECT payload FROM observations WHERE route_key=? AND kind='native-accepted' ORDER BY seq DESC LIMIT 1`, r.IdempotencyKey).Scan(&raw)
	if err == nil {
		var p gate.DeliveryReceipt
		if decode(raw, &p) != nil {
			return gate.DeliveryReceipt{}, ErrRefused
		}
		expected := deliveryReceipt(r, res, gate.DeliveryAcknowledged)
		if p.Validate() != nil || p.DecisionRef != expected.DecisionRef || p.Binding != r.Binding || !p.NativeRequestID.Equal(r.NativeRequestID) || p.AdapterID != r.Adapter.AdapterID {
			return gate.DeliveryReceipt{}, gate.ErrBinding
		}
		return p, nil
	}
	if !isNoRows(err) {
		return gate.DeliveryReceipt{}, err
	}
	p := deliveryReceipt(r, res, gate.DeliveryUnknown)
	// A live SDK adapter that has never attempted acceptance is affirmative
	// negative evidence. A provider transport or absent/restarted adapter is not.
	if entry := h.receiver(r); entry != nil && entry.sdk {
		entry.mu.Lock()
		defer entry.mu.Unlock()
		if !entry.closed && !entry.attempted && h.Validate(ctx, r) == nil {
			p.Status = gate.DeliveryPending
			p.EvidenceRef = "same-live-sdk-receiver:never-attempted"
		}
	}
	return p, nil
}

type SDKGate struct{ Host *Service }

var _ gate.GatePort = SDKGate{}

func (g SDKGate) Capabilities(ctx context.Context, a gate.AdapterScope) (gate.Capabilities, error) {
	return g.Host.coordinator.Capabilities(ctx, a)
}
func (g SDKGate) Request(ctx context.Context, r gate.Request) (gate.Ticket, error) {
	return g.Host.coordinator.Request(ctx, r)
}
func (g SDKGate) Cancel(ctx context.Context, t gate.Ticket, cause hitl.CancelCause) (gate.Resolution, error) {
	return g.Host.coordinator.Cancel(ctx, t, cause)
}
func (g SDKGate) Await(ctx context.Context, t gate.Ticket, w gate.WaitOptions) (gate.Resolution, error) {
	result, err := g.Host.coordinator.Await(ctx, t, w)
	if err != nil || result.State == gate.Pending {
		return result, err
	}
	route, err := g.Host.Journal.Find(ctx, t)
	if err != nil {
		return gate.Resolution{}, err
	}
	accepted := make(chan gate.Resolution, 1)
	unregister, err := g.Host.origin.register(route.Request, true, func(c context.Context, res gate.Resolution) (gate.DeliveryStatus, error) {
		if c.Err() != nil || res.Ticket != t || res.Validate() != nil {
			return gate.DeliveryUnknown, ErrRefused
		}
		snapshot, snapshotErr := detached(res)
		if snapshotErr != nil {
			return gate.DeliveryUnknown, snapshotErr
		}
		select {
		case accepted <- snapshot:
			return gate.DeliveryAcknowledged, nil
		default:
			return gate.DeliveryUnknown, ErrRefused
		}
	})
	if err != nil {
		return gate.Resolution{}, err
	}
	defer unregister()
	p, err := g.Host.coordinator.Deliver(ctx, t)
	if err != nil {
		return gate.Resolution{}, err
	}
	if p.Status != gate.DeliveryAcknowledged {
		return gate.Resolution{}, gatecrasher.ErrUnknown
	}
	select {
	case snapshot := <-accepted:
		return snapshot, nil
	default:
		return gate.Resolution{}, gatecrasher.ErrUnknown
	}
}
func (s *Service) RecordExecution(ctx context.Context, p gate.ExecutionReceipt) error {
	if s.coordinator == nil {
		return ErrUnconfigured
	}
	return s.coordinator.RecordExecution(ctx, p)
}
func (s *Service) Write(ctx context.Context, e runtimeevents.Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	raw, err := encode(e)
	if err != nil {
		return err
	}
	_, err = s.st.ExecContext(ctx, `INSERT INTO host_events(event_json) VALUES(?)`, raw)
	if err != nil {
		return err
	}
	if e.Kind != runtimeevents.KindAgentToolResult {
		return nil
	}
	var payload sdk.EventPayload
	if json.Unmarshal(e.Payload, &payload) != nil {
		return ErrRefused
	}
	if payload.DecisionID == "" {
		return nil
	}
	if err = s.RecordExecution(ctx, gate.ExecutionReceipt{DecisionRef: payload.DecisionID, OperationID: payload.OperationID, Binding: payload.Binding, State: payload.Execution, EvidenceRef: "sdk-tool-result-event"}); err != nil {
		return err
	}
	if payload.Execution == gate.ExecutionNotStarted {
		return nil
	}
	return s.effect(ctx, logicalKey(payload.Binding, payload.DecisionID+"/"+payload.OperationID), string(payload.Execution), "sdk-tool-result-event")
}
