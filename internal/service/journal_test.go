package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hollis-labs/gatecrasher/internal/storage"
	"github.com/hollis-labs/libs/core/store"
	"github.com/hollis-labs/libs/core/store/migrate"
	"github.com/hollis-labs/libs/mesh/core/gate"
	"github.com/hollis-labs/libs/mesh/core/gate/gatetest"
	"github.com/hollis-labs/libs/mesh/core/hitl"
	"github.com/hollis-labs/libs/mesh/gatecrasher"
)

func openStore(t testing.TB, path string) *store.Store {
	t.Helper()
	cfg := store.Config{Driver: store.DriverSQLite, SQLite: store.SQLiteConfig{Path: path, Journal: "wal", Synchronous: "FULL", CreateParentDir: true}}
	st, err := store.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	fs, root := storage.Migrations()
	if err = migrate.Ensure(context.Background(), cfg, st, migrate.Source{FS: fs, Root: root}); err != nil {
		_ = st.Close()
		t.Fatal(err)
	}
	return st
}
func reserveRoute(t testing.TB, j *Journal, key string) gatecrasher.Route {
	t.Helper()
	r := gatetest.Request(time.Now())
	r.IdempotencyKey = key
	route, err := j.Reserve(context.Background(), gatecrasher.Route{OwnerRef: "tachyon-fixture", CallerScope: "gatecrasher", Request: r})
	if err != nil {
		t.Fatal(err)
	}
	return route
}
func TestJournalFileReopenImmutableIntentAndTicketCAS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.db")
	st := openStore(t, path)
	j := NewJournal(st)
	r := reserveRoute(t, j, "request-1")
	wrong := r
	wrong.OwnerRef = "another-owner"
	if _, err := j.Reserve(t.Context(), wrong); !errors.Is(err, gatecrasher.ErrConflict) {
		t.Fatal(err)
	}
	wrong = r
	wrong.Request, _ = r.Request.Snapshot()
	wrong.Request.Options[0].Payload = []byte(`{"edited":true}`)
	if _, err := j.Reserve(t.Context(), wrong); !errors.Is(err, gatecrasher.ErrConflict) {
		t.Fatal(err)
	}
	d, _ := r.Request.Digest()
	r.Ticket = &gate.Ticket{AuthorityRef: r.OwnerRef, RequestDigest: d, Binding: r.Request.Binding, Handle: hitl.Handle{ContractVersion: hitl.ContractVersion, ItemID: "item-1", State: hitl.StatePresented, Revision: 1}}
	attached, err := j.Swap(t.Context(), r.Request.IdempotencyKey, r.Version, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = j.Swap(t.Context(), r.Request.IdempotencyKey, r.Version, r); !errors.Is(err, gatecrasher.ErrCAS) {
		t.Fatal(err)
	}
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	st = openStore(t, path)
	defer st.Close()
	j = NewJournal(st)
	loaded, err := j.Find(t.Context(), *attached.Ticket)
	if err != nil || !reflect.DeepEqual(loaded, attached) {
		t.Fatal(loaded, err)
	}
	loaded.Request.Options[0].Payload[2] = 'X'
	loaded.Request.NativeRequestID[0] = '1'
	again, err := j.Load(t.Context(), r.Request.IdempotencyKey)
	if err != nil || !reflect.DeepEqual(again, attached) {
		t.Fatal("mutation escaped detached result", err)
	}
	changed := attached
	tc := *attached.Ticket
	tc.Handle.Revision++
	changed.Ticket = &tc
	if _, err = j.Swap(t.Context(), r.Request.IdempotencyKey, changed.Version, changed); !errors.Is(err, gatecrasher.ErrConflict) {
		t.Fatal(err)
	}
}
func TestJournalConcurrentCASAcrossStoreHandlesOneWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.db")
	one := openStore(t, path)
	defer one.Close()
	two := openStore(t, path)
	defer two.Close()
	a, b := NewJournal(one), NewJournal(two)
	r := reserveRoute(t, a, "same")
	var winners atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, j := range []*Journal{a, b} {
		wg.Add(1)
		go func(j *Journal) {
			defer wg.Done()
			<-start
			x := r
			x.Attempts++
			if _, err := j.Swap(t.Context(), x.Request.IdempotencyKey, x.Version, x); err == nil {
				winners.Add(1)
			} else if !errors.Is(err, gatecrasher.ErrCAS) {
				t.Error(err)
			}
		}(j)
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("CAS had multiple winners", winners.Load())
	}
}
func TestJournalRecoveryCursorAndAppendOnlyObservations(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "host.db"))
	defer st.Close()
	j := NewJournal(st)
	for _, key := range []string{"a", "b", "c"} {
		reserveRoute(t, j, key)
	}
	first, cursor, err := j.List(t.Context(), "", 2)
	if err != nil || len(first) != 2 || cursor == "" {
		t.Fatal(first, cursor, err)
	}
	last, next, err := j.List(t.Context(), cursor, 2)
	if err != nil || len(last) != 1 || next != "" || last[0].Request.IdempotencyKey != "c" {
		t.Fatal(last, next, err)
	}
	if _, _, err = j.List(t.Context(), "not a cursor", 2); err == nil {
		t.Fatal("malformed cursor accepted")
	}
	r := first[0]
	d, _ := r.Request.Digest()
	r.Ticket = &gate.Ticket{AuthorityRef: r.OwnerRef, RequestDigest: d, Binding: r.Request.Binding, Handle: hitl.Handle{ContractVersion: hitl.ContractVersion, ItemID: "item", State: hitl.StateResolved, Revision: 2}}
	r.DecisionRef = "resolution"
	r.Delivery = &gate.DeliveryReceipt{DecisionRef: r.DecisionRef, Binding: r.Request.Binding, AdapterID: r.Request.Adapter.AdapterID, NativeRequestID: r.Request.NativeRequestID, Status: gate.DeliveryUnknown}
	r, err = j.Swap(t.Context(), r.Request.IdempotencyKey, r.Version, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Executions = append(r.Executions, gate.ExecutionReceipt{DecisionRef: r.DecisionRef, OperationID: r.Request.OperationID, Binding: r.Request.Binding, State: gate.ExecutionUnknown})
	r, err = j.Swap(t.Context(), r.Request.IdempotencyKey, r.Version, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.ExecContext(t.Context(), `DELETE FROM observations`); err == nil {
		t.Fatal("receipt history was mutable")
	}
	r.Executions = nil
	if _, err = j.Swap(t.Context(), r.Request.IdempotencyKey, r.Version, r); !errors.Is(err, gatecrasher.ErrConflict) {
		t.Fatal(err)
	}
}
func TestExclusiveHostOwnershipAndPrivateSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.db")
	st := openStore(t, path)
	defer st.Close()
	cfg := Config{OwnerRef: "tachyon-fixture", CallerScope: "gatecrasher", CallbackSubject: "key:fixture"}
	first, err := New(t.Context(), st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = New(t.Context(), st, cfg); err == nil {
		t.Fatal("second effect owner admitted")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal(info, err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := New(t.Context(), st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
}
