package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	libauth "github.com/hollis-labs/libs/security/auth"

	"github.com/hollis-labs/gatecrasher/pkg/approvalapi"
)

// keepalive is how often an idle stream sends a comment, so proxies keep it open.
var keepalive = 15 * time.Second

// events streams the approval event log as server-sent events (text/event-stream), each
// event's id its seq and its data a FeedEvent, holding only what the caller may read. A
// client resumes with Last-Event-ID (or ?after=<seq>); without either it starts at the
// beginning of the log.
func (h *Handler) events(w http.ResponseWriter, r *http.Request, p libauth.Principal) {
	after, ok := resumeAt(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, approvalapi.ErrCodeInvalid, "after and Last-Event-ID must be a non-negative seq")
		return
	}
	rc := http.NewResponseController(w)
	// A stream outlives the server's write timeout.
	_ = rc.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return
	}
	ctx := r.Context()
	tick := time.NewTicker(keepalive)
	defer tick.Stop()
	for {
		wake := h.approvals.Changed()
		events, scanned, err := h.approvals.Feed(ctx, p, after)
		if err != nil {
			return
		}
		for _, e := range events {
			b, _ := json.Marshal(e)
			if _, err = fmt.Fprintf(w, "id: %d\nevent: approval\ndata: %s\n\n", e.Seq, b); err != nil {
				return
			}
		}
		after = max(after, scanned)
		if len(events) > 0 {
			if rc.Flush() != nil {
				return
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-tick.C:
			if _, err = fmt.Fprint(w, ": keepalive\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		}
	}
}

func resumeAt(r *http.Request) (int64, bool) {
	q := r.URL.Query()
	for k := range q {
		if k != "after" {
			return 0, false
		}
	}
	v := r.Header.Get("Last-Event-ID")
	if v == "" {
		v = q.Get("after")
	}
	if v == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil && n >= 0
}
