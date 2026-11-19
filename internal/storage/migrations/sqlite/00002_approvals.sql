-- Approval inbox and decision store (gate v1). Requests are immutable snapshots; a
-- status moves once, from pending to a terminal state; decisions and events are
-- append-only.
-- +goose Up
CREATE TABLE approvals (
 approval_id TEXT PRIMARY KEY,
 submitter TEXT NOT NULL,
 idempotency_key TEXT NOT NULL,
 request_digest TEXT NOT NULL,
 source TEXT NOT NULL,
 kind TEXT NOT NULL,
 tier TEXT NOT NULL CHECK(tier IN ('ground','elevated','critical')),
 approver_class TEXT NOT NULL,
 snapshot_json TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','expired','withdrawn')),
 status_at TEXT NOT NULL,
 UNIQUE(submitter, idempotency_key)
);
CREATE INDEX approvals_pending ON approvals(status, expires_at);
-- +goose StatementBegin
CREATE TRIGGER approvals_snapshot_immutable BEFORE UPDATE OF approval_id, submitter, idempotency_key, request_digest, source, kind, tier, approver_class, snapshot_json, expires_at, created_at ON approvals
BEGIN SELECT RAISE(ABORT, 'approval snapshot is immutable'); END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER approvals_status_once BEFORE UPDATE OF status ON approvals
WHEN OLD.status <> 'pending' OR NEW.status = 'pending'
BEGIN SELECT RAISE(ABORT, 'approval status is terminal'); END;
-- +goose StatementEnd
CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals BEGIN SELECT RAISE(ABORT, 'approvals are kept'); END;
CREATE TABLE approval_decisions (
 approval_id TEXT PRIMARY KEY REFERENCES approvals(approval_id),
 jti TEXT NOT NULL UNIQUE,
 outcome TEXT NOT NULL CHECK(outcome IN ('approved','denied')),
 decider_sub TEXT NOT NULL,
 decider_kind TEXT NOT NULL,
 decider_principal TEXT NOT NULL,
 narrowed_json TEXT NOT NULL,
 decided_at TEXT NOT NULL,
 kid TEXT NOT NULL,
 jws TEXT NOT NULL
);
CREATE TRIGGER decisions_no_update BEFORE UPDATE ON approval_decisions BEGIN SELECT RAISE(ABORT, 'append only'); END;
CREATE TRIGGER decisions_no_delete BEFORE DELETE ON approval_decisions BEGIN SELECT RAISE(ABORT, 'append only'); END;
CREATE TABLE approval_shadow_decisions (
 seq INTEGER PRIMARY KEY,
 approval_id TEXT NOT NULL REFERENCES approvals(approval_id),
 outcome TEXT NOT NULL CHECK(outcome IN ('approved','denied')),
 decider_sub TEXT NOT NULL,
 decider_principal TEXT NOT NULL,
 narrowed_json TEXT NOT NULL,
 decided_at TEXT NOT NULL
);
CREATE TRIGGER shadow_no_update BEFORE UPDATE ON approval_shadow_decisions BEGIN SELECT RAISE(ABORT, 'append only'); END;
CREATE TRIGGER shadow_no_delete BEFORE DELETE ON approval_shadow_decisions BEGIN SELECT RAISE(ABORT, 'append only'); END;
CREATE TABLE approval_events (
 seq INTEGER PRIMARY KEY,
 approval_id TEXT NOT NULL REFERENCES approvals(approval_id),
 type TEXT NOT NULL,
 actor TEXT NOT NULL,
 detail_json TEXT NOT NULL,
 at TEXT NOT NULL
);
CREATE INDEX approval_events_by_approval ON approval_events(approval_id, seq);
CREATE TRIGGER approval_events_no_update BEFORE UPDATE ON approval_events BEGIN SELECT RAISE(ABORT, 'append only'); END;
CREATE TRIGGER approval_events_no_delete BEFORE DELETE ON approval_events BEGIN SELECT RAISE(ABORT, 'append only'); END;
-- +goose Down
DROP TABLE approval_events;
DROP TABLE approval_shadow_decisions;
DROP TABLE approval_decisions;
DROP TABLE approvals;
