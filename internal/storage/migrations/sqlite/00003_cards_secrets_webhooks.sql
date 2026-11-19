-- Choice and question responses on decisions, the secret_request record (a reference
-- only; never a value) and webhook delivery cursors.
-- +goose Up
ALTER TABLE approval_decisions ADD COLUMN response_json TEXT NOT NULL DEFAULT '{}';
CREATE TABLE approval_secrets (
 approval_id TEXT PRIMARY KEY REFERENCES approvals(approval_id),
 intake_id TEXT NOT NULL,
 ref TEXT NOT NULL,
 provided_at TEXT NOT NULL,
 reported_by TEXT NOT NULL,
 recorded_at TEXT NOT NULL
);
CREATE TRIGGER approval_secrets_no_update BEFORE UPDATE ON approval_secrets BEGIN SELECT RAISE(ABORT, 'append only'); END;
CREATE TRIGGER approval_secrets_no_delete BEFORE DELETE ON approval_secrets BEGIN SELECT RAISE(ABORT, 'append only'); END;
CREATE TABLE webhook_cursors (
 name TEXT PRIMARY KEY,
 seq INTEGER NOT NULL,
 updated_at TEXT NOT NULL
);
-- +goose Down
DROP TABLE webhook_cursors;
DROP TABLE approval_secrets;
ALTER TABLE approval_decisions DROP COLUMN response_json;
