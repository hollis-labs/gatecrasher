-- Local routing/admission evidence only. Human decisions stay in Tachyon.
-- +goose Up
CREATE TABLE routes (
 route_key TEXT PRIMARY KEY,
 owner_ref TEXT NOT NULL,
 caller_scope TEXT NOT NULL,
 request_digest TEXT NOT NULL,
 version INTEGER NOT NULL CHECK(version > 0),
 ticket_json TEXT,
 decision_ref TEXT,
 binding_key TEXT NOT NULL,
 route_json TEXT NOT NULL
);
CREATE UNIQUE INDEX route_decision ON routes(decision_ref, binding_key) WHERE decision_ref IS NOT NULL;
CREATE TABLE provider_correlations (
 rpc_key TEXT PRIMARY KEY,
 route_key TEXT NOT NULL REFERENCES routes(route_key)
);
CREATE TABLE observations (
 seq INTEGER PRIMARY KEY,
 route_key TEXT NOT NULL REFERENCES routes(route_key),
 kind TEXT NOT NULL,
 payload TEXT NOT NULL,
 observed_at TEXT NOT NULL
);
CREATE TRIGGER observations_no_update BEFORE UPDATE ON observations BEGIN SELECT RAISE(ABORT, 'append only'); END;
CREATE TRIGGER observations_no_delete BEFORE DELETE ON observations BEGIN SELECT RAISE(ABORT, 'append only'); END;
CREATE TABLE run_reservations (
 logical_key TEXT PRIMARY KEY,
 reservation_json TEXT NOT NULL,
 reserved_at TEXT NOT NULL
);
CREATE TABLE operation_claims (
 claim_key TEXT PRIMARY KEY,
 binding_key TEXT NOT NULL,
 descriptor_json TEXT NOT NULL,
 claimed_at TEXT NOT NULL
);
CREATE TABLE effect_observations (
 seq INTEGER PRIMARY KEY,
 claim_key TEXT NOT NULL REFERENCES operation_claims(claim_key),
 state TEXT NOT NULL,
 evidence TEXT NOT NULL,
 observed_at TEXT NOT NULL
);
CREATE TRIGGER effects_no_update BEFORE UPDATE ON effect_observations BEGIN SELECT RAISE(ABORT, 'append only'); END;
CREATE TRIGGER effects_no_delete BEFORE DELETE ON effect_observations BEGIN SELECT RAISE(ABORT, 'append only'); END;
CREATE TABLE runtime_facts (
 slot_key TEXT PRIMARY KEY,
 facts_json TEXT NOT NULL,
 active INTEGER NOT NULL CHECK(active IN (0,1))
);
CREATE TABLE operation_facts (
 operation_key TEXT PRIMARY KEY,
 binding_key TEXT NOT NULL,
 descriptor_json TEXT NOT NULL,
 digest TEXT NOT NULL
);
CREATE TABLE host_events (
 seq INTEGER PRIMARY KEY,
 event_json TEXT NOT NULL
);
-- +goose Down
DROP TABLE host_events;
DROP TABLE operation_facts;
DROP TABLE runtime_facts;
DROP TABLE effect_observations;
DROP TABLE operation_claims;
DROP TABLE run_reservations;
DROP TABLE observations;
DROP TABLE provider_correlations;
DROP TABLE routes;
