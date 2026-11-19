# Changelog

## Unreleased

- Fix: the owner can read and decide approvals. The owner is matched by
  `owner.principal` id on a verified caller (`user:<id>` session or `key:<id>` owner
  key); the operator-kind requirement, which a live identity never stamps, is gone.
  Startup warns when `owner.principal` has neither prefix. Tested through the real
  identity module.
- Gatecrasher is now the human-in-the-loop and approval service: it owns the inbox,
  the decisions and their routing. README, AGENTS and project.yaml reflect this.
- Add the version 1 approval contract: `api/openapi/gate-v1.yaml` (submit, get, await,
  withdraw, JWKS; signed EdDSA decisions; request_secret intake shapes) and
  `pkg/approvalapi` (types, RFC 8785 request digest, decision sign/verify/check).
- Serve the approval inbox: submit, get, await (capped at 60s), withdraw, decide and
  JWKS routes over an immutable request store with append-only decisions, shadow
  decisions and event log. Ground requests are approved on arrival; elevated ones by
  configured approver agents within per-class ceilings (with a shadow mode) or the
  owner; critical ones by the owner only. Decisions are signed with a persisted
  Ed25519 key. A sweeper expires due requests. The JWKS route needs the read scope.
- Serve approvals without the Tachyon binding; create the decision key only when
  approvals are configured; refuse to start with nothing configured.
- Add the surface fan-out: a server-sent event stream (`/api/gate/v1/events`, filtered
  to what the caller may read, resumable with Last-Event-ID) and signed webhooks to
  configured subscribers (HMAC-SHA256, at least once, with stored cursors).
- Add cards (`/api/gate/v1/approvals/{id}/card`; approve, choose, answer,
  request_secret) and the choice and question kinds, whose responses are signed into
  the decision.
- Add `secret_request`: the card posts the value write-only to the producer's intake on
  an allowed origin, and the producer reports it provided
  (`/secret-provided`). Gatecrasher stores only the reference.
- Add `auth.trust: warden`: accept Warden-issued EdDSA JWTs (aud gatecrasher) on the
  approval routes, as `warden:`-prefixed principals that are never the owner.
- Add docs/integration-guide.md for surfaces.

- Add an experimental Substrate host with enforced own identity and scoped HTTP API.
- Persist immutable routing snapshots, CAS updates, append-only observations,
  logical run reservations and one-use claims in file SQLite.
- Integrate the Tachyon native gate profile with separate producer and callback
  credentials, complete binding validation and fresh current-role assessments.
- Compose the SDK fingerprint recipe with host policy, environment, admission and
  execution reporting. Provide a bounded HTTP-only recipe CLI.
- Preserve native numeric/string identity and original prepared callbacks through
  fenced physical delivery, bounded by the earliest verified expiry.
- Retain consumed work across cancellation, uncertainty, credential rotation and
  restart. Clean up exact expired bindings without revoking replacements; report
  cleanup failures as unknown outcomes.
- Add real-auth HTTP, SDK, SQLite, concurrency, crash/reopen, physical-send and
  strict transport failure coverage, plus scoped build and release workflows.
