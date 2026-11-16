# Changelog

## Unreleased

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
