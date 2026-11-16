# Gatecrasher

Gatecrasher coordinates exact, operation-bound approvals between a human decision
owner and an agent runtime. It combines durable routing, one-use admission and
native reply delivery with the Tradecraft SDK and Substrate application shell.
[Tachyon](https://github.com/hollis-labs/tachyon) owns the human inbox and decisions;
Gatecrasher stores routing and execution evidence.

This is experimental software. The standalone daemon requires explicit owner,
identity and credential configuration. Its fingerprint recipe also requires a
trusted model-provider composition; the supplied executable has no production
model binding and returns unavailable for that recipe until one is supplied.
There is no arbitrary runtime, provider or tool launcher.

## Build

Use Go 1.26.11 or later, with the module versions pinned by the Substrate BOM.
No replacement modules or workspace overrides are required.

```sh
go mod download
go build ./cmd/gatecrasher
```

See [identity bootstrap](docs/identity-bootstrap.md) and the
[runbook](docs/runbook.md) before configuring a daemon. Deployment descriptors
are templates with no target hosts; configure and review them for your environment.

## How it works

- Immutable request snapshots pin the owner, caller scope, operation and native
  identity before enqueue. Routing updates use CAS; observations append separately.
- File SQLite runs in WAL mode with FULL synchronous writes. One daemon owns
  admission and effects. SQL transactions contain no network or effect callbacks.
- Logical run reservations and one-use claims survive restart, cancellation and
  uncertain outcomes. Recovery does not replay a run or resend an old reply.
- The SDK adapter establishes delivery correlation before accepting a terminal
  result. Acknowledgement and execution success are separate durable observations.
- Provider delivery preserves the original prepared callback and keeps the local
  authority fence through physical send. Its context is bounded by the earliest
  current environment, request, decision or option expiry.

Unknown outcomes require reconciliation. Gatecrasher does not provide exactly-once
network delivery or external effects, a distributed revocation lock, or automatic
retry/resume after uncertainty.

## Authentication and approval

The daemon enforces its own Substrate identity boundary, including managed and
loopback listeners. Identity setup is offline. Credential directions are separate:

- Host to Tachyon: a Tachyon-issued mapped producer credential with explicit
  enqueue, get, await, withdraw and assessment grants. It cannot write a decision.
- Tachyon to host: a separate direct Gatecrasher-issued API key pinned to the
  Tachyon workload, audience and callback scope. The host checks its active key
  on every request; key-derived JWT callbacks are refused.

The Once policy requires an authenticated operator and distinct canonical
requester/responder mappings. Every terminal verification fetches fresh current-role
assessment from the pinned owner, including fenced and post-claim checks before
an effect. Missing, stale or mismatched evidence refuses. Assessments are
point-in-time observations, not transferable grants or a guarantee of instantaneous
distributed revocation. Session/multi-use grants and stronger presence policies
are unsupported and are never silently weakened.

## Fixed fingerprint recipe

`POST /api/gate/v1/recipes/fingerprint` requires `gatecrasher.recipe.run` and accepts
only `run_id` and bounded text. The registered tool computes SHA-256 without file,
process or network effects. Identity, owner, conversation and environment bindings
are derived by the daemon. Keep canonical mappings stable across credential rotation.

`gatecrasher recipe fingerprint` is an authenticated HTTP client for that daemon.
It reads bounded stdin, requires `--url`, `--token-file` and a unique `--run-id`,
and owns no second SQLite store. Receipts distinguish completed, pending,
canceled, conflict, refused, unavailable and unknown. The CLI succeeds only for
completed; no receipt authorizes automatic replay or SDK resume.

## Development and verification

```sh
go vet ./...
go test -race -count=1 ./...
golangci-lint run ./...
golangci-lint run --config .golangci.transport.yml ./...
go run github.com/hollis-labs/substrate/cmd/substrate pins check --app .
go run github.com/hollis-labs/substrate/cmd/substrate scan-public --ref HEAD
```

Folio preset provenance is retained in `.folio.yaml`. `folio inspect .` reviews
scaffolding drift without overwriting authored files.

CI checks module pins, generated wiring, both lint configurations and publication
hygiene. Build/release workflows use GitHub-hosted runners and checksummed
artifacts; a release requires an explicit version tag. Each archive contains
`fleet-build-info/v1` metadata, also supplied as `build-info.json` alongside
`SHA256SUMS`; checksums cover both metadata and tarball. The executable currently
has no dedicated version linker variable, so the workflow records the artifact
version in build metadata rather than injecting an unsupported `main.version`.

Repository tests exercise real own-identity HTTP, file SQLite, SDK execution,
concurrent/restarted reservations, cleanup failure and prepared physical delivery.
Their owner transport peers are contract fixtures. Separate isolated paired
acceptance has exercised actual Tachyon browser decisions, confirmation, fresh
assessment and SDK effects with SQLite and a PostgreSQL owner, using a synthetic
model. Neither test setup configures a live installation or a production model.

See the [wire contract](docs/wire-contract.md),
[transport boundary](docs/transport-boundary.md) and [changelog](CHANGELOG.md).

## License

[MIT](LICENSE), copyright 2026 hollis-labs.
