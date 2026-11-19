# gatecrasher

The portfolio's human-in-the-loop and approval service: it owns the inbox, the signed decisions and their routing. Tachyon, Basalisk and Surface are surfaces that show requests and send decisions back through the API.

It is not: an arbitrary runtime launcher, a secret store (request_secret values go straight to Warden), or a source of authority from caller assertions.

Direction set by the owner on 2026-11-19. Earlier text saying "Tachyon owns the human inbox and decisions" is superseded. The native Tachyon profile below still runs until that cutover.

## Start Here

- `cmd/gatecrasher/substrate.yaml` — the manifest: modules and config defaults. `substrate_wiring.go` is generated from it (`substrate generate`); never edit it.
- `cmd/gatecrasher/serve.go` — the HTTP handler stack: Host check, identity middleware, the host (guard and scoped routes).
- `internal/api/api.go` — every route and the scope it needs. The owner of a row is the verified principal, never a request field.
- `internal/service/service.go` — the service layer, the only code that runs SQL; handlers call it. `.golangci.transport.yml` (second lint run) enforces that; `docs/transport-boundary.md` says how.
- `internal/storage/migrations/sqlite/00001_init.sql` — the schema. Until the first release this is the only migration.
- `docs/identity-bootstrap.md` — the owner is created offline; there is no open setup over HTTP.
- `api/openapi/gate-v1.yaml` and `pkg/approvalapi` — the producer contract (version 1). They must agree; change both together and note it in CHANGELOG.
- `.github/workflows/check.yml` — the full CI gate (vet, pins, wiring current, race tests, both lint runs, scan-public).

## Commands

```sh
gofmt -l .
go vet ./...
go test -race -count=1 ./...
```

CI (`.github/workflows/check.yml`) is the full gate.

## Boundaries

- Pins are edited only in the Substrate `bom/bom.yaml`: run `substrate pins sync --app .`, never hand-edit a version in `go.mod`.
- Transports (`internal/api`) never import `internal/storage`, the Substrate `database` module or `database/sql`; go through `internal/service`.
- A route without a scope is refused in `enforce`: add it to `Routes()` in `internal/api/api.go` (`TestEveryRouteHasAScope` guards this).
- Reads go through `Reader()`, writes through `WriteTx` or one `ExecContext`; never write while a cursor is open on the write handle (SQLite has one write connection).
- No secret, host name, address or personal path in a file, a commit or CI: `substrate scan-public --ref HEAD` must stay clean.

## Approval and admission

- Gatecrasher owns decisions. Critical decisions come from the owner only, and elevated
  ones from approver agents holding `approve.<class>`. Every decision is signed
  (EdDSA, `pkg/approvalapi`). A surface never decides on its own.
- request_secret values never touch Gatecrasher storage, logs or a model transcript.
  Record only that the secret was provided and the producer's reference.
- Native Tachyon profile (until cutover): the producer client refuses Respond, and
  Tachyon decides those native requests.
- Callback authentication uses a separately provisioned direct Gatecrasher-issued
  service API key pinned to the Tachyon workload. Reverify with the own identity
  service. Key-derived JWT callbacks are unsupported because parent revocation
  is not immediate in that credential form. Outbound producer custody is separate.
- Native-profile operator authority is owner-attested at decision time; the host
  resolves a configured canonical actor mapping and refuses self approval. Fresh
  gate.assess-response current-role evidence is mandatory at terminal verification
  and fenced admission. Never cache it as a grant. Stronger presence and zero-lag
  distributed revocation remain unsupported, never downgraded.
- Request snapshots are not live facts. Recompute SDK descriptors, verify live
  runtime/environment/resources/policy, commit one-use claims, then recheck under
  the host fence immediately before the callback/physical write.
- SQLite reservations/claims survive crash. Never delete or release uncertain
  work as a retry mechanism. Recovery attaches the same owner; it never replays.
- Preserve the versioned native transport contract and fail-closed checks.
  Contract fixtures and isolated paired acceptance do not configure a live
  installation or production model.
- Keep credentials and environment-specific deployment configuration outside the
  repository. Deployment templates have no configured target hosts.
