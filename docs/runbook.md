# Gatecrasher operations

Gatecrasher requires operator-supplied identity, owner mapping and credential
configuration. The deployment templates contain no target hosts. Configure
endpoints, secret custody and process supervision for your environment before use.

## Configuration

The Folio shell uses `SUBSTRATE_CONFIG` or the XDG Gatecrasher config file. Data
and identity state use XDG locations or `GATECRASHER_DATA_DIR`. Every listener,
including loopback/managed, enforces auth. Identity setup is offline. The app
selects no MCP module. The approval inbox (gate v1, below) is served only once its
`approvals` block names an owner; until then its routes answer 503 and no decision
key is created.

Gatecrasher serves approvals on their own: the Tachyon response binding below is
optional. Configure either, or both; with neither, `serve` refuses to start ("nothing
to serve"). If any Tachyon key is set, all of them must be valid.

Tachyon response binding, in the `gatecrasher` block:

| Key | Meaning |
|---|---|
| owner_ref | immutable identity of the single Tachyon owner instance |
| caller_scope | mapped Gatecrasher producer namespace in that owner |
| callback_subject | pinned own-identity service key subject for Tachyon callbacks |
| actor_map | issuer-qualified actors to canonical people, for no-self-approval |
| tachyon_url | trusted HTTPS owner origin; no credentials, path, query or fragment |
| producer_token_file | private external Tachyon producer credential, reread for rotation |
| allowed_hosts | additional explicit listener Host names |

No example identity or deployment hostname is accepted as configured. Callback
credentials are direct Gatecrasher-issued API keys; key-derived JWTs are refused
to retain immediate credential-revocation behavior. The API re-verifies with its
own identity service, not an implicitly trusted Tachyon issuer. Outbound service
mapping and verb grants belong to Tachyon. Neither direction has decision-writing
authority on the host. Canonical requester and responder must be distinct; the
accountable project operator metadata grants no approval exception. The producer
also needs the separate explicit `tachyon.gate.assess-response` grant. Each
terminal verification freshly checks current owner role evidence; unavailable or
mismatched observations refuse. Observation TTL is at most five seconds; clocks
need to agree within one second. This does not promise zero-lag distributed
revocation, and observations cannot be reused as grants.

The registered SDK recipe is composed through `Service.Recipe` / `RunRecipe` and
requires an explicitly supplied host model router. `gatecrasher recipe fingerprint`
sends stdin text to the one fixed `/api/gate/v1/recipes/fingerprint` daemon route,
using an own-identity credential with `gatecrasher.recipe.run`. Only run_id and
bounded text are accepted. The command opens no local data store and accepts no
runtime, tool or model selection. Without a trusted model binding, the daemon
returns unavailable; the current executable does not invent a fake model.

Keep canonical actor mappings stable: they define the fixed recipe conversation
and run reservation namespace, including across credential rotation. The service
serializes enrollment and refuses consumed IDs before allocating new bindings.
HTTP pending (202) is a retained approval receipt after the bounded SDK run stops,
not a resumable session. Canceled (200) stops the run but does not withdraw its
owner item or undo admitted effects. Unknown (503), lost responses, conflicts and
other non-completed receipts require reconciliation; never replay automatically.
See wire-contract.md for the closed response states. The CLI accepts no binding
or launcher parameters, and returns success only for completed. Runtime telemetry
and error responses omit raw input, tool arguments and credential material.

## Approval inbox (gate v1)

The contract is `api/openapi/gate-v1.yaml`; the store is `internal/approvals`. Configure
it in the `gatecrasher` block:

```yaml
gatecrasher:
  approvals:
    owner: { principal: "user:<owner user id>", sub: "<owner registry id>" }   # or "key:<owner key id>"
    producers: { "key:<warden key id>": warden }
    classes:
      # Warden's starter rules route elevated requests to these two classes.
      approve.enroll:
        agents: { "key:<approver key id>": "<approver registry id>" }
        ceiling: { max_ttl_seconds: 86400, audiences: [llm-gateway], scopes: [llm-gateway.decide] }
        shadow: true
      approve.credentials:
        agents: { "key:<approver key id>": "<approver registry id>" }
        ceiling: { max_ttl_seconds: 86400, audiences: [llm-gateway], scopes: [llm-gateway.decide] }
        shadow: true
    decision_key_file: decision-signing.key   # relative to the database directory
```

`owner.principal` is the owner's Gatecrasher identity principal id exactly as the identity
module stamps it: `user:<user id>` for a signed-in session, or `key:<key id>` for an owner
key (create one with `--scope gatecrasher.approval.read,gatecrasher.approval.decide`).
It is matched by id on a verified caller; the kind is not checked. A value without a
`user:` or `key:` prefix never matches, and startup logs a warning. `owner.sub` is the
owner's registry id that decisions carry as `decider.sub`; Warden's `approvals.owner` must
be the same value, because Warden pins critical decisions to it.

Credentials are Gatecrasher identity keys (principal id `key:<id>`, audience `gatecrasher`):

```sh
gatecrasher identity key create --name warden --audience gatecrasher \
  --scope gatecrasher.approval.submit,gatecrasher.approval.read --out /path/to/warden.key
gatecrasher identity key create --name approver-credentials --audience gatecrasher \
  --scope gatecrasher.approval.decide,gatecrasher.approval.read,approve.credentials --out /path/to/approver.key
```

Rules the store enforces:

- A producer submits only as its configured `source`; that name is the `aud` of its
  decisions. Idempotency keys are per producer.
- `ground` is approved on arrival by Gatecrasher (`decider.kind: app`).
- `elevated` is decided by the owner, or by an agent listed for the class that also
  holds the class as an exact scope (a `*` grant never counts). An agent's approval must
  fit the ceiling after narrowing; an empty ceiling means agents cannot approve at all.
  With `shadow: true` agent decisions are recorded only and the request waits for the owner.
- `critical` is decided by the owner only (the configured `owner.principal`).
- Producers, the owner and the class's agents can read an approval; anyone else gets 404.
- Decisions are EdDSA compact JWS, valid for redemption 10 minutes after the decision.
  A producer that misses the window submits a new request.
- A sweep every 15 seconds (and every read) expires pending requests past `expires_at`.

The decision signing key is created 0600 on first start and refused if group or others
can read it. Back it up with the database: losing it invalidates outstanding decisions
only (they expire in 10 minutes), but producers caching the key set must refetch
`/api/gate/v1/jwks.json`. Requests, decisions, shadow decisions and the event log
(`approval_events`) are append-only; a status moves once, from pending.

### Kinds

- `credential_grant` (and any other kind): approve or deny `requested`.
- `choice` and `question`: `prompt` carries the question (and 2 to 20 choices); the
  owner approves with `choice` or `answer`, or declines with `denied`. The response is
  in the signed decision.
- `secret_request` (always `critical`): `secret_intake` names the producer's one-use
  intake. Allow each producer's intake origins:

  ```yaml
  gatecrasher:
    approvals:
      intake_origins: { warden: ["https://<warden origin>"] }
  ```

  The card's form posts the value write-only to the intake. The producer then reports
  `POST /api/gate/v1/approvals/{id}/secret-provided` with the intake id and the
  reference it stored the value under; Gatecrasher records the reference and time and
  closes the request approved (decider: the producer, `kind: app`). Gatecrasher has no
  route that accepts a value, keeps none, and logs none. The owner declines with decide.

### Surfaces: stream, webhooks, cards

See [integration-guide.md](integration-guide.md). `GET /api/gate/v1/events` is the
server-sent event stream; webhooks push the same events to configured subscribers:

```yaml
gatecrasher:
  approvals:
    webhooks:
      - { name: basalisk, url: "https://<surface>/hooks/gatecrasher", secret_file: basalisk-webhook.key, view: owner }
      - { name: credentials-bot, url: "https://<agent>/hook", secret_file: bot-webhook.key, view: approve.credentials }
```

The key file (relative to the database directory) holds at least 32 random bytes and
must not be readable by group or others (`head -c 48 /dev/urandom | base64 > key;
chmod 600 key`). A subscriber starts at the end of the log the first time it runs, then
receives every later event it may see, in order, at least once; its cursor is in
`webhook_cursors`. Failed deliveries retry with backoff up to a minute. URLs must be
https, or http on loopback.

### Trusting Warden (`auth.trust: warden`)

```yaml
gatecrasher:
  auth:
    trust: warden
    warden:
      issuer: warden
      jwks_url: "https://<warden origin>/.well-known/jwks.json"
      # bootstrap_key_file: warden-jwks.json   # used until the first fetch succeeds
```

The approval routes (and the outer guard) then also accept Warden-issued EdDSA JWTs
with `aud: gatecrasher`, that issuer, and the scopes in `scope`. A Warden principal's
id is `warden:<sub>`: list it under `producers` (for example
`"warden:<warden service sub>": warden`) or a class's `agents`. It is never the owner,
whatever `kind` it claims; the owner is Gatecrasher's own operator identity. The Tachyon
callback and recipe routes keep accepting only Gatecrasher's own keys. `standalone`
(the default) trusts only Gatecrasher's own keys.

## Storage and recovery

Use a private local file SQLite database, WAL and FULL synchronous. One process
holds the OS admission lock. A second effect owner refuses startup; this is not
an HA lease. The Substrate database module owns migration/opening; service code
owns SQL. SQL transactions contain no network, model, effect or native send.

On restart, existing runtime attachments become inactive. Logical run reservations
and once claims remain consumed. Unfinished work receives append-only unknown
observations. Re-enrollment must use a fresh higher generation and trusted facts;
reusing an old logical RunID still refuses. Returned-run cleanup can deactivate
its exact expired binding without live admission authority; it cannot deactivate
a replacement attempt/generation or release a reservation/claim. Cleanup storage
failure is an unknown response requiring reconciliation, never successful
completion. Do not edit SQL to reset consumed work.

`Service.RecoverRoutes` processes a bounded cursor page and retries only the
stable enqueue key against its pinned owner. It repairs mapping, never sends a
reply, switches owners, reconstructs a callback or reruns an effect. An unknown
transport write or effect requires explicit old-binding reconciliation. No timeout,
missing acknowledgement or stopped process means an effect was safe to repeat.

Use a Tachyon native profile that confirms durable outcomes before exposing them
as authority. Configure separate credential custody and explicit grants, then
verify the complete operator-to-owner-to-host path in your environment. Isolated
acceptance fixtures do not supply production identities or model configuration.

## Backup, rollback and publication

Use the framework's consistent SQLite backup path,
including required WAL state. Do not copy an actively written main file alone.
Keep the existing owner/store untouched: host rollback does not roll back a human
decision or an external effect. Binary rollback must preserve reservation/claim
semantics and compatible schema; restore does not release uncertain work.

Release workflows build immutable artifacts, `build-info.json` using
`fleet-build-info/v1`, and `SHA256SUMS`. The same metadata is inside each tarball
and alongside it; checksums cover the metadata file and tarball. App, commit,
short SHA, version, Go version, UTC build time and targets retain the fleet
artifact contract. No version linker variable is defined by the executable;
artifact version is recorded in metadata. Option B fleet-install
places the binary and Cerberus supervises the installed link; the supervisor does
not build from source. Before rendering deployment files, select the real target
in project.yaml and review all generated paths, health URLs and supervisor
identity. Keep environment-specific values and credential files outside the
repository.
