# Gatecrasher operations

Gatecrasher requires operator-supplied identity, owner mapping and credential
configuration. The deployment templates contain no target hosts. Configure
endpoints, secret custody and process supervision for your environment before use.

## Configuration

The Folio shell uses `SUBSTRATE_CONFIG` or the XDG Gatecrasher config file. Data
and identity state use XDG locations or `GATECRASHER_DATA_DIR`. Every listener,
including loopback/managed, enforces auth. Identity setup is offline. The app
selects no MCP module and serves no inbox or human respond endpoint.

Required operator bindings in the `gatecrasher` block:

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

Release workflows build immutable artifacts and SHA256SUMS. Option B fleet-install
places the binary and Cerberus supervises the installed link; the supervisor does
not build from source. Before rendering deployment files, select the real target
in project.yaml and review all generated paths, health URLs and supervisor
identity. Keep environment-specific values and credential files outside the
repository.
