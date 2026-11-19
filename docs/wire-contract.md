# Tachyon native integration contract

> This is the native Tachyon gate profile, which runs until the Tachyon cutover. The producer approval API, where Gatecrasher owns decisions, is [api/openapi/gate-v1.yaml](../api/openapi/gate-v1.yaml).

Gatecrasher implements the versioned Tachyon native gate profile. The producer
client refuses decision writes; Tachyon owns the sole inbox and terminal outcome.
The host imports no Tachyon internal packages. A compatible owner must confirm
durable outcomes before exposing them as authority.

## Producer to owner

Path: `/api/agent/v1/data/providers/tachyon/verbs/gate.<verb>`.

| Verb | Method | Input | Successful data |
|---|---|---|---|
| enqueue | POST JSON | HITL EnqueueRequest, kind gate_native_v1 | HITL Handle |
| get | GET input query | HITL GetCommand | HITL RetrievalResult |
| await | GET input query | HITL AwaitCommand | HITL RetrievalResult |
| withdraw | POST JSON | HITL WithdrawCommand | HITL Outcome |

The successful wrapper is `{version:1, provider:"tachyon", verb:"gate.enqueue",
data:...}` with the exact invoked verb. This wrapper and mutation POST JSON /
read GET transport apply to the native gate profile. GET carries
one `input` query parameter with at most 16 KiB of decoded JSON; the client refuses
larger input. Wrapper version/provider/verb must match exactly. Unknown or duplicate
wrapper fields, missing/null data and malformed JSON refuse, while opaque payloads
remain raw JSON.

Native gate failures use the flat HITL error codec with the HITL contract
version and all applicable revision, idempotency or terminal evidence. The client
accepts typed conflicts only when that evidence is complete and valid.
Unknown, malformed or incomplete error bodies refuse as transport errors, never
inferred decision or grant evidence. This gate-only codec does not change older
non-gate verb semantics; global identity refusals retain their own HTTP errors.

The producer has a Tachyon-issued mapped service credential and each explicit
`tachyon.gate.*` verb grant, including the distinct assessment grant below. The owner authenticates and pins the source namespace;
`source.application_id`, caller labels and forwarded headers are assertions.
No producer Respond is available. Get/Await query input contains handles/options,
not credentials or operation payloads. Await cancellation ends the wait only.

`gate_request` is a JSON STRING holding the serialized neutral gate.Request.
Do not add UI fields to the authoritative snapshot or decode raw IDs/opaque
payloads through float64. Changed snapshots conflict under the same stable key.
Credential rotation retains the configured mapped identity/owner namespace.

## Owner to host

`POST /api/gate/v1/authorize-response`, scope
`gatecrasher.gate.authorize-response`, is restricted to a separately provisioned
**direct Gatecrasher-issued API key** pinned to Tachyon. It is not the outbound
producer credential and trusts no arbitrary external JWT issuer. Own-key
verification checks active custody on every call; missing/wrong subject, audience,
scope, expiry or revocation refuses. Key-derived JWT callbacks are unsupported.

Input uses string `contract_version:"1"`, `owner_ref`, `idempotency_key`, `item_id`,
`request_digest`, `operation_digest`, `expected_revision`,
`presented_projection_revision`, `option_id`, `binding`, exact raw
`native_request_id`, owner-attested `participant` and `actor_scopes`, and
`assessed_at` / `expires_at` timestamps bounded to at most five seconds and the
request/selected option expiry. Only the pinned workload can make that
attestation. Caller JSON from any other credential never supplies authority.

The host loads durable intent, checks its pinned owner/caller and complete digest,
reloads the actual authenticated owner item, checks its immutable snapshot and
native current revision, and verifies the exact option, policy, actor mapping and
expiry. This also handles lost ticket attachment without manufacturing a revision.
Presented revision equals the current native revision for this Tachyon profile.

Success echoes the complete proposal above and adds `authorized:true`. The host
validates every binding and timestamp before returning it. It is a one-attempt pre-CAS assessment, not a
stored decision, transferable grant or effect admission. Tachyon must re-read its
current view and let its existing CAS select the terminal outcome. The host
rechecks authority at actual admission; a past positive assessment is insufficient.

Only Once/MaxUses=1 is supported. Native allow, deny and cancel remain exact
selected options; withdrawal/expiry remain separate HITL outcomes. Stronger
presence policies remain unsupported and must not be silently weakened. Current
responder roles use the separate fresh observation below.

## Fresh terminal responder assessment

`gate.assess-response` is GET, with the normal version/provider/verb envelope and
separate explicit `tachyon.gate.assess-response` grant. Its `input` query JSON is
only a scoped HITL GetCommand (`contract_version:"1.0"`, `item_id`, `caller`) plus
`expected_terminal_revision`. HITL input uses `hitl.ContractVersion` (`"1.0"`);
assessment output and callback use `gate.ContractVersion` (`"1"`). These are
separate discriminators: wrong versions refuse, with no normalization or shared
substitute constant. No owner, actor, digests or selected option are
accepted as lookup authority. The owner derives those from its retained terminal
record, reads current user roles/disabled state and producer mapping, and performs
no expiry materialization or decision transition.

Data contains `contract_version`, `owner_ref`, `item_id`, `idempotency_key`,
`binding`, exact raw `native_request_id`, `request_digest`,
`operation_digest`, `option_id`, `terminal_revision`, complete `participant`,
`assessed_at` and `expires_at`. The host compares every field, including explicit
binding/native identity and the immutable request digest, against the actual
terminal decision and stored intent. Every response member is required under its
exact wire name. Missing/null fields, aliases, duplicate/unknown fields and invalid
native values refuse at decode; no fallback reconstructs key/binding/native ID
from a digest or request. Same numeric digits encoded as JSON number versus string
remain distinct identities and a mismatch refuses before effect/send admission.
It fetches anew on each verification,
including after the claim/intent commits and immediately before effect admission
inside the local fence. No cached observation supplies a grant. TTL is at most
five seconds, bounded by the request and selected scope; the host permits at most
one second of inter-host clock discrepancy. Missing/expired/mismatched evidence
refuses. This is point-in-time evidence, not zero-lag distributed revocation.

Isolated paired acceptance has exercised this contract through actual owner
handlers, browser decisions, host callbacks and SDK effects. Live installations
still require their own identity, credential and trusted model configuration.

## Admission and delivery

SDK handoff registers a live request-specific receiver. `Coordinator.Deliver`
establishes correlation first; acknowledgement follows actual adapter acceptance
and durable evidence. Tool admission rehashes the registered SDK descriptor,
verifies the exact reservation/current host facts, claims once, records start
intent, rechecks and invokes the callback synchronously under the revocation fence.

Provider handoff registers the original prepared callback only after writer
serialization. Its original WithFence/Claim/recheck spans physical send, bounded
by the verified current environment expiry as well as request/decision/option
expiry. A delayed send cannot outlive that environment; consumed claims remain
consumed after cancellation or uncertainty. Runtime
reply observations retain complete native identity and are recorded only against
established correlation. An abandoned lease retains observations and uncertainty;
it does not authorize resend. Native positive reconciliation is unsupported
without affirmative evidence for the old exact origin.

## Bounded recipe entry point

`POST /api/gate/v1/recipes/fingerprint`, scope `gatecrasher.recipe.run`, accepts
only `{run_id, text}` through the own identity boundary. It selects one registered
SDK recipe, never an arbitrary runtime, model or tool. A trusted composition
supplies the model port; without one it answers unavailable. Duplicate/busy logical
runs conflict and cannot silently replay. The companion CLI reads text from stdin
and calls this route, rather than becoming another SQLite admission owner.

Recipe binding allocation is serialized in the single daemon. A configured
canonical actor determines its stable owner and conversation; the operative is
the fixed fingerprint recipe. Credential rotation to another key mapped to that
same actor cannot create a new conversation. Existing logical RunID reservations
are checked before fresh enrollment and enforced durably by SDK ReserveRun.
Attempt/generation/environment may advance for a new RunID; they never release
an existing reservation. Same-ID changed text is a conflict, including after
reopening the identity and SQLite files. No body field chooses these bindings.

A valid authenticated command returns a version 1 receipt with `run_id`, `state`,
optional SDK `result`, `replay_allowed:false`, `resume_available:false`, and
`reconciliation_required`. Authentication/invalid-input failures remain scoped
HTTP errors before execution.

| HTTP | State | Meaning |
|---|---|---|
| 200 | completed | SDK completed with its recorded result |
| 202 | pending | Approval ticket retained; bounded SDK run has stopped |
| 200 | canceled | SDK run stopped; admitted effects are not undone |
| 409 | conflict | Logical RunID consumed or caller slot already active |
| 403 | refused | Host authority or exact approval refused |
| 503 | unavailable | Required configured composition is unavailable |
| 503 | unknown | Run did not establish a reliable completion outcome |

Every non-completed receipt requires reconciliation. Pending/canceled receipts
may retain the exact ticket for inspection; they confer no continuation authority.
Stopping a wait does not withdraw the owner item. A later decision never resumes
this SDK run. A lost HTTP response is unknown to the caller even if the host
finished; neither side replays automatically. The thin CLI prints validated
receipts, exits successfully only for completed, and otherwise reports the state
without retry. There is no SDK resume, run replay or generic launch endpoint.
Partial model text and raw diagnostics are omitted from non-completion responses.
SDK telemetry contains references/outcomes, never raw submitted text, tool args
or credentials. All acceptance credentials/state remain isolated test fixtures.
