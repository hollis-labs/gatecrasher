# Integrating a surface with Gatecrasher

Gatecrasher is the portfolio's approval service: it owns the inbox, the decisions and
their routing. A *surface* is an app the owner is using (Tachyon, Basalisk,
Surface/ADE, a chat through the MCP UI) that shows approvals and sends the owner's
answers. Each surface does three things:

1. **Follow** approvals: the event stream or a webhook.
2. **Render** each one: the card.
3. **Decide**: the decide endpoint (or, for a secret, the write-only form).

The contract is [api/openapi/gate-v1.yaml](../api/openapi/gate-v1.yaml); Go types are
in [`pkg/approvalapi`](../pkg/approvalapi). Gatecrasher owns the card content and the
decide endpoint. How a card is drawn is the surface's concern; in chats (Claude,
Codex), the MCP UI work owns the rendering transport.

## Credentials

A surface acting for the owner needs a credential that resolves to the owner's
Gatecrasher operator principal (the `approvals.owner.principal` the operator set), with
`gatecrasher.approval.read` and `gatecrasher.approval.decide`. An approver agent needs a
key listed under its class's `agents`, with `gatecrasher.approval.decide`,
`gatecrasher.approval.read` and the class itself (`approve.<class>`) as exact scopes.
A surface that only shows approvals needs `gatecrasher.approval.read`.

What a caller sees: the owner sees everything; a producer sees what it submitted; an
approver agent sees its classes' elevated requests. Anything else is 404, on every
route and in the stream.

## 1. Follow

### Event stream (server-sent events)

```http
GET /api/gate/v1/events
Authorization: Bearer <credential>
Last-Event-ID: <last seq you handled>      (optional)
```

```text
id: 42
event: approval
data: {"seq":42,"approval_id":"apr_…","type":"submitted","at":"…","status":"pending","tier":"critical","kind":"credential_grant","source":"warden"}
```

- `type`: submitted, decided, shadow_decided, withdrawn, expired, secret_provided.
- `status` is the approval's status now, so a surface that reconnects late can
  drop the alert for an approval that was already decided.
- Keep the last `id` you handled and send it as `Last-Event-ID` (or `?after=`) when you
  reconnect. Without it the stream starts at the beginning of the log.
- An idle stream sends `: keepalive` every 15 seconds.

### Webhooks

When a surface cannot hold a stream open, the operator configures a webhook for it
(see the runbook). Gatecrasher POSTs batches of the same events:

```json
{"subscriber":"basalisk","events":[{"seq":42,"approval_id":"apr_…","type":"submitted",…}]}
```

Check the signature before trusting the body:

```go
err := approvalapi.VerifyWebhook(key, body, r.Header.Get(approvalapi.HeaderWebhookSignature), time.Now())
```

The header is `t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">`, accepted within 5
minutes. Answer 2xx to advance; anything else is retried with backoff, from the same
place. Deliveries are at least once and in order: dedupe by `seq`.

## 2. Render

```http
GET /api/gate/v1/approvals/{id}/card
```

```json
{
  "version": "gatecrasher.card/v1",
  "approval_id": "apr_…",
  "type": "approve",
  "status": "pending",
  "tier": "critical",
  "kind": "credential_grant",
  "source": "warden",
  "title": "credential_grant: llm-gateway for agt_x",
  "summary": "<the producer's purpose>",
  "principal": {"sub": "agt_x", "kind": "agent"},
  "requested": {"audience": "llm-gateway", "scopes": ["llm-gateway.decide"], "ttl_seconds": 600, "constraints": {}},
  "evidence": {"task_id": "…"},
  "expires_at": "…",
  "deciders": "owner",
  "actions": [
    {"kind": "approve", "label": "Approve", "outcome": "approved", "decide": "/api/gate/v1/approvals/apr_…/decide"},
    {"kind": "deny", "label": "Deny", "outcome": "denied", "decide": "/api/gate/v1/approvals/apr_…/decide"}
  ]
}
```

| `type` | Shows | Actions |
|---|---|---|
| `approve` | the grant (`requested`), who it is for, purpose, evidence | approve, deny |
| `choose` | `prompt.question` and `prompt.choices` | choose (with a choice id), decline |
| `answer` | `prompt.question` | answer (with text), decline |
| `request_secret` | title and purpose, and `secret`, a one-field form | provide_secret, decline |

Show `tier` and `expires_at`. A decided card has no actions and carries `outcome`
(status, decider, and the choice or answer); replace the alert with it.

## 3. Decide

```http
POST /api/gate/v1/approvals/{id}/decide
Content-Type: application/json

{"outcome": "approved"}
{"outcome": "denied", "note": "not now"}
{"outcome": "approved", "choice": "b"}
{"outcome": "approved", "answer": "Use the staging key."}
{"outcome": "approved", "narrowed": {"scopes": ["llm-gateway.decide"], "ttl_seconds": 600}}
```

- 200: decided; the body has the signed `decision`.
- 202 with `shadow: true`: an approver agent in shadow mode; the request still waits
  for the owner.
- 409 `terminal`: someone else decided first, or it expired or was withdrawn. Refresh
  the card.
- 403 `not_decider` or `ceiling`: this caller may not decide it. Leave it for the owner.

`narrowed` may only drop requested scopes or shorten the TTL.

### request_secret: the write-only form

```json
"secret": {"intake_id": "int_…", "post_url": "https://<producer intake>", "field": "value", "expires_at": "…", "write_only": true}
```

The value goes from the owner's input **directly to `post_url`**, as the form field
`value`. It never goes to Gatecrasher, to your server, or to any model.

- Never put the value in a chat message, a model prompt or transcript, a tool call or
  result, a log, analytics, a draft or local storage.
- In a chat, render the form as UI that posts from the owner's client; the model sees
  only that a secret was provided.
- After the post the producer tells Gatecrasher (`/secret-provided`), and the approval
  closes `approved` with `response.secret_ref`: a reference, never the value.
- To refuse, decide `denied`. A secret_request cannot be approved through decide.

## Per-surface notes

- **Tachyon**: subscribe with the owner credential; Tachyon's own approval inbox keeps
  running until its cutover. Show Gatecrasher cards beside it, and send decisions to
  Gatecrasher rather than storing them.
- **Basalisk**: the stream from the app's Go host, an alert per pending card, and the
  card in the panel. The request_secret form must post from the webview, never through
  the agent.
- **Surface/ADE**: a module that follows the stream and renders cards in the shell, so
  every ADE app gets approvals.
- **MCP UI (chats)**: render the card JSON as a component. Actions call decide with the
  owner's credential from the client, and the secret form posts from the client.
