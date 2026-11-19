# Transport boundary

Run from the module root, with golangci-lint v2.11.4 or later:

```sh
GOWORK=off golangci-lint run --config .golangci.transport.yml ./...
```

Handlers in `internal/api` decode a request, call
the service layer and encode the answer. They do not import `internal/storage`, the Substrate `database`
module or `database/sql`: the service layer (`internal/service`, and `internal/approvals` for the
approval inbox) is the boundary and the only place that runs SQL. The
composition root, `cmd/gatecrasher`, opens the store and hands `internal/service` its read pool and write
handle.

CI runs this as a second lint step next to the ordinary one (`.github/workflows/check.yml`).

Limits: the rule is an import ban, so it sees imports, not calls through an interface; tests are
excluded; a transport directory that is not listed in `.golangci.transport.yml` is not checked. It is not
an authorization check: scopes (`internal/api` `Routes()`) and the owner of a row still need their tests.
