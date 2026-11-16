# Identity bootstrap

gatecrasher is its own identity provider (the Substrate `identity` module). There is no open
first-run setup over HTTP: `POST /api/setup` is refused (`setup_offline`). The owner and the first
machine keys are created on the host, before the service starts.

```sh
export SUBSTRATE_CONFIG=/path/to/gatecrasher.yaml   # your override file; never committed

# 1. the owner: the password is typed twice at the terminal and not echoed
gatecrasher identity setup --username owner --display-name "Owner"

# 2. a separate key for the fixed recipe caller, written once to a new 0600 file
gatecrasher identity key create --name recipe-caller --scope gatecrasher.recipe.run --out /path/to/recipe-caller.key
```

See the runbook for the separate Tachyon callback subject and credential binding. No MCP endpoint is enabled. Callback credential
audience, subject and scope must match the configured host policy; the outbound
Tachyon producer credential is issued separately by Tachyon.

For automation only, `identity setup` reads the password from the first line of stdin when stdin is not a
terminal; supply it from your secret store, never from a shell variable, the command line or shell history.

The data directory is `$GATECRASHER_DATA_DIR`, else `$XDG_DATA_HOME/gatecrasher`, else
`~/.local/share/gatecrasher`: the database and identity signing key (never lose or commit it).
Secret backend state uses `$XDG_STATE_HOME/gatecrasher` or `~/.local/state/gatecrasher`. Details: Substrate `docs/identity.md`.
