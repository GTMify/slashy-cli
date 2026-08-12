# slashy-cli

`gsl` is a command-line client for [Slashy](https://slashy.com), the AI email client. It speaks to Slashy's Model Context Protocol endpoint directly, so everything Slashy exposes to an AI assistant (email, calendar, contact research, meeting prep, automations) is available from a shell, a script, or a cron job.

```sh
gsl login
gsl tools -q calendar
gsl call search_emails -a query="from:alice unread" -a limit=10
```

## Why a CLI and not an MCP server

An MCP server loads every tool definition into the model's context at session start, whether or not a single tool is ever called. That cost is paid on every launch, by every user, before any work happens. A CLI is lazy: nothing at boot, and roughly 200 tokens per call, because the binary does the work and hands back a summary instead of raw JSON.

The same property makes it useful outside an agent entirely. `gsl` is an ordinary program: it pipes, it scripts, it exits with a status code.

## Install

Requires Go 1.23 or newer.

```sh
go install github.com/GTMify/slashy-cli/cmd/gsl@latest
```

Make sure `$(go env GOPATH)/bin` is on your `PATH`. Or build from source:

```sh
git clone https://github.com/GTMify/slashy-cli.git
cd slashy-cli
go build -o gsl ./cmd/gsl
```

## Authentication

Slashy issues no API keys. Auth is OAuth 2.1 with PKCE, so there is no secret to copy, store, or rotate.

```sh
gsl login
```

That opens a browser, you sign in with Google and approve, and the token is written to `~/.config/gsl/credentials.json` at mode `0600`. It refreshes automatically; you should not need to run `login` again.

The client registers itself dynamically (RFC 7591) at login, so there is no client ID to provision either. `gsl logout` revokes the token and deletes the local file.

If your network or the authorization server rejects the loopback redirect, `gsl login --redirect-host localhost` switches the redirect URI from `127.0.0.1` to `localhost`.

## Commands

| Command | What it does |
|---|---|
| `gsl login` | Browser sign-in. Once per machine. |
| `gsl logout` | Revoke the token and delete the local store. |
| `gsl whoami` | Show the account, endpoint, token expiry, and tool count. |
| `gsl tools [-q TEXT]` | List the tools Slashy exposes to your account. |
| `gsl schema <tool>` | Show one tool's arguments, marking which are required. |
| `gsl call <tool>` | Invoke a tool. |
| `gsl doctor` | Check connectivity, discovery, credentials, and a live call. |

`gsl <tool-name>` is shorthand for `gsl call <tool-name>`, so `gsl send_email -a ...` works directly.

### Passing arguments

```sh
gsl call <tool> -a key=value      # JSON-coerced: 42, true, [1,2], {"k":"v"}
gsl call <tool> -s key=value      # always a string, no coercion
gsl call <tool> --args '{"k":1}'  # the whole argument object as JSON
```

Values are coerced to the type they look like, so `-a limit=10` sends a number and `-a unread=true` sends a boolean. Use `-s` when a value should stay text, such as a subject line that happens to read `true`.

Add `--json` to any command for the raw result instead of the summary. Add `--dry-run` to a call to validate arguments against the tool's schema without sending anything.

### The tool surface is discovered, not compiled in

`gsl` does not ship a hardcoded list of Slashy tools. It calls `tools/list` at runtime and validates against the schema the server returns. Tools Slashy adds server-side work the moment they ship, with no upgrade here. Run `gsl tools` to see what your account actually has.

This also means argument validation is real: `gsl call` checks required fields and rejects unknown ones before spending a round trip, and a mistyped tool name suggests the closest matches.

## Scripting

Every command exits non-zero on failure and writes errors to stderr, so the usual patterns work:

```sh
# How many tools does this account have?
gsl tools --json | jq 'length'

# Fail a script early if the token has gone stale
gsl doctor >/dev/null || { echo "Slashy auth needs attention"; exit 1; }
```

`GSL_CONFIG_DIR` overrides the credential location, which is useful for keeping separate accounts side by side or for CI:

```sh
GSL_CONFIG_DIR=~/.config/gsl-work gsl login
```

## How it works

Slashy publishes an MCP endpoint at `https://slashy.ctrlcenter.ai/mcp`. `gsl` is a JSON-RPC client over it, speaking the Streamable HTTP transport.

The parts worth knowing about, because each one fails in a way that looks like something else:

- **Discovery** follows RFC 9728 protected-resource metadata to find the authorization server, then RFC 8414 to find its endpoints. Nothing about the OAuth topology is hardcoded.
- **The RFC 8707 `resource` parameter** goes on both the authorize request and the token exchange. Omitting it returns something that reads like a scope error.
- **Refresh tokens rotate.** The new one is persisted on every refresh; keeping the old one makes the second refresh fail with an opaque `invalid_grant`.
- **The loopback listener is bound before client registration**, so the redirect URI registered is a port actually held.
- **Responses may arrive as JSON or as an SSE stream**, sometimes with progress notifications interleaved ahead of the real answer. Both framings are handled.
- **A 401 mid-session** triggers exactly one refresh and retry, then reports the remedy. It never loops.

## Development

```sh
go test ./...          # unit tests, no network or credentials needed
go test -race ./...
go vet ./...
```

The tests cover argument coercion, JSON Schema introspection, tool-name resolution, token expiry and rotation, PKCE generation, and the SSE unframing including the interleaved-notification case.

## Related

This CLI also ships inside [`GTMify/gtmify-clis`](https://github.com/GTMify/gtmify-clis) as `cmd/gsl`, alongside GTMify's other service CLIs. The two copies are the same program; this repository is the standalone, public one. If you are fixing a bug, note that the change belongs in both.

Slashy's own MCP documentation: <https://help.slashy.com/features/integrations/mcp>

## License

MIT. See [LICENSE](LICENSE).

`gsl` is an independent client. It is not affiliated with or endorsed by Slashy.
