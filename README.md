# Hemmelig CLI

`hemmelig` is the command line client for [Hemmelig](https://hemmelig.app), the encrypted secret sharing app. It encrypts and decrypts on your machine, so the server gets only ciphertext. The CLI also runs a local MCP server for AI assistants.

Version 2 works with Hemmelig 7.

## Install

Download the binary for your platform from the [releases](https://github.com/HemmeligOrg/hemmelig-cli/releases):

```bash
VERSION=2.0.0
PLATFORM=linux-amd64 # or linux-arm64, darwin-amd64, darwin-arm64
curl -fL "https://github.com/HemmeligOrg/hemmelig-cli/releases/download/v${VERSION}/hemmelig-${PLATFORM}" -o hemmelig
chmod +x hemmelig
sudo mv hemmelig /usr/local/bin/
```

On Windows, download `hemmelig-windows-amd64.exe`. Each release has a `checksums.txt` file with the SHA-256 checksums.

## Quick start

```bash
# Create a secret. The CLI prints the link.
hemmelig "db password: hunter2" --expires 1h

# Open a secret link and print the content.
hemmelig secrets get "https://hemmelig.app/s/<id>#<key>"

# Use your own instance and your account.
hemmelig config set url https://secrets.example.com
hemmelig login
hemmelig secrets create "for Kari only" --to kari@example.com --notify
hemmelig inbox send acme "The new API key is ..." --subject "API key"
```

## Commands

| Command   | What it does                                                               |
| --------- | -------------------------------------------------------------------------- |
| `secrets` | Create, read, list, burn and delete secrets, and show the view receipts    |
| `orgs`    | List organizations and members, read audit logs, manage email domains      |
| `inbox`   | Send encrypted messages to an organization inbox                           |
| `account` | Your account, 2FA and API keys                                             |
| `admin`   | Users, invites, instance settings, analytics and the audit log             |
| `login`   | Sign in and store a session. `logout` ends it, `whoami` shows it          |
| `config`  | Store the instance URL and an API key                                      |
| `mcp`     | Run the local MCP server on stdio                                          |
| `health`  | Check that the instance is ready                                           |

Run `hemmelig <command> --help` for the flags. The full guide is [docs/cli.md](docs/cli.md). The MCP server is in [docs/mcp.md](docs/mcp.md).

## Build

Use Go 1.25 or later:

```bash
go build -o hemmelig .
./hemmelig --help
```

## Test

The unit tests include crypto vectors from the web app, the chunked file format, the inbox encryption, argument parsing and the MCP tools:

```bash
go test ./...
```

`e2e/run.sh` runs the commands and the MCP server against a real Hemmelig server. The top of the script shows how to start a test server. The Hemmelig repository also has a Playwright test, `tests/e2e/cli.spec.ts`, that checks the CLI against the web app. Set `HEMMELIG_E2E_CLI` to a built binary to run it.

## Release

A tag `v<version>` starts the release workflow. It builds the binaries for Linux, macOS and Windows, writes `checksums.txt`, and publishes a GitHub release. Change `version` in `main.go` first.

```bash
git tag v2.0.0
git push origin v2.0.0
```

## Layout

| Path                 | Content                                                         |
| -------------------- | --------------------------------------------------------------- |
| `*.go`               | The commands, the flag parser and the output                    |
| `internal/hcrypto`   | The secret, file and inbox encryption, as in the web app        |
| `internal/api`       | The HTTP client                                                 |
| `internal/service`   | The operations that the commands and the MCP server share       |
| `internal/mcpserver` | The MCP tools                                                   |
| `internal/config`    | The config file, the session and the delete tokens              |
| `internal/links`     | Secret links                                                    |
| `internal/prompt`    | Prompts without echo                                            |
| `internal/htmltext`  | Converts web app HTML to plain text                             |
| `testdata`           | Crypto vectors and the script that makes them                   |
| `e2e`                | The end-to-end test and its helpers                             |

## License

MIT
