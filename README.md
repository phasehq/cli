# phase cli

```
λ phase --help
Keep Secrets.

             /$$
            | $$
    /$$$$$$ | $$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$
   /$$__  $$| $$__  $$ |____  $$ /$$_____/ /$$__  $$
  | $$  \ $$| $$  \ $$  /$$$$$$$|  $$$$$$ | $$$$$$$$
  | $$  | $$| $$  | $$ /$$__  $$ \____  $$| $$_____/
  | $$$$$$$/| $$  | $$|  $$$$$$$ /$$$$$$$/|  $$$$$$$
  | $$____/ |__/  |__/ \_______/|_______/  \_______/
  | $$
  |__/

Commands:
  auth                              💻 Authenticate with Phase
  init                              🔗 Link your project with your Phase app
  run                               🚀 Run and inject secrets to your app
  shell                             🐚 Launch a sub-shell with secrets as environment variables
  apps list                         📱 List available apps and their environments
  secrets list                      📇 List all the secrets
  secrets get                       🔍 Fetch details about one or more secrets in JSON
  secrets create                    💳 Create a new secret
  secrets update                    📝 Update an existing secret
  secrets delete                    🗑️ Delete secrets
  secrets import                    📩 Import secrets from a .env file
  secrets export                    🥡 Export secrets in a specific format
  dynamic-secrets list              📇 List dynamic secrets & metadata
  dynamic-secrets lease generate    ✨ Generate a lease (create fresh dynamic secret)
  dynamic-secrets lease get         🔍 Get leases for a dynamic secret
  dynamic-secrets lease renew       🔁 Renew a lease
  dynamic-secrets lease revoke      🗑️ Revoke a lease
  users whoami                      🙋 See details of the current user
  users switch                      🪄 Switch between Phase users, orgs and hosts
  users logout                      🏃 Logout from phase-cli
  users keyring                     🔐 Display information about the Phase keyring
  ai enable                         🪄 Enable the local Phase AI credential proxy
  ai disable                        🚫 Disable AI integrations
  ai status                         📡 Show Phase AI setup and proxy health
  ai skill                          📄 Print the Phase AI skill document
  ai run                            🚀 Launch an AI Agent behind the Phase AI credential proxy
  ai exec                           ⚡ Execute one command behind a transient Phase AI credential proxy
  relay start                       🛰️ Run a Phase AI relay for remote Agent sandboxes
  console                           🖥️ Open the Phase Console in your browser
  docs                              📖 Open the Phase CLI Docs in your browser
  completion                        ⌨️ Generate the autocompletion script for the specified shell

Flags:
  -h, --help      help for phase
  -v, --version   version for phase
```

## Features

- **End-to-end encryption** — App secrets in E2E mode are encrypted client-side before leaving your machine
- **Secret types** — `config` (non-sensitive), `secret` (sensitive), and `sealed` (write-only) with enforced visibility rules
- **`phase run`** — inject secrets as environment variables into any command without code changes
- **`phase shell`** — launch a sub-shell (bash, zsh, fish, etc.) with secrets preloaded
- **Dynamic secrets** — generate short-lived credentials (e.g. AWS IAM) with automatic lease management (generate, renew, revoke)
- **Secret references** — reference secrets across environments and apps, resolved automatically at runtime
- **Personal overrides** — override shared secrets locally without affecting your team
- **Import / Export** — import from `.env` files; export to dotenv, JSON, YAML, TOML, CSV, XML, HCL, INI, Java properties, and more
- **Path-based organisation** — organise secrets in hierarchical paths for monorepos and microservices
- **Tagging** — tag secrets and filter operations by tag
- **Random secret generation** — generate hex, alphanumeric, base64, base64url, 128-bit, or 256-bit keys on create or update
- **AI Agent proxy** — workflow-scoped third-party Integration credentials for HTTP, PostgreSQL, and AWS without exposing live material
- **Multiple auth methods** — browser login, personal access tokens, service account tokens, Agent tokens, and AWS IAM identity auth
- **Multi-user & multi-org** — switch between Phase accounts, orgs and self-hosted instances
- **OS keyring integration** — credentials stored in macOS Keychain, GNOME Keyring, or Windows Credential Manager
- **Multiple environments** — dev, staging, production, and custom environments with per-project defaults via `phase init`

## Installation

You can install Phase CLI using curl:

```bash
curl -fsSL https://pkg.phase.dev/install.sh | bash
```

## Usage

### Prerequisites

- Create an app in the [Phase Console](https://console.phase.dev)

### Login

```bash
phase auth
```

### Initialize

Link the Phase CLI to your project:

```bash
phase init
```

Or non-interactively:

```bash
phase apps list                                    # find your app ID
phase init --app-id "your-app-id" --env Development
```

### Import .env (optional)

Import and encrypt existing secrets and environment variables:

```bash
phase secrets import .env
```

### List / view secrets

```bash
phase secrets list --show
```

### Run and inject secrets

```bash
phase run 'npm start'
phase run 'go run main.go'
phase run --env production 'python manage.py runserver'
```

## AI Agent proxy

Phase AI gives coding agents (Claude Code, Cursor, Codex, OpenCode, Devin, VS Code Copilot) workflow-scoped access to third-party services (HTTP APIs, AWS, PostgreSQL) without ever handing them a live credential. The agent's process receives decoys; a local proxy on `127.0.0.1:9543` (PostgreSQL adapter on `9544`) swaps them for the real credential on the way out, enforces the Connections approved in the Phase Console, and blocks calls that would mint new credentials.

```bash
phase ai enable --harness claude-code   # install the hook/plugin and skills for one harness; repeat for others
phase ai status                          # setup, proxy health, Connections, CA expiry
phase ai disable
```

- **Claude Code and OpenCode** get the Phase environment automatically: provider CLIs just work while the proxy runs, and fall back to failing on the decoy (never to ambient credentials) when it is down.
- **Cursor, Codex and Devin** run Phase-managed commands explicitly with `phase ai exec -- <command>` (`--connection <id>` picks one of several identities for a service); `phase ai run -- <agent>` launches a harness inside the environment.
- **Remote sandboxes** that cannot run the CLI use a relay: `phase relay start --advertise-host <host> --tls-cert <pem> --tls-key <pem>` on a machine logged in with an Agent token prints one line that bootstraps a sandbox over curl.
- Two skills are installed per harness: `phase-cli-ai-relay` (the proxy, Connections and requests) and `phase-cli-app-secrets` (Phase app secrets). Agents reach the proxy's control API at `http://phase.invalid` and can request new Connections, which a human approves in the Console.

`phase ai enable` creates a per-installation CA (valid 90 days, renewed automatically) and offers to trust it for the current user; it never changes system-wide trust or requires sudo.

## Development

### Prerequisites

- [Go](https://go.dev/dl/) 1.25 or later

### Project structure

```text
src/
├── main.go          # Entrypoint
├── cmd/             # Cobra command definitions
├── internal/        # Agent API, runtime, and proxy internals
├── pkg/
│   ├── ai/          # Agent detection and embedded skill
│   ├── config/      # Config file handling
│   ├── keyring/     # OS keyring integration
│   ├── proxy/       # CA, environment, routing, and injection helpers
│   └── version/     # Version constant
└── go.mod
```

### Run from source

```bash
cd src
go run main.go --help
```

### Build a binary

```bash
cd src
go build -o phase .
./phase --version
```

You can set the version at build time with `-ldflags`:

```bash
go build -ldflags "-X github.com/phasehq/cli/pkg/version.Version=2.0.0" -o phase .
```

### Install locally (development)

Build and install to `/usr/local/bin` so `phase` is available globally:

```bash
cd src
sudo go build -o /usr/local/bin/phase .
phase --version
```

Or if `$GOPATH/bin` is in your `$PATH`:

```bash
cd src
go build -o $(go env GOPATH)/bin/phase .
```

### Run tests

```bash
cd src
go test ./...
```

### Local SDK development

The CLI uses the Phase Go SDK via a `replace` directive in `go.mod`. To develop against a local copy of the SDK:

```go
// go.mod
replace github.com/phasehq/golang-sdk/v2 => /path/to/your/golang-sdk
```
