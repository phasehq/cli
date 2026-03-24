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
  ai enable                         🪄 Enable AI integrations and configure secret visibility
  ai disable                        🚫 Disable AI integrations and remove skill docs
  ai skill                          📄 Print the Phase AI skill document
  console                           🖥️ Open the Phase Console in your browser
  docs                              📖 Open the Phase CLI Docs in your browser
  completion                        ⌨️ Generate the autocompletion script for the specified shell

Flags:
  -h, --help      help for phase
  -v, --version   version for phase
```

## Features

- **End-to-end encryption** — secrets are encrypted client-side before leaving your machine
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
- **AI agent integration** — skill-based integration with Claude Code, Cursor, VS Code Copilot, Codex, and OpenCode with automatic value redaction and safety guardrails
- **Multiple auth methods** — web-based login, personal access tokens, service account tokens, and AWS IAM identity auth
- **Multi-user & multi-org** — switch between Phase accounts, orgs, and self-hosted instances
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

### AI integration

Enable AI agent support (installs a skill doc for your AI coding tool):

```bash
phase ai enable
```

This installs the Phase skill to your chosen AI tool (Claude Code, Cursor, VS Code Copilot, Codex, or OpenCode) and configures secret visibility. Sealed secrets are never revealed to AI agents regardless of settings.

## Development

### Prerequisites

- [Go](https://go.dev/dl/) 1.24 or later

### Project structure

```
src/
├── main.go          # Entrypoint
├── cmd/             # Cobra command definitions
├── pkg/
│   ├── ai/          # AI agent detection, skill doc, redaction
│   ├── config/      # Config file handling (~/.phase/, .phase.json)
│   ├── display/     # Output formatting (tree view, tables)
│   ├── errors/      # Error types
│   ├── keyring/     # OS keyring integration
│   ├── phase/       # Phase client helpers (auth, init)
│   ├── util/        # Misc utilities (color, spinner, browser)
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
