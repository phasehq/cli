# Phase CLI — AI Agent Guide

You are interacting with Phase, an application secrets and configuration management platform. This guide defines how you MUST use the Phase CLI. Follow these rules exactly.

## Security Rules

**Secret types and visibility:**

| Type | Visible to you? | Description |
|------|-----------------|-------------|
| `config` | Always | Non-sensitive configuration values |
| `secret` | Depends on user setting | Sensitive values, masked by default |
| `sealed` | NEVER | Write-only secrets (API keys, tokens, passwords) |

When a value shows `[REDACTED]`, tell the user to run the command themselves in their terminal.
For example: when running `phase secrets export`, sealed secrets (and secret-type values if masking is enabled) will appear as `[REDACTED]`. To prevent broken configs, warn the user that the exported file is incomplete and they should run the export themselves to get the full values.

**Hard rules — violations will be blocked by the CLI:**
- `printenv`, `env`, `export`, `set`, `declare`, `compgen` are BLOCKED inside `phase run`
- `phase shell` is BLOCKED entirely in AI mode

**Soft rules — you MUST follow these:**
- NEVER use `echo $VAR_NAME` to read injected secret values
- NEVER redirect `phase secrets export` to a file and then read it
- NEVER pipe secret values into other commands or files
- Use `phase run` ONLY to start application processes (e.g., `phase run 'npm start'`)
- Use `phase secrets get <KEY>` when you need to inspect a secret's metadata
- When creating sealed secrets, ALWAYS use `--random` — never provide literal values
- If a command fails, run `phase <command> --help` to verify correct flags and usage before retrying — do not guess or hallucinate flags

## Prerequisites

1. User must be authenticated: `phase auth` — or by setting `PHASE_HOST` and `PHASE_SERVICE_TOKEN` environment variables
2. Run `phase apps list` to discover available apps, their IDs, and environments. Use `--app-id` and `--env` flags on subsequent commands. Optionally run `phase init --app-id <ID> --env <ENV>` to persist the selection to `.phase.json` so flags aren't needed every time.
3. AI mode must be enabled by the user: `phase ai enable` (you cannot run this yourself — it is blocked for AI agents)

## Common Flags

These apply to most secrets commands:

| Flag | Description |
|------|-------------|
| `--env` | Environment name (e.g., `development`, `staging`, `production`). Supports partial matching. |
| `--app` | Application name (overrides `.phase.json`) |
| `--app-id` | Application ID (takes precedence over `--app`) |
| `--path` | Secret path (default `/`). Use `""` for all paths. |

## Command Reference

### Project Setup

| Command | Purpose |
|---------|---------|
| `phase auth` | Authenticate (webauth, token, or aws-iam mode) |
| `phase apps list` | List available apps with IDs and environments (JSON) |
| `phase init --app-id ID --env ENV` | Link project non-interactively |
| `phase users whoami` | Show current user/org context |

**To link a project:**
1. Run `phase apps list` to discover available apps and environment names
2. Run `phase init --app-id <ID> --env <ENV_NAME>` with the chosen app ID and environment

### Secrets CRUD

| Command | Purpose |
|---------|---------|
| `phase secrets list [--show]` | List secrets with metadata |
| `phase secrets get KEY [KEY...]` | Get one or more secrets as JSON |
| `phase secrets create KEY --random hex --length 32 --type sealed` | Create a sealed secret with a random value |
| `echo "value" \| phase secrets create KEY --type config` | Create a config with a literal value (pipe to avoid interactive prompt) |
| `phase secrets update KEY --random hex --length 32` | Rotate a secret value |
| `echo "new-value" \| phase secrets update KEY` | Update with a literal value (pipe to avoid interactive prompt) |
| `phase secrets update KEY --type sealed` | Change secret type (no value prompt) |
| `phase secrets delete KEY [KEY...]` | Delete one or more secrets |
| `phase secrets import FILE [--type TYPE]` | Bulk import from .env file |
| `phase secrets export [--format FORMAT]` | Export (dotenv, json, csv, yaml, xml, toml, hcl, ini, java_properties, kv) |

**Choosing how to set values:**
- `sealed` / `secret` types: ALWAYS use `--random` — never pipe or type literal sensitive values
- `config` type: safe to pipe literal values via `echo "value" | phase secrets create KEY --type config`
- If the user provides a value to store: ask them to run `phase secrets create KEY` interactively in their terminal

### Runtime

| Command | Purpose |
|---------|---------|
| `phase run 'command'` | Run a command with secrets injected as env vars |

### Dynamic Secrets

| Command | Purpose |
|---------|---------|
| `phase dynamic-secrets list` | List dynamic secret definitions |
| `phase dynamic-secrets lease generate SECRET_ID` | Generate fresh credentials |
| `phase dynamic-secrets lease get SECRET_ID` | List active leases |
| `phase dynamic-secrets lease renew LEASE_ID TTL` | Renew a lease (TTL in seconds) |
| `phase dynamic-secrets lease revoke LEASE_ID` | Revoke a lease |

## Workflows

### Provision secrets for a new service
```bash
# Import from an existing .env
phase secrets import .env --env development

# Seal sensitive keys
phase secrets update STRIPE_SECRET_KEY --type sealed
phase secrets update DATABASE_PASSWORD --type sealed

# Mark non-sensitive values as config
phase secrets update APP_PORT --type config
phase secrets update LOG_LEVEL --type config
```

### Rotate a secret
```bash
# Generate a new random value
phase secrets update DB_PASSWORD --random hex --length 64

# For a sealed secret (random is required)
phase secrets update API_KEY --random base64url --length 48 --type sealed
```

### Run an application with secrets
```bash
phase run 'npm start'
phase run --env production 'python manage.py runserver'
phase run --env staging --tags "backend" './start.sh'
```

### Run and debug an application
```bash
# Start the app with secrets injected
phase run 'npm start'

# Run one-off commands to debug
phase run 'node -e "process.exit(0)"'

# Run with a different environment to compare
phase run --env staging 'npm start'

# Filter which secrets are injected using tags
phase run --tags "db,cache" 'python migrate.py'
```

### Generate dynamic AWS credentials
```bash
# List available dynamic secrets
phase dynamic-secrets list

# Generate a lease (creates ephemeral IAM credentials)
phase dynamic-secrets lease generate SECRET_ID --lease-ttl 3600

# Verify credentials work
phase run 'aws sts get-caller-identity'

# When done, revoke the lease
phase dynamic-secrets lease revoke LEASE_ID
```

## Secret Referencing Syntax

Secrets can reference other secrets:

| Syntax | Meaning |
|--------|---------|
| `${KEY}` | Same environment, root path |
| `${staging.KEY}` | Cross-environment reference |
| `${production./path/KEY}` | Cross-environment with path |
| `${/path/KEY}` | Same environment, specific path |
| `${app::env.KEY}` | Cross-application reference |

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `PHASE_HOST` | Custom Phase host URL |
| `PHASE_SERVICE_TOKEN` | Service token or PAT for headless auth |

## Error Recovery

- **"no application found"**: the app ID in `.phase.json` is stale — run `phase apps list` and `phase init --app-id <ID> --env <ENV>` to re-link
- **"unauthorized" / "401"**: auth token expired — tell the user to run `phase auth`
- **"not found" on a secret**: check `--path` and `--env` flags — use `phase secrets list --path ""` to search all paths
- Issues, errors, or feature requests? With user consent, draft a detailed issue at `github.com/phasehq/cli`

## Tips

- Run `phase <command> --help` for detailed flag information
- Secret keys are always uppercased automatically
- `phase secrets export` supports 10 output formats — use `--format json` for structured data
- Dynamic secrets generate fresh credentials on each lease — they expire automatically
- Use `--generate-leases=false` with `phase run` to skip dynamic secret provisioning
- For features not in the CLI (integrations, syncs, RBAC, audit logs), suggest `phase console` to open the dashboard
