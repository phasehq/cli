# Phase Application Secrets — AI Agent Guide

Use this guide only to manage configuration records in a Phase Application and Environment. It does not grant runtime access to AWS, GitHub, PostgreSQL, or another provider.

## Boundary

- For provider connectivity, approvals, credentials, proxy, or TLS behavior, use the `phase-cli-ai-relay` skill and Phase Agent Connections.
- Never use Application Secrets as an alternate way to obtain provider credentials.
- With an Agent login (`phase auth --mode token`), `phase secrets list|get|create|update|delete|import|export`, `phase run`, `phase apps list` and `phase init` work for the apps and environments this Workflow has access to (next section). `phase shell`, `phase dynamic-secrets`, `--override`, `--toggle-override` and offline mode are not available to an Agent login.
- CLI output shows `secret` and `sealed` values as `[REDACTED]`; `config` values are shown. A masked value is expected and must not be worked around. `phase run` gives the values to the command it starts: never print, log, or copy them from there.
- Never ask the user to paste a sensitive value into chat or place one in a command, file, log, or environment variable.
- If a literal sensitive value is required, ask the user to enter it through the trusted Phase Console or an interactive terminal. An Agent may create or rotate sensitive values only with the CLI's `--random` option.
- Treat create, update, rotate, and delete operations as mutations. Perform them only when the user explicitly requests them, and confirm the Application, Environment, path, and key before a destructive operation.

If authentication is missing or expired, ask the user to run `phase auth` themselves. Do not inspect or replace their Phase authentication material.

## Access for an Agent login

`phase apps list` shows the apps and environments this Workflow can use now. Inside a Phase AI session, `GET http://phase.invalid/v1/connections` lists the same access as Connections with `serviceType` `phase_app`, each with its `app`, `environments`, what each kind of call does (`access`: `read`, `create`, `update`, `delete`, each `allow`, `ask`, or `block`), and `grantExpiresAt`.

Every call is checked by the Phase Console. When it refuses one, the command prints the reason and, when access can be asked for, a complete request: send that JSON unchanged to `POST http://phase.invalid/v1/requests` from inside a Phase AI session, show the human the `approvalUrl`, wait for approval, then run the command again. Outside a session the request cannot be filed; tell the human what the task needs. A blocked call cannot be requested. The request is one of:

```json
{"kind": "setup", "title": "Read secrets in <app> (<environment>)", "action": {"type": "agent_connection.app_access", "version": 1, "appId": "<app-id>", "environments": ["<environment>"], "access": "read"}}
{"kind": "access_change", "title": "Create, update and delete secrets", "action": {"type": "agent_grant.allow", "version": 1, "connectionId": "<connection-id>", "allow": {"classes": ["create", "update", "delete"]}}}
{"kind": "access_change", "title": "Renew access to <connection name>", "action": {"type": "agent_grant.renew", "version": 1, "connectionId": "<connection-id>"}}
```

`access` is `read` or `read_write`; the app may be named by `appName` instead of `appId`. Ask only for what the task needs. Only server-side encrypted apps can be used by an Agent.

Inside a Phase AI session, `phase run` does not inject a secret whose name the session reserves (proxy, CA and Phase variables, and provider credential variables such as `AWS_SECRET_ACCESS_KEY`); it names the ones it skipped on stderr.

## Select the Application and Environment

Discover the available non-secret scope:

```bash
phase apps list
```

Prefer explicit scope on every command:

```bash
phase secrets list --app-id APP_ID --env development --path / --generate-leases=false
```

When the user asks to link the current project, persist the selection in `.phase.json` non-interactively:

```bash
phase init --app-id APP_ID --env development
```

`--app-id` and `--env` override `.phase.json`. `--path /` selects the root path; use a specific path such as `--path /backend`. For metadata across all paths, pass `--path ""`.

## Inspect Metadata Safely

List keys and metadata without revealing sensitive values or generating dynamic leases:

```bash
phase secrets list --app-id APP_ID --env development --path /backend --generate-leases=false
```

Never add `--show`. Non-sensitive configuration values may be shown; a redacted or masked sensitive value is expected and must not be worked around.

## Safe CRUD and Rotation

Create a random write-only secret:

```bash
phase secrets create API_TOKEN --app-id APP_ID --env development --path /backend --type sealed --random base64url --length 48
```

Create or update a non-sensitive config value:

```bash
printf '%s' 'info' | phase secrets create LOG_LEVEL --app-id APP_ID --env development --path /backend --type config
printf '%s' 'debug' | phase secrets update LOG_LEVEL --app-id APP_ID --env development --path /backend
```

Only literal values that are genuinely non-sensitive may be passed this way.

Rotate a secret without exposing the new value:

```bash
phase secrets update API_TOKEN --app-id APP_ID --env development --path /backend --type sealed --random base64url --length 48
```

Change only the stored type:

```bash
phase secrets update API_TOKEN --app-id APP_ID --env development --path /backend --type sealed
```

Delete explicitly named keys only after confirming the exact scope:

```bash
phase secrets delete OLD_KEY --app-id APP_ID --env development --path /backend
```

If a command rejects a flag, run `phase <command> --help` and verify the supported syntax instead of guessing. If an item is not found, re-check the Application, Environment, and path before retrying.
