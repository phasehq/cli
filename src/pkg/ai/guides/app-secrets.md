# App secrets

Use this guide to manage configuration records in a Phase app and environment. It does not grant runtime access to AWS, GitHub, PostgreSQL, or another provider: for that, use Connections (`phase ai guide connections`). Never use app secrets as another way to obtain provider credentials.

## Boundary

- With an Agent login (`phase auth --mode token`), `phase secrets list|get|create|update|delete|import|export`, `phase run`, `phase apps list` and `phase init` work for the apps and environments this Workflow has access to. `phase shell`, `phase dynamic-secrets`, `--override`, `--toggle-override` and offline mode are not available to an Agent login.
- With a personal or service account token, every command works as it does for that person or account. An Agent token gives AI tools narrower access; the human can switch with `phase auth --mode token`.
- `phase secrets get` and `list` show `secret` and `sealed` values as `[REDACTED]`; `config` values are shown. A masked value is hidden on purpose: never try to recover, decode, or work around it. `phase secrets export` writes the real values: use it only to write a file or pipe to a program (`phase secrets export > .env`), and never print its output into the conversation, log it, or copy it elsewhere. `phase run` gives the values to the command it starts: never print, log, or copy them from there.
- Never ask the human to paste a sensitive value into chat or place one in a command, file, log, or environment variable. If a literal sensitive value is required, ask the human to enter it through the Phase Console or an interactive terminal. An Agent may create or rotate sensitive values only with the CLI's `--random` option.
- Create, update, rotate, and delete are changes. Make them only when the human explicitly asks, and confirm the app, environment, path, and key before a destructive one.
- If authentication is missing or expired, ask the human to run `phase auth` themselves. Do not inspect or replace their Phase authentication material.

## Access for an Agent login

`phase apps list` shows the apps and environments this Workflow can use now. Inside a Phase AI session, `GET http://phase.invalid/v1/connections` lists the same access as Connections with `serviceType` `phase_app` and `state` `active` or `expired`, each with its `app`, `environments`, what each kind of call does (`access`: `read`, `create`, `update`, `delete`, each `allow`, `ask`, or `block`), and `grantExpiresAt`.

Every call is checked by the Phase Console. When it refuses one, the command prints the reason and, when access can be asked for, a complete request: send that JSON unchanged to `POST http://phase.invalid/v1/requests` from inside a Phase AI session, show the human the `approvalUrl`, wait for approval, then run the command again. Outside a session the request cannot be sent; tell the human what the task needs. A blocked call cannot be requested. The request is one of:

```json
{"kind": "setup", "title": "Read secrets in <app> (<environment>)", "action": {"type": "agent_connection.app_access", "version": 1, "appId": "<app-id>", "environments": ["<environment>"], "access": "read"}}
{"kind": "access_change", "title": "Allow create secrets on <connection name>", "action": {"type": "agent_grant.allow", "version": 1, "connectionId": "<connection-id>", "allow": {"classes": ["create"]}}}
{"kind": "access_change", "title": "Renew access to <connection name>", "action": {"type": "agent_grant.renew", "version": 1, "connectionId": "<connection-id>"}}
```

`access` is `read` or `read_write`; the app may be named by `appName` instead of `appId`. Ask only for what the task needs. Only server-side encrypted apps can be used by an Agent. An approved app access request returns `retry`: run the command again. An approver may grant fewer environments than asked: `phase apps list` shows what was granted. When `resolution.followOnRequestId` is set, the rest is still waiting in that request for another approver: poll it, do not ask again.

Inside a Phase AI session, `phase run` does not inject a secret whose name the session reserves (proxy, CA and Phase variables, and provider credential variables such as `AWS_SECRET_ACCESS_KEY`); it names the ones it skipped on stderr.

## Select the app and environment

Discover the available scope, then prefer explicit scope on every command:

```bash
phase apps list
phase secrets list --app-id APP_ID --env development --path / --generate-leases=false
```

When the human asks to link the current project, save the selection in `.phase.json` non-interactively:

```bash
phase init --app-id APP_ID --env development
```

`--app-id` and `--env` override `.phase.json`. `--path /` selects the root path; use a specific path such as `--path /backend`. For metadata across all paths, pass `--path ""`.

## Inspect metadata safely

List keys and metadata without revealing sensitive values or generating dynamic leases:

```bash
phase secrets list --app-id APP_ID --env development --path /backend --generate-leases=false
```

Never add `--show`. Non-sensitive configuration values may be shown; a redacted or masked sensitive value is expected and must not be worked around.

## Create, update, rotate, delete

Create a random write-only secret:

```bash
phase secrets create API_TOKEN --app-id APP_ID --env development --path /backend --type sealed --random base64url --length 48
```

Create or update a non-sensitive config value (only genuinely non-sensitive literals may be passed this way):

```bash
printf '%s' 'info' | phase secrets create LOG_LEVEL --app-id APP_ID --env development --path /backend --type config
printf '%s' 'debug' | phase secrets update LOG_LEVEL --app-id APP_ID --env development --path /backend
```

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

If a command rejects a flag, run `phase <command> --help` and check the supported syntax instead of guessing. If an item is not found, re-check the app, environment, and path before retrying.
