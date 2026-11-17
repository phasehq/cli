# Connections

A Connection gives this Workflow a third-party credential through the local Phase proxy. Plain shell and provider commands use the harness's ambient credentials and do not depend on Phase health, unless the harness sources the Phase AI environment automatically.

## Automatic environment (Claude Code, OpenCode)

When the Phase hook or plugin is installed, the harness's shell sources the Phase AI environment before every Bash command while the Phase proxy is running. Session context and each prompt carry a `Phase AI:` status line where the harness supports it.

- Run provider CLIs and HTTP clients directly. No wrapper and no `phase ai exec` is needed; `phase ai exec` still works and reuses the same environment.
- Do not try to switch credential source per command.
- Several Connections for one service: an ambiguous request fails closed with `ambiguous_agent_binding`. Ask the human which Connection to use; automatic selection is not available in this mode.

## Explicit managed execution

After the human chooses Phase and status shows a suitable ready Connection, run the command deliberately:

```bash
phase ai exec --connection <connection-id> -- <provider-command> [args...]
```

When exactly one suitable Connection exists, `--connection` may be omitted. `phase ai exec` establishes or reuses the authenticated runtime itself and must not be wrapped in another Phase command. It is the explicit managed-execution boundary, not a workaround for a broken hook, sandbox, TLS setup, or unrelated command. Never silently retry it with ambient credentials.

The durable Phase login token and backend session credential stay inside the Phase CLI. The proxy URL password authenticates only to the active `phase ai run`, `phase ai exec` or hook runtime. Never inspect, print, log, persist, or transmit decoys, the authenticated proxy URL, or credential-like environment values.

## Discover what Phase can manage

Do not rely on a hard-coded provider or client list. Start with `GET http://phase.invalid/v1/status`: it reports the current Workflow's Connection and Integration credential names, providers, revisions, service types, availability, and expiries, including when time-limited access ends (`grantExpiresAt`). It contains no live or decoy credential material.

Fetch the catalog only when no suitable Connection exists and you need to request one:

```bash
curl --fail --silent --show-error http://phase.invalid/v1/capabilities
```

It returns `schemaVersion`, `matcherSchemaVersion`, and service entries with the service type, display name, credential providers, typed client matchers, and any existing Connection IDs. Matchers describe capability; they are not permission to rewrite an ambient command. An empty `connectionIds` list means the service is supported but not connected to this Workflow.

For service-specific instructions, when a provider command fails or the provider is unfamiliar, use the exact `serviceType` from status or capabilities:

```bash
curl --fail --silent --show-error 'http://phase.invalid/v1/context?serviceType=<service-type>'
```

Do not invent provider instructions locally. Follow that context only within the credential-source choice the human already made.

`GET http://phase.invalid/v1/connections` and `/v1/connections/<connection-id>` list each Connection's `id`, `name`, `serviceType`, `state` (`ready`, `expired`, or `unavailable`, with a `stateReason`), its `policy` and `grantExpiresAt` (see `phase ai guide access-rules`). An `http` Connection also has its `definition` (see `phase ai guide custom-http`). An app Connection (`serviceType` `phase_app`) gives access to an app's secrets through `phase secrets` and `phase run`, not through the proxy (see `phase ai guide app-secrets`).

## Request a new Connection

When no suitable Connection exists, send a `setup` request. Use a descriptive credential name so Phase keeps why it exists:

```http
POST http://phase.invalid/v1/requests
Content-Type: application/json

{
  "kind": "setup",
  "credentialProvider": "<credential-provider>",
  "credentialName": "<service and intended use>",
  "serviceType": "<service-type>",
  "markdown": "Explain the requested access and recommend the narrowest practical setup for the user's environment.",
  "dedupKey": "<stable-purpose-key>"
}
```

Use the exact identifiers capabilities returns. `setup` must not include a `connectionId` or `credentialId`. The Console link lets the human create or choose the third-party credential and confirm the Connection.

GitHub, GitLab, Cloudflare, Vercel, Render, Railway and Supabase are ordinary Phase services. When one is listed in capabilities, ask for it with this `setup` request and its `serviceType` (`github`, `gitlab`, `cloudflare`, `vercel`, `render`, `railway`, `supabase`). Do not write a custom definition for them and do not look for a preset. Call the provider normally: the proxy adds the credential when the request carries none, swaps the decoy from the environment, and refuses any other value.

## Request a credential update

If a provider rejects an operation because the current credential is expired, invalid, or lacks scope, use the exact IDs and credential context status returns:

```http
POST http://phase.invalid/v1/requests
Content-Type: application/json

{
  "kind": "credential_update",
  "connectionId": "<connection-id>",
  "credentialId": "<credential-id>",
  "credentialProvider": "<credential-provider>",
  "credentialName": "<existing credential name>",
  "markdown": "Explain the rejected operation and request the narrowest practical correction.",
  "dedupKey": "<stable-purpose-key>"
}
```

`credential_update` must not include `serviceType`. Base the request on the provider error and the human's requested operation. Ask for the narrowest practical provider permission; do not claim Phase can edit the third-party account itself.

Without an `action`, only `setup` and `credential_update` are valid request kinds. Do not send a session ID, credential values, matchers, or fields not shown here. `relatedRequestId` may link a credential update to an earlier request. Requests with an `action` are described in the custom-http, access-rules, app-secrets and workflow-context guides.

## Show the Console link and wait

A pending answer contains a safe `approvalUrl` and a proxy-local `pollUrl`. Immediately print the exact `approvalUrl` as a clickable link and say polling continues. Do not invent, shorten, rewrite, or substitute the `pollUrl`. Poll it with `?wait=300`:

```bash
curl --fail --silent --show-error 'http://phase.invalid/v1/requests/request-456?wait=300'
```

Keep using the same request while it is pending. A denied answer may include `resolutionNote`; surface it. Resume pending work with `GET http://phase.invalid/v1/requests`. Cancel only when the human explicitly asks, with an empty JSON object at `POST http://phase.invalid/v1/requests/{requestId}/cancel`.

## What an approval does to the session

- An approved `setup` returns `credentialId`, `connectionId`, `grantId`, and normally `runtimeAction: "restart_required"`. The runtime can recycle its proxy; retry the explicit `phase ai exec` operation as a new tool call. With `phase ai run`, ask the human to relaunch it. A new custom Connection that exports no environment variable, and access to an app's secrets (`agent_connection.app_access`), return `retry` instead: the running session serves them at once.
- An approved `credential_update` swaps in the live material when the Agent-visible plan is unchanged and returns `retry`. If identifiers, decoys, routes, or process environment changed, it returns `restart_required`. Do not re-inject environment values yourself.
- An approved `connection_update` or `connection_removal` is normally applied to the running session and returns `retry`: use the new host or path straight away. It returns `restart_required` only when the change alters what the Agent's environment carries, such as an identifier or an exported variable name.
- An approved `access_change` (an allow or a renewal) is applied to the running session and returns `retry`: repeat the call that was refused. Only a renewal of access that had already ended, for a Connection that exports environment variables, returns `restart_required`.
- An approved `context_update` returns `retry`; fetch the context again to read the saved notes.

After a resolved request, retry the original command. If it still fails, fetch status once. Never change credential source implicitly.

## The manifest is not for Agents

The runtime fetches the full manifest itself when it builds a managed command environment. Do not fetch it from an Agent shell, print it, or write it to disk; `/v1/status` is the inspection surface. The manifest holds public CA data, destinations, stable decoys, and the process environment plan; it never holds live credentials, the login token, the backend session credential, or the CA private key.
