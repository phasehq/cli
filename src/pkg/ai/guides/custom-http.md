# Custom HTTP Connections

A member can define a Connection for any HTTP service Phase has no packaged Integration for: which hosts and paths, and where the secret goes (a header, Basic auth, or a query parameter). Its `serviceType` is `http`. Call the service normally. If the request carries nothing at the configured place, the proxy adds the live credential; if it carries the decoy from the environment, the proxy swaps it. Any other value there is refused.

## Read your Connections

The answer is served locally and never contains a secret or a decoy:

```bash
curl --fail --silent --show-error http://phase.invalid/v1/connections
curl --fail --silent --show-error http://phase.invalid/v1/connections/<connection-id>
```

An `http` Connection carries its full `definition`, `valueRevision`, and `keyVersion` beside the fields every Connection has.

## Ask for a change

You never change a Connection yourself, and you can never supply a secret value. Ask for the change as an `action` on a request; a member reviews it in the Console and enters any secret there. The `kind` must match the action:

| To | `kind` | `action` |
| --- | --- | --- |
| request a new Connection | `setup` | `{"type": "agent_connection.create", "version": 1, "serviceType": "http", "name": "<name>", "definition": {…}}` |
| request a change | `connection_update` | `{"type": "agent_connection.update", "version": 1, "connectionId": "<id>", "name": "<optional new name>", "definition": {…}}` |
| ask for a new secret | `credential_update` | `{"type": "agent_connection.secret_update", "version": 1, "connectionId": "<id>"}` |
| ask to remove it from this Workflow | `connection_removal` | `{"type": "agent_connection.remove", "version": 1, "connectionId": "<id>"}` |

```http
POST http://phase.invalid/v1/requests
Content-Type: application/json

{
  "kind": "setup",
  "title": "Connect the Example API",
  "markdown": "The task reads invoices from the Example API.",
  "action": {
    "type": "agent_connection.create",
    "version": 1,
    "serviceType": "http",
    "name": "Example API",
    "definition": {
      "specVersion": 1,
      "hosts": [{"match": "exact", "value": "api.example.com", "port": 443, "path": "/v1/*"}],
      "fields": [{"name": "token", "kind": "secret", "source": {"type": "sealed"}, "env": "EXAMPLE_API_KEY"}],
      "injections": [{"type": "header", "name": "Authorization", "prefix": "Bearer ", "field": "token", "whenAbsent": "attach"}]
    }
  }
}
```

- The action is what the member reviews. A `title` (at most 120 characters) and a `markdown` reason are welcome but not required.
- Send the whole requested `definition`, never a patch. To change a Connection, start from the definition `/v1/connections/<connection-id>` returns and change only what the task needs. Ask for the narrowest hosts and paths.
- An injection `type` is `header` (`name`, optional `prefix`), `query` (`name`), or `basic` (`usernameField` names an `identifier` field that carries its `value`; `field` names the secret). `whenAbsent` is `attach` or `block`. The Console validates the definition and says what to correct.
- A `secret` field says where a value goes and never contains it. A request that puts a `value` on anything but an `identifier` field is refused before it leaves this machine. Never put a secret in a title, a reason, or a name, and never ask the human to paste one into chat.
- A changed host list makes the member enter the secret again; that is expected.
- The credential travels only over HTTPS. A plain `http://` request to the Connection is refused unless the Connection sets `"allowPlainHttp": true`; request that only for a service with no HTTPS endpoint.
- After a member replaces a secret, the proxy picks it up within about 15 seconds, or right after the service answers 401 or 403. To fetch it immediately, send an empty `POST http://phase.invalid/v1/refresh`, then retry once. The refresh endpoint is only for custom Connections.

## Presets

For some well-known services (Anthropic, Stripe, Slack, Linear, Sentry, OpenAI, Datadog, a generic MCP server) a Connection can be asked for by preset, without writing a definition. List the presets, then name one in place of `definition`:

```bash
curl --fail --silent --show-error http://phase.invalid/v1/presets
```

```json
{"kind": "setup", "title": "Connect Stripe", "action": {"type": "agent_connection.create", "version": 1, "serviceType": "http", "name": "Stripe", "preset": "stripe"}}
```

Send `hosts` beside `preset` only for a preset whose `hostsEditable` is true, such as a self-hosted service. A member still enters the secret in the Console. Packaged Phase services (GitHub, GitLab, Cloudflare, Vercel, Render, Railway, Supabase) are not presets: request them as in `phase ai guide connections`.

## Hosts without a Connection

When a service answers 401 or 403 and no Connection covers its host, or the proxy refuses a host with `unbound_host_blocked`, fetch the hints:

```bash
curl --fail --silent --show-error http://phase.invalid/v1/hints
```

Each hint names the host and carries a `request` that asks for a Connection to it: the ordinary `setup` request for a Phase service (the hint's `service`) when the host belongs to one, otherwise by preset when the host belongs to one. Send it unchanged, or adjust its `definition` first when the service does not take a bearer token in the `Authorization` header. Only ask when the human's task needs that service through Phase.
