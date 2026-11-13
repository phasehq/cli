# Phase AI proxy: the `phase.invalid` control API

The local proxy (`phase ai` daemon, `phase ai run/exec/serve`) serves a small HTTP
control API on the reserved host `http://phase.invalid`. The host never resolves
in DNS; requests only reach it *through the proxy*, so the proxy capability is
the authentication. Everything below is implemented in
`internal/aiproxy/control.go` (routes), `connections.go` (Connection reads),
`bootstrap.go` (manifest) and `selection.go` (per-Connection environment). Wire
types live in
`internal/agentapi/types.go`, `internal/remoteapi/types.go` and the Go SDK
(`phase/agents/types.go`).

All IDs, URLs and values in the examples are dummies.

## 1. Reaching it

| | |
|---|---|
| Base URL | `http://phase.invalid` (plain `http`; the proxy answers before any upstream) |
| Transport | Any HTTP client whose proxy settings point at the Phase proxy. In transparent mode and under `phase ai run/exec`, `HTTP_PROXY`/`HTTPS_PROXY` already carry the credentials, so `curl http://phase.invalid/v1/status` just works. |
| Authentication | `Proxy-Authorization: Basic base64("phase:<capability>")`. The capability is the per-process proxy password that only the runtime hands out; it is never a Phase token. |
| Connection selection | Username `phase.<connectionId>` instead of `phase` scopes the request to one Connection (used for `/v1/connections/{id}/environment` and for proxied traffic when two Connections share a host). |
| Content type | JSON in, JSON out. `Cache-Control: no-store` on every control response. |
| Query strings | Rejected (400 `invalid_control_query`) except `?wait=` on request creation/polling and `?serviceType=` on context. |
| Browser safety | A `POST` carrying `Origin`, `Referer` or a `Sec-Fetch-Site` other than `none` is refused with 403 `browser_control_mutation_rejected`. |
| Remote (relay) mode | Same routes over the relay's TLS proxy (`phase relay start`), except `GET /v1/discover`, `POST /v1/revoke` and `POST /v1/rotate`, which are local-only. `GET /v1/bootstrap` exists only on a relay. |
| Limits | Request bodies ≤ 64 KiB. IDs match `^[A-Za-z0-9._-]{1,128}$`. `markdown` ≤ 16 KiB. `title` ≤ 120 characters. `wait` is 0–300 whole seconds. |

Missing or wrong capability on **any** proxied request:

```http
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="Phase Agent session"
X-Phase-Error-Code: invalid_runtime_capability
Content-Type: application/json

{"error":{"code":"invalid_runtime_capability","message":"A valid Phase AI runtime capability is required.","retryable":false,"details":{}}}
```

## 2. Who calls what, and when

| Caller | Routes | When |
|---|---|---|
| The Agent, following the `phase-cli` skill | `GET /v1/capabilities`, `GET /v1/status` | When the human asks for Phase, or to find out whether Phase can manage a service. In transparent mode the per-prompt status line already names the ready Connections, so this is mostly for service discovery. |
| The Agent | `GET /v1/context?serviceType=…` | Before using a service through Phase: provider-specific instructions and limitations, rendered by Console. |
| The Agent | `POST /v1/requests`, `GET /v1/requests/{id}?wait=300`, `GET /v1/requests`, `POST /v1/requests/{id}/cancel` | No suitable Connection exists (`setup`), the provider rejected the credential (`credential_update`), or the Agent proposes a change to a custom HTTP Connection (an `action`). The Agent prints `approvalUrl` for the human, then long-polls. |
| The Agent | `GET /v1/connections`, `GET /v1/connections/{id}` | To read what its Connections are, and to get the current definition of a custom HTTP Connection before proposing a change. Served from the session the proxy already holds. |
| The Agent | `POST /v1/refresh` | After a member replaced the secret of a custom HTTP Connection, to use the new value now instead of at the next periodic refresh. |
| `phase ai exec --connection <id>` (the CLI, not the Agent) | `GET /v1/connections/{id}/environment` | Builds the per-Connection process environment (decoys + scoped proxy URL) for one command. Sensitive: contains the proxy password. |
| Hook wrapper `phase ai __harness-exec` and `phase ai exec` attach | `GET /.well-known/agents` (manifest) | Right before running a wrapped command, to fetch the exact process environment of the live runtime. Sensitive; the skill forbids the Agent from fetching it. |
| Claude Code hooks in transparent mode | nothing | SessionStart and heartbeat read local files only; the shell sources `~/.phase/ai/env.sh`. |
| `phase ai disable`, daemon replacement | `POST /v1/revoke` | Authenticated local shutdown: Console revokes the session, the proxy stops. |
| Nothing today | `POST /v1/rotate`, `GET /v1/discover` | Lifecycle/diagnostic routes kept for tooling and tests. |

## 3. Error envelope

Every control error (and every non-AWS proxied failure) uses the same body and
also sets `X-Phase-Error-Code`. Proxied failures that belong to a Connection add
`X-Phase-Connection-Id` and `X-Phase-Grant-Id`.

```json
{
  "error": {
    "code": "invalid_control_request",
    "message": "Use setup with serviceType or credential_update with connectionId and credentialId; credentialProvider, credentialName, markdown, and an optional dedupKey are required. Or send an action of a known type with version 1 under its request kind; an action never carries a secret value.",
    "retryable": false,
    "details": {}
  }
}
```

Console-side failures are relayed with Console's status, code and message;
unreachable Console becomes 502 `agent_control_relay_failed` with
`retryable: true`.

## 4. Endpoints

### GET /v1/status

Printable summary of the current Workflow session. Safe to show the human; no
credential, decoy or proxy material.

```http
GET /v1/status HTTP/1.1
Host: phase.invalid
```

```json
{
  "schemaVersion": 1,
  "kind": "phase.ai.status",
  "safeToPrint": true,
  "connections": [
    {
      "connectionId": "c0a80101-0000-4000-8000-0000000000a1",
      "name": "AWS identity checks for agent",
      "credentialId": "c0a80101-0000-4000-8000-0000000000c1",
      "credentialName": "aws-agent-readonly",
      "credentialProvider": "aws",
      "credentialRevision": "r-7",
      "serviceType": "aws",
      "protocol": "http",
      "state": "ready",
      "expiresAt": "2026-10-17T18:00:00Z"
    },
    {
      "connectionId": "c0a80101-0000-4000-8000-0000000000a2",
      "name": "PostgreSQL agent psql access",
      "credentialId": "c0a80101-0000-4000-8000-0000000000c2",
      "credentialName": "analytics-readonly",
      "credentialProvider": "postgres",
      "serviceType": "postgres",
      "protocol": "postgres",
      "state": "ready"
    }
  ],
  "links": {
    "listRequests": "http://phase.invalid/v1/requests",
    "cancelRequest": "http://phase.invalid/v1/requests/{requestId}/cancel",
    "connectionEnvironment": "http://phase.invalid/v1/connections/{connectionId}/environment",
    "connections": "http://phase.invalid/v1/connections",
    "connection": "http://phase.invalid/v1/connections/{connectionId}",
    "capabilities": "http://phase.invalid/v1/capabilities",
    "status": "http://phase.invalid/v1/status",
    "context": "http://phase.invalid/v1/context",
    "createRequest": "http://phase.invalid/v1/requests",
    "pollRequest": "http://phase.invalid/v1/requests/{requestId}"
  }
}
```

`state` is `ready`, `expired` (credential expiry passed) or `unavailable` (not
authorized, or a sealed value the proxy could not open). A custom HTTP
Connection appears with `serviceType` and `credentialProvider` `http`; its
`credentialId` is the Connection ID and `credentialRevision` is the value
revision.

### GET /v1/connections and GET /v1/connections/{connectionId}

What the Agent may read about its Connections. Both are answered from the
session configuration the proxy already holds: no Console call, so they cost
nothing against the plan rate limit. They never carry a secret, a decoy, or
session material; a payload that would is refused with 502
`unsafe_connection_response`.

```json
{
  "schemaVersion": 1,
  "kind": "phase.ai.connections",
  "connections": [
    {
      "id": "c0a80101-0000-4000-8000-0000000000b1",
      "name": "Example API",
      "serviceType": "http",
      "state": "ready",
      "definition": {
        "specVersion": 1,
        "hosts": [{ "match": "exact", "value": "api.example.com", "port": 443, "path": "/v1/*" }],
        "fields": [
          { "name": "token", "kind": "secret", "source": { "type": "sealed" }, "env": "EXAMPLE_API_KEY", "decoyPrefix": "sk-" },
          { "name": "username", "kind": "identifier", "value": "alice" }
        ],
        "injections": [
          { "type": "header", "name": "Authorization", "prefix": "Bearer ", "field": "token", "whenAbsent": "attach" }
        ],
        "preset": "bearer"
      },
      "valueRevision": 3,
      "keyVersion": 2
    },
    {
      "id": "c0a80101-0000-4000-8000-0000000000a1",
      "name": "AWS identity checks for agent",
      "serviceType": "aws",
      "state": "ready"
    }
  ]
}
```

`definition`, `valueRevision` and `keyVersion` exist only for `serviceType`
`http`. `state` uses the same values as status. When a custom Connection's
value cannot be used, `stateReason` names why, for example
`sealed_material_host_mismatch` (the value was entered for a different set of
hosts and a member must enter it again),
`sealed_material_agent_key_unavailable`, `material_missing` (the session
carried no value for it) or `material_exposed` (the value also appears inside
something the Agent can see, such as an identifier or a decoy, so the proxy
withheld it; a member must enter a different value). Only that Connection is
affected. A packaged service in the same position still refuses the session.

`GET /v1/connections/{connectionId}` returns one entry flat, with
`"kind": "phase.ai.connection"`:

```json
{ "schemaVersion": 1, "kind": "phase.ai.connection", "id": "c0a80101-0000-4000-8000-0000000000b1", "name": "Example API", "serviceType": "http", "state": "ready", "definition": { "…": "…" }, "valueRevision": 3, "keyVersion": 2 }
```

Errors: 400 `invalid_connection_id`, 404 `connection_unavailable` when the ID
is not part of this session.

### GET /v1/capabilities

Versioned catalog of every service this Phase instance can manage, relayed from
Console, plus the IDs of Connections that already exist in this Workflow. The
matchers are descriptive metadata (which executables and URI schemes a service
usually involves); they never grant anything.

```json
{
  "schemaVersion": 1,
  "matcherSchemaVersion": 1,
  "kind": "phase.ai.capabilities",
  "sessionUid": "sess_01HZX9K3M2",
  "services": [
    {
      "serviceType": "aws",
      "displayName": "Amazon Web Services",
      "credentialProviders": ["aws", "aws_assume_role"],
      "clientMatchers": [
        { "kind": "executable", "values": ["aws", "terraform", "pulumi"] },
        { "kind": "uri_scheme", "values": ["s3"] }
      ],
      "connectionIds": ["c0a80101-0000-4000-8000-0000000000a1"]
    },
    {
      "serviceType": "github",
      "displayName": "GitHub",
      "credentialProviders": ["github"],
      "clientMatchers": [{ "kind": "executable", "values": ["gh", "git"] }],
      "connectionIds": []
    },
    {
      "serviceType": "postgres",
      "displayName": "PostgreSQL",
      "credentialProviders": ["postgres"],
      "clientMatchers": [
        { "kind": "executable", "values": ["psql", "pg_dump"] },
        { "kind": "uri_scheme", "values": ["postgres", "postgresql"] }
      ],
      "connectionIds": ["c0a80101-0000-4000-8000-0000000000a2"]
    }
  ]
}
```

An empty `connectionIds` means "supported, not connected here": the Agent should
create a `setup` request rather than invent instructions.

### GET /v1/context?serviceType=aws

Service-specific guidance rendered by Console for this Workflow (supported
operations, limitations, how re-signing works). Exactly one `serviceType`
parameter; omit it for the general context.

```json
{
  "schemaVersion": 1,
  "sessionUid": "sess_01HZX9K3M2",
  "serviceType": "aws",
  "markdown": "Requests are re-signed with the live key. Presigned URLs and credential-minting calls (sts:GetSessionToken, iam:CreateAccessKey, …) are refused. …"
}
```

Errors: 400 `invalid_context_query`, 502 `unsafe_agent_context_response` if
Console answers for a different service than asked.

### POST /v1/requests

Ask the human for something through Console. Two kinds. Optional `?wait=N`
(0–300 s) makes the proxy long-poll before answering, so a quick approval comes
back in the same response.

Setup (no suitable Connection yet):

```http
POST /v1/requests?wait=60 HTTP/1.1
Host: phase.invalid
Content-Type: application/json

{
  "kind": "setup",
  "credentialProvider": "github",
  "credentialName": "GitHub release automation for agent",
  "serviceType": "github",
  "markdown": "The task needs to open a pull request on acme/console. Recommended: a fine-grained token limited to that repository with pull-requests: write.",
  "dedupKey": "github-release-automation"
}
```

Credential update (provider rejected the current credential):

```json
{
  "kind": "credential_update",
  "connectionId": "c0a80101-0000-4000-8000-0000000000a1",
  "credentialId": "c0a80101-0000-4000-8000-0000000000c1",
  "credentialProvider": "aws",
  "credentialName": "aws-agent-readonly",
  "markdown": "s3:PutObject on bucket acme-artifacts was denied (AccessDenied). Please add s3:PutObject for arn:aws:s3:::acme-artifacts/* to this credential.",
  "dedupKey": "aws-agent-readonly-s3-put",
  "relatedRequestId": "req_01HZXA0B1C"
}
```

Rules enforced by the proxy: `setup` needs `serviceType` and must not carry
`connectionId`/`credentialId`; `credential_update` is the reverse;
`credentialProvider`, `credentialName` (≤ 64 chars) and `markdown` are required;
`dedupKey` and `relatedRequestId` are optional IDs. Anything else → 400
`invalid_control_request`. Wrong content type → 415.

Change to a custom HTTP Connection (an `action`). The Agent never changes a
Connection and never supplies a secret: it proposes, a member reviews the action
in Console and enters any secret there.

```json
{
  "kind": "connection_update",
  "title": "Allow /v2 on the Example API",
  "markdown": "The v2 endpoints replaced v1 for the invoices the task reads.",
  "action": {
    "type": "agent_connection.update",
    "version": 1,
    "connectionId": "c0a80101-0000-4000-8000-0000000000b1",
    "name": "Example API",
    "definition": { "…": "the full proposed definition" }
  }
}
```

| `action.type` | `kind` | meaning |
|---|---|---|
| `agent_connection.create` | `setup` | propose a new custom Connection: `serviceType: "http"`, `name`, `definition` |
| `agent_connection.update` | `connection_update` | propose a new definition and/or name for a granted Connection |
| `agent_connection.secret_update` | `credential_update` | ask a member to enter a new secret; carries no value |
| `agent_connection.remove` | `connection_removal` | ask to remove this Workflow's grant of a Connection |

Rules enforced by the proxy for a request with an `action`: the type is one of
the four above, `version` is `1`, `kind` is the one listed for the type, and the
action carries no secret value (no `value` member on the action itself, and in
`definition.fields` a `value` only on a field of kind `identifier`; a
`definition` that is not an object is refused). Everything else inside `action`
is forwarded to Console untouched, including members this CLI does not know, and
Console validates it. `title` (≤ 120 characters, plain text) and `markdown` are
optional beside an action; a missing `markdown` is forwarded as `""`.
`credentialProvider` and `credentialName` are not needed. The two new kinds are
valid only with an action. The response echoes `title` and `action`.

After approval, `connection_update` and `connection_removal` make the proxy
re-pull its configuration, and the proxy decides the `runtimeAction`. A custom
HTTP Connection whose hosts, definition, injections or `allowPlainHttp` changed
is reshaped in the running session, and a removed one is dropped from it:
`retry`. An approved `agent_connection.create` is handled the same way: the
proxy re-pulls its configuration, and a new custom Connection that exports
nothing (no agent env, no environment bindings, no config env) is served by the
running session, `retry`. Only a change to what the Agent process was given (an
identifier, a decoy, an exported variable, any other new grant, or a host that
an inherited `NO_PROXY` entry covers) answers `restart_required`. Packaged services still
recycle on any change to their hosts, configuration or injection. A removed
Connection's variable stays in processes that already run; it names a decoy
nothing accepts any more, and the manifest does not treat it as drift.

Pending (the normal first answer):

```json
{
  "schemaVersion": 1,
  "id": "req_01HZXB7Q9D",
  "status": "pending",
  "kind": "setup",
  "credentialProvider": "github",
  "credentialName": "GitHub release automation for agent",
  "serviceType": "github",
  "approvalUrl": "https://console.example.com/acme/agents/requests?request=req_01HZXB7Q9D",
  "pollUrl": "http://phase.invalid/v1/requests/req_01HZXB7Q9D",
  "progress": { "stage": "awaiting_approval" },
  "requestExpiresAt": "2026-10-18T09:00:00Z"
}
```

The Agent prints `approvalUrl` for the human verbatim and polls `pollUrl`.
`approvalUrl` is validated to point at the Console origin; `pollUrl` is always
rewritten to the proxy-local URL.

Approved (returned by the create call when `wait` was long enough, otherwise by
polling):

```json
{
  "schemaVersion": 1,
  "id": "req_01HZXB7Q9D",
  "status": "approved",
  "kind": "setup",
  "credentialId": "c0a80101-0000-4000-8000-0000000000c3",
  "connectionId": "c0a80101-0000-4000-8000-0000000000a3",
  "grantId": "c0a80101-0000-4000-8000-0000000000e3",
  "runtimeAction": "restart_required",
  "resolution": {
    "revision": "r-1",
    "credentialId": "c0a80101-0000-4000-8000-0000000000c3",
    "connectionId": "c0a80101-0000-4000-8000-0000000000a3",
    "grantId": "c0a80101-0000-4000-8000-0000000000e3"
  },
  "resolvedAt": "2026-10-17T09:12:30Z"
}
```

`runtimeAction` tells the runtime what the approval changed:

| value | meaning | what happens |
|---|---|---|
| `retry` | live material hot-swapped, Agent-visible plan unchanged | retry the operation, nothing else |
| `restart_required` | decoys, identifiers, routes or environment changed | the hook-owned daemon recycles its session and rewrites `env.sh`; the next command picks it up. `phase ai run/serve` must be relaunched by the human |

If the approval cannot be applied safely the proxy answers 502
`approved_request_refresh_failed` (`retryable: true`) and the Agent must wait
until status shows the Connection as `ready`.

Denied:

```json
{
  "schemaVersion": 1,
  "id": "req_01HZXB7Q9D",
  "status": "denied",
  "kind": "setup",
  "resolutionNote": "Use the existing deploy bot account instead.",
  "resolvedAt": "2026-10-17T09:12:30Z"
}
```

`cooldown: true` can accompany a denial or a repeated `dedupKey`: Console is
refusing to re-ask the human for a while.

### GET /v1/requests/{requestId}?wait=300

Poll one request. `wait` long-polls up to 300 s and returns `pending` when the
time runs out. Same body shapes as above.

### GET /v1/requests

Pending requests of this Workflow, for resuming after a restart or compaction.

```json
{
  "schemaVersion": 1,
  "requests": [
    {
      "id": "req_01HZXB7Q9D",
      "status": "pending",
      "kind": "setup",
      "credentialProvider": "github",
      "credentialName": "GitHub release automation for agent",
      "serviceType": "github",
      "approvalUrl": "https://console.example.com/acme/agents/requests?request=req_01HZXB7Q9D",
      "pollUrl": "http://phase.invalid/v1/requests/req_01HZXB7Q9D"
    }
  ]
}
```

### POST /v1/requests/{requestId}/cancel

Body: empty or `{}`. Only when the human asks. Returns the request with
`"status": "cancelled"`.

### GET /v1/connections/{connectionId}/environment

The process environment for exactly one Connection: proxy URL whose username is
`phase.<connectionId>`, CA variables, and that Connection's decoys. This is how
`phase ai exec --connection` builds the child environment when several
Connections exist for one service. **Sensitive**: the proxy password is in it.
Agents never print or persist it.

```json
{
  "schemaVersion": 1,
  "connectionId": "c0a80101-0000-4000-8000-0000000000a1",
  "configGeneration": 4,
  "processEnvironment": {
    "set": {
      "PHASE_AI_ENABLED": "1",
      "HTTPS_PROXY": "http://phase.c0a80101-0000-4000-8000-0000000000a1:psxrt_REDACTED@127.0.0.1:9543",
      "HTTP_PROXY": "http://phase.c0a80101-0000-4000-8000-0000000000a1:psxrt_REDACTED@127.0.0.1:9543",
      "NO_PROXY": "127.0.0.1,localhost,::1",
      "PHASE_AI_CA_BUNDLE": "/Users/dev/.phase/ai/runtime-ca-bundle.pem",
      "AWS_CA_BUNDLE": "/Users/dev/.phase/ai/runtime-ca-bundle.pem",
      "NODE_EXTRA_CA_CERTS": "/Users/dev/.phase/ai/runtime-ca-bundle.pem",
      "AWS_ACCESS_KEY_ID": "AKIAPHASEDECOY0000001",
      "AWS_SECRET_ACCESS_KEY": "decoy/9f3kQ2vL8pR1tX7wZ4bN6mC0sD5hJ2gF",
      "AWS_REGION": "eu-central-1"
    },
    "unset": ["AWS_PROFILE", "AWS_SESSION_TOKEN", "PHASE_SERVICE_TOKEN", "PHASE_AGENT_TOKEN"]
  }
}
```

Errors: 400 `invalid_connection_id`, 404 `connection_unavailable`, 503 while the
session is unavailable.

### GET /.well-known/agents (manifest)

The full runtime manifest: endpoints, the CA certificate PEM, the control links,
the default process environment (same shape as above, username `phase`) and the
Console `discover` payload. Fetched by the hook wrapper and by `phase ai exec`
when attaching to a running daemon. **Sensitive**; the skill forbids Agents from
fetching, printing or storing it.

```json
{
  "schemaVersion": 1,
  "sessionUid": "sess_01HZX9K3M2",
  "configGeneration": 4,
  "proxy": { "host": "127.0.0.1", "port": 9543, "tls": false, "tlsServerName": "" },
  "postgres": { "host": "127.0.0.1", "port": 9544, "tls": true, "tlsServerName": "127.0.0.1" },
  "caCertificatePem": "-----BEGIN CERTIFICATE-----\nMIIB…\n-----END CERTIFICATE-----\n",
  "links": { "status": "http://phase.invalid/v1/status", "…": "…" },
  "processEnvironment": { "set": { "…": "…" }, "unset": ["…"] },
  "discover": { "schemaVersion": 1, "sessionUid": "sess_01HZX9K3M2", "configGeneration": 4, "configEnv": {}, "connections": [ "…" ] }
}
```

When the manifest detects that the Agent-visible environment changed under it
(an approval landed), it answers once with 503 and the runtime recycles:

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 1
X-Phase-Error-Code: agent_manifest_refresh_required

{"error":{"code":"agent_manifest_refresh_required","message":"The Phase AI session is refreshing.","retryable":true,"details":{}}}
```

### GET /v1/bootstrap (relay only)

The one-shot sandbox bootstrap. `phase relay start` prints a handoff line that
fetches it through the relay and evaluates it in the sandbox shell:

```bash
eval "$(curl -fsS --proxy 'https://phase:psxrt_REDACTED@relay.example.ts.net:9543' http://phase.invalid/v1/bootstrap)"
```

The response is a POSIX `sh` snippet (`Content-Type: text/x-shellscript`). It
writes the Phase CA to `~/.phase/ai/phase-ca.pem`, merges it with the sandbox's
system roots into `~/.phase/ai/ca-bundle.pem` (replacement-root variables such
as `SSL_CERT_FILE` are only exported when a system store was found), writes
`~/.phase/ai/env.sh` with the proxy routing, CA variables, decoys and adapter
endpoints (paths rewritten to the sandbox), installs the `phase-cli` skill for
every known harness, loads `env.sh` into the calling shell, and appends a
marker-guarded loader to `~/.profile` (and `~/.bashrc`/`~/.zshrc` when they
exist). Re-running it is idempotent. **Sensitive**: the snippet repeats the
proxy credential the caller already holds and the Workflow's decoys; it never
contains live credential material (checked before it is served; a hit returns
502 `unsafe_relay_bootstrap`).

```sh
# Phase AI relay bootstrap (schema 1). Evaluate in the sandbox shell: eval "$(curl ...)"
phase_ai_home="$HOME/.phase/ai"
phase_ai_ok=1
(
  umask 077
  mkdir -p "$phase_ai_home" || exit 1
  cat > "$phase_ai_home/phase-ca.pem" <<'PHASE_AI_CA_EOF'
-----BEGIN CERTIFICATE-----
MIIB...REDACTED...
-----END CERTIFICATE-----
PHASE_AI_CA_EOF
  ...
  cat > "$phase_ai_home/env.sh" <<'PHASE_AI_ENV_EOF'
# Phase AI relay environment (schema 1). Written by the relay bootstrap; do not edit.
unset AWS_PROFILE AWS_SESSION_TOKEN PHASE_AGENT_TOKEN PHASE_SERVICE_TOKEN
export AWS_ACCESS_KEY_ID='AKIAPHASEDECOY0000001'
export AWS_CA_BUNDLE="$HOME/.phase/ai/ca-bundle.pem"
export AWS_SECRET_ACCESS_KEY='decoy/9f3kQ2vL8pR1tX7wZ4bN6mC0sD5hJ2gF'
export HTTPS_PROXY='https://phase:psxrt_REDACTED@relay.example.ts.net:9543'
export HTTP_PROXY='https://phase:psxrt_REDACTED@relay.example.ts.net:9543'
export NO_PROXY='127.0.0.1,localhost,::1'
export PGHOST='relay.example.ts.net'
export PGPASSWORD='pgdecoy_REDACTED'
export PGPORT='9544'
export PGSSLMODE='verify-full'
export PGSSLROOTCERT="$HOME/.phase/ai/ca-bundle.pem"
export PHASE_AI_CA_BUNDLE="$HOME/.phase/ai/ca-bundle.pem"
export PHASE_AI_ENABLED='1'
PHASE_AI_ENV_EOF
  ...
) || phase_ai_ok=0
if [ "$phase_ai_ok" = 1 ]; then
  . "$phase_ai_home/env.sh"
  printf '%s\n' 'Phase AI relay environment loaded for aws-prod (aws), analytics (postgres). New login shells load ~/.phase/ai/env.sh automatically.'
else
  printf '%s\n' 'Phase AI relay bootstrap failed; nothing was loaded into this shell.' >&2
fi
unset phase_ai_home phase_ai_ok
```

Errors: 404 `control_route_not_found` on a local proxy, 503
`agent_session_unavailable` while the relay's session is refreshing, 502
`relay_bootstrap_unavailable` / `unsafe_relay_bootstrap`.

Decoys are minted per backend session. A relay keeps one proxy credential for
its lifetime and remembers every decoy generation it handed out, so a sandbox
bootstrapped before a session recycle keeps working: requests carrying an older
decoy are translated to the live credential of the same Connection.

### GET /v1/discover (local only)

The Console discovery payload for this session: Connections with hosts,
injection action, identifiers, decoys and bindings, never live material. A
diagnostic view of what the proxy is configured to do.

### POST /v1/refresh

Body empty or `{}`. Asks the proxy to re-pull the Workflow configuration now.
This is how an Agent picks up a secret a member has just replaced on a custom
HTTP Connection. The proxy also refreshes on its own every 15 seconds, and once
(at most every 30 seconds per session) right after an upstream answers 401 or
403 to a request it injected a custom Connection's credential into; that request
is returned as it is, never retried or delayed.

```json
{ "schemaVersion": 1, "sessionUid": "sess_01HZX9K3M2", "configGeneration": 5, "refreshed": true }
```

### POST /v1/rotate (local only)

No body. Rotates the proxy's *backend* session credential with Console. The
process-local capability does not change.

```json
{ "schemaVersion": 1, "sessionUid": "sess_01HZX9K3M2", "expiresAt": "2026-10-17T10:12:30Z", "configGeneration": 5, "rotated": true }
```

### POST /v1/revoke (local only)

No body. Revokes the session in Console and stops the proxy; used by
`phase ai disable` and by a hook replacing an outdated daemon.

```json
{ "schemaVersion": 1, "sessionUid": "sess_01HZX9K3M2", "revokedAt": "2026-10-17T10:13:02Z" }
```

## 5. Proxied traffic (for contrast)

Everything that is **not** `phase.invalid` is ordinary proxied traffic. Hosts
bound to a Connection are intercepted and get the credential swap; unbound hosts
are tunnelled untouched (unless `--lockdown`). A packaged service must present
its decoy. A custom HTTP Connection lists one or more injections (header, Basic
auth, query parameter), each with `whenAbsent`: a request carrying exactly the
decoy form is swapped, a request carrying nothing there gets the live value when
`whenAbsent` is `attach`, and anything else is refused. All injections are
checked before any is applied. A custom Connection's credential is neither
swapped nor attached on a plain-HTTP request unless the Connection carries
`allowPlainHttp: true`; the request is refused with
`agent_credential_injection_failed`. Failures on bound traffic use the
envelope from §3 for most services and an AWS-style XML error
(`<Error><Code>PhaseProxyError|PhaseAccessDenied|PhaseCredentialMintingBlocked</Code>…`)
for `aws_sigv4` Connections. Codes worth knowing: `agent_connection_denied`
(403, Connection not authorized), `credential_minting_blocked` (403, see
`pkg/proxy/minting.go`), `agent_credential_injection_failed` (403, e.g. the
request was not signed with the decoy), `agent_binding_unavailable` (503, session
recycling), `upstream_unavailable` (502), `unbound_host_blocked` (403, lockdown).

Every response to bound traffic, success or refusal, carries `X-Phase-Event-Id:
event-…`, the ID of the event the proxy reports to the Console for that request
(AWS-style errors repeat it as `<RequestId>`). It is credential-free; agents
quote it when reporting a problem so the human can find the request, its
decision, and its outcome in the Console. Unbound passthrough traffic has no
event and no header.
