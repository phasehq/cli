# Phase AI proxy: the `phase.invalid` control API

The local proxy (`phase ai` daemon, `phase ai run/exec/serve`) serves a small HTTP
control API on the reserved host `http://phase.invalid`. The host never resolves
in DNS; requests only reach it *through the proxy*, so the proxy capability is
the authentication. Everything below is implemented in
`internal/aiproxy/control.go` (routes), `connections.go` (Connection reads),
`presets.go` and `hints.go` (presets and hints), `policy.go` (access policy
answers), `bootstrap.go` (manifest) and `selection.go` (per-Connection
environment). Wire
types live in
`internal/agentapi/types.go`, `internal/remoteapi/types.go` and the in-tree
Agent client (`internal/agentsdk/types.go`, `internal/agentsdk/app_access.go`).

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
| Limits | Request bodies ≤ 128 KiB. IDs match `^[A-Za-z0-9._-]{1,128}$`. `markdown` ≤ 16 KiB. `title` ≤ 120 characters. A Workflow context ≤ 16384 characters. `wait` is 0–300 whole seconds. |

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
| The Agent, following the `phase-cli` skill and its guides | `GET /v1/capabilities`, `GET /v1/status` | When the human asks for Phase, or to find out whether Phase can manage a service. In transparent mode the per-prompt status line already names the ready Connections, so this is mostly for service discovery. |
| The Agent | `GET /v1/context?serviceType=…` | Before using a service through Phase: provider-specific instructions and limitations, rendered by Console. |
| The Agent | `POST /v1/requests`, `GET /v1/requests/{id}?wait=300`, `GET /v1/requests`, `POST /v1/requests/{id}/cancel` | No suitable Connection exists (`setup`), the provider rejected the credential (`credential_update`), or the Agent requests a change with an `action`: to a custom HTTP Connection, to this Workflow's access (allow a call the policy asks about, renew time-limited access), or to the Workflow's saved context. The Agent prints `approvalUrl` for the human, then long-polls. |
| The Agent | `GET /v1/connections`, `GET /v1/connections/{id}` | To read what its Connections are, and to get the current definition of a custom HTTP Connection before requesting a change. Served from the session the proxy already holds. |
| The Agent | `POST /v1/refresh` | After a member replaced the secret of a custom HTTP Connection, to use the new value now instead of at the next periodic refresh. |
| The Agent | `GET /v1/presets` | To ask for a Connection to a well-known service by preset ID instead of writing a definition. |
| The Agent | `GET /v1/hints` | After a refusal whose body its client hid, or after a service answered 401 or 403 on a host no Connection covers: the ready-to-send requests for recent dead ends. |
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
    "message": "Use setup with serviceType or credential_update with connectionId and credentialId; credentialProvider, credentialName, markdown, and an optional dedupKey are required. Or send an action of a known type with version 1 under its request kind; an action never carries a secret value. durationSeconds, when sent, is a positive whole number on a request that ends in access.",
    "retryable": false,
    "details": {}
  }
}
```

Console-side failures are forwarded with Console's status, code and message;
unreachable Console becomes 502 `agent_control_forward_failed` with
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
      "expiresAt": "2026-10-17T18:00:00Z",
      "grantExpiresAt": "2026-10-18T09:00:00Z"
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
    "pollRequest": "http://phase.invalid/v1/requests/{requestId}",
    "presets": "http://phase.invalid/v1/presets",
    "hints": "http://phase.invalid/v1/hints"
  }
}
```

`state` is `ready`, `expired` (the credential expiry or the time limit on this
Workflow's access passed) or `unavailable` (not authorized, an access policy
this CLI cannot enforce, or a sealed value the proxy could not open).
`stateReason` names the cause when the proxy knows it, for example
`access_expired`. `grantExpiresAt` is present when access to the Connection is
time-limited; `expiresAt` is the credential's own expiry. A custom HTTP
Connection appears with `serviceType` and `credentialProvider` `http`; its
`credentialId` is the Connection ID and `credentialRevision` is the value
revision.

### POST /v1/inventory/key and POST /v1/inventory (leak protection)

Used by the CLI itself (`internal/leakguard`), never by the Agent's own tools.
Before a command hands out secret values it looks for a running proxy, tells
it who the command itself is (the tenant and login of the login that command
uses), fetches the keys the proxy hands such a command, indexes each value
locally with `pkg/censor`, and registers the entries, saying who it is again.
The entries carry keyed hashes and lengths, never a value.

The proxy it finds may be running as another login: a daemon started before
`phase users switch`, or a command with another account's token in its
environment. So nothing is decided by the proxy's login alone. The proxy
knows who its own session is from the session the Console opened for it, the
command says who it is, and where a registration goes follows from the two:

| The command states | It is handed | The proxy does |
|---|---|---|
| the proxy's tenant and the proxy's login | The stored keys of that login: the tenant's lookup key and the login's confirming key. | Stores the values under that login and writes them as `ph:<type>:<id>`. |
| anything else: another login of the proxy's tenant, another tenant, nothing, or anything that is not a well-formed identity | Keys of this proxy process alone, with nothing of the store in them. | A guest: protects the values in memory only, until this proxy process exits or the guests' share drops them for newer ones, as `ph:<type>` with no id, in the request and in events. Nothing is stored, for the proxy's login, for the login the command stated or for anyone, and nothing is counted but the registration itself (`unstored`). |

A proxy whose own session the Console did not name, as an older Console's
does not, has no tenant and no login to keep apart, so the table does not
apply to it. Every command, whatever it states, is handed the one key that
proxy process made, and its values are held as they were before there was a
store: with their ids, fragments matched, the whole index theirs, and nothing
stored. A proxy never hands out the keys of, and never writes into, the
stored partition of a login other than its session's own.

What a proxy loads is wider than what it writes. At start it loads the stored
entries of every login of its tenant, each written by that login's own proxy,
and matches the other logins' as withheld: whole values only, `ph:<type>` and
no id. So a value a person registered through their own login's proxy is
still removed from their Agent's traffic after a restart, and a value
registered through somebody else's proxy is protected until that proxy exits.

The proxy is looked for through an ordered list of sources, and the first one
that finds a proxy is used (`leakguard.AddSource` adds another):

1. The session the command runs in: `PHASE_AI_ENABLED=1` and the proxy
   variables in its environment.
2. The hook-managed proxy, through its runtime state (`runtime.json` in the
   Phase AI directory, the file `phase ai status` reads), when the process
   that wrote it is alive. This is what covers a command in a shell that does
   not load the Phase environment: Codex's and Cursor's shells, or another
   terminal.

The hook-managed proxy is away for some seconds whenever its daemon starts or
recycles its session: the listener closes, the state is withdrawn, and both
come back once the Console has answered. A value handed out in that gap would
never reach the inventory the daemon comes back with, so the gap is not taken
for no proxy. The daemon is told from its runtime lock (`runtime.lock`): its
process is alive, and it is starting or recycling, or it still owns the state
it published while nothing listens there. A registration then waits for the
state, asking again every 25 ms, and registers with the proxy that comes
back. The wait is one second in all (`leakguard.Timeout`), counted from the
first look, so the dials that found nothing listening are part of it, and the
last of them is cut short where the wait ends. A dial cut short that way says
nothing of what listens there: the answer is that the proxy was not back in
time. A source says this through `leakguard.Source.Restarting`; the session's
own environment never does.

Nothing listening at the proxy's address is told in one of two ways, and both
mean the same on every system: the connection is refused, or it is not made
within the 250 ms a registration gives its dial. The address is a loopback
one, so no network is to blame for a dial that hangs, and a port nothing
listens on shows that way where the system is slow to refuse. Windows can be:
left to itself it tries again for a second or two before it refuses. Go asks
it not to for a loopback address, so current Windows refuses at once, but
that is best effort and builds before 16299 honour it only in part. A proxy
that listens takes the connection at once, so the short dial costs it
nothing; the key request and the registration that follow keep one second
each. Stale state so costs a command a quarter of a second at most on any
system. A proxy that took the connection and did not answer in time is
another matter: it is there, and failed.

With no proxy and no daemon the lookup costs two file checks, of the state
and of the lock: nothing is read, nothing is called and nothing is waited
for. Process liveness is all the lock is judged by, so a lock and state left
by a daemon that was killed, whose process id another program now holds,
read as a daemon between two sessions. What a failed registration means
depends on how the proxy was found:

| The proxy was found through | When the registration fails |
|---|---|
| the session's environment | An Agent-token login is refused before any value leaves. Any other login gets one warning line on stderr and carries on. Nothing listening there is such a failure too: the session's own proxy is meant to be there. |
| the runtime state, and nothing listens at its address (the connection is refused, or is not made within 250 ms) | No proxy is running: the last row applies. Nothing listens there, so the state is stale or its process id now belongs to another program, and a warning would repeat on every command in every shell. |
| the runtime lock or state of a daemon that is starting or recycling, and it is not back within the second | The next row applies: a proxy is there and could not be reached. It is never taken for no proxy. |
| the runtime state, any other failure | One warning line on stderr, once per process, and the command carries on, whoever is logged in. A timeout, an HTTP error, an answer that cannot be read and a full inventory are such failures: a proxy is there and did not take the values. |
| nothing | Nothing is registered. An Agent-token login is told once that leak protection is not active; any other login is told nothing. |

#### The inventory across restarts

The inventory outlives the proxy process (`phaseproxy.InventoryStore`), so a
conversation resumed after the hook-managed proxy's idle exit, an upgrade or
a reboot still has its values replaced before anything registers them again:

- One master key is kept in the system keystore, beside the CA key (service
  `phase-cli-ai-leak-inventory`), one per user, made on first use, never
  written to disk and never handed out by any route. It carries an id. A
  master is made only when the keystore says it holds none. If the keystore
  cannot be read for any other reason (a locked keychain, a refused prompt, a
  value this version cannot parse), the proxy runs from memory
  (`key_unreadable`) and writes neither the keystore nor the file.
- Everything is kept apart by tenant. A tenant is a Console and an
  organisation id, and a Console is the whole address it is served at:
  scheme, host, port and the path it is served under. A login is its kind
  (`user`, `service_account` or `agent`, the principal types of a session)
  and its id: an Agent's id, a service account's, and for a user the
  organisation member's id. One function writes both, for the proxy, for
  every registering command and for a logout
  (`phaseproxy.NewInventoryIdentity`): the address is parsed, so its scheme
  and name in any case, a default port written or not, a trailing slash or
  dot, and the API's own path written after it (`/service/public`,
  `/service/public/v1/agents`) are one tenant. Another host, port, scheme or
  path is another: two Consoles served under different paths of one origin
  share nothing, even with the same organisation and account ids, as a
  copied database has. The path is read as the client that opens the
  session reads it (`agentapi.DeploymentPath`), so the proxy
  (`agentapi.Client.Host`) and a command say the same of one login. An
  address that can be read two ways (one that ends in the API's path twice)
  names no tenant, and nothing is kept for such a login.
- The proxy's identity is what the session it opened says
  (`airuntime.Runtime`): the response that opens a session carries
  `"organisation":{"id":...}` and `"principal":{"type":"agent"|"user","id":...}`,
  where the id is the Agent's or, for a user's token, the organisation
  member's. The proxy asks no other route for it and reads no login file, so
  a token from the environment has a tenant like any other, and so has a
  proxy that serves a peer elsewhere. A session that names no organisation or
  no principal, as an older Console's does not, or a principal of another
  kind than its token, has no identity: its inventory is in memory only
  (`no_tenant`), nothing is read from or written to the store, and every
  command is its own (above). Nothing is guessed and no other route is
  tried. A runtime whose first session named nobody stays so for its life.
- A registering command has no session, and states its own identity: a saved
  login's from its own record, as the Console gave it when it was saved, read
  for the account the command's token was read for; a token from the
  environment asks the Console (the Agent identity route, `agent.id` and
  `organization.id`, or the route a login is saved from,
  `GET /service/secrets/tokens/`: `user_id` or `account_id`, and
  `organisation.id`). The ids are the session's: `user_id` there is the
  organisation member's id. A command that cannot tell states nothing.
  The proxy never takes a tenant or a login from a command as its own.
- A proxy process serves one identity for its life. A session of another
  tenant or login is refused before anything is opened for it.
- One account never matches what another account's organisation registered:
  - a proxy derives its own tenant's keys from the master and no other
    tenant's. The lookup key, the confirming keys, and the keys records are
    sealed and tagged with all differ by tenant, so the same value
    registered in two tenants gives unrelated lookup values and hashes;
  - a record carries a keyed tag of its tenant. A proxy opens, loads and
    matches the records of its own tenant alone. Another tenant's records
    are left in the file as they are until they expire, and a session
    learns nothing of them: no id, no type, no size and no count, since a
    count would move whenever another organisation registered a value;
  - a request that holds a value another tenant stored is sent on
    unchanged, and no event or status says anything of it;
  - the key route hands every command that does not state the proxy's own
    tenant and login nothing derived for any stored tenant or login: it
    hands it a lookup key and a confirming key made from what this proxy
    process drew when it started, which is kept nowhere and which the next
    proxy does not have. Guests share the lookup key. The confirming key is
    one per stated identity, so no guest that says who it is confirms what
    another registered. Commands that state none (a login the Console is
    slow or unable to identify, a saved login with no organisation id) are
    handed one between them for the life of the proxy and are one guest to
    it, so what such a command registers on every run is held once. Entries
    made under them are matched by a pass of their own, written
    `ph:<type>`, and never stored.
- Within a tenant, every key is derived from the tenant's root with
  HKDF-SHA-256, each under its own label, so none gives the master or
  another back:
  - the lookup key, which keys the rolling hash a chunk is found by. It is
    the same for every proxy and login of the tenant, so a scan rolls one
    hash per position however many logins registered values;
  - a confirming key per principal, which keys the SHA-256 that confirms a
    chunk and the tail hashes. A principal is a login of the tenant: the
    Console's address, the kind of login and its account or Agent id (never a
    token). It is named by a keyed tag of that login, and its confirming key
    is expanded from that tag. A proxy hands out one stored confirming key:
    its own session's login's, to a command that states that tenant and
    login. No statement gets a command the key of another login or of
    another tenant;
  - the keys the file is sealed and tagged with.
- The entries are kept in `leak-inventory.bin` in the Phase AI directory,
  owner-only, replaced whole through a temporary file, sync and rename, and
  read only as a regular owner-only file of this user that is not a symlink.
  Each record is one registered value: its entries as they came over this
  API, whether its id is a key name and the id of the principal that
  registered it, sealed (AES-256-GCM) under its tenant's sealing key. Before
  it comes the record's head: the matching scheme, the time it was last
  registered, and keyed tags of its tenant, its login and its content,
  sealed under a file key derived from the master, which every proxy of
  this user derives and no tenant's keys give. The file's header names its
  store format and the master's id.
- What the file shows in the clear is therefore its format, the master's
  id, how many records it holds in all, and how long each record is, which
  grows with the value's length. It does not show whose a record is, of
  which login, when it was registered, or which records share a tenant, a
  login or a placeholder. A proxy opens every head, to keep other tenants'
  records where they are, and the bodies of its own tenant alone. It gives
  no figure of the other tenants' records to a session, a command or a log:
  the size of the whole store is the file's size, for whoever may read it.
- A proxy acts as one principal and writes that principal's records alone.
  It matches the records of every principal of its tenant, each written by
  that login's own proxy: a candidate is confirmed with the confirming
  key of the principal its record names. A value a person's own login
  registered with their own proxy is therefore still replaced when their
  Agent's tool reads it, and the same value stored by two logins is a record
  each, matched through either.
- A value stored by another login than the session's is replaced by
  `ph:<type>` with no id, in the request and in events alike: the id (a
  secret's id or key name) may be one the session's login cannot see. When
  the session's own login registered the same value, its own placeholder
  with its id is written. Such a value, and a guest's, is replaced only
  where it stands whole: the whole value in any of its encodings, a JSON
  value's whole leaf, or a URL's whole password. A fragment of it, a copy
  cut short, or single lines of a multi-line value are not replaced, so
  that no command learns from the proxy that a guessed piece belongs to a
  value it cannot name. Each such value found is reported once, like any
  other; an event names it `ph:<type>` and counts it.
- Counts are per login. `secretsKnown` counts a type and id once for each
  login of the tenant that registered it, so no count says whether another
  login holds an id, and it counts nothing a guest registered.
- Every proxy of the user loads the file when it starts and writes what its
  own login registers with it, under `leak-inventory.lock`: the file is read
  again under the lock and written whole, so nothing another proxy stored is
  lost. A proxy does not pick up what another registers while both run. A
  process that waits for the lock holds `leak-inventory.queue` meanwhile, so
  the next to write is one that waited: a proxy that writes again and again
  keeps no other out. Neither file is ever removed, and the keystore is never
  asked while one is held. A proxy waits at most two seconds. A registration
  that did not get the lock is in the running proxy and not in the store
  (`store_busy`), and the next registration tries again: nothing is given up
  for the life of the proxy. `phase users logout` and `phase ai disable` wait
  up to 15 seconds, and say so when the store was still in use and its
  records remain.
- A registration's answer does not wait for any of that. Its values are in
  the running proxy's index before the store is touched, and the answer
  waits a quarter of a second at most for the write: well inside the second
  a client gives a registration. A write that takes longer (a store in use,
  a keystore that waits on a person, a large file on a slow disk) finishes
  behind the answer, and status says how it went. At most four such writes
  wait at once. A registration that arrives then is not queued behind them:
  its values are held in memory only, and status says `store_busy` until a
  later registration is stored.
- Only entries of scheme 2 are stored. Scheme 1 entries, which an older
  client may register, carry whole rolling hashes: they are matched while
  the proxy runs and never written.
- No record replaces another's. A `type` and `id` may name several values (a
  key name is shared across apps and environments): each is its own record,
  and a record goes when it has not been registered for 30 days, or when its
  own login stores past a bound.
- What is stored is bounded for a login (4096 records, 8 MiB), for a tenant
  (8192 records, 16 MiB, 64 logins) and in all (65536 records, 64 MiB). Past
  any of them only the login that is writing loses records: its own oldest,
  and what it just registered when even that leaves no room. A record of
  another tenant, or of another login of the same tenant, is never dropped
  to make room. What a bound dropped of the proxy's own records since it
  started is counted (`dropped`): the inventory is stored, and those values
  are not in it. An entry not registered again for 30 days is dropped
  whosever it is. The bound on the whole file is shared, so it is the one
  place a tenant can notice the others' volume: once other tenants have
  filled the file, which takes several of them at their own bounds, what
  this one registers is not stored, and `dropped` counts it.
- What the running proxy holds is bounded the same way: the session's own
  login registers up to half the index (5000 values, half the chunks) and
  gets 507 past that, while guests still register. Guests hold a quarter
  together and are never refused for a full one. A value a guest registers
  again is held once, and commands that state nothing are one guest. When
  the quarter is full the guests' entries registered longest ago are dropped
  to make room, whichever guest's they are, and a value dropped is protected
  again when a command next reads it. What a registration costs the quarter
  does not depend on whether its type and id are held, so no guest learns
  from it what another holds. Only one registration that is by itself more
  than the quarter (2500 values, or a quarter of the chunks) gets 507. A
  proxy that starts loads at most half the index, and a quarter for one
  login: the session's own login's values first, then the others', each most
  recently registered first. The rest stay in the store and are counted
  under `notLoaded`, so a proxy that starts again always has room, however
  much one client registered before.
- A value the proxy knows only from the store never stops a request. Where
  a value registered with the running proxy stands in a URL or a binary body
  the request is refused (403 `secret_in_request`). One that was loaded at
  start is replaced where it can be and reported where it cannot, until a
  command registers it with this proxy again. A value that sits in every
  request's URL would otherwise stop every model request, for every login of
  the tenant, for as long as it stays stored.
- A value that is a host name or a path of a model host's own requests, as
  the host table names them (`api.anthropic.com`, `/v1/messages`), is not
  indexed: it is counted under `unprotected`, and for a guest in the
  registration's answer. A longer value that begins or ends as one is
  indexed, and that piece of it is structure: alone it is no match.
- `phase users logout` removes the records of the login that logs out, and
  every record of its tenant when no saved login of that tenant is left on
  the machine. It makes no key and no file, and leaves other tenants'
  records as they are. Picking a login's records out needs the master: it
  is all that says whose a record is. When the keystore does not give it (a
  shell with no session bus, a refused prompt, no key there), or the file is
  one that key does not open (another key's, a newer store format's, not an
  owner-only file), the logout does not leave the records for a later proxy
  to load: it removes the whole file, every login's, and says so on stderr.
  A value is stored again when a command next reads it. A logout that could
  not remove what it should says that instead, and reports nothing gone
  that is still there.
- Two versions are stored. The store format is the file's layout: a version
  of Phase reads every format up to its own and leaves a newer file
  untouched, running from memory. The matching scheme is each record's own:
  records of a scheme the running version does not match stay in the file as
  they are, are not matched, and are counted under `unmatchedScheme`.
- A file under another key id is not matched and is dropped when the proxy
  that found it starts. Status says so (`unmatchedKey`) and gives no count:
  under another key no head opens, so nothing tells this tenant's records
  from another's.
- A file that is damaged, cut short, too large or not what it claims never
  stops the proxy. Within a file this version can open, what can be
  authenticated and passes the same validation as a registration is loaded,
  and the rest is counted and dropped. A record is found by its head, which
  is sealed under the key, and not by trusting the length before it: a
  damaged length or head costs the record it is in, the records after it
  are still read, whosever they are, and a damaged key id in the header of
  a file whose heads open is put right. A file that exists and cannot be
  opened or understood at all (not an owner-only regular file of this user,
  too large, no inventory header) is never written over: the proxy runs
  from memory (`store_unreadable`) until `phase ai disable` or a logout
  removes it.
- On a machine with no system keystore nothing is stored: no key, no file,
  and the inventory is in memory as before.
- `phase ai disable` removes the master, then the file, and `phase users logout
  --purge` removes the master with the CA key and the file with `~/.phase`.
  Every derived key goes with it. A
  proxy still running says `key_replaced` the next time its status is asked
  (the keystore is asked at most once a second) and stores nothing more.
  The disable deletes the master without reading it first, so a keychain
  that refuses the read still loses it. A master the keystore cannot delete
  is replaced, and one it will neither delete nor replace is not left behind
  unsaid: the disable fails with that and asks to be run again. The file is
  removed either way. A purge from a shell that cannot reach the keystore
  says in one line which keys it left there, the CA's, the inventory's or
  both, and only of those this machine made.

What each party can do with this. What is stored per chunk is 24 bits of its
rolling hash, under the lookup key, and a SHA-256 truncated to 128 bits, under
the confirming key of the principal that registered it; the smallest chunk is
12 bytes of a value's form, and 24 characters where the form is hex digits or
the base64 of a hex value.

- **A session of another tenant**, client or proxy, can test nothing: it
  holds no key of this tenant, opens none of its records, and is told
  nothing of them, their number included.
  A command of another tenant that registers with this proxy is a guest: it
  is handed keys of this process alone and learns nothing of what is stored.
- **A command that states another login of the proxy's tenant** is a guest
  too. It is handed nothing derived from the master, so with the file, and
  even with that login's entries out of their seal, it holds no key their
  hashes were made under: a right guess indexes to other hashes. The proxy
  takes a right and a wrong guess registered in that login's name alike,
  and writes neither.
- **The file alone** says nothing a guess can be tested against: every
  record is sealed under a key derived from the master, and so is its head.
  It shows how many records are stored in all and how long each is.
- **A client of a session with the file.** Any process that holds a proxy's
  capability, an AI Agent included, is handed the tenant's lookup key and
  the confirming key of the proxy's own login when it states that login,
  for as long as the master lasts, and no other login's by any statement.
  Neither opens the file, so with the file it is where the file alone is.
  Were its tenant's entries out of their seal, it could confirm a guessed
  chunk only of its own principal's values, which it can read anyway. Of
  another principal's (the developer's own login, another Agent) it would
  hold the lookup values, under the tenant's lookup key it is handed, and
  no hash it can compute. One lookup value lists the guesses of its chunk
  that fit, one in 2^24, and does not say which is right, so by itself it
  leaves a chunk of b unknown bits 2^(b-24) candidates. All of a value's
  together do not hide a value that can be guessed whole (a wrong guess
  fits its n lookup values about once in 2^(24n)), or a chunk whose guesses
  can be listed, since each form its bytes stand in has a lookup value of
  its own. `pkg/censor`'s Limits say exactly what they give. A client is trusted
  this far and no further: one that states the proxy's own login is handed
  that login's keys, as that login's commands are, since leak protection is
  against accidents. A client can still send guesses through the proxy and
  see whether they are replaced: a chunk's bytes of traffic a guess for a
  value of the proxy's login, and for another login's only a guess of the
  whole value is answered, with nothing stored to narrow either. Entries it
  forges under a guess's lookup value push out none but its own: how many
  chunks a lookup value leads to is bounded for each confirming key apart.
- **A client of the same proxy that times its requests** learns less than it
  did and not nothing. A value it cannot name is looked up by one chunk, the
  first that is not structure, and where that chunk's 24 lookup bits turn up
  the scan hashes it and three more, those that are not structure first,
  whether or not any confirms, and the rest only when all four did. So no
  chunk is confirmed by the time a request takes, and no other chunk of the
  value is looked for at all. What timing still tells such a client: whether a
  guess of that one chunk has the lookup bits of some withheld value's (a
  right guess always, a wrong one about once in 2^24 for each form held); with
  the lookup key it holds, which lookup values are in use that way, which
  narrows a guess of that chunk by 2^24 for each form that is looked up by
  those bytes, and no further; and whether a guess of
  those four chunks together is right. Keeping the lookup values from it would
  take a second lookup key, one no client of another login is handed, for
  entries a login cannot name, and so a second pass over every request, which
  the proxy does not make. Even then a lookup that hits takes longer than one
  that misses. `pkg/censor`'s Limits say the same in full.
- **A process of the same user with the keystore and the file** has the
  master, hence every key of every tenant, and confirms a guessed chunk of any principal's
  value by hashing it. The 24 bits let it skip all but one guess in 2^24
  without hashing, so a chunk of b unknown bits costs about 2^(b-24)
  confirming hashes: about 2^72 for 24 digits of a hex value (96 bits), and
  about 2^47 for 12 characters of a value made of letters and digits (71
  bits), which is days of work for hardware built for it. Chunks that hold
  few bits are found whatever is stored (2^24 hashes for 24 digits of the hex
  of a hex value); `pkg/censor`'s Limits list them and give every figure.
  Such a process can read the saved logins from the same keystore.

Entries made by this version are scheme 2. Scheme 1 entries hold the whole
rolling hash, from which a 12-character chunk is found in about 2^36 steps,
and their confirming hash is keyed from the lookup key: they exist only in
the memory of a running proxy that an older client registered with, and are
never stored.

Every caller reaches the control API through one client,
`phaseproxy.ControlClient`: `phase ai status`, the hooks and this registration.

```http
POST http://phase.invalid/v1/inventory/key
Content-Type: application/json

{"schemaVersion":1,"tenant":"https://console.phase.dev\norganisation\n<organisation id>","login":"https://console.phase.dev\nuser\n<account id>"}

200 {"schemaVersion":1,"key":"<base64, 32 bytes>","confirmKey":"<base64, 32 bytes>","format":2,"keyId":"<16 hex digits>"}
```

`tenant` and `login` say who the command is, as
`phaseproxy.NewInventoryIdentity` writes them; both are left out by a command
that cannot tell, and `GET /v1/inventory/key` states nothing either. Unknown
fields, another `schemaVersion` and a body over 4 KiB are 400
`invalid_inventory`. For a command that states the proxy's own tenant and
login, `key` is that tenant's lookup key and `confirmKey` that login's
confirming key. For any other command both are keys of this proxy process
alone: the lookup key its guests share, and a confirming key of the identity
the command stated or, when it stated none, the one every such command is
handed. A proxy with no identity hands every command its one key. The answer
never holds the master, a confirming key of a login that is not the proxy's
own, or anything derived for a stored tenant or login the command is not of.
A client indexes with both keys; `confirmKey` is left out only by a proxy
that reads scheme 1 alone, whose one key did both.

`keyId` names the two keys without giving either. A registration sends it
back, and the proxy refuses entries made under keys it does not hand that
command (409 `inventory_key_changed`, nothing added): entries under other
keys would be held and never matched. The client fetches the key again and
registers again, once. A registration that sends no `keyId`, as a client
older than key ids does, is taken as made under the keys the proxy hands
that command. Such a client fetches the key with `GET`, reads `key` alone
and indexes under scheme 1: its entries are held in memory, as a guest's at
a proxy with an identity, and are never stored.

`format` is the matching scheme the proxy's own version indexes under
(`censor.EntriesVersion`). The proxy takes entries of every scheme it still
matches (1 and 2), each as it was made; `pkg/censor`'s documentation says what
a scheme covers. A client indexes under `format` whenever its own version
knows that scheme, so a client and a proxy of different versions still
register; a `format` the client does not know is the warning of the table
above.

```http
POST http://phase.invalid/v1/inventory
Content-Type: application/json

{"schemaVersion":1,"entries":[{"v":2,"type":"secret","id":"<secret id>","forms":[...]}],"idKinds":["phase_id"],
 "tenant":"<as in the key request>","login":"<as in the key request>","keyId":"<from the key answer>"}

200 {"schemaVersion":1,"added":1,"unprotected":0}
```

- `tenant` and `login` say who the command is, as in the key request, and
  where the entries go is decided from them on every registration (the table
  above), never from an earlier request. Left out, or not a well-formed
  identity, the command is nobody's: its values are protected until the
  proxy exits and are not stored.

- Body ≤ 4 MiB (413 `inventory_too_large`), at most 4096 entries; unknown
  fields, another `schemaVersion` or any malformed entry is 400
  `invalid_inventory` and nothing of the batch is added.
- `idKinds` says, entry by entry, what each entry's `id` is: `phase_id` (an id
  the Console issued, such as a secret's id or a lease's id) or `key_name` (a
  secret's key name, which is what a login other than an Agent token registers
  a secret under). It holds one member per entry, or is left out; any other
  length or word is 400 `invalid_inventory`. Left out, every id is taken for a
  key name. The proxy never guesses the kind from the id's shape. It remembers
  it per placeholder, and a placeholder once registered as a key name stays
  one.
- 507 `leak_inventory_full` once the proxy's own login holds its share of the
  index (5000 values or half the chunks), or the index holds 10000 values or
  its chunk cap. A guest gets it only for one registration that is by itself
  more than the guests' quarter: otherwise the guests' oldest entries make
  room. It does not outlive the proxy: one that starts again loads the most
  recently registered values into half the index. A restart makes room; it
  does not clear what is stored.
- A value too short or plain to protect is counted once for its type and id,
  however often it is registered, and at most 4096 such are remembered; past
  that the count stays where it is.
- Entries never replace those held for the same `type` and `id`, whatever
  their schemes: another value may share the id, and both stay matched.
- No route returns entries, hashes or the id of a secret. `GET /v1/status`
  adds `leakProtection` with counts, host names, reasons and rule ids only:
  `{"mode":"censor","secretsKnown":12,"unprotected":1,"inspectedHosts":[...],"unreadHosts":[...],"inventory":{...}}`.
  `inspectedHosts` is every host the table reads, whichever tool the proxy
  was started for.
- `inventory` says whether the values outlive the proxy, in counts of the
  session's own tenant. None counts what another host or organisation
  stored:
  `{"storage":"stored","loaded":9,"notLoaded":0,"unmatchedScheme":0,"unmatchedKey":false}`,
  with `unstored` when commands that are not of the session's own login
  registered with this proxy (its guests): a count of those registrations, each one counted
  whatever it held, so it says nothing of an id or of whether a value was
  seen before; and `dropped` when a bound of the store dropped records of
  the proxy's own login as it wrote: values it registered that are not
  stored.
  `storage` is `stored` or `memory`, and `reason` says why it is `memory`:
  `no_keystore` (the machine has no system keystore), `key_unreadable` (the
  keystore did not give the key; nothing is written), `newer_store_format`
  (the file was written by a newer version of Phase and is left as it is),
  `store_unreadable` (the file exists and could not be opened or understood,
  and is left as it is), `key_replaced` (the key was replaced or removed
  while this proxy ran), `store_busy` (another process held the store's lock
  for two seconds the last time this proxy wanted it, or writes were already
  waiting on the store; the next registration tries again), `store_unusable` (the directory or file could not be
  written), `no_tenant` (the Console did not say which organisation and
  login the session is, so nothing is kept for it) or `not_configured`. `loaded` is how many values the proxy knew
  from the store when it started, and `notLoaded` how many more the store
  held that were left out to keep the index room. `unmatchedScheme` counts stored entries of a matching
  scheme this version does not match: they are kept and need registering
  again. `unmatchedKey` is true when the store was written under a key that
  has been replaced: nothing in it was matched and it was dropped. `damaged`, when
  present, counts stored entries that could not be read. `phase ai status`
  prints this on its `Leaks:` line.
- A host the table reads is listed under `unreadHosts`, and not under
  `inspectedHosts`, while it is not being read, for any tool or any one
  client of a tool: in a pass-through window (which is for the client that
  refused, see below); while a tunnel opened in a window is still open, which
  can be long after the window ended; and while a connection to it that was
  handed to the service unread (below) is open, and for a minute after such a
  connection was opened. `unreadReasons` says why, by host:
  `{"opencode.ai":["hello_resumption"],"api.anthropic.com":["tls_refused"]}`.
  It is absent when every such host is being read. A name under a domain
  entry is listed by itself; the domain stays under `inspectedHosts`.
  `phase ai status` prints the reasons after the host on its `Leaks:` line.
- `mirroredHosts` counts, since the proxy process started, the client
  connections to each host that is sent a copy of its client's hello:
  `[{"host":"opencode.ai","copied":41,"rebuilt":2,"passedThrough":{"hello_resumption":1}}]`.
  `copied` were opened with a copy and read. `rebuilt` is how often the hello
  sent was rebuilt from one that offered a session, the client not having been
  seen without one; such a hello can differ from the client's own in its
  padding, so it is the first number to look at when the service turns
  connections or requests away, and it is counted whether or not the service
  took the hello. `passedThrough` counts the connections handed over unread,
  by reason, `tls_refused` for tunnels opened in a window.
- A rule file can be newer or older than the binary. A pattern rule in it
  that this version cannot apply, and one of Phase's own token rules that it
  does not hold, never stop the proxy: the rules that do apply still protect,
  and status adds `"rulesSkipped": 2, "skippedRules": ["<rule id>", ...]`.
  `rulesSkipped` counts them all; `skippedRules` names at most 64, and only
  ids that are plain identifiers. Both members are absent when every rule
  applies, as with the rule file the CLI ships. `phase ai status` adds
  `; 2 pattern rules skipped` to its `Leaks:` line and names none.
- The mode comes from `PHASE_AI_LEAK_PROTECTION` in the proxy's environment:
  `censor` (default; anything unknown counts as censor), `observe`, `off`.

#### Whose traffic is read

The table (`internal/aiproxy/leak_hosts.go`) has one list of model hosts per AI
tool: `claude`, `codex`, `opencode`, `cursor`. A provider's API that several
tools call is listed under each of them with the same rule (`api.anthropic.com`
and `api.openai.com` are also in OpenCode's list). Every connection carries a
flow: how it reached the proxy (`capture`) and which tool opened it, when that
is known.

| Captured by | The tool is | A host is read when |
|---|---|---|
| the proxy environment (`proxy`) | known or not | any tool's list reads it |
| a tunnel (`tunnel`) | known | that tool's list reads it |
| a tunnel (`tunnel`) | not known | never |

Everything behind the proxy environment runs in an AI tool's process tree. A
tool started inside another tool's session (Codex from a Claude Code shell, or
the reverse) sends conversation content through the same proxy, so every
host a list reads is read there, whichever tool the proxy was started for,
and in the same way: by the entry of the first list, in the table's order,
that reads it. The tool the proxy was started for decides nothing of that. A
host its own list leaves unread, or reads only part of, is still read as that
first entry says. The tool only names such a flow: `harness` in an event is
the flow's own tool when that tool's list reads the host too, otherwise the
tool whose entry the host is read by. Within one list an exact entry wins
over a domain entry, so a list can leave one name of a domain it reads
unread; that holds for that list and no further. A tunnel carries every
program on the machine, so the strict rule applies to it alone: another
program's traffic to the same host passes through untouched.

A host that is read is answered with the proxy's certificate on port 443 even
when no Connection covers it. A flow that is not read is not inspected at all.
When a Connection covers its host the tunnel is still terminated for the
Connection, as for any other host. The answer offers HTTP/1.1; for a host
whose entry says `http2`, and that no Connection covers, it offers HTTP/2 as
well (below).

Where a flow comes from:

- A capture layer in the proxy's own process (a tunnel's router) calls
  `Engine.NoteFlow(remoteAddr, FlowContext{Capture, Tool})` with the loopback
  address and port its connection to the proxy comes from, before it sends the
  CONNECT. The note is used up by the first CONNECT from that address,
  whatever becomes of that CONNECT: one refused for its capability (407) or
  while the session is refreshing (503) uses it up like one that is served,
  so a second CONNECT on the same connection needs a note of its own. A note
  nobody uses waits about ten seconds; `Engine.ForgetFlow(remoteAddr)` drops
  it at once, and a capture layer calls it when a connection it noted ends
  without sending its CONNECT. A note left behind would name the next
  connection from the same address and port. At most 4096 notes wait at once;
  `NoteFlow` returns an error when it could not keep one, and the flow must
  then not be handed over.
- Nothing a request carries sets a flow: no header, target or proxy user name.
- A CONNECT nobody noted is a client of the proxy environment. Its tool is the
  one the proxy was started for (`phase ai run -- claude` is `claude`,
  `phase ai exec` the harness that invoked it); the hook-managed proxy serves
  every harness and names none. A harness label that is not a listed tool
  leaves the tool unknown. For such a client the tool decides what the flow
  is called, never whether a host is read.
- `Engine.ShouldRead(tool, host)` and `Engine.ReadHosts(tool)` tell a capture
  layer which flows to hand over, without a copy of the table.

What the proxy remembers about a host it remembers per tool and host: the
pass-through windows, the once-a-minute limit on unread reports and the
placeholders already reported. The tool is the one the flow is named as
(`harness` in its events). One tool's refused handshakes never open a window
for another tool on the same host.

A pass-through window is narrower still: it is for the client that refused.
Every program started in a session is named as the session's tool, so a
program the harness runs that does not trust the proxy's certificate would
otherwise open the window for the harness's own traffic to that host. The
proxy tells clients apart by the TLS hello each opens its tunnel with: the
cipher suites, groups, versions, signature schemes and application protocols
it offers, whatever their order and without GREASE values. A window passes
through the connections whose hello offers the same as the one that was
refused, and every other client of the tool is still read on that host. No
process is looked up, so two programs that offer the same (two programs on
one TLS library with the same settings) share a window. A client whose hello
cannot be read, one that sends it late or split over several records, is
counted per tool and host as before, and a window opened that way is for
every client of the tool on that host.

#### What is read, and what happens to it

Each request to a read host is inspected before the secret guard, the access
policy and credential injection. The URL of every request is read; headers
(all but `Authorization`, `Proxy-Authorization`, `X-Api-Key` and `Cookie`) and
the body only when there is a body. On the paths that carry conversation
content (`conversationPaths` in the table) every pattern rule applies;
elsewhere on the host only registered values and Phase's own token formats are
looked for.

One table (`internal/aiproxy/leak_policy.go`) says what happens in each kind of
bytes, and a request body, a WebSocket message and a message of a Connect
stream are read by it alike. What a body or a message is, is read from its
bytes and from nothing the client calls it: valid JSON is JSON, other valid
UTF-8 with no NUL byte is text, and anything else is not text, whatever the
`Content-Type` and whichever opcode (text or binary) a message was framed
with. Protobuf is the one kind the bytes do not show, and protobuf that
happens to be text must not be rewritten as text. So on a host whose entry
says `connect`, and nowhere else, the `Content-Type` says what a body is
(below): only a type that says text or JSON is read as text, every other body
and everything there that is not text is read as protobuf, and nothing found
in a body or a message stops a request.

| Found in | A registered value or a Phase token | Anything else |
|---|---|---|
| the URL | blocks | reported |
| a header | reported | reported |
| JSON, or other text (a body, a message) | replaced | replaced or reported, as the rule says |
| bytes that are not text (a body, a message) | blocks | reported |
| a protobuf message, or any bytes that are not text, on a host that speaks Connect (a body, a message of a stream) | overwritten where it sits, by the placeholder padded or cut to its length; never blocks | overwritten or reported, as the rule says |
| a body or message that cannot be decoded (an encoding the proxy does not undo, a message compressed against the handshake) | blocks, and it is reported as unread | reported as unread |
| a body that cannot be decoded, on a host that speaks Connect | reported, and it is reported as unread; never blocks | reported as unread |
| a body or message over 16 MiB, or a message in more than 4096 frames | not read: passes, reported as unread | |

`observe` reads the same way and never replaces or blocks. A blocked request
is refused:

```http
HTTP/1.1 403 Forbidden
X-Phase-Error-Code: secret_in_request

{"error":{"code":"secret_in_request","message":"Phase blocked this request: ...","retryable":false,"details":{}}}
```

On a WebSocket the compression offer is removed from the handshake, each
client message is held until its last frame has arrived, and a message that is
replaced goes out as one new frame of the opcode the client framed it with:
JSON sent in a binary frame is replaced like JSON anywhere else, and stays a
binary message. At most 16 MiB and 4096 frames of one message are held; a
message past either is not read, and what was held and the rest of it go out
as the client framed them. A blocked message is never sent: the client gets a
close frame with code 1008 (policy violation) and the reason, the service a
close frame with code 1001, and the connection ends. The service's own frames
are passed back untouched, one whole frame at a time.

#### Events

Events have `eventType` `leak_protection` and never carry matched content.
A request or message is reported when:

- it is blocked (always);
- it holds a placeholder not yet reported for its tool and host by this proxy
  process (at most 4096 per tool and host; past that, at most one event a
  minute);
- it was left unread, once for its tool, host and reason and then at most
  once a minute, whatever the reason. A connection handed to the service
  unread is reported again at that pace for as long as it stays open;
- its only finding sits in text the provider signed (a thinking block,
  `encrypted_content`), which is never changed: one `reported` event, then at
  most one a minute for its tool and host.

Alerts alone are not reported. `outcome` is `denied` (blocked), `censored`
(something was replaced), `reported` (found, nothing changed), `observed`
(`observe` mode), `unread` or `bypass`. Only blocks are spooled durably; the
others may be dropped while the Console is unreachable and never make the
session unavailable. `detail` holds:

| Member | Meaning |
|---|---|
| `mode` | `censor` or `observe` |
| `harness` | the flow's tool when that tool's list reads the host, otherwise the tool whose entry the host is read by |
| `capture` | `proxy` or `tunnel` |
| `where` | `url`, `header`, `body`, `message` (of a WebSocket, or of a Connect stream), comma-separated |
| `inventoryHits`, `ruleRedactions`, `ruleAlerts`, `signedFindings` | counts; `signedFindings` is what was found in text the provider signed and left as it was |
| `labels` | rule labels |
| `placeholders` | the newly seen ones, comma-separated, cut to 512 characters. A placeholder registered as a key name is written `ph:<type>` with no id, once per type |
| `placeholderCount` | the distinct placeholders of the request, key names included: a placeholder found many times counts once. Exact up to 4096 |
| `replacedCount` | how many of them were actually replaced in what went out; 0 in `observe` mode and for a header or a block |
| `placeholdersCapped` | `true` when the request held more distinct placeholders than are counted (more than 4096, or so many findings that only the first 4096 were listed): the two counts are then a floor. Absent otherwise |
| `severity` | `high` when the request held 5 or more distinct placeholders, or a Phase token, or was blocked; `medium` for 1 to 4; `low` when it held only alerts or findings in signed text. Not on `unread` and `bypass` events |
| `scope` | on `unread` events and on a block of something unread: `request`, `message` (of a WebSocket, or of a Connect stream) or `connection` |
| `windowSeconds` | on a `bypass` event, the length of the pass-through window |

An event's `protocol` is `http`, `http2` when the request reached the proxy
over HTTP/2, or `websocket` for a message of one.

A pass-through window opens only when a client answers the proxy's
certificate with a TLS certificate alert twice in a row for a tool and host,
and it is for that client alone (see above). A client that drops the
connection without an alert keeps failing on that host;
`PHASE_AI_LEAK_PROTECTION=off` is the way out. The host is the name the
client connected to, not the table's entry: under a domain entry, refusals on
one name open a window for that name and leave every other name of the
domain read.

#### Connect over protobuf, and HTTP/2

Two flags of a table entry, both set for Cursor (`cursor.sh` and every name
under it): `http2`, the host's clients may speak HTTP/2, and `connect`, the
host's API is Connect (connectrpc.com) over protobuf. On such a host a path
shaped like a call (`/<dotted.package.Service>/<Method>`) is read with every
pattern rule whatever its body's type; any other path keeps its own rules.

Cursor's command-line agent takes the proxy and its certificate from its
environment (`HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`). Its unary calls go to
`api2.cursor.sh` over HTTP/1.1 with no protocol offered in the TLS hello; the
stream of its session goes to a host named for the session's region
(`agentn.global.api5.cursor.sh`, `agentn.us.api5.cursor.sh`, ...) and offers
`h2` alone. A proxy that answers that hello with HTTP/1.1 only ends the
session: the client has no other way. The desktop app's main process refuses
the proxy's certificate on every host and its extension host on some; those
names go through the pass-through windows above, each on its own.

**HTTP/2.** For a host whose entry says `http2`, when no Connection covers
it, the proxy's TLS offers `h2` and `http/1.1` and serves what the client
picks. A host a Connection covers is answered with HTTP/1.1 only, as before,
whatever its entry says. On an HTTP/2 tunnel:

- each stream is one request, handled like a request of the HTTP/1.1 tunnel
  and independent of the others; at most 100 are served at a time, which the
  client is told, and a request for another authority than the CONNECT's is
  refused with 403 `connect_authority_mismatch`;
- a request's body is not waited for. It is forwarded as it arrives and the
  answer goes back as it comes, each piece flushed, so a stream that both
  ends keep open works. A unary body whose length the client did not state
  (`application/proto`, `application/x-protobuf`, `application/protobuf`,
  JSON and text types) ends, and is waited for and read whole; when no byte
  of it comes for 30 seconds, what came is sent on with the rest, unread:
  `body_streamed`, `scope` `request`. A body of any other type that is not
  read envelope by envelope may never end: it is sent on at once, with the
  same report. A chunked body over HTTP/1.1, to any host that is read, is
  waited for or sent on the same way. The end of either direction is passed on, trailers
  are copied (the answer's whether announced or not; the request's when the
  client announced them), and an end that gives up, by reset or by closing
  the connection, ends the other;
- what is forwarded is what was sent, less the headers of one hop
  (`Connection` and what it names, `Keep-Alive`, `Proxy-Authenticate`,
  `Proxy-Authorization`, `Proxy-Connection`, `TE`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`) and `Expect`. `TE: trailers` from a client
  that spoke HTTP/2 is kept: gRPC refuses a call without it. Nothing is added: no `Accept-Encoding`, so an answer is never
  decompressed on its way back, and no `User-Agent` when the client sent
  none. That holds for the HTTP/1.1 clients of such a host as well;
- the service is reached with the proxy's own TLS and dialer for hosts no
  Connection covers, over HTTP/2 when it offers it;
- when the tunnel's connection ends, every stream on it ends, and the proxy
  lets go of the tunnel once the last one has. The proxy ends the connection
  itself when the session is revoked, expires or is no longer validated, as
  it ends a raw tunnel.

**Bodies.** On a host whose entry says `connect` the `Content-Type` says what
a body is (the type alone: `application/connect+proto; charset=utf-8` is
`application/connect+proto`):

| `Content-Type` | Read as |
|---|---|
| `application/proto` | one protobuf message. Read whole (16 MiB), any `Content-Encoding` undone as for other bodies, overwritten in place, encoded again the same way |
| `application/connect+proto` | a stream of protobuf messages, read as it is sent (below) |
| `application/connect+json` | a stream of JSON messages: each is read as JSON is anywhere, so a placeholder there is not padded and the envelope states the new length. One that is not text is overwritten in place |
| `application/grpc`, `application/grpc-web`, either with `+proto` or another name | a stream of protobuf messages in the same envelopes; the encoding of a compressed one is what `Grpc-Encoding` names |
| `application/grpc+json`, `application/grpc-web+json` | the same with JSON messages |
| `application/json`, `+json`, `text/*`, `application/x-ndjson`, `application/x-www-form-urlencoded` | what its bytes say; bytes that are not text are overwritten in place |
| `application/x-protobuf`, `application/protobuf` | one protobuf message with the rules of its path: read whole (16 MiB), overwritten in place |
| `application/grpc-web-text`, with or without a name | gRPC-Web envelopes in base64, which an overwrite would break: looked at for the report and sent on unread, `body_undecodable`, `scope` `request`; with no stated length, sent on at once as `body_streamed` |
| anything else (`application/octet-stream`, none) | bytes whose length must not change: overwritten in place when their length is stated, sent on unread over HTTP/2 when it is not |

Connect and gRPC calls, in protobuf or JSON, carry conversation content
whatever their path, and so does any body on a path shaped like a call, so
every pattern rule applies to them. Everything else on such a host, traces
for one, is read for registered values and Phase's own tokens only, with the
rules of its path.

A stream is a sequence of envelopes: a flag byte, the payload's length in
four bytes, big-endian, and the payload, which is one message. The proxy
hands on one envelope at a time and holds no more than that one. For each:

- flag bit 1, the end of a stream, which only a service sends: forwarded as
  it came and reported as `unread`, `message_flags_unexpected`, `scope`
  `message`, with what was found in it;
- a first byte with a bit set that no envelope has (any but bits 0, 1 and 7):
  the body is not what its type says, and its length field means nothing.
  That byte and everything after it goes on as it comes:
  `body_not_enveloped`, `scope` `request`;
- flag bit 0, compressed: inflated with the encoding `Connect-Content-Encoding`
  names when that is gzip. Any other encoding, or none named, is
  `message_encoding_unsupported`; a payload that does not inflate, or
  inflates past 64 MiB, is `message_undecodable`. Both go on as they came and
  are reported as `unread` with `scope` `message`;
- a payload over 16 MiB goes on as it comes: `body_over_limit`, `scope`
  `message`;
- otherwise the message is read. When something in it was replaced the new
  message goes on, compressed again if it came compressed, under a prefix
  that states its length; a protobuf message keeps its length, so its prefix
  only changes when it is compressed. When nothing was replaced the envelope
  goes on byte for byte, compressed or not.

A stream compressed as a whole (a `Content-Encoding` on the request) shows no
envelopes and is forwarded unread: `body_undecodable`, `scope` `request`. A
stream whose length the client stated, up to 16 MiB, is whole before any
answer and is read whole, so what is sent states the length it then has; any
other is forwarded as it comes, and a stated length over 16 MiB is dropped in
`censor` mode, since a compressed message may come out another length. An
envelope the client never finished goes on as far as it came, and the stream
ends as the client's did: `message_truncated`, `scope` `message`.

**The overwrite** (`censor.RewriteBinary`). Protobuf writes the length of
every string and nested message it holds, so nothing in a message may change
length. The message is walked without a schema: a length-delimited field
that parses completely as a message is descended into, anything else is a
leaf, and each leaf is scanned on its own. What is found is overwritten with
its placeholder followed by `*` up to its length
(`ph:secret:<id>*********`), or with as much of the start of the placeholder
as fits. The message stays as long as it was and parses as it did; a
placeholder that is already there, padded or cut, is never matched again. A
value split over two fields is not found.

Events are those of any request: one for the URL and headers when they hold
something, then one for each body or message in which something new was
found, with `where` `body` or `message`. The service's answers are not read.
A streamed body of a type the table does not name is held until it ends, as
a body is on every other host.

#### Hosts that answer only their own client's TLS

`mirrorHello` in the table; `opencode.ai`, for OpenCode's hosted models. A
request re-sent over Go's TLS is refused by such a service, so the proxy
re-sends over connections that open with a copy of the ClientHello the client
sent (`internal/tlsmirror`). It decides before it terminates the client's TLS,
in this order:

1. The CONNECT is answered. The client's first TLS record is read (5 second
   limit, at most 16384 bytes), starting with whatever arrived with the
   CONNECT: a client may send its hello without waiting for the answer. If it
   is not one record holding exactly one whole ClientHello, or does not arrive
   in time: `hello_unreadable`.
2. A hello that offers to resume a session (a `pre_shared_key` extension or a
   session ticket) is never copied as it is: the session is the client's with
   the service. The proxy rebuilds the hello that client sends on a
   connection that resumes nothing (`pre_shared_key` and `early_data` dropped,
   the ticket emptied, everything else kept in its order) and copies that
   one. When the same client was seen without a session earlier (for the same
   tool and host, the same hello once padding is set aside), the hello it
   sent then is copied instead: a client pads a hello by its length, which
   the rebuilt one cannot show. Up to four such hellos are kept per tool and
   host, in memory only. A hello that says early data follows (`early_data`)
   is passed through instead, `hello_resumption`: the proxy's TLS can neither
   read that data nor skip it.
3. The copy is built and compared with the hello it copies; the random, the
   session id, the key shares and GREASE values are its own, everything else
   must be equal byte for byte. If it is not: `hello_not_mirrored`, or
   `hello_resumption` when the client's hello offered a session.
4. The upstream connection is opened with the copy, through the proxy's dialer
   for hosts no Connection covers, and the service's certificate is verified
   for the CONNECT host against the roots the proxy's own TLS trusts. The copy
   offers everything the client offered, the legacy cipher suites a client
   still carries included, so what the service chose is checked once the
   handshake is done: a TLS version below 1.2, or a cipher suite that is not
   in Go's `tls.CipherSuites()` (RSA key exchange, 3DES, RC4, CBC with
   SHA-256), is refused as the proxy's own TLS would refuse it. If the
   handshake fails or is refused so: `upstream_handshake_failed`. If the
   service cannot be reached at all, the client's connection is closed: there
   is nothing to hand it to.
5. If the service chose a protocol other than HTTP/1.1: `upstream_not_http1`.
6. Only then is the client's own hello answered with the proxy's certificate
   and a full handshake (HTTP/1.1, no session tickets, whatever session the
   hello offered), and the tunnel is read like any inspected host's. A client
   that refuses the certificate counts toward the pass-through window above.

So a client that holds the service's ticket, from a connection that went
through unread, is read on its next connection like any other; it is not
passed through for the life of its process.

At each named reason nothing has been sent to the client's TLS yet, so the
connection is handed to the service as the client opened it (a new TCP
connection, the bytes already read, then both directions copied) and is not
read, for as long as the client keeps it: a whole session can run over one
such connection. That is an `unread` event with `method` `CONNECT`, `path`
`/`, the reason, and `detail` `harness`, `mode`, `capture` and `scope`
`connection`. It is sent once for a tool, host and reason, then at most once a
minute, and it is sent again at that pace for as long as such a connection
stays open. Status lists the host under `unreadHosts` with the reason
meanwhile (above). No event, status member or log carries anything of a
hello.

Every request of a terminated tunnel leaves over connections opened with that
tunnel's copy: the one opened in step 4, then, when another is needed, a new
one opened the same way. If that fails the request fails with 502
`upstream_unavailable`; Go's own hello is never sent to such a host from such
a tunnel. The forwarding adds no header of its own: no `Accept-Encoding`, so
answers are not decompressed, and no `User-Agent` when the client sent none
(the proxy's usual transport names itself `Go-http-client/1.1` then). A
WebSocket upgrade is carried like any inspected host's, over such a
connection. A Connection's own host is not handled this way: its tunnel is
always terminated and sent with the proxy's usual transport.

On every other path too, what a client sent with its CONNECT is not lost: a
host that is read without its hello being copied, a host the proxy leaves
alone, and a host in a pass-through window all begin with the bytes that
arrived before the proxy's answer.

### GET /v1/connections and GET /v1/connections/{connectionId}

What the Agent may read about its Connections. Both are answered from the
session configuration the proxy already holds: no Console call, so they cost
nothing against the plan rate limit. They never carry a secret, a decoy, or
session material; a payload that would is refused with 502
`unsafe_connection_response`. A decoy, a session credential or a packaged
Connection's live value is looked for anywhere in the payload. A custom
Connection's value is one a member chose and may read like an ordinary word,
so it is compared only with what the Console said about that Connection (its
name, definition and policy). A match refuses that Connection's own read and
the list, never the read of another Connection; in a session opened through
the Console such a value has already been withheld (`material_exposed`,
below), so the reads answer and show the Connection as `unavailable`.

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
      "policy": {
        "version": 1,
        "default": "allow",
        "rules": [{ "class": "delete", "effect": "ask" }, { "match": { "methods": ["POST"], "path": "/v1/charges/*" }, "effect": "block" }],
        "temporaryAllows": [{ "id": "allow-1", "match": { "methods": ["DELETE"], "path": "/v1/items/42" }, "expiresAt": "2026-10-17T19:00:00Z" }],
        "managed": [{ "id": "secret_guard", "locked": true, "rules": [{ "class": "credential_minting", "effect": "block" }] }]
      },
      "grantExpiresAt": "2026-10-18T09:00:00Z",
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
    },
    {
      "id": "c0a80101-0000-4000-8000-0000000000a9",
      "name": "Staging AWS",
      "serviceType": "aws",
      "state": "expired",
      "stateReason": "access_expired",
      "expiredAt": "2026-10-16T09:00:00Z",
      "request": {
        "kind": "access_change",
        "title": "Renew access to Staging AWS",
        "action": { "type": "agent_grant.renew", "version": 1, "connectionId": "c0a80101-0000-4000-8000-0000000000a9" }
      }
    }
  ]
}
```

`policy` is the access policy on the Connection, with this Workflow's
temporary allows, as Console sent it: its rules, the temporary allows a member approved, and the
managed secret guard (see §5). `grantExpiresAt` is when time-limited access
ends. A Connection whose access has ended is listed with `state: "expired"`,
`stateReason: "access_expired"`, `expiredAt` and a `request`: a complete body
for `POST /v1/requests` that asks a member to renew it, sent unchanged. That
covers both a Connection whose time ran out since the last refresh and those
Console lists as expired in the last 30 days (`expiredConnections` in the
session payload); the latter have no other members.

An app Connection gives access to an app's secrets: `serviceType`
`phase_app`, `state` `active` (or `expired`, as above), and `app`,
`environments` and `access`, the effect (`allow`, `ask` or `block`, with
`until` on a temporary allow) of each class of secrets call (`read`, `create`,
`update`, `delete`). It comes from `appConnections` in the session payload and
is listed only: `phase secrets` and `phase run` call the Console's secrets API
with the Agent token, never through the proxy. `/v1/status` lists it the same
way.

```json
{ "id": "c0a80101-0000-4000-8000-0000000000c1", "name": "orders-service secrets (Development, Staging)", "serviceType": "phase_app", "state": "active",
  "app": { "id": "c0a80101-0000-4000-8000-0000000000e1", "name": "orders-service" },
  "environments": [{ "id": "c0a80101-0000-4000-8000-0000000000f1", "name": "Development", "envType": "dev" }],
  "access": { "read": { "effect": "allow" }, "create": { "effect": "allow", "until": "2026-11-17T12:00:00Z" }, "update": { "effect": "ask" }, "delete": { "effect": "block" } } }
```

`definition`, `valueRevision` and `keyVersion` exist only for `serviceType`
`http`. `state` uses the same values as status. When a custom Connection's
value cannot be used, `stateReason` names why, for example
`sealed_material_host_mismatch` (the value was entered for a different set of
hosts and a member must enter it again),
`sealed_material_agent_key_unavailable`, `material_missing` (the session
carried no value for it) or `material_exposed` (the proxy withheld the value
and a member must enter a different one: it also appears inside something the
Agent can see, such as an identifier, a decoy, or the Connection's own name,
definition or policy, or it is shorter than 8 bytes, which the Console refuses
when a value is entered). Only that Connection is affected. When it is the
Connection's own name that holds the value, the name is withheld with it:
status, these reads, discovery and events call the Connection
`name withheld` until a member renames it. A packaged service
whose value appears inside something the Agent can see still refuses the
session.

`GET /v1/connections/{connectionId}` returns one entry flat, with
`"kind": "phase.ai.connection"`:

```json
{ "schemaVersion": 1, "kind": "phase.ai.connection", "id": "c0a80101-0000-4000-8000-0000000000b1", "name": "Example API", "serviceType": "http", "state": "ready", "definition": { "…": "…" }, "valueRevision": 3, "keyVersion": 2 }
```

Errors: 400 `invalid_connection_id`, 404 `connection_unavailable` when the ID
is not part of this session.

### GET /v1/capabilities

Versioned catalog of every service this Phase instance can manage, forwarded from
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

When the Workflow has saved context, Console appends a "Workflow notes"
section to the general context, between the markers
`<<<BEGIN WORKFLOW NOTES>>>` and `<<<END WORKFLOW NOTES>>>`. The proxy forwards
the text as it is. The notes are written by members; they are background for
the Agent, not instructions from Phase.

Errors: 400 `invalid_context_query`, 502 `unsafe_agent_context_response` if
Console answers for a different service than asked.

### GET /v1/presets

The provider presets a Connection can be asked for by ID, read from Console's
Agent registry (`GET /v1/agents/registry/`, `presets`) and kept in memory for
five minutes per session. If Console cannot be reached the list last read is
served; with none, Console's error is forwarded.

```json
{
  "schemaVersion": 1,
  "kind": "phase.ai.presets",
  "presets": [
    { "id": "stripe", "name": "Stripe", "description": "Stripe API", "category": "payments", "hosts": [{ "match": "exact", "value": "api.stripe.com", "port": 443 }] },
    { "id": "mcp-server", "name": "MCP server", "category": "tools", "hosts": [] }
  ]
}
```

`hosts` is forwarded as Console lists it. GitHub, GitLab, Cloudflare, Vercel,
Render, Railway and Supabase are not presets: they are ordinary Phase services
asked for by service type (a `setup` request with `serviceType`, found in
`GET /v1/capabilities`), with no custom definition. To use a preset, send
`agent_connection.create` with `"preset": "<id>"` in place of `definition`
(see `POST /v1/requests`).

### GET /v1/hints

Recent dead ends of this session and the request that asks a member to open
each one. Kept in memory only, at most 20, oldest first; a repeated dead end is
counted, not repeated. Nothing in a hint is secret, and a hint about a host
never holds a path.

```json
{
  "schemaVersion": 1,
  "kind": "phase.ai.hints",
  "hints": [
    {
      "kind": "access_policy_ask",
      "reason": "agent_access_policy_ask",
      "host": "api.example.com",
      "method": "DELETE",
      "path": "/v1/items/42",
      "class": "delete",
      "connectionId": "c0a80101-0000-4000-8000-0000000000b1",
      "connectionName": "Example API",
      "request": { "kind": "access_change", "title": "Allow DELETE /v1/items/42 on Example API", "action": { "…": "…" } },
      "count": 1,
      "firstAt": "2026-10-17T09:12:30Z",
      "latestAt": "2026-10-17T09:12:30Z"
    },
    {
      "kind": "connection_needed",
      "reason": "upstream_rejected_unbound_host",
      "host": "api.stripe.com",
      "statusCode": 401,
      "preset": "stripe",
      "request": { "kind": "setup", "title": "Connect Stripe", "action": { "type": "agent_connection.create", "version": 1, "serviceType": "http", "name": "Stripe", "preset": "stripe" } },
      "count": 2,
      "firstAt": "2026-10-17T09:13:02Z",
      "latestAt": "2026-10-17T09:13:40Z"
    }
  ]
}
```

| `kind` | `reason` | recorded when |
|---|---|---|
| `access_policy_ask` | `agent_access_policy_ask` | the access policy asked about a call (§5); `request` is the one the 403 carried |
| `access_expired` | `access_expired` | a call reached a Connection whose time-limited access has ended; `request` asks to renew it |
| `connection_needed` | `lockdown_unbound_host` | `--lockdown` refused a host no Connection covers |
| `connection_needed` | `upstream_rejected_unbound_host` | a service answered 401 or 403 to a plain-HTTP request on a host no Connection covers; its answer was passed on untouched |
| `connection_needed` | `unbound_preset_host` | the Agent tunnelled to a host no Connection covers that belongs to a preset. The proxy cannot see the answers inside such a tunnel, so this is how an HTTPS 401 or 403 is addressed |

A hint repeats text the Agent sent (a host, a method, a path). One in which
that text holds a Connection's live value is left out of the list.

For `connection_needed` the `request` is built when the hints are read. When the
host belongs to a packaged service in the Console's registry (`services`, read
with the presets and cached with them; `aws` is never matched), the hint carries
`service` and the ordinary packaged setup request (`kind: "setup"`,
`serviceType`, the service's first `credentialProvider`, `credentialName`,
`markdown`), with no definition and no preset. Otherwise it is built by
preset ID when the host belongs to a preset, otherwise an
`agent_connection.create` whose definition has the host filled in and a bearer
token attached in the `Authorization` header (it exports no variable, so an
approval is served by the running session). Adjust the definition before
sending when the service authenticates differently. A host a Connection covers
by now is no longer listed.

### POST /v1/requests

Ask the human for something through Console: a packaged request (the two
kinds below) or a request with an `action`. Optional `?wait=N`
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
Connection and never supplies a secret: it asks, a member reviews the action
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
    "definition": { "…": "the full requested definition" }
  }
}
```

| `action.type` | `kind` | meaning |
|---|---|---|
| `agent_connection.create` | `setup` | request a new custom Connection: `serviceType: "http"`, `name`, `definition` |
| `agent_connection.update` | `connection_update` | request a new definition and/or name for a granted Connection |
| `agent_connection.secret_update` | `credential_update` | ask a member to enter a new secret; carries no value |
| `agent_connection.remove` | `connection_removal` | ask to remove this Workflow's grant of a Connection |
| `agent_connection.create` with `preset` | `setup` | request a new Connection from a preset: `preset` (an ID from `GET /v1/presets`) in place of `definition`; `hosts` only for a preset whose hosts are editable |
| `agent_connection.app_access` | `setup` | request access to an app's secrets: `appId` or `appName`, `environments` (1 to 20 names or IDs), `access` (`read` or `read_write`) |
| `agent_grant.allow` | `access_change` | ask to allow, for a limited time, a call the access policy asks about: `connectionId`, `allow` (exactly one of `class`, `classes`, `match` or `operation`), optional `blockedCall` |
| `agent_grant.renew` | `access_change` | ask to renew time-limited access: `connectionId` |
| `agent_workflow.context_update` | `context_update` | ask to replace the Workflow's saved context: `markdown`, the complete new text |

Rules enforced by the proxy for a request with an `action`: the type is one of
those above, `version` is `1`, `kind` is the one listed for the type, and the
action carries no secret value (no `value` member on the action itself, and in
`definition.fields` a `value` only on a field of kind `identifier`; a
`definition` that is not an object is refused). Four types have one more local
check each: a `preset` is an ID and stands in place of `definition`, never
beside it; `allow` has exactly one of `class`, `classes` (a list of different classes,
as an app Connection's refusal asks for), `match` or `operation` (an AWS
action such as `ec2:TerminateInstances`), and no class is ever
`credential_minting`; an app access request names one app (`appId` or
`appName`), 1 to 20 different environments and `access` `read` or
`read_write`; `markdown` of a context update is text of at most
16384 characters. Everything else inside `action` is forwarded to Console
untouched, including members this CLI does not know, and Console validates it. `title` (≤ 120 characters, plain text) and `markdown` are
optional beside an action; a missing `markdown` is forwarded as `""`.
`credentialProvider` and `credentialName` are not needed. `connection_update`,
`connection_removal`, `access_change` and `context_update` are valid only with
an action. The response echoes `title` and `action`.

Time-limited access. A request that ends in access (`setup`, packaged or with
an action, and `access_change`) may carry a top-level `durationSeconds`:

```json
{
  "kind": "access_change",
  "title": "Allow DELETE /v1/items/42 on Example API",
  "durationSeconds": 3600,
  "action": {
    "type": "agent_grant.allow",
    "version": 1,
    "connectionId": "c0a80101-0000-4000-8000-0000000000b1",
    "allow": { "match": { "methods": ["DELETE"], "path": "/v1/items/42" } },
    "blockedCall": { "method": "DELETE", "host": "api.example.com", "path": "/v1/items/42", "class": "delete" }
  }
}
```

Absent, the organisation's default applies; the requests the proxy builds leave
it out. The proxy refuses only what can never be valid (zero, negative, not a
whole number, or on a kind that does not end in access); Console owns the
bounds and answers `invalid_duration` with the maximum in the message. The
member who approves may change the duration. Other Console codes forwarded as
they are: `invalid_access_allow`, `access_policy_blocks_allow` (a block rule
covers the allow, so approval could not help), `secret_guard_blocks_call`,
`access_policy_not_supported`, `connection_not_renewable`,
`invalid_connection_preset`, `invalid_workflow_context`,
`credential_in_workflow_context`.

After approval, `connection_update` and `connection_removal` make the proxy
re-pull its configuration, and the proxy decides the `runtimeAction`. A custom
HTTP Connection whose hosts, definition, injections or `allowPlainHttp` changed
is reshaped in the running session, and a removed one is dropped from it:
`retry`. An approved `agent_connection.create` is handled the same way: the
proxy re-pulls its configuration, and a new custom Connection that exports
nothing (no agent env, no environment bindings, no config env, no credential
environment names) is served by the
running session, `retry`. Only a change to what the Agent process was given (an
identifier, a decoy, an exported variable, a Connection's
`credentialEnvironment`, any other new grant, or a host that
an inherited `NO_PROXY` entry covers) answers `restart_required`. Packaged services still
recycle on any change to their hosts, configuration or injection. A removed
Connection's variable stays in processes that already run; it names a decoy
nothing accepts any more, and the manifest does not treat it as drift.

An approved `access_change` also makes the proxy re-pull its configuration. A
temporary allow and a later expiry are enforced by the proxy alone and never
reach the Agent's environment, so they apply to the running session: `retry`,
and the refused call goes through when repeated. The same holds for every
change to a policy, to `operationClasses`, to a Connection's `secretGuard` or
`actionClasses`, to `grantExpiresAt` and to the list of expired Connections,
whoever made it: they apply at the next refresh, never
recycle the session, and are not compared by the manifest or by discover.
Only a renewal that creates a new grant for a Connection that exports
something answers `restart_required`. An approved `context_update` changes
nothing in the proxy and answers `retry`.

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

`resolutionNote` is a member's own words. When it holds a live credential
value of the session, or the session's credential, the proxy replaces the
note with one sentence saying it was withheld; everything else in the answer
is as the Console sent it.

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
      "PHASE_AI_CA_BUNDLE": "/Users/dev/.phase/ai/runtime-ca-bundle-5d41402abc4b2a76b9719d911017c592.pem",
      "AWS_CA_BUNDLE": "/Users/dev/.phase/ai/runtime-ca-bundle-5d41402abc4b2a76b9719d911017c592.pem",
      "NODE_EXTRA_CA_CERTS": "/Users/dev/.phase/ai/runtime-ca-bundle-5d41402abc4b2a76b9719d911017c592.pem",
      "AWS_ACCESS_KEY_ID": "AKIAPHASEDECOY0000001",
      "AWS_SECRET_ACCESS_KEY": "decoy/9f3kQ2vL8pR1tX7wZ4bN6mC0sD5hJ2gF",
      "AWS_REGION": "eu-central-1",
      "PHASE_AI_RESERVED_ENV": "AWS_ACCESS_KEY_ID,AWS_CONFIG_FILE,AWS_PROFILE,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN,…"
    },
    "unset": ["AWS_PROFILE", "AWS_SESSION_TOKEN", "PHASE_SERVICE_TOKEN", "PHASE_AGENT_TOKEN"]
  }
}
```

`PHASE_AI_RESERVED_ENV` lists, comma-separated, the `credentialEnvironment`
names of the Connections the environment covers (here, that one). `phase run`
runs as its own process, so it reads the names it must not let an app secret
replace from there, beside Phase's own variables.

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

Decoys are minted per backend session. A proxy process keeps one proxy
credential for its lifetime and remembers every decoy generation it handed out,
so a client started before a session recycle keeps working: requests carrying
an older decoy are translated to the live credential of the same Connection.

### GET /v1/discover

The Console discovery payload for this session: Connections with hosts,
injection action, identifiers, decoys and bindings, never live material. A
diagnostic view of what the proxy is configured to do. `policy`,
`operationClasses`, `grantExpiresAt` and `expiredConnections` are forwarded as
Console sent them and are not checked against the proxy's configuration.

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

### POST /v1/rotate

No body. Rotates the proxy's *backend* session credential with Console. The
process-local capability does not change.

```json
{ "schemaVersion": 1, "sessionUid": "sess_01HZX9K3M2", "expiresAt": "2026-10-17T10:12:30Z", "configGeneration": 5, "rotated": true }
```

### POST /v1/revoke

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
checked before any is applied. A header, query or Basic credential of any HTTP
Connection (custom or packaged) is neither swapped nor attached on a
plain-HTTP request unless the Connection carries `allowPlainHttp: true`
(AWS request signing is handled on its own); the request is refused with
`agent_credential_injection_failed`. Failures on bound traffic use the
envelope from §3 for most services and an AWS-style XML error
(`<Error><Code>PhaseProxyError|PhaseAccessDenied|PhaseCredentialMintingBlocked|PhaseAccessPolicyAsk|PhaseAccessPolicyBlocked|PhaseAccessExpired</Code>…`)
for `aws_sigv4` Connections. Codes worth knowing: `agent_connection_denied`
(403, Connection not authorized), `agent_access_policy_ask` and
`agent_access_policy_blocked` (403, below), `agent_access_expired` (403,
time-limited access ended), `agent_credential_injection_failed` (403, e.g. the
request was not signed with the decoy), `agent_binding_unavailable` (503, session
recycling), `upstream_unavailable` (502), `unbound_host_blocked` (403, lockdown),
`invalid_proxy_request` (400, the request cannot be judged or forwarded as it
is written).

The request-target of a proxied request is a path, or an absolute `http` or
`https` URL of the host the request is sent to. Any other form, such as
`scheme:rest` with no `//`, has no path the proxy could check against a host
rule, an access policy or the secret guard, and is refused with 400
`invalid_proxy_request` inside a tunnel and outside one; the refusal is
recorded as an event with reason `unclassifiable_request`.

### Access policy

The Connection's `policy` (rules from the Connection, temporary allows from
this Workflow's grant) is evaluated for every request to an HTTP Connection before
its credential is swapped in or attached. A policy that only allows (the
default) is not evaluated at all, and the Connection behaves as without one.

1. The call is classified. For the `aws` service by action name, with the
   tables the Console sends as the Connection's `actionClasses` (scheme
   `aws_actions`, applied by `pkg/proxy/aws_classes.go`: a read verb is `read`; a write in IAM,
   Organizations, an account service, or to a policy, permission or ACL is
   `admin`, as are the listed calls that share a resource or open it to
   others, such as `ec2:ModifySnapshotAttribute` or
   `lambda:CreateFunctionUrlConfig`; then `create` and `delete` verbs; anything
   else `update`), read from `X-Amz-Target`, the `Action` query parameter, the
   `Action` field of a form body, and the path of a Smithy RPC v2 request
   (`/service/<Service>/operation/<Name>`). Names are compared without regard
   to letter case, except that only a read verb spelled as AWS spells it makes
   a `read`. A query-protocol service (EC2, IAM, STS and the others listed
   there) has its body read for `Action` whatever `Content-Type` the request
   claims. A request that names no action (S3 and the other REST services) is
   classified by method, with the sub-resources of the S3 family (`?delete`,
   `?policy`, `?acl` and similar) and an ACL set in headers (`x-amz-acl`,
   `x-amz-grant-*`, `admin`) called out; `POST ?select&select-type=…` is a
   `read` only when those are its whole query. An action selector decides on
   its own only on a query-protocol or JSON-target service. On any other
   service the method and sub-resource class is a further candidate, so an
   `X-Amz-Target` or `Action` added to a REST call hides nothing.
   `operationClasses` is ignored on the `aws` service. For any other HTTP
   Connection, packaged or custom: the Connection's `operationClasses` (a
   custom definition's, or a packaged service's own, for example its single
   GraphQL endpoint as `update`), first match wins, then the method (`GET`,
   `HEAD`, `OPTIONS` read; `POST` create; `PUT`, `PATCH` update; `DELETE`
   delete; anything else update).

   On every HTTP Connection two things add a further candidate. A method
   override (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`, or
   a `_method` query parameter) adds the class of the method it names, and
   rules by method are matched against that method too; a name that is no HTTP
   method counts as `update`. A protocol upgrade (a WebSocket handshake) adds
   `update`, because the proxy does not see what travels afterwards, unless an
   `operationClasses` entry classifies that request.
2. The secret guard runs first (below).
3. A rule or temporary allow is one of a `class`, a `match` or an `operation`.
   An `operation` (`{"operation": "ec2:TerminateInstances"}`) matches an `aws`
   call whose classified action equals it, compared without regard to case; it
   never matches a call on another service, and a policy with an `operation`
   rule on a non-`aws` Connection is unsupported (below). Every matching rule is collected and the strongest effect wins: `block`,
   then `ask`, then `allow`. No matching rule: the policy's `default`.
4. An `ask` becomes an `allow` when a temporary allow matches the call and its
   `expiresAt` has not passed. That is read from the clock on every request. A
   temporary allow never changes a `block`.

A request that could belong to several classes (an AWS request naming two
actions, a method override, an upgrade, a path the proxy cannot bring into
canonical form) is judged by the most restricted one. Such a path matches every
`ask` or `block` path rule and no `allow` path rule.

Path globs are compared in two ways, on purpose. An `ask` or `block` rule and
an `operationClasses` entry also match a path that differs only in letter case,
one trailing slash, or a `;params` tail on its last segment (`/v1/admin`,
`/V1/Admin/` and `/v1/admin;x` are one path to many servers); an entry of
`operationClasses` that matches only this way adds its class as a further
candidate. An `allow` rule and a temporary allow match the path exactly as it
was sent, so a respelled path never borrows an allow written for another one.

An AWS query-protocol body that is too large to read (256 KiB), or that names
no action at all (in an encoding the proxy does not read, for one), is
refused with `agent_access_policy_uninspectable`. A policy this CLI cannot read
in full (an unknown version, effect, class or rule member) is never enforced in
part: the Connection is `unavailable` with `stateReason`
`access_policy_unsupported` and its calls answer 403
`agent_access_policy_unsupported`. The same holds for a `secretGuard` this CLI
cannot read, and for `actionClasses` in a scheme or version it does not know
on an `aws` Connection (whose secret guard reads them too) or under a policy
that can stop calls. An AWS Connection (the `aws` service, or one signed with
SigV4) that arrives without its `secretGuard` or `actionClasses` is never
used: it is `unavailable` with `stateReason` `provider_rules_missing`, and its
calls answer 403 `agent_provider_rules_missing` (the Console must be updated).

The answer when the policy stops a call is 403, at once; the proxy never holds
a call open waiting for approval:

```json
{
  "error": {
    "code": "agent_access_policy_ask",
    "message": "Phase did not send this call: this DELETE (a delete call) on Example API needs a member's approval under this Workflow's access policy. To ask for it, send the JSON in details.request unchanged to POST http://phase.invalid/v1/requests, show the human the approvalUrl, and retry the call once the request is approved.",
    "retryable": false,
    "details": {
      "connectionId": "c0a80101-0000-4000-8000-0000000000b1",
      "grantId": "c0a80101-0000-4000-8000-0000000000e1",
      "connectionName": "Example API",
      "class": "delete",
      "method": "DELETE",
      "path": "/v1/items/42",
      "rule": { "class": "delete", "effect": "ask" },
      "request": {
        "kind": "access_change",
        "title": "Allow DELETE /v1/items/42 on Example API",
        "action": {
          "type": "agent_grant.allow",
          "version": 1,
          "connectionId": "c0a80101-0000-4000-8000-0000000000b1",
          "allow": { "match": { "methods": ["DELETE"], "path": "/v1/items/42" } },
          "blockedCall": { "method": "DELETE", "host": "api.example.com", "path": "/v1/items/42", "class": "delete" }
        }
      }
    }
  }
}
```

`rule` is the rule that decided, `"default"`, or `"secret_guard"`. `operation`
is added when an AWS request names its action (`"ec2:TerminateInstances"`).
`method` is the request's own method, or `UNKNOWN` when that is not a short
token or holds a live value.
`agent_access_policy_blocked` has the same details without `request`: a blocked
call cannot be requested.

`request` names the narrowest thing that covers the call. For an AWS call
whose action the proxy can name it is that one action,
`"allow": {"operation": "ec2:TerminateInstances"}`, and `blockedCall` carries
the same `operation`: an action carried in a header or a body shares `POST /`
with every other action of the service, so a path would cover them all. For any
other call it is the method and the exact path (glob characters escaped), as
for an AWS request that names no action (S3 object paths); when a method
override decided, the method is the one it names, and the message says so
("this POST, which asks to be run as DELETE"). It names the call's
class instead when the path cannot be used or the action name is not one an
allow may carry: a path that
is not canonical, is longer than 1024 characters, or holds a decoy or
something shaped like a credential is never repeated (`blockedCall.path` is
then `/redacted`). No `durationSeconds` is set. An AWS client shows only an
error code and message, so for `aws_sigv4` Connections the message ends with
the same request as `JSON: {…}`; `GET /v1/hints` lists it too.

### Secret guard

Calls that mint a new credential or assume another identity (AWS STS
`AssumeRole*`, `GetSessionToken`, `GetFederationToken`, IAM `CreateAccessKey`,
ECR `GetAuthorizationToken`, a GitHub App installation token and the rest of
the Connection's `secretGuard`, which the Console sends from the service's
manifest; `pkg/proxy/minting.go` applies it) are blocked on every Connection,
with or without a policy. No rule, temporary allow or Connection setting turns the
guard off. The answer is 403 `agent_access_policy_blocked` with
`"class": "credential_minting"` and `"rule": "secret_guard"`
(`PhaseCredentialMintingBlocked` in the AWS envelope); a request the proxy
cannot inspect for it keeps `credential_minting_uninspectable`. The guard's
path rules are compared like `ask` and `block` rules, and with repeated
slashes and dot segments removed, so a respelled path is still the same call.

As a backstop, responses on `aws_sigv4` Connections are scanned for credential
material in the shape STS uses: a `SecretAccessKey` (or `SecretKey`) value with
an `AccessKeyId` value within 8 KiB of it, as XML elements or JSON members, in
any letter case. That secret key, the nearest access key ID and the nearest
`SessionToken` are replaced with `PHASE_REDACTED_CREDENTIAL` before the
response reaches the Agent, and an event with reason
`credential_response_scrubbed` and the number of values is recorded. A lone
`AccessKeyId`, as in a list of a user's keys, is left as it is. Only XML and
JSON bodies (or bodies with no `Content-Type`) are scanned; custom HTTP
Connections are never scanned. The scan runs as the body streams, so chunked
and arbitrarily large bodies are covered with a bounded window and
`Content-Length` is dropped (the proxy frames the body itself). A gzip body is
decoded to look and re-encoded only when something was replaced; a body in any
other encoding, or a gzip body above 8 MiB, cannot be inspected and is refused
with 502 `unsafe_aws_response`.

### Time-limited access

A Connection past its `grantExpiresAt` is refused by the clock on every
request, before the next refresh removes it: 403 `agent_access_expired`
(`PhaseAccessExpired`), with `details.request` holding the renew request and
`details.expiredAt`. Open WebSocket and PostgreSQL streams of that Connection
are closed.

### Hosts no Connection covers

Under `--lockdown` the 403 `unbound_host_blocked` names how to ask for a
Connection: `details.host`, `details.hints` (the hints URL) and, once the
session holds the preset list, `details.request` (by preset ID when the host
belongs to a preset, `details.preset`). The proxy never waits for Console to
answer a proxied request: the first refusal starts reading the preset list in
the background and carries no `request`; `GET /v1/hints` always has it. A
refused CONNECT rarely shows its body to the caller, which is the other reason
the hints route exists.

Without lockdown, a service's own 401 or 403 on such a host is passed on
untouched, body and headers; the proxy only records a hint.

### Events

An asked call is recorded with `proxyDecision: "ask"` and reason
`agent_access_policy_ask`; a blocked one, the secret guard included, with
`"block"` and `agent_access_policy_blocked`. `detail` carries `connectionId`,
`connectionName`, `class`, `method`, `path`, `rule` (`"default"`,
`"secret_guard"` or the one rule object) and `operation` when known. The
ready-to-send request is never part of an event. A scrubbed response is an
event of its own: `proxyDecision: "allow"`, `outcome: "scrubbed"`, reason
`credential_response_scrubbed`, `detail.rule: "secret_guard"` and
`detail.scrubbedValues`. All of these are spooled to disk like denials until
Console has them.

Every response to bound traffic, success or refusal, carries `X-Phase-Event-Id:
event-…`, the ID of the event the proxy reports to the Console for that request
(AWS-style errors repeat it as `<RequestId>`). It is credential-free; agents
quote it when reporting a problem so the human can find the request, its
decision, and its outcome in the Console. Unbound passthrough traffic has no
event and no header.
