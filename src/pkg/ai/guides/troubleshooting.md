# Troubleshooting

## Recognise Phase failures

- Provider-specific failures may keep the provider's native error format.
- Proxy control failures use a structured Phase error with a `code`. `agent_control_forward_failed` means the proxy could not reach the Phase Console to forward a control call; try again later or tell the human.
- `agent_access_policy_ask`, `agent_access_policy_blocked`, and `agent_access_expired` are decisions about this Workflow's access, not outages: see `phase ai guide access-rules`. Do not retry unchanged and do not switch credentials.
- `ambiguous_agent_binding`: several Connections match the call; choose one (below) or ask the human which to use.
- `unbound_host_blocked`: no Connection covers the host; see "Hosts without a Connection" in `phase ai guide custom-http`.
- TLS or CA errors while Phase is active mean bootstrap or trust is broken; never add an insecure flag. Keep hostname verification enabled. If a managed client cannot use Phase's trust configuration, stop that Phase operation and surface the error.

Every proxied request and every proxy refusal carries an `X-Phase-Event-Id` response header (AWS-shaped errors repeat it as `RequestId`). It holds no credential material. Quote it when reporting a Phase problem so the human can find the event in the Console. The proxy swaps credentials in requests and never rewrites responses, so identities in provider output are real; the one exception is the secret guard (`phase ai guide access-rules`).

## Leak protection

The proxy reads what AI tools send to their model providers and replaces secret values Phase handed out with `ph:<type>:<id>` placeholders. `phase ai status` shows the mode on its `Leaks:` line. The human sets it with `PHASE_AI_LEAK_PROTECTION` where the proxy starts:

- `censor` (the default): values are replaced, in JSON and in any other text. A value in a URL, or in bytes that are not text (a binary body), cannot be replaced, so that request is refused with `secret_in_request`. A WebSocket message is treated the same way: text is replaced, and a binary message that holds a value closes the WebSocket with close code 1008. A value in a header is reported and the request goes out, and text the provider signed (thinking blocks) is never changed.
- `observe`: values are found and reported to the Console, nothing is changed.
- `off`: model traffic is not read.

A command registers the values it hands out with the proxy before it prints or exports them. Inside a Phase AI session it uses that session's proxy. In a shell that does not load the Phase environment it uses the proxy the harness hooks keep running, when one runs. `Phase: leak protection could not be reached` on stderr means the values of that command were not registered and are not removed from model traffic; `phase ai status` shows whether the proxy runs. With an Agent login inside a session the command refuses to run instead.

Each AI tool has its own list of model hosts, and a host is read for that tool only when Phase knows which tool is calling. A proxy started with `phase ai run -- <tool>` reads that tool's hosts and lists the others as not inspected.

A host listed as not inspected is a model host whose traffic Phase does not read: its client refuses the proxy's certificate (Cursor), it belongs to another tool than the one the proxy was started for, or its client refused the proxy's certificate twice in a row and is passed through for a while. Secrets sent there reach the provider. Never change the mode, or the proxy settings, to get past a placeholder.

Only a client that refuses the certificate with a TLS alert opens that pass-through window, and only for that tool on that host. A client that drops the connection without saying why keeps failing on that host; the human can set `PHASE_AI_LEAK_PROTECTION=off` where the proxy starts and restart the session to let it through unread.

OpenCode's hosted models (`opencode.ai`) are read. That service answers only OpenCode's own TLS, so Phase re-sends each request over a connection that opens with a copy of the TLS hello OpenCode sent. A client that offers to resume an earlier TLS session is read too: Phase copies the hello that client sends without a session and answers the client with a full handshake. A connection it cannot open that way is passed through unread, and the Console shows an `unread` leak protection event with the reason: `hello_unreadable` (what the client sent first was not a TLS hello), `hello_resumption` (the client's hello says early data follows it, or offers a session and cannot be copied exactly without it), `hello_not_mirrored` (no exact copy of the hello could be made), `upstream_handshake_failed` (Phase's own connection to the service failed) or `upstream_not_http1` (the service chose HTTP/2). Secrets sent on that connection reach the provider.

An `unread` event is sent once for a tool, host and reason, then at most once a minute. Other reasons: `body_undecodable` (a request body in an encoding Phase does not undo), `body_over_limit` (a body or message over 16 MiB) and `message_compressed` (a WebSocket message compressed although no compression was agreed).

## When Phase is unavailable

Failure to reach `phase.invalid` blocks only the requested Phase operation. Bash, Git, GitHub CLI, provider clients, builds, tests, and other ambient tools remain available. Do not recommend disabling Phase, rerunning `phase ai enable`, or restarting the harness because discovery is unavailable.

Only when setup output explicitly says a just-installed or refreshed adapter must reload should you tell the human to restart that harness. Never infer restart recovery from an ordinary tool or Phase operation failure.

After a resolved request, retry the original command. If it still fails, fetch status once. Never change credential source implicitly.

## Provider limits

The managed process sees provider-compatible decoys. Never replace them with an ambient profile or value, print the managed environment, or copy a decoy into another process.

Follow the service-specific context Phase returns (`GET http://phase.invalid/v1/context?serviceType=<service-type>`) for supported operations and limits. Do not generate a presigned request or another provider-issued bearer capability unless that context explicitly says the operation is supported. Never print, persist, reuse, or transmit a live short-lived capability returned to a local helper. If the task cannot tolerate that process seeing such a capability, do not perform the operation.

## Select one Connection

When a Phase-managed operation needs one of several identities for the same service, use the `connectionId` from status:

```sh
phase ai exec --connection <connection-id> -- <provider-command> [args...]
```

Plain tools are not captured automatically. Use explicit managed execution only after the human chooses a Phase Connection for that operation. Concurrent commands may select different identities. An ambiguous unselected request fails closed. Selection never changes the global default or relaxes destination, expiry, or credential checks. In the automatic environment (Claude Code, OpenCode) selection is not available: ask the human which Connection to use.
