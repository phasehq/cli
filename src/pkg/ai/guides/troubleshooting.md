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

- `censor` (the default): values are replaced, in JSON and in any other text. A value in a URL, or in bytes that are not text (a binary body), cannot be replaced, so that request is refused with `secret_in_request`. On Cursor's hosts nothing in a body is refused: there a value in protobuf, or in any other bytes that are not text, is overwritten where it sits (below). A WebSocket message is treated like a body of the same bytes, whichever way the client framed it: text is replaced, and bytes that are not text and hold a value close the WebSocket with close code 1008. A value in a header is reported and the request goes out, and text the provider signed (thinking blocks) is never changed.
- `observe`: values are found and reported to the Console, nothing is changed.
- `off`: model traffic is not read.

A command registers the values it hands out with the proxy before it prints or exports them. Inside a Phase AI session it uses that session's proxy. In a shell that does not load the Phase environment it uses the proxy the harness hooks keep running, when one runs. That proxy is away for a few seconds while it starts and whenever it refreshes its session; a command then waits up to a second for it and registers once it is back. `Phase: leak protection could not be reached` on stderr means the values of that command were not registered and are not removed from model traffic, which includes a proxy that did not come back within that second; `phase ai status` shows whether the proxy runs. With an Agent login inside a session the command refuses to run instead. Outside a session, when no proxy runs, there is nothing to register with and the command says nothing (an Agent login is told once that leak protection is not active); a state file left behind by a proxy that has stopped counts as no proxy.

Every listed model host is read, whichever tool the session was started for: a tool started from another tool's shell (Codex from a Claude Code shell, or the reverse) sends its conversation through the same proxy and is read like any other.

A host listed as not inspected is a model host whose traffic Phase is not reading at this moment: its client refused the proxy's certificate twice in a row and is passed through for a while, or a connection to it was handed to the provider unread and is still open. The `Leaks:` line gives the reason after the host, `api2.cursor.sh (tls_refused)` or `opencode.ai (hello_resumption)`, and the host is listed for as long as such a connection stays open, then read again. Secrets sent there reach the provider. Never change the mode, or the proxy settings, to get past a placeholder.

Cursor's hosts (`cursor.sh` and every name under it) are read. Cursor's command-line agent, `cursor-agent`, takes the proxy and its certificate from its environment: its calls to `api2.cursor.sh` are read, and so is the stream of its session, which goes over HTTP/2 to a host named for the session's region (`agentn.global.api5.cursor.sh` and its like). In the Cursor desktop app some processes refuse the proxy's certificate, the main one on every host. Their connections fail twice, then that one host is passed through unread for a while, for every Cursor process: the Console shows a `bypass` event and the `Leaks:` line shows the host with `tls_refused`. The other hosts of Cursor are still read.

Cursor talks to its service in protobuf, which writes down the length of everything it holds, so nothing in it may change length. A value there is overwritten where it sits: by its placeholder followed by `*` up to the value's length, as in `ph:secret:<id>*****`, or by as much of the start of the placeholder as fits when the value is the shorter. A placeholder with `*` after it, or one that stops short, is the same placeholder: refer to the secret by its key name, as with any other. A message of Cursor's stream that Phase cannot read goes on as it came and is reported as `unread`.

`N pattern rules skipped` on the `Leaks:` line means the proxy's rule file holds rules this version of the CLI cannot apply, or lacks one of Phase's own token rules; every other rule and every registered value still protect. `http://phase.invalid/v1/status` names them under `leakProtection.skippedRules`. Tell the human.

Only a client that refuses the certificate with a TLS alert opens that pass-through window, and only for that tool on that host. A client that drops the connection without saying why keeps failing on that host; the human can set `PHASE_AI_LEAK_PROTECTION=off` where the proxy starts and restart the session to let it through unread.

OpenCode's hosted models (`opencode.ai`) are read. That service answers only OpenCode's own TLS, so Phase re-sends each request over a connection that opens with a copy of the TLS hello OpenCode sent. A client that offers to resume an earlier TLS session is read too: Phase copies the hello that client sends without a session and answers the client with a full handshake. A connection it cannot open that way is passed through unread, and the Console shows an `unread` leak protection event with the reason: `hello_unreadable` (what the client sent first was not a TLS hello), `hello_resumption` (the client's hello says early data follows it, or offers a session and cannot be copied exactly without it), `hello_not_mirrored` (no exact copy of the hello could be made), `upstream_handshake_failed` (Phase's own connection to the service failed, or the service chose a TLS version or cipher suite Phase does not use) or `upstream_not_http1` (the service chose HTTP/2). Secrets sent on that connection reach the provider, for as long as the client keeps it. `http://phase.invalid/v1/status` counts these connections per host under `leakProtection.mirroredHosts`.

An `unread` event is sent once for a tool, host and reason, then at most once a minute; for a connection passed through unread it is sent again at that pace while the connection stays open. Other reasons: `body_undecodable` (a request body in an encoding Phase does not undo, or a gRPC-Web text body, whose base64 is looked at for the report and sent on as it came), `body_over_limit` (a body or message over 40 MiB, or a WebSocket message in more than 4096 frames), `message_compressed` (a WebSocket message compressed although no compression was agreed), `message_encoding_unsupported` (a message of a Cursor stream compressed with anything but gzip), `message_undecodable` (one marked as gzip that does not inflate), `message_truncated` (a stream that ended inside a message), `message_flags_unexpected` (a message marked in a way only the service marks one), `body_not_enveloped` (a stream that is not made of messages, sent on as it came) and `body_streamed` (a body with no stated length, chunked over HTTP/1.1 or open over HTTP/2, that is of no kind Phase knows to end, gRPC-Web text included, or that stopped coming for 30 seconds, sent on as it came).

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
