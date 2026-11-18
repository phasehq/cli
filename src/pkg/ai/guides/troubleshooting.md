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

- `censor` (the default): values are replaced; a value in a URL or a binary body cannot be replaced, so that request is refused with `secret_in_request`. A value in a header is reported and the request goes out, and text the provider signed (thinking blocks) is never changed.
- `observe`: values are found and reported to the Console, nothing is changed.
- `off`: model traffic is not read.

A host listed as not inspected is a model host whose traffic Phase does not read: its client refuses the proxy's certificate or its service refuses re-sent requests (Cursor, OpenCode's hosted models), or its client refused the proxy's certificate twice in a row and is passed through for a while. Secrets sent there reach the provider. Never change the mode, or the proxy settings, to get past a placeholder.

Only a client that refuses the certificate with a TLS alert opens that pass-through window. A client that drops the connection without saying why keeps failing on that host; the human can set `PHASE_AI_LEAK_PROTECTION=off` where the proxy starts and restart the session to let it through unread.

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
