# Access rules: allowed, ask, blocked

A member can set rules on this Workflow's access to a Connection. Each call is sorted into a class by its HTTP method alone (`GET`, `HEAD`, `OPTIONS` are `read`; `POST` is `create`; `PUT`, `PATCH` are `update`; `DELETE` is `delete`; any other method is `update`), on every Connection: an AWS action or a GraphQL query sent as a `POST` is a `create`. The rules decide per class, method, or path whether the call is allowed, needs a member's approval, or is blocked. `GET http://phase.invalid/v1/connections` shows each Connection's `policy`. The proxy decides before it uses the credential and answers at once with HTTP 403; it never holds a call open.

These answers are decisions about this Workflow's access, not outages. Do not retry unchanged and do not switch credentials.

## When a call is refused

- `agent_access_policy_ask`: the call needs approval. The answer's `details.request` is a complete request body. Send it unchanged to `POST http://phase.invalid/v1/requests`, show the human the `approvalUrl`, wait (see `phase ai guide connections`), then retry the call. Approval allows that call for a limited time only. The request asks for the call's method and exact path (`"allow": {"match": {"methods": ["POST"], "path": "/"}}`), AWS calls included. AWS clients show the same JSON inside the error message, and `GET http://phase.invalid/v1/hints` lists it again if your client hid the answer.
- `agent_access_policy_blocked`: the call is blocked. A blocked call cannot be requested, and approval of anything else does not lift it. The message names the rule that blocked it. Tell the human what the task needs: a member can change the Connection's access rules in the Phase Console. Do not look for another route to the same effect.
- Do not rewrite the request to slip past a rule, for example with another method, another spelling of the path, or another credential. Ask, or stop.

## The secret guard

The secret guard is always on for every Connection: calls that mint new credentials or assume another identity (for example AWS STS `AssumeRole` or `GetSessionToken`) are blocked with `"rule": "secret_guard"`. It cannot be requested around; ask the human for a Connection that already has the access the task needs. Newly minted credential values in an AWS response are replaced with `PHASE_REDACTED_CREDENTIAL`; that value is masked on purpose and cannot be recovered.

## Time-limited access

Access to a Connection may end at a set time. `grantExpiresAt` in status and in `/v1/connections` says when. After that the proxy answers `agent_access_expired`, and `/v1/connections` lists the Connection with `state: "expired"`, `stateReason: "access_expired"`, and a `request`. Send that `request` unchanged to `POST http://phase.invalid/v1/requests` to ask a member to renew it:

```json
{"kind": "access_change", "title": "Renew access to <connection name>", "action": {"type": "agent_grant.renew", "version": 1, "connectionId": "<connection-id>"}}
```

Any request that ends in access (a `setup`, an allow, a renewal) may carry a top-level `"durationSeconds"` saying how long the task needs it. Leave it out unless the human named a duration: the organisation's default then applies, and the member who approves may change it. The Console refuses a duration above the organisation's maximum and says what the maximum is.

An approved allow or renewal is applied to the running session and returns `retry`: repeat the call that was refused.
