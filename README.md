# okta-agent-identity

A [Bifrost](https://github.com/maximhq/bifrost) MCP plugin that makes **Okta the policy
decision point** for AI agent tool calls, with **Bifrost as the enforcement point**.

Bifrost is a capable MCP gateway. It terminates OAuth 2.1, supports dynamic client
registration and PKCE, sanitises headers by default, and brokers upstream credentials
six different ways. What it has no concept of is an **agent**. Its identity model
resolves a human user or a gateway-local virtual key, and its delegated token exchange
carries the caller only. There is no way to express "agent A acted on behalf of
service S", because that requires a delegation chain the gateway never constructs.

This plugin supplies that, without forking Bifrost.

## What it does

Two things, at the two points Bifrost allows them:

**At connection time** it mints a short-lived access token from Okta and sets it as the
upstream `Authorization` header. That token names both the calling service and the
acting agent, so the MCP server on the other side can attribute the call to a specific
agent rather than to a shared robot account.

**At every tool call** it re-asks Okta whether it would still issue that token, and
refuses the call if the answer is no.

The second is not redundant, and it is the reason this plugin exists. A Bifrost MCP
request carries no headers, so a token can only be attached when the connection is
established. An issued bearer token cannot be withdrawn. So the per-call check is the
only thing standing between a deactivated agent and a connection holding a token that
is still technically valid.

Asking Okta to mint is used deliberately as the authorization question, rather than
reading agent status from a management API. The grant **is** the decision, it needs no
second admin credential, and it exercises the same policy path the real call depends on
instead of a status field that could drift from it.

## What it does not do

Stated plainly, because the gaps matter more than the features:

- **It does not catch scope narrowing.** The token in flight was minted at connect and
  still carries the scopes granted then. Tightening a connection's scope list takes
  effect on the next connection, not the next call. Closing that needs the connection
  re-established, which no MCP hook can do.
- **It does not receive revocation signals.** Revocation is detected by asking, within
  `agent_status_ttl`. `Plugin.InvalidateVerdicts()` is the seam for an Okta event hook
  or shared-signals receiver; nothing calls it yet.
- **It does not do per-object authorization.** A scope can say an agent may dispatch. It
  cannot say whether the agent may dispatch *this particular* vehicle. That belongs in a
  fine-grained authorization layer above this one.
- **It does not implement DPoP.** Tokens are bearer tokens.

## Requirements

| | |
|---|---|
| Bifrost | `core` v1.8.4 or compatible |
| Go | **1.27.0**, matching Bifrost exactly |
| Platform | Linux or macOS. Go plugins do not work on Windows |
| Architecture | must match the Bifrost host |

Native Go plugins are `.so` shared objects. Go refuses to load one unless the plugin
and the host binary agree on the Go version **and** on every shared dependency version.
That is the most common reason a plugin silently fails to load, so this repo builds in a
pinned container and you should not use a local toolchain.

For the same reason, this plugin depends on **nothing outside the standard library**.
Every library added is another way for it to refuse to load inside someone else's
Bifrost build, which is why the RS256 signing here is hand-rolled on `crypto/rsa`
rather than pulled from a JWT package.

## Build

```bash
make plugin                          # defaults to linux/amd64
make plugin PLATFORM=linux/arm64     # Graviton
make check                           # fmt, vet, test
```

The artifact lands at `bin/okta-agent-identity-<arch>.so` with the architecture in the
name, so two builds cannot be mistaken for each other. No local Go install is needed.

## Configure

Add an entry to Bifrost's plugin configuration pointing `path` at the built `.so`:

```json
{
  "enabled": true,
  "name": "okta-agent-identity",
  "path": "/etc/bifrost/plugins/okta-agent-identity-amd64.so",
  "placement": "pre_builtin",
  "config": {
    "okta_domain": "your-tenant.okta.com",
    "agent_id": "wlp...",
    "agent_resource_url": "https://your-app.example/agent",
    "private_key_jwk": "{\"kty\":\"RSA\",...}",
    "agent_status_ttl": "10s",
    "bindings": {
      "your-mcp-client": {
        "authorization_server_id": "aus...",
        "target_resource_url": "https://your-app.example/read",
        "scopes": ["your.scope.read"],
        "tools": ["optional_tool_allowlist"]
      }
    }
  }
}
```

`placement: pre_builtin` runs the check before Bifrost's own plugins.

Notes on the config:

- **Unknown keys are rejected.** A typo in a key name must not silently disable a
  setting, so `Init` fails rather than starting with a setting you thought you set.
- **A client with no binding is refused**, never passed through. That way an MCP server
  someone forgot to configure cannot be reached through the gateway unmanaged.
- **`fail_open` defaults to false** and should stay false. It exists only so that
  failure mode is an explicit, auditable choice rather than an accident.
- **`agent_status_ttl` is the staleness bound on revocation.** Keep it small.
- `private_key_jwk` is a secret. Supply it from the environment or a secret store, never
  from a committed file.

## Okta prerequisites

The plugin performs only the **last two** steps of a three-step machine-context
exchange. The first step happens in the calling service, not here:

1. The **calling service** mints its own token via `client_credentials` at this agent's
   authorization server, with `resource` set to the agent's own resource URL. This
   cannot happen in the plugin: registered agents are not permitted the
   `client_credentials` grant at all, only token-exchange and jwt-bearer. The resulting
   token is what must reach Bifrost as the caller's bearer.
2. The plugin exchanges that token at the **org** authorization server for an ID-JAG.
3. The plugin redeems the ID-JAG at the **target** authorization server for the access
   token that goes upstream, carrying the nested `act` chain.

The plugin is indifferent to which of two Okta connection types sits underneath, because
steps two and three are the same request either way. What differs is what the agent is
reaching:

| Target | Okta connection type | Shape |
|---|---|---|
| An API behind a custom authorization server | `IDENTITY_ASSERTION_CUSTOM_AS` | carries a `resourceIndicator` |
| Another registered agent | `IDENTITY_ASSERTION_A2A_SERVER` | carries a `resource` (name + orn) and its `authorizationServer`, and has **no** `resourceIndicator` |

Worth knowing when you copy an existing connection as a template: those two shapes are
not interchangeable, and the agent-to-agent one additionally requires the target agent to
be registered as an A2A server and a **delegation link** from the caller to the agent. The
delegation link's `tokenType` is what selects machine context (`ACCESS_TOKEN`) from human
context (`ID_TOKEN`), and it is easy to miss entirely because nothing else hints at it.

Four things that otherwise cost real debugging time:

- **`aud` comes from `resource`, not from the authorization server's `audiences`
  field.** A resource server validating `aud` must check the resource URL. Two servers
  can share an `audiences` value and still issue tokens with entirely different `aud`.
- **Scope is enforced on the managed connection**, not only on the authorization
  server's policy rule. Publishing a scope on the server and adding it to the policy is
  not sufficient. Update the connection with
  `Content-Type: application/merge-patch+json` and include `scopeCondition` in the body.
- **Registering the agent as a resource is console-only.** The API returns 405, and the
  resource URL cannot be edited afterwards, only deleted and recreated.
- **Okta does not down-scope.** A scope the connection does not grant fails the whole
  request rather than returning the grantable subset, so there is no partial success to
  accidentally accept.

The caller must present its token in a Bifrost client configured for `headers` or
`both` auth mode. In `oauth` mode there is no caller token to delegate from, and the
plugin refuses rather than falling back to the agent's own authority.

## Reading a denial

Denials carry Okta's own message rather than one this plugin invented, because Okta's
wording distinguishes cases that look identical from the outside:

| Okta says | Means |
|---|---|
| `invalid_scope`, naming the scope | A permission refusal. The agent may use this connection, and may not use it this way |
| `invalid_target` | No active connection matches `resource`. True, but usually a misconfiguration |
| `access_denied`, policy evaluation failed | The caller is not a listed client of that authorization server |

For demonstrating least privilege, ask a disallowed **scope** over a connection the
agent legitimately holds. That produces the first row, which is unambiguous. Pointing at
a resource with no connection produces the second, which reads like a config error.

## Design

`main.go` is a thin shim. Bifrost's loader resolves plugins as free functions by name
rather than as a type satisfying an interface, so `main.go` exports the symbols the
loader looks up and forwards them to `./plugin`, which is an ordinary testable package
with no plugin machinery in it.

A signature mismatch in that shim is a **runtime** failure, surfacing only when a
customer starts Bifrost. So `main.go` pins every exported signature in a `var` block,
turning it into a build failure here instead.

An uninitialised plugin **denies**. If `Init` failed, nothing has authorized anything,
so refusing is safer than passing through.

## Licence

Apache 2.0, matching Bifrost.
