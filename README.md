# okta-agent-identity

A [Bifrost](https://github.com/maximhq/bifrost) MCP plugin that makes **Okta the policy
decision point** for AI agent tool calls, with **Bifrost as the enforcement point**.

---

# Part 1. For readers who will never run this

Plain language, no jargon, no code. Skip to [Part 2](#part-2-for-developers) if you are here
to build it.

### The problem

An AI agent cannot do anything useful until it is allowed to reach a real system. Today
almost every deployment grants that access the same way: one shared account, used by
everything. Every call the agents make arrives looking identical.

Three consequences follow, and they compound.

- **You cannot tell which agent did what.** The log records the shared account. Twelve
  agents means twelve suspects.
- **You cannot stop one without stopping all of them.** So in practice nobody stops any of
  them, because the cost is everything going dark.
- **Permissions drift to the widest need.** The shared account has to cover everything
  anyone might do, so read-only agents carry write access they never use.

### What changes

Every call now carries two separate facts: **who asked**, and **who acted**. A service
starts the work. An agent carries it out. The receiving system is told both, and can log
both, and can decide on both. The credential that carries those facts is issued by Okta one
call at a time, and it expires in minutes rather than sitting in a config file.

### The division of labour

**Okta decides.** It holds the policy and answers one question: would I issue this agent a
credential for this thing, right now.

**Bifrost enforces.** It asks that question on every call and obeys the answer. It holds no
policy of its own. This plugin is the piece that connects the two.

### Why the gateway is load-bearing, not incidental

A credential that has been issued cannot be taken back. That is not a flaw in Okta, it is
how access tokens work everywhere. The credential is a signed statement that was true when
it was made, and nothing can reach out and un-say it.

So when you deactivate a misbehaving agent, two things are true at once. Okta will not issue
it anything new, instantly. And the credential it is already holding keeps working until it
expires on its own.

Closing that gap needs something that **keeps asking**, gating every call on a recent answer
rather than checking once per session. The only component that sees every call is the gateway.
That is why this is a gateway plugin rather than a library, and why the per-call check is the
reason the plugin exists rather than an optimisation on top of it.

### What it does not do

Stated plainly, because someone who believes a wider claim and later finds the narrower
reality will trust none of it.

- **No per-object permissions.** It can say an agent may dispatch. It cannot say whether it
  may dispatch *this particular* vehicle. Object-level rules need a separate fine-grained
  authorization layer above this one.
- **Credentials are bearer credentials.** Anyone holding one can use it. They are protected
  by being short-lived and re-checked, not by being unstealable.
- **No sender-constrained tokens (DPoP).** Not implemented.
- **Narrowing permissions applies to the next session,** not the next call. Turning an agent
  off is caught on the next call. Reducing what it may do is picked up when the connection is
  next established.
- **No revocation push.** Revocation is detected by asking, not by being told.

---

# Part 2. For developers

## What this plugin is for

Bifrost is a capable MCP gateway. It terminates OAuth 2.1, supports dynamic client
registration and PKCE, sanitises headers by default, and brokers upstream credentials six
different ways. What it has no concept of is an **agent**. Its identity model resolves a
human user or a gateway-local virtual key, and its delegated token exchange carries the
caller only. There is no way to express "agent A acted on behalf of service S", because that
needs a delegation chain the gateway never constructs.

This plugin supplies that, without forking Bifrost.

## What it does

Two things, at the two points Bifrost allows them.

**At connection time** it mints a short-lived access token from Okta and sets it as the
upstream `Authorization` header. That token names both the calling service and the acting
agent, so the MCP server on the other side can attribute the call to a specific agent rather
than to a shared robot account. It does that through an `act` claim, which is **undocumented
by Okta and verified empirically**; see [Proven live](#proven-live).

**At every tool call** it re-asks Okta whether it would still issue that token, and refuses
the call if the answer is no.

The second is not redundant, and it is the reason this plugin exists. A `BifrostMCPRequest`
carries no headers field, so a token can only be attached when the connection is
established. An issued bearer token cannot be withdrawn. The per-call check is therefore the
only thing standing between a deactivated agent and a connection holding a token that is
still technically valid.

Asking Okta to mint is used deliberately as the authorization question, rather than reading
agent status from a management API. The grant **is** the decision, it needs no second admin
credential, and it exercises the same policy path the real call depends on instead of a
status field that could drift from it.

## Proven live

Against a real Okta tenant, through Bifrost with this plugin loaded:

| Tool call | Scope required | Agent granted it | Outcome |
|---|---|---|---|
| a read tool | `task.read` | yes | **Succeeded.** The upstream server returned data and read the delegation chain out of the token |
| a command tool | `task.dispatch` | no, never granted | **Refused by Okta:** `invalid_scope: The following scopes are not allowed for this request: [task.dispatch].` |

**No tenant change between them.** Repeatable in either order. The issued token carries an
`act` claim naming both parties, with a `sub_profile` on each level typing it `service` or
`ai_agent`.

> **Sourcing, stated exactly.** `act` and `sub_profile` are **not** in Okta's published
> developer documentation. We verified them empirically by decoding real tokens from a live
> tenant. They behave consistently. Do not present them to a customer as documented
> behaviour.

---

## The host must be a dynamically-linked Bifrost you build yourself

**Read this before anything else.** It is the step that surprises people, and no amount of
correct plugin building gets around it.

**Bifrost's published images are statically linked and cannot load any Go plugin.** Not this
one, not any. Go's plugin system requires a dynamically-linked host binary. This is
[documented behaviour on Maxim's side](https://docs.getbifrost.ai/plugins/building-dynamic-binary),
not a defect and not something to file a bug about.

So running a plugin means building and maintaining your own Bifrost binary. That is a real
operational cost, and it belongs in the conversation before the plugin route is chosen.

The sibling `fleetops-bifrost-demo` repo has a working `bifrost/Dockerfile.dynamic`. The
only difference from Bifrost's own build is dropping `-extldflags '-static'` from the link
step. It also fails the build deliberately if the output comes out static, because the
runtime symptom is `plugin.Open: Dynamic loading not supported`, which does not obviously
point at a linker flag.

## Requirements

| | |
|---|---|
| Bifrost `core` | Must match the host **exactly**. Currently pinned to `v1.8.3` in `go.mod` |
| Go | Must match the host **exactly**. Currently `1.27.0` |
| Platform | Linux or macOS. Go plugins do not work on Windows |
| Architecture | Must match the Bifrost host |

Native Go plugins are `.so` shared objects. Go refuses to load one unless the plugin and the
host binary agree on the Go version **and on every shared dependency version**. Patch
versions count: `core` v1.8.4 against a v1.8.3 host does not load. That is the most common
reason a plugin silently fails to load.

**Do not guess any of the three.** Read them out of the image you are loading into:

```bash
make compat BIFROST_IMAGE=your-bifrost:tag
```

```
inspecting your-bifrost:tag ...
  go:   go1.27.0
  core: v1.8.3
```

Then pin and build:

```bash
make pin BIFROST_CORE=v1.8.3
make plugin PLATFORM=linux/amd64      # most EC2, ECS on x86
make plugin PLATFORM=linux/arm64      # Graviton, or local Apple Silicon
```

The artifact lands at `bin/okta-agent-identity-<arch>.so`, with the architecture in the name
so two builds cannot be mistaken for each other. **No local Go install is needed**; the build
runs in a pinned container, because building on a developer's own toolchain is the single
most reliable way to produce a plugin that will not load.

```bash
make check      # fmt, vet, test
make race       # the verdict cache is read concurrently
```

For the same dependency-matching reason, this plugin depends on **nothing outside the
standard library**. Every library added is another way for it to refuse to load inside
someone else's Bifrost build. That is why the RS256 signing is hand-rolled on `crypto/rsa`
rather than pulled from a JWT package: RS256 is a SHA-256 hash and a PKCS#1 v1.5 signature,
which the standard library already provides.

---

## Configure

Add an entry to Bifrost's plugin configuration pointing `path` at the built `.so`.

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
    "private_key_jwk_file": "/secrets/agent-key.jwk",
    "agent_status_ttl": "10s",
    "fail_open": false,
    "allow_connect_without_caller": true,
    "bindings": {
      "your_mcp_client": {
        "authorization_server_id": "aus...",
        "target_resource_url": "https://your-app.example/target",
        "scopes": ["your.scope"],
        "tools": ["your_mcp_client-your_tool"]
      }
    }
  }
}
```

`placement: pre_builtin` runs the check before Bifrost's own plugins.

### Config reference

| Key | Required | Notes |
|---|---|---|
| `okta_domain` | yes | Hostname, **no scheme**. Validation rejects one containing `://` |
| `agent_id` | yes | The `wlp...` workload principal id. The plugin authenticates as this agent with `private_key_jwt` |
| `agent_resource_url` | yes | This agent's own resource URL. Used to verify the inbound audience, not to mint |
| `private_key_jwk_file` | one of | Path to the agent's private key as a JWK. **Prefer this** |
| `private_key_jwk` | one of | The JWK inline. Puts key material in the gateway config, which then has to be treated as a secret everywhere it is stored, rendered, or backed up |
| `bindings` | yes | One entry per Bifrost MCP client. Keyed by client name |
| `agent_status_ttl` | no | Cache lifetime for Okta's answer, and therefore the revocation staleness bound. Default and shipped value `10s`. See [the verdict cache](#the-verdict-cache-and-what-agent_status_ttl-really-controls) before changing it |
| `fail_open` | no | Default `false`, and should stay false |
| `allow_connect_without_caller` | no | Default `false`. **You almost certainly need `true`.** See below |

Per binding:

| Key | Required | Notes |
|---|---|---|
| `authorization_server_id` | yes | The `aus...` custom authorization server protecting the target |
| `target_resource_url` | yes | Sent as `resource`. This is what Okta stamps into the token's `aud` |
| `scopes` | yes | Requested on the minted token |
| `tools` | no | Restricts which tools this binding serves. Empty means all. **Namespaced names**, see below |

### Behaviour worth knowing

- **Unknown keys are rejected.** A typo in a key name must not silently disable a setting,
  so `Init` fails rather than starting with a setting you thought you set.
- **A client with no binding is refused,** never passed through. An MCP server someone forgot
  to configure cannot be reached through the gateway unmanaged.
- **An uninitialised plugin denies.** If `Init` failed, nothing has authorized anything, so
  refusing is safer than passing through.
- **Denial is a short-circuit, never a returned error.** Bifrost treats a hook's returned
  error as non-blocking, so denying by error would let the call through and silently invert
  the security posture.

---

## Configuration traps in the Bifrost config itself

These are Bifrost's behaviour, not the plugin's. Every one was hit for real.

| Trap | What happens | What to do |
|---|---|---|
| **Hyphens in MCP client or tool names** | Bifrost **silently skips** the client. No error, no warning, the tool simply is not there | Use underscores. `fleetops_read`, not `fleetops-read`. No spaces, no leading digit either |
| **`tools_to_execute` vs `bindings[].tools`** | `tools_to_execute` takes **bare** tool names (`get_telemetry`). This plugin's `bindings[].tools` needs the **namespaced** form (`fleetops_read-get_telemetry`). In the same file | Bare in one, namespaced in the other. This is the nastiest inconsistency in the setup. Note the hyphen in the namespaced form is Bifrost's own separator, and is fine there; the ban applies to the names you declare |
| **Missing `needs_session_stickiness: false`** | One shared connection with no caller context, so the plugin has nothing to delegate from | Set it `false` on every MCP client |
| **Config in the wrong place** | Bifrost starts on defaults, the plugin never loads, and the only hint is one info line saying the config file was not found | It must be at `$APP_DIR/config.json`, which is `/app/data/config.json` |
| **`docker compose restart`** | Silently breaks everything. See the warning below | `down -v`. Always |

> ## Never `docker compose restart`. Always `down -v`.
>
> **Tools are discovered only on FIRST registration.** On a restart, Bifrost reloads its MCP
> clients from its sqlite store **without re-running discovery**. The result is a gateway
> that lies to you:
>
> - `GET /api/mcp/clients` still reports all three tools, read from the database.
> - The live in-memory tool registry is **empty**.
> - Every call 404s with `tool not found`.
>
> The symptom points nowhere near the cause. You will look at the plugin, at Okta, and at
> your bindings, and all three will be fine. There is no log line saying discovery was
> skipped.
>
> ```bash
> docker compose down -v && docker compose up -d
> ```

### Why `allow_connect_without_caller: true` is required, and is not a bypass

Bifrost registers MCP clients, and discovers their tools, **at startup**. There is no inbound
HTTP request at that moment, so there is no caller token to delegate from.

Leave this false and the connect is refused, registration fails, no tools are discovered, and
every later call fails with `tool not found` rather than with anything resembling an
authorization error. The gateway is unusable for a reason that looks nothing like its cause,
and the only hint is an empty tools array.

Turning it on does not weaken enforcement, for two independent reasons:

1. **No `Authorization` header is attached** to such a connection, so the upstream server,
   which validates independently, rejects any tool call over it.
2. **`PreMCPHook` still denies** every `execute`, `chat_tool_call` and
   `responses_tool_call` without a caller token and a live Okta mint, and is unaffected by
   this setting. Discovery needs only `initialize` and `tools/list`, which that hook
   deliberately does not gate.

That pairing, connect permitted while execute denied, is the invariant.
`TestTokenlessConnectAllowedButExecuteDenied` pins both halves; changing either without the
other fails the test.

### `auth_type` must be `none`

```json
"auth_type": "none",
"needs_session_stickiness": false
```

**This is not a placeholder, and not the absence of a choice. It is the only value that
works.** Two independent reasons, both verified live.

**1. `none` is the only option whose resolver returns no headers.** Every other auth type
resolves upstream headers of its own, which **overwrite the `Authorization` header this
plugin sets** on the connect request. The plugin mints correctly, the header is replaced, and
the upstream server rejects a credential the plugin never sent. The failure looks like a
minting bug and is not one.

**2. `per_user_headers` additionally requires pre-stored per-caller credentials** and aborts
the connect when it finds none. There are none to store: the whole point is that the
credential is minted per call from Okta rather than kept anywhere.

> **Ignore any guidance that says caller context requires `per_user_headers`,
> `per_user_oauth` or `token_exchange`.** Those are the per-call connection types, so the
> reasoning looks sound, and it sends you down a path that cannot work. `token_exchange` in
> particular makes Bifrost run its own single-hop exchange, which is the thing this plugin
> replaces.

### Where the caller's token is read from

The caller presents its own token to the gateway as `Authorization: Bearer`, and that token
is the **subject** of the exchange.

The plugin reads it from `BifrostContextKeyRequestHeaders`, which carries every request
header with lowercased keys, needs **no `auth_type` configuration at all**, and was confirmed
to round-trip the token intact. That is why `auth_type: "none"` costs nothing: the plugin was
never relying on Bifrost's credential brokering to find the caller.

`BifrostContextKeyMCPInboundBearer` is checked first, because its declaration says exactly
"the caller's validated identity-provider token, used as the subject of delegated token
exchange". On an open-source Bifrost it is **never populated**: nothing writes it outside
tests, and both readers are admin console handlers where the subject is the signed-in admin's
own token. Verified empirically as absent at every hook, in every configuration tried,
including when the caller demonstrably sent the header. Whether a non-OSS auth layer
populates it is untested, which is why it is still tried first rather than dropped.

`BifrostContextKeyMCPExtraHeaders` is deliberately **not** read. Enabling the header there
also forwards the caller's raw token to the upstream MCP server, which is a credential leak
with no upside: this plugin wants to *read* the caller's token as an exchange subject, not
pass it on. Reading from request headers keeps the caller's credential inside the gateway.

---

## Okta prerequisites

The plugin performs only the **last two** steps of a three-step machine-context exchange.
The first happens in the calling service.

| Step | Who | What |
|---|---|---|
| 1 | the **calling service** | `client_credentials` at the invoked agent's own authorization server, with `resource` set to that agent's resource URL. The result is what must reach Bifrost as the caller's bearer |
| 2 | the **plugin** | Exchange that token at the **org** authorization server for an ID-JAG |
| 3 | the **plugin** | Redeem the ID-JAG at the **target** authorization server for the access token that goes upstream, carrying the nested `act` chain (**undocumented, verified empirically**, see [Proven live](#proven-live)) |

Step 1 cannot happen in the plugin: registered agents are not permitted the
`client_credentials` grant at all, only token-exchange and jwt-bearer.

Note the org authorization server in step 2. It has no authorization server id in its path.
That is the only place an ID-JAG can be obtained, and exchanging at a custom authorization
server instead is the mistake that makes a gateway look like it supports delegation when it
only supports a single hop.

### Authorization server topology

**Two authorization servers, one per invoked agent. Not three.** The caller mints at the
**invoked agent's own** server.

The three-server layout, an agent server plus separate read and command lanes, is correct
only for the agent-to-**API** shape, where the target is a resource server rather than
another agent.

### The things that cost real time

| | |
|---|---|
| **Audience and resource URL are the same string** | The authorization server's audience and the agent's resource URL are one value per agent |
| **The console requires `https://`** | The audience and resource URL form rejects the `api://` style, even though older objects in the same tenant use it |
| **The resource URL is immutable** | Once saved it cannot be edited, only deleted and recreated. The authorization server can be changed later, after removing callers. Choose the URL deliberately |
| **Registering an agent as a resource is console-only** | The API returns 405 on every verb and shape. The console calls it **Delegations > Non-human identity > Configure**, **not** "register as an A2A server", which is why it is hard to find |
| **Assigning owners is console-only too** | Also 405 over the API. Okta recommends at least two owners |
| **Activation *is* available over the API** | `POST /workload-principals/api/v1/ai-agents/{id}/lifecycle/activate` returns 202. Only merge-patching `status` fails |
| **The `clients` condition is at POLICY level** | Not on the rule. And it must name the **caller** |
| **`people.groups` must not be a user group** | An agent is a workload principal, not a user, so it will never match a specific user group. Use **EVERYONE**. That is permissive and worth tightening for production |
| **Scopes are enforced on the managed CONNECTION** | Not only on the authorization server's policy. Publishing a scope on the server is **not enough** |
| **Okta does not down-scope** | An ungrantable scope fails the **whole** request rather than returning the grantable subset |
| **Agent JWK registration requires `use: "sig"`** | Otherwise it 400s with "Key 'use' must be 'sig'" |
| **`aud` comes from `resource`** | Not from the authorization server's `audiences` field. Two servers can share an `audiences` value and issue tokens with entirely different `aud`. A resource server validating `aud` must check the resource URL |

To change connection scopes over the API:

```
PATCH /workload-principals/api/v1/ai-agents/{wlp}/connections/{mcn}
Content-Type: application/merge-patch+json
```

```json
{ "scopes": ["task.read"], "scopeCondition": "INCLUDE_ONLY" }
```

`application/json` and `application/json-patch+json` both return `E0000021`. `PUT` returns
405. The body must include `scopeCondition` alongside `scopes` or you get `E0000001`.

### Connection types

The plugin is indifferent to which sits underneath, because steps 2 and 3 are the same
request either way. What differs is what the agent is reaching.

| Target | Okta connection type | Shape |
|---|---|---|
| An API behind a custom authorization server | `IDENTITY_ASSERTION_CUSTOM_AS` | carries a `resourceIndicator` |
| Another registered agent | `IDENTITY_ASSERTION_A2A_SERVER` | carries a `resource` (name plus orn) and its `authorizationServer`, and has **no** `resourceIndicator` |

Worth knowing when copying an existing connection as a template: the two shapes are not
interchangeable. The agent-to-agent one additionally needs the target agent registered as an
A2A server, and a **delegation link** from the caller to the agent. That link's `tokenType`
is what selects machine context (`ACCESS_TOKEN`) from human context (`ID_TOKEN`), and it is
easy to miss entirely because nothing else hints at it.

---

## How to verify it is really working

Three tiers. Each rules out a different way of fooling yourself.

**Tier 1. The plugin loaded.**

```bash
docker compose logs bifrost | grep "plugin status"
```

```
plugin status: okta-agent-identity - active
```

Anything else means the `.so` did not load. Go back to `make compat`. A silent non-failure
here is the usual outcome of a version or architecture mismatch.

**Tier 2. The upstream server received a token the caller never held.** This is what proves
delegation rather than pass-through. Compare the two tokens:

| | Caller's token | Token the upstream received |
|---|---|---|
| `aud` | the agent's resource URL | the **target's** resource URL |
| `scp` | the caller's own scope | the **target** scope |
| `act` | absent | **present**, naming the agent |

Same token in both columns means the gateway is forwarding the caller's credential, and
nothing has been delegated.

`act` and `sub_profile` are **not in Okta's published developer documentation.** They are
verified empirically against a live tenant. If you are scripting an assertion on them, treat
their shape as observed behaviour that could change, not as a contract.

**Tier 3. Set `"enabled": false` on the plugin, `down -v`, and call a tool.** It must fail
completely, with no `Authorization` header reaching the upstream server at all. That failure
is the proof the plugin is the only thing supplying credentials. If the call still succeeds,
something else is authenticating and the test was never measuring what you thought.

## Reading a denial

Denials carry Okta's own message rather than one this plugin invented, because Okta's wording
distinguishes cases that look identical from the outside.

| Okta says | Means |
|---|---|
| `invalid_scope`, naming the scope | A permission refusal. The agent may use this connection, and may not use it this way |
| `invalid_target` | No **ACTIVE** connection matches `resource`. True, but usually a misconfiguration |
| `access_denied`, policy evaluation failed | The caller is not a listed client of that authorization server, or the acting agent is deactivated |
| `'subject_token' is invalid` | The caller presented an ID token, or a token from the **org** authorization server. It must be an access token from a **custom** authorization server with a resource-scoped `aud` |
| `invalid_client` | The agent's `private_key_jwt` does not match the key registered on the agent |
| The upstream rejects a token the plugin clearly minted | Not a denial. `auth_type` is not `none`, so Bifrost overwrote the plugin's `Authorization` header |
| A refusal naming a scope the call never requested | Not a denial. This was a verdict-cache key collision, fixed by `Binding.verdictKey()`. If you see it, you are on a build predating that fix |

For demonstrating least privilege, ask a disallowed **scope** over a connection the agent
legitimately holds. That produces the first row, which is unambiguous. Pointing at a resource
with no connection produces the second, which reads like a config error.

## Design

`main.go` is a thin shim. Bifrost's loader resolves plugins as free functions by name rather
than as a type satisfying an interface, so `main.go` exports the symbols the loader looks up
and forwards them to `./plugin`, which is an ordinary testable package with no plugin
machinery in it.

A signature mismatch in that shim is a **runtime** failure, surfacing only when a customer
starts Bifrost. So `main.go` pins every exported signature in a `var` block, turning it into a
build failure here instead.

`Exchange` returns both artifacts, the ID-JAG and the access token, not only the one that
goes on the wire. The ID-JAG is the assertion that actually asserts the delegation; the
access token is merely what it was redeemed for. It also returns the assertion **on a
redemption failure**, as a partial result alongside the error, which is what lets a caller
tell "Okta would not assert this delegation" apart from "Okta asserted it and the target
authorization server refused to honour it". Those are different problems with different
fixes. On a non-nil error the result may be nil or partial: check the error first, and treat
`AccessToken` as present only when `err` is nil.

`MintResourceToken` is the narrow wrapper the hooks use, since they only ever need the token
that goes upstream.

## The verdict cache, and what `agent_status_ttl` really controls

The plugin caches Okta's answer so that repeated identical questions do not each cost a round
trip. `agent_status_ttl` bounds how long an answer is reused. It ships at `10s`, which is also
the plugin default.

### A fixed bug worth knowing about

The cache key was originally the authorization server id alone. Two bindings on **one**
authorization server therefore shared a verdict, so a denial recorded for one was reported for
the other, citing a scope the second call never requested. That is a misleading error rather
than an unsafe one, and it is exactly the shape this demo would hit, since both its bindings
sit on the same authorization server.

**Fixed at the root.** `Binding.verdictKey()` in `plugin/config.go` now keys on the
authorization server id, the target resource URL, and the **sorted** scope set, NUL-joined.
Sorting means the same set in a different order shares an answer; NUL means no combination of
values can be concatenated into a collision, because it cannot occur in an Okta id, a URL, or
an OAuth scope token.

Two tests cover it in both directions, and both were **mutation-tested**: reverting the key
makes them fail, so they actually bite.

| Test | Asserts |
|---|---|
| `TestVerdictIsNotSharedAcrossBindingsOnOneAuthorizationServer` | two bindings on one server do not share a verdict |
| `TestVerdictKeyIgnoresScopeOrderButNotScopeContent` | scope **order** shares an answer, scope **content** does not |

The caching path is verified at the live `10s` TTL, not only with caching disabled. An
interleaved six-call sequence across both bindings is order-independent and correct every
time.

### The honest caveat on `10s`

`10s` is a **demo default, not a tuned production value**, and the number is doing two jobs at
once. It is the cache lifetime, and it is therefore also the **revocation staleness bound**.

**Raising it widens the window in which a deactivated agent still passes.** That is the real
tradeoff, and it is not a free performance dial. Choose it against how quickly your
environment needs a deactivation to bite, not against latency alone.

### What actually costs a round trip

Worth separating, because it is easy to attribute the wrong cost to the wrong mechanism.

| | Frequency | Why |
|---|---|---|
| The **authorization check** | at most once per `10s` per distinct question | cached, keyed on the exact binding |
| The **mint** | two token requests per call | Bifrost connections are per-call, so the connect-time mint runs per call. Nothing to do with the TTL |

So the per-call cost is driven by Bifrost's per-call connection model, not by the cache
setting. Lowering the TTL does not add the minting cost, and raising it does not remove it.

## Known limitations

- **It does not catch scope narrowing.** The token in flight was minted at connect and still
  carries the scopes granted then. Tightening a connection's scope list takes effect on the
  next connection, not the next call. Closing that needs the connection re-established, which
  no MCP hook can do.
- **It does not receive revocation signals.** Revocation is detected by asking, within
  `agent_status_ttl`, so at the shipped `10s` a deactivation can take up to ten seconds to
  bite. `Plugin.InvalidateVerdicts()` is the seam for an Okta event hook or a shared-signals
  receiver, which would close that window. Nothing calls it yet.
- **It does not do per-object authorization.** A scope can say an agent may dispatch. It
  cannot say whether the agent may dispatch *this particular* vehicle. That belongs in a
  fine-grained authorization layer above this one.
- **It does not implement DPoP.** Tokens are bearer tokens.

## Licence

Apache 2.0, matching Bifrost.
