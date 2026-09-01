# Security

> **Status: unsupported sample code.** This is not an Okta product. It carries no SLA, no
> support commitment, and no security patching commitment. It is Apache 2.0 sample code
> published to demonstrate an integration path. Read
> [Support status and reporting](#support-status-and-reporting-a-vulnerability) before you
> plan around it.

This document is written for a reviewer whose job is to find what we did not tell you. Where
something is weak, unproven, or undocumented by Okta, it is named here rather than left for
you to discover. Where a claim is backed by a live run, that is stated. Where it is backed
only by reading the code, that is stated differently, and the difference is deliberate.

**Contents**

1. [Threat model](#1-threat-model)
2. [What is enforced where](#2-what-is-enforced-where)
3. [The revocation gap, stated precisely](#3-the-revocation-gap-stated-precisely)
4. [What it does not do](#4-what-it-does-not-do)
5. [Credential handling](#5-credential-handling)
6. [Failure modes and their security consequence](#6-failure-modes-and-their-security-consequence)
7. [Attack surface the plugin adds](#7-attack-surface-the-plugin-adds)
8. [Claims and their evidence](#8-claims-and-their-evidence)
9. [Undocumented Okta behaviour this depends on](#9-undocumented-okta-behaviour-this-depends-on)
10. [Support status and reporting a vulnerability](#support-status-and-reporting-a-vulnerability)

---

## 1. Threat model

### What this is built to address

The starting condition is a shared service account, used by every agent in a deployment.
Three properties follow from that, and they compound.

| Property of a shared account | What this plugin changes |
|---|---|
| **No attribution.** Every call arrives as the same principal, so the log names the account rather than the agent. Twelve agents means twelve suspects for one bad call | The token carries two distinct principals: the service that asked, and the agent that acted. The receiving system reads both out of the credential itself, with no log correlation |
| **No individual stop.** Disabling the account stops every agent, so in practice nobody disables it | Each agent is its own Okta principal with its own credential. Deactivating one stops that one |
| **Union permissions.** The account must cover everything anyone might need, so a read-only agent carries write access it never uses | Each call is minted for one binding with one scope set. A read lane cannot request a command scope, and Okta refuses if it tries |

The mechanism is a per-call authorization question put to Okta, and a short-lived credential
minted per connection rather than stored in configuration.

### What this does not address

Read this list as carefully as the one above. Several of these are the attacks most likely to
matter in a real deployment, and none of them are stopped here.

- **A compromised gateway host.** The plugin runs inside the Bifrost process and holds the
  agent's RSA private key in that process's memory for its whole lifetime. Code execution,
  a debugger, or a readable core dump on that host makes the attacker the agent. This is the
  single largest concentration of trust in the design.
- **A compromised caller.** The plugin delegates from whatever caller token it is handed. If
  the calling service's client credentials are stolen, the thief mints a valid subject token
  and the exchange succeeds normally. The plugin authenticates the *agent*; it does not judge
  whether the *caller* is behaving.
- **A stolen minted token, inside its lifetime.** These are bearer tokens with no sender
  constraint. See [What it does not do](#4-what-it-does-not-do).
- **A manipulated agent acting inside its permissions.** If an agent is prompt-injected into
  doing something it is *allowed* to do, nothing here stops it or notices. Scopes bound the
  blast radius. They do not detect misuse. For a fleet system, "an agent that may dispatch was
  talked into dispatching" is fully inside policy.
- **Per-object misuse.** The plugin decides on the *tool name* and the binding. It never reads
  tool arguments. `dispatch_vehicle(vehicle_id=A)` and `dispatch_vehicle(vehicle_id=B)` are
  indistinguishable to it.
- **Exfiltration through permitted reads.** A read scope is a read scope. There is no volume
  limit, no anomaly detection, and no per-agent rate limit in this plugin.
- **A malicious or compromised upstream MCP server.** The gateway hands that server a valid
  agent credential. There is a real mitigation, which is that the token's audience is the
  target's own resource URL, so a hostile server cannot replay it against a different resource.
  But it does learn a working credential scoped to itself, and it can lie about tool
  descriptions and results. Tool poisoning is out of scope here.
- **Argument or response inspection.** No content validation, no schema enforcement, no
  data-loss inspection of either direction.
- **The Bifrost supply chain.** You must build your own dynamically-linked Bifrost (see
  [docs/PRODUCTION.md](docs/PRODUCTION.md)). That build, and its dependency graph, is yours to
  secure. This plugin depends on nothing outside the Go standard library, which narrows its own
  contribution to that graph, but it does not narrow Bifrost's.
- **Anything at the network layer.** No mutual TLS to the upstream, no egress control, no
  network policy.

---

## 2. What is enforced where

There are two independent enforcement points. That independence is the point: neither takes
the other's word for anything.

### The gateway asks Okta and refuses

The plugin makes no authorization decision of its own. It asks Okta one question, "would you
issue this agent a credential for this binding, right now", and obeys the answer. The
question is asked by attempting the mint, so the grant *is* the decision. There is no separate
status field that could drift from the policy the real call depends on, and no second admin
credential is needed.

| Hook | What it gates |
|---|---|
| `PreMCPConnectionHook` | Mints the upstream token and sets it as the `Authorization` header on the connect request. This is the only point at which a header can be attached, because `BifrostMCPRequest` carries no headers field |
| `PreMCPHook` | Gates `execute_tool`, `chat_tool_call` and `responses_tool_call`. Re-asks Okta and short-circuits with HTTP 403 if the answer is no |

Three implementation properties are load-bearing and worth checking in the source yourself:

- **Denial is a short-circuit, never a returned error.** Bifrost treats a hook's returned
  error as non-blocking. Denying by error would let the call through and silently invert the
  posture. `TestDenialIsNeverReturnedAsError` pins this.
- **An unbound MCP client is refused, never passed through.** A server someone forgot to
  configure cannot be reached through the gateway unmanaged. `plugin/config.go`,
  `bindingFor`.
- **An uninitialised plugin denies.** If `Init` failed, nothing has authorized anything, so
  every hook refuses with `okta_plugin_uninitialised`. `main.go`.

Denials carry Okta's own error text verbatim rather than a message the plugin invented, because
`invalid_scope` (a permission refusal) and `invalid_target` (a misconfiguration) look identical
from outside and only Okta knows which happened.

### The resource server validates independently

In the reference implementation (`fleetops-bifrost-demo/server/auth.go`) the protected server
does not trust the gateway. It performs, in order:

1. **A real RSA signature verification** against the issuer's published JWKS, fetched from
   `{issuer}/v1/keys` and cached for one hour. `rsa.VerifyPKCS1v15` over a SHA-256 digest,
   not a decode-and-hope.
2. **`RS256` pinned.** The header algorithm is compared to the literal string `RS256` and
   anything else is rejected before a key is even selected. That rejects `alg: none` and the
   HMAC-with-the-public-key algorithm-confusion family.
3. **Issuer check** against an explicit allow-list. An untrusted issuer is named in the error.
4. **Expiry check.**
5. **Audience check** against the accepted resource URLs.
6. **Per-tool scope check.** Each tool declares the scope it demands, and a token lacking it is
   refused with the scopes it actually carries printed in the log.

Claims are decoded before the signature is verified, but only to learn which issuer's key set
to fetch. Nothing from the token is trusted until the signature checks out.

**Bypassing the gateway does not bypass authorization. It just means no token.** A caller that
reaches the resource server directly presents nothing, and the server refuses at step zero
with "no Authorization header reached this server". The negative control for this is in
[docs/PRODUCTION.md](docs/PRODUCTION.md): disable the plugin, restart clean, and confirm calls
fail completely rather than falling back to some other credential.

**This second line of defence is your responsibility, not the plugin's.** The plugin attaches a
token. It cannot make your MCP server check it. If your upstream servers do not validate
independently, the gateway becomes the only control, and the caveats in section 6 get much
sharper.

---

## 3. The revocation gap, stated precisely

This is the part most likely to be misrepresented in a sales conversation, so here it is in
exact terms.

**An issued bearer token cannot be withdrawn.** That is not a defect in Okta, it is how access
tokens work everywhere. The token is a signed statement that was true when it was made, and
nothing can reach out and un-say it.

So when you deactivate a misbehaving agent, two things are true at the same moment:

- **Okta stops issuing it anything new, instantly.** No new mint succeeds.
- **The credential it already holds keeps working until it expires on its own.** The resource
  server will validate that token correctly, because it is correctly signed and not yet
  expired.

The per-call re-ask is what closes that window. It does not close it to zero.

> **`agent_status_ttl` is the revocation staleness bound, not a performance dial.**
>
> The plugin caches Okta's answer for `agent_status_ttl` so that repeated identical questions
> do not each cost a round trip. That same cache lifetime is the maximum time a deactivated
> agent can continue to pass the gate. At the shipped default of `10s`, a deactivation takes
> **up to ten seconds** to bite.
>
> Raising the TTL to reduce load widens that window by exactly the amount you raised it.
> Choose it against how fast a deactivation must take effect in your environment, not against
> latency.

Four further precision points a reviewer should have:

- **The cache is per process.** It is an in-memory map on the plugin instance. With more than
  one gateway instance, each has its own independent TTL window and each must expire before
  the deactivation is uniform across the fleet.
- **Denials are cached symmetrically.** `record` stores the outcome whether it was a permit or
  a refusal. So *restoring* a permission is also up to one TTL stale, and an operator who
  re-grants a scope and immediately retests will see a stale refusal.
- **Revocation is detected by asking, never by being told.** There is no push, no Okta event
  hook, and no shared-signals receiver. `Plugin.InvalidateVerdicts()` exists as the seam for
  one and **nothing calls it today**, verified by grep across the repository. It is also
  process-local, so a future receiver would need to fan out to every gateway instance.
- **The token already in flight is not re-validated by this plugin.** The per-call check asks
  whether Okta *would* issue a token now. The token discarded by that check is not compared
  against the one the connection is holding. The narrowing consequence of this is in the next
  section.

---

## 4. What it does not do

Stated plainly, because a reviewer who believes a wider claim and later finds the narrower
reality will discount everything else in this document.

### Scope narrowing is not caught per call

Turning an agent **off** is caught on the next call, within the TTL. **Reducing what it may
do** is not.

The token in flight was minted at connect time and still carries the scopes granted then.
Tightening a managed connection's scope list takes effect on the **next connection**, not the
next call. Closing that would require the connection to be re-established, which no MCP hook
can do.

In the reference demo this matters less than it sounds, because Bifrost's connection model is
per call, so the connect-time mint runs per call in practice. Do not rely on that: it is a
property of how Bifrost happens to manage connections, not a guarantee this plugin makes, and
a Bifrost configuration or version that reuses connections would widen the gap without any
change here.

### Bearer tokens, with no sender constraint

Tokens are plain bearer credentials. **DPoP is not implemented.** Neither is mTLS-bound token
binding, nor any other proof of possession. Anyone holding the token can use it until it
expires.

The protection is that the tokens are short-lived, audience-scoped to one target resource, and
re-checked. It is not that they are unstealable.

### No per-object authorization

The plugin can say an agent may **dispatch**. It cannot say whether it may dispatch **this
particular vehicle**. Object-level rules need a fine-grained authorization layer above this
one, evaluated where the object identity is known. The plugin never reads tool arguments at
all: the decision inputs are the MCP client name, the tool name, and the binding.

### Tool discovery is deliberately not gated

`ping` and `tools/list` are not gated. Only execution is. This is a decision, not an oversight,
and there are two reasons:

1. Hiding a tool name adds no control. A hidden tool still has to be refused when called
   directly, so the refusal is the control and the concealment is decoration.
2. Gating discovery stops Bifrost registering tools at all, because registration happens at
   startup where there is no caller to authorize. The result is every call failing with
   `tool not found` rather than with anything resembling an authorization error.

Expect to be asked why an agent can see a tool it may not use. The answer is that listing is
not gated and running is.

### No audit trail of its own

The plugin emits **no logs and no metrics**. Verified: there is no `log`, `fmt.Print`, or
direct writer use anywhere in `plugin/`. Every observable event is Bifrost's own tool-handler
logging, plus whatever Okta records in its System Log, plus whatever the resource server
writes. Denial-rate monitoring has to be built from those, and
[docs/PRODUCTION.md](docs/PRODUCTION.md) treats that as a production gap.

### It does not validate the caller's token itself

The plugin extracts the caller's bearer token and passes it to Okta as `subject_token` without
parsing it. It does not check the caller token's signature, issuer, audience, or expiry
locally. Okta performs that validation and rejects a bad subject token, which is a legitimate
division of labour, but it means an Okta outage is the only thing standing between the gateway
and an unvalidated inbound credential, and the gateway itself learns nothing about the caller.

**One discrepancy to know about.** `agent_resource_url` is documented in `plugin/config.go` as
being "used to verify the inbound audience". It is not. It is required by `Config.Validate`
and then **never read by any code path**, verified by grep. The audience binding it describes
is real and is enforced by Okta, which refuses a subject token whose audience is not this
agent's resource URL, but it is not enforced in the gateway. Treat the setting as required
configuration with no local effect.

---

## 5. Credential handling

### The agent's private key

The plugin authenticates to Okta as the agent using `private_key_jwt`, signed RS256. The key
is an RSA private key supplied as a JWK, by one of two routes.

| Setting | Recommendation |
|---|---|
| `private_key_jwk_file` | **Use this.** A path read once, at startup, by `os.ReadFile`. The gateway config stays non-secret |
| `private_key_jwk` | Avoid. Puts key material inside Bifrost's plugin configuration, which then has to be treated as a secret everywhere that config is stored, rendered, backed up, or displayed |

Exactly one of the two must be set; `Config.Validate` rejects both and neither.

**Why the inline form is worse than it looks.** Bifrost persists configuration to a config
store, sqlite in the reference setup, and may render configuration in its admin console if you
build the console into your image. Whether plugin `config` blocks specifically are persisted
and rendered in your build is something you should confirm for yourself rather than take from
this document. The file form makes the question moot, which is the reason to prefer it.

**Do not put the key in an environment variable.** Two independent reasons:

- Environment is readable from `/proc/<pid>/environ`, appears in process listings on some
  platforms, is inherited by child processes, and is routinely captured whole by crash
  reporters and container introspection.
- A JWK pasted unquoted into a `.env` file is destroyed the moment a shell sources it: the
  double quotes are stripped and the commas are treated as brace expansion. The result is a
  mangled key and a JSON parse error some distance from its cause.

### What an operator must do, because the plugin will not

- **Set file permissions yourself.** The plugin calls `os.ReadFile` and performs **no
  permission check**. It will happily read a world-readable key and say nothing. Target `0400`
  or `0600`, owned by the identity the gateway runs as. In the reference setup the key
  directory is mounted read-only into the container, which prevents modification but does
  nothing about who can read it.
- **Keep it out of version control.** In the reference demo the key directory is gitignored
  and the plugin repository's `.gitignore` covers `.env` and build output. Neither is a
  substitute for a secret scanner in your own pipeline, and neither helps if the key was
  committed once and the commit is still reachable.
- **Plan rotation before you need it.** The key is parsed once in `NewClient`, at `Init`. A
  rotated key file is not picked up until the Bifrost process restarts, so rotation is a
  restart. Zero-downtime rotation is covered in
  [docs/PRODUCTION.md](docs/PRODUCTION.md#key-rotation).
- **Assume it is exposed if the host is.** The parsed key lives in process memory for the
  lifetime of the gateway, with CRT values precomputed. Disable core dumps on that process.

### What the plugin does with credentials in flight

Verified by reading the source, and partly pinned by tests:

- The caller's token is **never logged, never placed in an error message, and never returned to
  the caller**. `TestSubjectTokenErrorNeverContainsTheToken` asserts that a denial arising from
  an unusable credential does not contain the credential.
- The caller's raw token is **not forwarded upstream**. `BifrostContextKeyMCPExtraHeaders` is
  deliberately not read, because enabling the header there would also forward the caller's
  credential to the upstream MCP server. The plugin reads the caller's token as an exchange
  subject; it does not pass it on.
- Request bodies to Okta are never logged. They carry a live subject token.
- The minted token is **not retained** in the verdict cache. Only the outcome is cached, never
  the credential, so a cached permit cannot be turned back into a usable token.
- The per-call check **discards** the token it mints. It cannot be attached to an MCP request,
  so it exists only to make Okta answer.
- The key material is precomputed rather than trusted from the JWK: only `n`, `e`, `d`, `p`, `q`
  are read and the CRT values are recomputed, so a JWK with stale precomputed values cannot
  produce silently invalid signatures. `key.Validate()` runs at startup.
- The client assertion carries a random 128-bit `jti` and a five minute expiry, so Okta can
  reject replay.

**There is no config-redaction path.** A constant named `redactedPlaceholder` exists in
`plugin/config.go` with a comment referring to a `RedactConfig` function, and **no such
function exists**, verified by grep. Do not assume configuration is redacted anywhere by this
plugin. If your logging or your support tooling captures plugin configuration, it captures
whatever is in it, which is the third reason to keep the key in a file.

---

## 6. Failure modes and their security consequence

| Condition | Behaviour | Security consequence |
|---|---|---|
| `Init` fails (bad config, unreadable or malformed key) | Every hook refuses with HTTP 403 `okta_plugin_uninitialised` | **Fail closed.** Nothing has authorized anything, so refusing is correct |
| Unknown key in the plugin config | `Init` fails, so the plugin denies everything | **Fail closed.** A typo must not silently disable a security setting. `DisallowUnknownFields` in `main.go` |
| MCP client with no binding | Connect and every call refused | **Fail closed.** An unconfigured MCP server cannot be reached unmanaged |
| Tool outside the binding's `tools` list | Call refused, naming the tool | **Fail closed** |
| No caller token on a tool call | Call refused with "no caller identity token" | **Fail closed.** Without a caller there is nothing to delegate from, and minting anyway would grant the agent's own broader authority |
| Okta unreachable on a tool call | Call refused | **Fail closed**, and see the `fail_open` note below |
| Okta refuses the mint | Call refused, carrying Okta's error verbatim | **Fail closed** |
| Connect with no caller token, `allow_connect_without_caller: true` | Connect permitted, **no `Authorization` header attached**, no mint attempted | Safe, and explained below |
| The `.so` fails to load | Bifrost starts **without** the plugin | **Fail open, and quietly.** See below |

### `fail_open`

`fail_open` defaults to `false` and exists so that the failure mode is an explicit, auditable
choice rather than an accident of implementation. **Leave it false.**

What turning it on actually does, verified in the source rather than from its documentation:

- **At connect time it takes effect.** On a mint failure the connection is permitted and, because
  the code returns before the header assignment, **no `Authorization` header is attached**. So
  a resource server that validates independently refuses every call over that connection. A
  resource server that does *not* validate independently, or that holds a static credential of
  its own, or a stdio server with no auth at all, is now reachable with no authorization
  decision behind it. **In that configuration `fail_open: true` converts an Okta outage into an
  authorization bypass. Say it that plainly to anyone who asks for it.**
- **At the per-call hook it currently does nothing.** This is a code-level discrepancy you
  should know about before you read the config documentation and conclude otherwise.
  `Config.FailOpen` is documented as allowing "tool calls through when Okta cannot be reached".
  In `PreMCPHook` the `fail_open` branch is guarded by `err != nil` from `stillPermitted`, and
  `stillPermitted` returns `nil` for its error on every one of its three return paths. An Okta
  outage becomes `permitted == false` with a reason, which lands in the `!permitted` branch and
  **denies regardless of the setting**.

So today the per-call gate is fail-closed unconditionally. That is the safer direction, and it
is still a discrepancy: the setting does not do what its own documentation says, and anyone
"fixing" that later would change the security posture of every deployment that had set the flag.
We would rather you heard it here than found it in a diff.

### `allow_connect_without_caller`

Defaults to `false`. You will almost certainly need `true`, and it is not a bypass.

Bifrost registers MCP clients and discovers their tools **at startup**, where there is no
inbound HTTP request and therefore no caller token. Left false, the connect is refused,
registration fails, no tools are discovered, and every later call fails with `tool not found`
rather than with anything resembling an authorization error.

Turning it on does not weaken enforcement, for two independent reasons:

1. **No credential is attached** to such a connection, and no mint is even attempted, so an
   independently-validating upstream refuses any tool call over it.
2. **`PreMCPHook` still denies** every `execute`, `chat_tool_call` and `responses_tool_call`
   without a caller token and a live Okta answer, and is entirely unaffected by this setting.

`TestTokenlessConnectAllowedButExecuteDenied` pins both halves of that pairing, so changing
either without the other fails the test. Reason 1 depends on your upstream validating. Reason 2
does not.

### The failure mode with no good detection

**A plugin that does not load leaves Bifrost running without it.** Bifrost starts, serves
traffic, and the only signal is the absence of an expected line in its log. Go refuses to load
a `.so` unless the plugin and host agree on the Go version and on **every** shared dependency
version, patch versions included, and on architecture. So a Bifrost upgrade, a dependency bump,
or a build on the wrong platform can silently remove your enforcement point.

Treat "the plugin is loaded" as a monitored invariant, not a build-time assumption. See
[docs/PRODUCTION.md](docs/PRODUCTION.md#is-the-plugin-actually-loaded-and-deciding).

---

## 7. Attack surface the plugin adds

Three additions, all on the request path.

### An outbound dependency on Okta, on the request path

Every mint is **two** HTTPS requests to your Okta org: an ID-JAG exchange at the org
authorization server, then a redemption at the target authorization server. Bifrost's
connection model is per call, so the connect-time mint runs per call.

Consequences:

- **Okta is now a request-path dependency for tool execution.** Its availability is your tool
  availability. The plugin fails closed, so an Okta outage denies rather than admits, which is
  the right direction and is still an outage.
- **One fixed 30 second HTTP timeout**, set in `NewClient`. There is **no retry, no backoff,
  and no circuit breaker**. A hung connection to Okta holds a tool call for up to 30 seconds
  before the denial, which exceeds many client timeouts, so the symptom an operator sees is a
  client timeout rather than a clean refusal.
- **Load amplification.** See [docs/PRODUCTION.md](docs/PRODUCTION.md#3-okta-rate-limits) for why
  a low TTL under load is a real hazard rather than a theoretical one.
- **Traffic-analysis exposure.** Your Okta org now sees a request pair per tool call, carrying
  the target resource URL and the requested scopes. That is a fairly detailed picture of agent
  activity leaving your perimeter, and it is a feature for audit and a consideration for
  anything sensitive about which tools are being used how often.

The plugin sets `User-Agent: okta-bifrost-plugin/0.1` on its Okta calls so an operator can
attribute them in the System Log without correlating by timestamp.

### An in-memory cache of authorization decisions

The verdict cache holds one entry per distinct question, keyed by
`Binding.verdictKey()`: the authorization server id, the target resource URL, and the
**sorted** scope set, joined with NUL. Sorting means the same set in a different order shares
an answer. NUL means no combination of values can be concatenated into a collision, because it
cannot occur in an Okta id, a URL, or an OAuth scope token.

- **Keys derive from configuration, so the cache is bounded** by the number of configured
  bindings. It is not attacker-growable, and it is not a memory exhaustion vector.
- **It caches denials as well as permits.** See section 3.
- **It is read concurrently** under an `RWMutex`, and the suite is run under the race detector
  via `make race`.
- **There is no request coalescing.** On TTL expiry, concurrent calls for the same binding all
  miss and each fires its own mint, because no lock is held across the Okta call. Under
  concurrency the load spike at expiry is proportional to in-flight requests, not to one.

> **A fixed bug worth knowing, because it shows the failure class.** The key was originally the
> authorization server id alone. Two bindings on one authorization server therefore shared a
> verdict, so a permit recorded for one answered for the other. That is the worst failure
> available to an authorization check, because it does not look like a failure. It is fixed at
> the root in `Binding.verdictKey()`, and two tests cover both directions. Both were
> mutation-tested: reverting the key makes them fail, so they actually bite.
>
> If you see a refusal naming a scope the call never requested, you are on a build predating
> that fix.

### A dependency on the TLS trust store

The plugin's Okta calls use Go's default HTTP transport and therefore the process's system
trust store. It does not pin certificates and does not carry its own root set.

On networks that intercept TLS, which is common in the environments this is aimed at, that
means a **custom CA bundle**, and three specific hazards:

- **A replacement, not an addition.** Pointing `SSL_CERT_FILE` at a bundle **replaces** the
  default trust store rather than adding to it. The bundle must contain your interception root
  **and** the normal public roots, or Okta calls start failing with an unknown-authority error.
- **The failure mode is indistinguishable from no configuration.** An unknown-authority TLS
  error looks the same whether you configured nothing or configured a path that does not exist
  inside the container. In the reference demo the variable is deliberately named
  `EXTRA_CA_BUNDLE` in `.env` and mapped to `SSL_CERT_FILE`, because Compose gives the host
  shell precedence and `SSL_CERT_FILE` is commonly already exported on a developer machine,
  which would let a stale host value silently win.
- **Interception is a real trust decision.** Every mint, and therefore the agent's
  `private_key_jwt` client assertion, traverses a proxy that can read it. The assertion is
  audience-bound to the specific Okta token endpoint and expires in five minutes with a `jti`,
  which limits what a captured one is worth, and it is still worth knowing that your proxy sees
  it.

---

## 8. Claims and their evidence

A reviewer should not have to guess which claims came from a live run and which from reading
code. This table is the whole distinction.

### Verified live, against a real Okta tenant

| Claim | Evidence |
|---|---|
| A refused tool call **never reached the resource server** | A count of matching `tools/call` lines in the resource server's log: **zero**. Not "received and rejected". It never arrived |
| The per-call refusal path is what fired, not connect-time | **36** per-call refusals against **0** connect-time, distinguished by the wording of the denial |
| The denial is a real round trip, not a cache hit | Denials measured at **320 to 710ms**, consistent with two HTTPS requests to Okta |
| The resource server's account is of the same token the gateway sent | The token id in the server's log matches the one the app displays, **byte for byte** |
| The refusal is Okta's decision, relayed rather than composed | Okta's own error text, `invalid_scope` naming the scope, present in the gateway's log |
| Nothing changed in the tenant between the allowed and refused call | Repeatable in either order, as many times as you like |

### Verified in code and by test, but not observed in a live run

| Claim | Status |
|---|---|
| The resource server rejects a bad token | **The code path is present and reviewed. It has never been observed firing in a live run.** No bad token was presented during verification. Real signature check, `RS256` pinned, issuer, audience and expiry checked, and today untested against an actual bad token |
| Denial is never delivered as a returned error | Pinned by `TestDenialIsNeverReturnedAsError` |
| A tokenless connect attaches no credential and still cannot execute | Pinned by `TestTokenlessConnectAllowedButExecuteDenied` |
| Two bindings on one authorization server do not share a verdict | Pinned in both directions, mutation-tested |
| The client assertion is a valid RS256 JWT that verifies against the public half | Pinned by `TestClientAssertionIsAValidRS256JWT` |
| A public key mistaken for a private one is rejected with a legible error | Pinned by `TestRejectsAPublicKeyMistakenForPrivate` |

### Not verified. Do not let anyone imply otherwise

- **Revocation was never demonstrated end to end.** The mechanism is real, the unit test
  `TestRevocationFlipsAPermittedAgentToDenied` covers the plugin's half against a fake Okta,
  and **no live deactivate-then-call sequence was run**. If revocation matters to your
  evaluation, run it yourself and measure the actual staleness against your configured TTL.
- **The resource server was never observed refusing a bad token in a live run.** Repeated from
  the table above because it is the claim most likely to be softened in retelling.
- **What determines `aud` is an open question.** See the next section.

### Where Okta's own record lives

Okta's System Log is reachable through the **Admin Console**: Reports > System Log. Relevant
event types are `app.oauth2.token.grant.id_jag` for the ID-JAG issuance and
`app.oauth2.as.token.grant.access_token` for the grant at a custom authorization server. Check
`outcome.result` and `outcome.reason`.

**Do not expect to pull it from a terminal using this demo's credentials.** They are scoped
`agent.invoke` only, so `GET /api/v1/logs` returns **401**. That is correct: a demo client has
no business holding management-API scopes. It is not a gap in the integration, and it does mean
the System Log evidence requires console access.

---

## 9. Undocumented Okta behaviour this depends on

Two of the mechanisms this integration relies on are **not in Okta's published developer
documentation**. They were verified empirically by decoding real tokens from a live tenant, and
they behave consistently.

| Claim | Sourcing |
|---|---|
| The issued access token carries an `act` claim naming the acting agent, nesting so a multi-hop chain is readable from the token alone | **Not documented by Okta. Verified empirically** |
| Each level carries a `sub_profile` typing the principal as `service` or `ai_agent` | **Not documented by Okta. Verified empirically** |

**Never present these as documented Okta behaviour.** If you script an assertion on them, treat
their shape as observed behaviour that could change, not as a contract. The reference resource
server treats `sub_profile` as optional throughout for exactly that reason: if it stops being
emitted, output degrades to bare principal ids rather than breaking.

### Open question: what determines `aud`

**Do not claim that `aud` comes from the `resource` parameter.** It is not established, and it
is easy to conclude wrongly from a working setup.

**What is observed:** the issued token's `aud` equals the `resource` value sent on the exchange,
repeatedly, against this tenant.

**Why that is not proof:** in the reference demo both bindings share **one** authorization
server, and both send the same target resource URL. If that server's configured `audiences`
holds the same string, then `resource` and the server's own `audiences` setting predict the
**same** `aud`, and no observation available here can tell them apart. A matching `aud` is
consistent with `resource` being authoritative. It does not demonstrate it.

**Settling it needs one of two experiments:** read the authorization server's `audiences` value
and confirm it differs from the `resource` sent, then see which `aud` follows; or send a
`resource` the server's `audiences` does not contain, and see which one wins.

Until then, "validate `aud` against the resource URL" is the correct operational instruction,
because it follows from what the tokens carry rather than from why they carry it, and the
mechanism should be treated as unknown.

### Reading a denial

Okta's wording distinguishes cases that look identical from outside. This matters for incident
response, because two of these are permission decisions and the rest are configuration.

| Okta says | Means |
|---|---|
| `invalid_scope`, naming the scope | **A permission refusal.** The agent may use this connection, and may not use it this way. Note that Okta does not down-scope: an ungrantable scope fails the whole request rather than returning the grantable subset, so there is no partial success to accidentally accept |
| `invalid_client` | **A deactivated agent presents this way**, as does a `private_key_jwt` that does not match the key registered on the agent. Worth knowing: it is easy to expect a policy-shaped error for a deactivated agent and look in the wrong place |
| `access_denied`, policy evaluation failed | The caller is not a listed client of that authorization server |
| `invalid_target` | No **ACTIVE** connection matches the `resource` sent. Reads like a permission decision, is almost always a misconfiguration or a staged connection |
| `'subject_token' is invalid` | The caller presented an ID token, or a token from the org authorization server. It must be an access token from a custom authorization server with a resource-scoped audience |

For demonstrating least privilege honestly, ask a disallowed **scope** over a connection the
agent legitimately holds. That produces the first row, which is unambiguous. Pointing at a
resource with no connection produces `invalid_target`, which reads like a config error and
proves less than it appears to.

---

## Support status and reporting a vulnerability

### Status

**This is unsupported sample code. It is not an Okta product.**

- **No SLA.** No response-time commitment, no uptime commitment, no patch commitment.
- **Not covered by Okta's product support.** Opening a support case about this plugin will not
  get it fixed. It is not in the supported-product catalogue.
- **Not covered by Okta's product security programme or bug bounty**, because it is not an Okta
  product. See below for what to do instead.
- **Licensed Apache 2.0**, which includes the warranty disclaimer and limitation of liability in
  sections 7 and 8 of that licence. Read them; they are the actual terms.
- **You own what you deploy.** If you run this, you are running your own fork of sample code
  inside your own build of a third-party gateway. The review, the hardening, the monitoring, and
  the patching are yours.

### Reporting a vulnerability

**Do not open a public issue for a security defect, and do not include live credentials, real
tenant identifiers, or captured tokens in any report.**

If you have an Okta account team or an assigned Professional Services or solutions engineering
contact for this engagement, that is the fastest route: report it to them directly and ask them
to route it to the maintainers of this repository. That path exists and is known to work.

If you do not, report it privately to the repository maintainers through whatever private
channel the repository offers, such as GitHub's private vulnerability reporting, rather than
through a public issue or pull request. If neither is available to you, escalate through your
Okta account team.

**A useful report contains:** what an attacker gains, the configuration required to reach it
including the relevant plugin settings, the plugin commit or build, the `bifrost/core` version
and Go version the host was built with, and the smallest reproduction you can construct. If the
defect is in Bifrost itself rather than in this plugin, it belongs upstream with
[Bifrost](https://github.com/maximhq/bifrost); say so in your report either way and we will help
work out which it is.

**What to expect:** best effort. There is no committed response time. If a fix lands it will be
a commit in this repository, and you will need to rebuild the plugin against your own Bifrost
and redeploy it. There is no update channel that reaches your deployment on its own.

### If a defect in Okta itself is involved

If what you found is a flaw in Okta's token exchange, its authorization server behaviour, or
its agent lifecycle rather than in this plugin, that **is** in scope for Okta's product security
process and should go there, through your account team or Okta's published security contact
route, in addition to being reported here.
