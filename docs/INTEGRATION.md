# Integrating the plugin into your own Bifrost

This document is for a team that already runs Bifrost and is deciding whether, and how, to
adopt `okta-agent-identity` into that deployment.

It is deliberately not a second copy of the reference material. Three documents already
exist and are not repeated here:

| Read | For |
|---|---|
| [`README.md`](../README.md) in this repo | what the plugin does, the config reference, the failure table |
| `fleetops-bifrost-demo/docs/RUNBOOK.md` | click-by-click Okta setup, with the console paths and the console-only steps |
| `fleetops-bifrost-demo/docs/PROVING-IT.md` | how to show the enforcement is real rather than asserted |

What none of them answer is the question you are actually asking: **what changes in our
deployment, what do we have to own afterwards, and how do we get there without a single
cutover.** That is what follows, in the order a real team hits it.

**This is unsupported sample code.** It is not an Okta product, it carries no SLA, and
nothing about it is covered by an Okta support contract. Adopting it means adopting the
maintenance of it. Read [Stage 0](#stage-0-decide-whether-you-are-taking-on-a-bifrost-build)
before you spend engineering time anywhere else.

---

## Stage 0. Decide whether you are taking on a Bifrost build

**Bifrost's published images are statically linked and cannot load any Go plugin.** Not this
one, not any. Go's plugin system requires a dynamically-linked host binary. This is
[documented behaviour on Maxim's side](https://docs.getbifrost.ai/plugins/building-dynamic-binary),
not a defect, and not something to raise with them as one.

The consequence lands on your build pipeline, not on your application code:

**You stop consuming `maximhq/bifrost` and start building it.** From that point you own a
Go build of a third-party service. Every Bifrost release you want, you rebuild. Every CVE in
their dependency tree is yours to notice and to ship. Every upgrade is a coordinated
release of two artifacts that must agree on Go version and on every shared dependency
version, because the plugin will silently fail to load if they do not. That coupling is
described in [Stage 1](#stage-1-pin-the-three-axes) and it does not go away.

The change to the build itself is one line. `fleetops-bifrost-demo/bifrost/Dockerfile.dynamic`
is a working example: it clones Bifrost at a pinned ref, builds their `bifrost-http`, and
differs from their own build only by **not** passing `-extldflags '-static'` to the linker.
It also asserts on the output with `file`, and fails the build if the binary comes out
static, because the runtime symptom is `plugin.Open: Dynamic loading not supported`, which
does not point at a linker flag.

So the work is small and the ongoing obligation is not. **This is the single biggest reason
a team should decide not to take the plugin route.** If your organisation will not accept
maintaining a fork-free but self-built Bifrost image, stop here: the honest answer is that
this integration is not for you, and the same authorization model can be reached by putting
the exchange in a sidecar or in the calling service instead, at the cost of losing the
per-call decision point that only the gateway has.

Two further things that Dockerfile does, worth knowing because they will bite your own
build:

- **The admin console is embedded with `//go:embed all:ui`,** so `bifrost-http/ui` must exist
  and be non-empty at Go build time. The demo's Dockerfile builds the real console with
  their lockfile and their build script, then asserts the output is a real console rather
  than a stub. A stub satisfies the embed and yields a server that boots and serves a blank
  page, which is a confusing thing to debug later.
- **A corporate CA bundle may be needed twice,** once in the system trust store for the
  `git clone` and once handed to Node for the `npm ci`, because npm uses Node's own trust
  store rather than the system one. Only relevant on networks that re-sign TLS.

---

## Stage 1. Pin the three axes

A `.so` loads only if it agrees with the host binary on **all three** of these. Not two.

| Axis | Requirement |
|---|---|
| Go toolchain version | Exact match. Not "compatible" |
| Every shared dependency version | Exact match. `bifrost/core` v1.8.4 against a v1.8.3 host does not load. Patch versions count |
| Architecture | Exact match with the **Bifrost image**, see [Stage 2](#stage-2-build-for-the-target-architecture) |

**Do not read these off this repo's defaults.** `go.mod`, the `Makefile` and
`Dockerfile.dynamic` in the demo each carry a pinned value that was correct for one image at
one time, and the comments in them are not all in step with each other. Read the values out
of the image you are actually loading into:

```bash
make compat BIFROST_IMAGE=your-registry/bifrost:your-tag
```

```
inspecting your-registry/bifrost:your-tag ...
  go:   go1.27.0
  core: v1.8.3
```

That target extracts `/app/main` from the image and runs `go version -m` against it, so what
it prints is what the binary was actually built with rather than what any file claims. Then:

```bash
make pin BIFROST_CORE=v1.8.3      # the value it printed
make plugin PLATFORM=linux/amd64
```

`make pin` also runs `go mod tidy`, so the indirect dependency set is re-resolved against
that core version. That is the point: the constraint is not only `bifrost/core`, it is the
whole graph underneath it.

**The failure mode here is silence.** A mismatched plugin does not crash Bifrost and does
not produce an obvious error. It fails to load, Bifrost carries on, and the first thing you
notice is that nothing is being authorized. Make [Tier 1 of the verification](#tier-1-the-plugin-loaded)
a startup assertion in your deployment rather than something you check by hand.

### Why the plugin has no dependencies

`plugin/` imports only the Go standard library and `bifrost/core/schemas`. That is a
deliberate constraint rather than minimalism for its own sake: every library added is
another version that has to match your Bifrost build exactly, and therefore another way for
the artifact to refuse to load in your environment. It is why the RS256 client assertion is
hand-rolled on `crypto/rsa` instead of using a JWT library.

**If you extend the plugin, keep that property.** A single added dependency turns a
one-value pin into a two-value pin, and the second one will be the one that breaks on your
next Bifrost upgrade.

---

## Stage 2. Build for the target architecture

The `.so` must match the architecture of the **Bifrost image**, not of the machine doing the
build. Building on an Apple Silicon laptop for amd64 Linux is the normal case, and it is
what this repo's `PLATFORM ?= linux/amd64` default assumes.

```bash
make plugin PLATFORM=linux/amd64      # x86 EC2, ECS on x86
make plugin PLATFORM=linux/arm64      # Graviton, or an arm64 node pool
```

The artifact carries the architecture in its filename, `bin/okta-agent-identity-<arch>.so`,
so two builds cannot be mistaken for each other on disk.

The build runs in a pinned container. **No local Go install is used, and that is on
purpose:** building on a developer's own toolchain is the single most reliable way to produce
a plugin that will not load in your Bifrost.

> **The architecture mismatch has a failure mode worse than not loading.** On a clean
> checkout the two sides disagree and the plugin simply fails to load, which is at least
> loud. On a machine where an `.so` of the *other* architecture already exists, the build
> **succeeds while being wrong**: the artifact nobody loads is rebuilt, Bifrost loads the
> stale file already on disk, and a source change looks applied when it is not. If a change
> appears to have no effect, check which architecture is in `bin/` and which one your
> Bifrost config names.

**Do not derive `PLATFORM` from the build host.** The demo repo does derive it from the
host, and that is correct *there* because everything in it runs on one machine. In a real
pipeline the build host and the runtime architecture are routinely different, and
host-derivation will hand you an arm64 `.so` that cannot load on amd64.

If you run mixed architectures, build both and select by architecture at deploy time. The
plugin config's `path` is a single string, so the selection has to happen in whatever renders
that config.

Before shipping:

```bash
make check      # gofmt, go vet, go test
make race       # the verdict cache is read concurrently, so run this too
```

---

## Stage 3. Create the Okta objects

`RUNBOOK.md` in the demo repo has the console paths, the exact form fields, and the
console-only steps. This section is the **shape** of what you are building and why, so you
can map it onto your own tenant conventions rather than following someone else's naming.

### Decide the topology first

This is the most expensive decision here, because getting it wrong produces a misleading
error on a different object than the one at fault.

| Shape | The agent reaches | Authorization servers |
|---|---|---|
| **Agent to agent** | another registered agent | **two**, one per invoked agent |
| **Agent to API** | a resource server, optionally split into read and command lanes | **three** |

The reference demo runs agent-to-agent, and that is the shape that was proven live. The
agent-to-API variant is in `RUNBOOK.md` Appendix A. The plugin is indifferent to which you
pick: steps 2 and 3 of the exchange are the same requests either way.

### The objects, and why each exists

| Object | Why it has to exist |
|---|---|
| **A calling service**, as an API Services app | Registered agents are **not permitted the `client_credentials` grant at all**, only token-exchange and jwt-bearer. Something that is not an agent must start the chain. This app stands in for your scheduler, pipeline, or front door |
| **The acting agent**, registered under AI Agents | The identity Bifrost authenticates as. Needs owners assigned, and a key pair generated |
| **An authorization server per invoked agent** | Its audience value and that agent's resource URL are **one string**, used in both places |
| **Each agent registered as a resource** | Console-only. This is what makes the agent addressable as a target, and everything downstream fails until it exists |
| **A resource connection** from the acting agent to the target | **This is where scopes are actually enforced.** Publishing a scope on the authorization server is not sufficient |

### The grants, stated as a checklist

- The calling service is granted access to the **acting agent's own** authorization server,
  and is added as a permitted caller **on the acting agent**. Both, not one.
- On each authorization server, the access policy's `clients` condition names **the caller**
  at that endpoint: the calling service on the agent's own server, the acting agent on the
  target's server. The `clients` condition is at **policy** level, not on the rule.
- Grant types differ per server: **Client Credentials** on the agent's own server, **JWT
  Bearer** on the target's.
- The resource connection lists the scopes with **Only allow**, and the list is what an
  exchange is validated against.

### Five facts that will cost you time if you meet them cold

1. **The resource URL is immutable once saved.** It can be deleted and recreated, not edited.
   Choose it deliberately, and choose it to be something you would be happy validating
   against for years.
2. **Registering an agent as a resource, and assigning owners, are console-only.** The API
   returns 405 on every verb and shape. The console calls the first one **Delegations >
   Non-human identity > Configure**, which is why searching for "A2A server" finds nothing.
3. **An access rule's `people.groups` must not name a user group.** An agent is a workload
   principal, not a user, so it will never match and the rule will never fire. The demo uses
   EVERYONE, which is permissive and is worth tightening for your production tenant.
4. **Okta does not down-scope.** A scope the connection does not grant fails the **whole**
   request rather than returning the grantable subset. There is no partial success to
   accidentally accept, which is a good property, and it means an over-broad `scopes` list in
   one binding breaks that binding entirely rather than degrading it.
5. **A connection must be ACTIVE.** A staged one produces `invalid_target`, which reads like
   a typo in a URL.

### Validate `aud` against the resource URL

Your resource server must validate the token it receives, and the audience it should check
is **the resource URL** you send as `resource` on the exchange.

That is the operational instruction and it is correct. The mechanism behind it is **an open
question**, and it is worth stating precisely so nobody on your side builds a mental model
on it:

**What is observed:** the issued token's `aud` equals the `resource` value sent on the
exchange. Verified repeatedly against a live tenant.

**Why that does not establish causation:** in the reference demo both bindings share **one**
authorization server. If that server's configured `audiences` holds the same string, then
`resource` and `audiences` predict the **same** `aud`, and no observation in that setup can
distinguish them. A matching `aud` is consistent with `resource` being authoritative. It is
not proof of it.

**How you could settle it in your own tenant,** which is worth doing if you are going to
depend on the distinction: read the target authorization server's configured `audiences` and
check whether it differs from the resource URL you send, then see which one `aud` follows.
Or send a `resource` the server's `audiences` does not contain and see which one wins.

Until then, validate against the resource URL. That is correct under either explanation.

---

## Stage 4. Bifrost configuration

Three things in this section are Bifrost's behaviour rather than the plugin's, and every one
was hit for real during the reference build.

### The two settings that look wrong and are not

```json
"auth_type": "none",
"needs_session_stickiness": false
```

Set on **every** MCP client the plugin governs.

**`auth_type: "none"` is not a placeholder and not the absence of a choice. It is the only
value that works,** for two independent reasons.

1. **`none` is the only resolver that returns no headers.** Every other auth type resolves
   upstream headers of its own, and those **overwrite the `Authorization` header the plugin
   set** on the connect request. The plugin mints correctly, the header is replaced, and the
   upstream server rejects a credential the plugin never sent. It presents as a minting bug
   and is not one.
2. **`per_user_headers` additionally requires pre-stored per-caller credentials** and aborts
   the connect when it finds none. There are none to store: the entire point is that the
   credential is minted per call from Okta rather than kept anywhere.

> **Discount any guidance, including your own reasoning, that says caller context requires
> `per_user_headers`, `per_user_oauth` or `token_exchange`.** Those are Bifrost's per-call
> connection types, so the argument looks sound, and it leads somewhere that cannot work.
> `token_exchange` in particular makes Bifrost run its **own** single-hop exchange, which is
> precisely the thing this plugin replaces.

The plugin does not need Bifrost's credential brokering to find the caller. It reads the
caller's `Authorization` header straight off the inbound request context, which needs no
`auth_type` configuration at all. That is why `auth_type: "none"` costs nothing.

**`needs_session_stickiness: false` gives you per-call connections, and the per-call
connection is what creates the per-call decision point.** With stickiness on you get one
shared connection with no caller context, so the plugin has nothing to delegate from. This
setting is the reason the enforcement model works at all, so it reads like a performance
knob and is actually load-bearing.

The direct consequence, stated here so it is not a surprise in
[capacity planning](#what-to-watch): because connections are per-call, the connect-time mint
runs **per call**. That is two Okta token requests per tool call, and it is unrelated to the
verdict cache TTL.

### Name rules, which Bifrost enforces silently

**Hyphens in MCP client or tool names make Bifrost skip the client.** No error, no warning,
the tool is simply not there. Use underscores: `fleetops_read`, not `fleetops-read`. No
spaces, no leading digit.

### `tools_to_execute` and `bindings[].tools` take different forms

In the same file:

| Field | Form | Example |
|---|---|---|
| Bifrost's `tools_to_execute` | **bare** tool name | `get_telemetry` |
| The plugin's `bindings[].tools` | **namespaced** | `fleetops_read-get_telemetry` |

This is the nastiest inconsistency in the setup. The hyphen in the namespaced form is
Bifrost's own separator and is fine there; the ban on hyphens applies to the names **you**
declare.

### Config location

Bifrost reads `$APP_DIR/config.json`, which in the published layout is
`/app/data/config.json`. Put it anywhere else and Bifrost starts on defaults, your plugin
never loads, and the only hint is one info line saying the config file was not found.

### Never restart. Always recreate.

**Tools are discovered only on FIRST registration.** On a restart, Bifrost reloads its MCP
clients from its sqlite store **without re-running discovery**. The result is a gateway that
lies to you:

- `GET /api/mcp/clients` still reports every tool, read from the database.
- The live in-memory tool registry is **empty**.
- Every call fails with `tool not found`.

There is no log line saying discovery was skipped, and the symptom points nowhere near the
cause. In Compose that means `down -v` rather than `restart`. **In your orchestrator, work
out the equivalent before you need it:** anything that preserves the sqlite store across a
process restart can reproduce this. If your Bifrost keeps its config store on a persistent
volume, a rolling restart is a candidate for exactly this failure, and the safe pattern is
to replace the pod and its volume rather than restart the process.

---

## Stage 5. Plugin configuration

The full key-by-key reference is in [`README.md`](../README.md#config-reference). Four things
matter more than the rest when you are fitting this to an existing deployment.

### `allow_connect_without_caller` must be `true`, and it is not a bypass

**Bifrost registers MCP clients, and discovers their tools, at startup.** There is no
inbound HTTP request at that moment, so there is no caller token to delegate from.

Leave this `false` and the connect is refused, registration fails, **zero tools are
discovered**, and every later call fails with `tool not found` rather than with anything
resembling an authorization error. The gateway is unusable for a reason that looks nothing
like its cause, and the only hint is an empty tools array.

Setting it `true` does not weaken enforcement, for two independent reasons:

1. **No `Authorization` header is attached** to such a connection, and no mint is even
   attempted. The upstream server validates independently, so it rejects any tool call
   arriving over that connection.
2. **The per-call hook still denies** every `execute`, `chat_tool_call` and
   `responses_tool_call` that has no caller token and no live Okta mint, and it is completely
   unaffected by this setting. Discovery needs only `initialize` and `tools/list`, which the
   per-call hook deliberately does not gate.

That pairing, connect permitted while execute denied, is the invariant. It is pinned in both
directions by `TestTokenlessConnectAllowedButExecuteDenied`, which also asserts that no
credential is attached and no mint is attempted, so changing one half without the other
fails the test.

If your reviewers push back on this setting, the useful reframing is: it permits exactly the
unauthenticated handshake and `tools/list` that any MCP server publishing a tool list
already permits. It does not permit execution.

### Every MCP client on the instance needs a binding

**A client with no binding is refused, never passed through.** That is the right default: an
MCP server someone forgot to configure cannot be reached through the gateway unmanaged.

It also has a direct adoption consequence that shapes [Stage 6](#stage-6-a-rollout-path-that-is-not-a-cutover):
once the plugin is loaded into a Bifrost instance, **every** MCP client on that instance
must have a binding or it stops working. You cannot govern one MCP server and leave the
others ungoverned within a single instance. Incremental adoption therefore happens **per
Bifrost instance**, not per MCP server.

### `agent_status_ttl` is your revocation staleness bound

It ships at `10s`, which is also the plugin default. It is doing two jobs at once: it is the
verdict cache lifetime, and it is therefore the **window in which a deactivated agent still
passes**.

**Raising it widens that window.** It is not a free performance dial. Choose it against how
quickly a deactivation needs to bite in your environment, not against latency, and note that
lowering it does **not** reduce the minting cost, which is driven by Bifrost's per-call
connection model instead. See
[the verdict cache](../README.md#the-verdict-cache-and-what-agent_status_ttl-really-controls)
and [`ARCHITECTURE.md`](ARCHITECTURE.md#the-verdict-cache).

### `fail_open` does less than its name suggests

Verified by reading the source, not inferred:

- **On the connect hook,** `fail_open: true` lets a connection be established when Okta
  refuses or is unreachable. No `Authorization` header is attached in that case, so the
  upstream rejects any call over it anyway.
- **On the per-call hook, it has no effect.** The internal check returns a denial verdict
  rather than an error when a mint fails, so the branch that consults `fail_open` is never
  reached. An Okta failure denies the call regardless of the setting.

So the call path is unconditionally fail-closed today. That errs in the safe direction, and
it means **`fail_open` is not a safety valve for an Okta outage and not a shadow mode.**
Leave it `false`, which is the default, and treat Okta reachability as a hard dependency of
your tool-call path. Size your availability expectations accordingly.

One related behaviour to know: a mint failure is **recorded in the verdict cache** as a
denial. A transient Okta failure therefore denies subsequent calls for up to
`agent_status_ttl` after Okta recovers, rather than being retried immediately.

### Key material

Prefer `private_key_jwk_file` over `private_key_jwk`. Inline means the key ends up in the
gateway config, which then has to be treated as a secret everywhere it is stored, rendered,
logged, or backed up, and it has to survive JSON escaping and whatever templating renders
your config. Mount the JWK as a file with its own permissions and keep the config
non-secret.

The key is read once, at startup, and parsed then, so a malformed key fails the plugin's
`Init` rather than the first tool call. `Init` failing means the plugin is loaded but not
initialised, and in that state **it denies everything** rather than passing through.

### `agent_resource_url` is required but currently unused

Stated because a reviewer will look for it. The field is validated as present at startup and
is **not read anywhere else in the current code.** The audience check its documentation
describes, that the caller's inbound token is addressed to this agent, is **not performed by
the plugin**.

That check is not absent from the system: the caller's token is submitted to Okta as
`subject_token`, and Okta refuses a subject token from the wrong server or of the wrong type
with `'subject_token' is invalid`. So the enforcement is at Okta rather than at the gateway.
If your threat model wants the gateway to reject a wrongly-addressed caller token locally,
before an Okta round trip, that is a small change you would need to make.

---

## Stage 6. A rollout path that is not a cutover

Two facts constrain what incremental means here:

- The dynamic Bifrost build is a change to your pipeline that is **independent** of the
  plugin, so it can and should be de-risked on its own.
- Once the plugin is loaded, every MCP client on that instance needs a binding, so the unit
  of incremental adoption is **an instance**, not a server.

There is no observe-only mode in the plugin. Shadowing therefore means a parallel instance,
not a flag.

### Phase 1. The dynamic binary, with no plugin

Build the dynamically-linked Bifrost, put it in your registry, and roll it out **with no
plugin configured**. Nothing about the gateway's behaviour should change.

What you are proving: your build works, your image scanning accepts it, your deploy is
unchanged, and you have somewhere to put the rebuild when Bifrost releases. What you are
deliberately not yet risking: any authorization behaviour.

Exit when the self-built image has been serving production traffic long enough that you trust
the pipeline. This phase carries most of the ongoing cost of the whole integration, so it is
worth living with before committing to the rest.

### Phase 2. A shadow instance, synthetic traffic

Stand up a **second** Bifrost instance from the same image, with the plugin loaded, one MCP
client bound, and no production traffic. Drive it with synthetic calls.

What you are proving:

- The `.so` loads. This is the version-and-architecture check, and it is the one most likely
  to fail first.
- Okta's objects are wired correctly end to end, including the parts of `RUNBOOK.md` that are
  console-only and therefore not in your infrastructure-as-code.
- The refusal path works, and its wording is legible to your operators.

Deliberately break things here, while it is free: point a binding at a scope the connection
does not grant and confirm you get `invalid_scope` naming that scope. Deactivate the agent
and confirm the call stops. Both are cheap now and expensive later.

### Phase 3. One low-consequence MCP server, real traffic

Move the traffic for a **single** MCP server, chosen for having read-shaped tools and a
tolerable failure mode, onto the shadow instance. Everything else stays on the instance from
Phase 1.

You are now measuring things you cannot measure synthetically: the added latency of two Okta
token requests per call, your actual request rate against Okta, and whether an Okta blip
denies calls in a way your callers handle.

Exit when you have seen it survive an Okta hiccup and an application deploy.

### Phase 4. Bind the rest, then cut over

Add bindings for every remaining MCP client, one at a time on the shadow instance, verifying
each. Then move traffic and retire the unplugged instance.

The reason to add bindings before moving traffic is the unbound-client behaviour: a missing
binding is a refusal, so a forgotten client is a hard outage for that server rather than a
degradation.

### Where a command-shaped tool belongs

Put the tools that change the world last, and give them their own binding with their own
scope. The whole argument for this integration is that reading telemetry and dispatching a
vehicle should not carry the same permission, and the mechanism for that is a separate
binding with a separate scope list on a separate connection. Adopting it with one binding
covering everything works, and gives up the point.

### What to watch

| Signal | Where | Why |
|---|---|---|
| `plugin status: okta-agent-identity - active` | Bifrost startup log | The only cheap proof the `.so` loaded. Assert on it in your deploy, do not eyeball it |
| `okta denied "<tool>" on "<client>"` | Bifrost log | The **per-call** hook fired. This is the strong claim |
| `okta refused to issue a token for` | Bifrost log | The **connect-time** path. Also correct, weaker: it proves the session could not start, not that a call was gated |
| `tool not found` on everything | Bifrost log | Either `allow_connect_without_caller` is false, or something restarted instead of being recreated |
| `app.oauth2.token.grant.id_jag` | Okta System Log | Step 2 of the exchange, at the source |
| `app.oauth2.as.token.grant.access_token` | Okta System Log | Step 3, the token that went upstream |
| Token endpoint request rate | Okta | **Two token requests per tool call at steady state,** plus two more whenever the per-call check misses the verdict cache. Check your tenant's token endpoint rate limits against your peak tool-call rate before you assume headroom |
| Denial rate by binding | Bifrost log | A binding denying steadily usually means a connection scope list, not an agent problem |

Do not build alerting on `act` or `sub_profile` claim shapes. See
[the accuracy note below](#what-not-to-say-about-this-internally-or-to-your-auditors).

---

## Stage 7. Verify it in your own environment

Adapted from `PROVING-IT.md`, which is written for demonstrating to a sceptic. This version
is written for convincing yourself.

Four checks. Each rules out a different way of fooling yourself, and they get progressively
harder to fake.

### Tier 1. The plugin loaded

```bash
<your log query> | grep "plugin status"
```

```
plugin status: okta-agent-identity - active
```

Anything else means the `.so` did not load, and [Stage 1](#stage-1-pin-the-three-axes) is
where to look. A silent non-failure here is the usual outcome of a version or architecture
mismatch, which is why this belongs in your deploy gate rather than in a runbook.

### Tier 2. The upstream received a token the caller never held

This is the check that distinguishes delegation from pass-through, and it is the cheapest
strong one. Decode the caller's token and the token your resource server logged, and compare:

| Claim | Caller's token | Token the upstream received |
|---|---|---|
| `aud` | the acting agent's resource URL | the **target's** resource URL |
| `scp` | the caller's own scope | the **target** scope |
| `act` | absent | **present**, naming the agent |

**Same token in both columns means the gateway is forwarding the caller's credential and
nothing has been delegated.** That is the failure this check exists to catch, and it is
invisible from the outside because the call succeeds either way.

### Tier 3. The refused call never arrived

The strongest single fact available, and it is a count. On your resource server, count
requests for the tool you expect to be refused.

**Expect zero.** Not "received and rejected". It never reached the protected system.

One trap: if your resource server logs a startup banner listing its tools, grepping the bare
tool name finds the banner and returns one rather than zero. Match on the request line.

### Tier 4. Turn the plugin off and watch it break completely

Set `"enabled": false` on the plugin entry, recreate the gateway, and call a tool. It must
fail **completely**, with **no `Authorization` header reaching your resource server at all**.

If the call still succeeds, something else is authenticating and none of the tiers above were
measuring what you thought. This is the check that validates the other three, so run it once
per environment, not once ever.

Set it back and recreate.

### What your resource server must still do

None of the above relieves your resource server of validating the token itself. It should
verify the RSA signature against Okta's published keys, **pin `RS256`** so a token claiming
`alg: none` is rejected, and check issuer, audience and expiry. The demo's `server/auth.go`
does exactly this and is a reasonable reference.

The property you want is that going around the gateway does not get you in, it just means no
token. See [`ARCHITECTURE.md`](ARCHITECTURE.md#trust-boundaries) for what the gateway is and
is not trusted for.

---

## Reading a denial

Denials carry Okta's own wording rather than something the plugin composed, because Okta's
messages distinguish cases that look identical from outside the tenant.

| Okta says | Means | Look at |
|---|---|---|
| `invalid_scope`, naming the scope | A permission refusal. The agent may use this connection, and may not use it this way | The **connection's** scope list, not the authorization server |
| `invalid_target` | No **ACTIVE** connection matches `resource`. Reads like permission, is almost always configuration | Byte-compare the resource URL; check the connection is active rather than staged |
| `access_denied`, policy evaluation failed | The caller is not a listed client of that authorization server | The policy-level `clients` condition |
| `invalid_client` | The agent's `private_key_jwt` was not accepted. **This is also how a deactivated agent presents** | The registered key, and the agent's status |
| `'subject_token' is invalid` | The caller presented an ID token, or a token from the **org** authorization server | The caller's step 1: it needs an access token from a **custom** server with a resource-scoped `aud` |
| The upstream rejects a token the plugin clearly minted | Not a denial | `auth_type` is not `none`, so Bifrost overwrote the plugin's header |

**`invalid_client` for a deactivated agent is the one worth internalising,** because it reads
as a broken credential rather than as a policy decision. An operator seeing it will go
looking for a key rotation problem. If you build runbooks off these strings, map that string
to "check whether the agent was switched off" as well as "check the key".

For demonstrating least privilege to your own reviewers, ask a **disallowed scope over a
connection the agent legitimately holds**. That produces `invalid_scope` naming the scope,
which is unambiguous. Pointing at a resource with no connection produces `invalid_target`,
which reads like a config error and proves less.

---

## What not to say about this, internally or to your auditors

The value of this integration collapses if any single claim about it is caught being wider
than the truth. These are the ones that are easy to overstate.

**Okta is not contacted on literally every call.** The gateway *evaluates* every call and
caches Okta's answer for `agent_status_ttl`. The accurate sentence is: the gateway checks
every call and remembers the answer for a few seconds. That same window is the revocation
staleness bound, so it is a real tradeoff and not a free performance setting.

**The per-call check catches an agent being switched off. It does not catch scopes being
narrowed.** The token in flight was minted at connect and still carries the scopes granted
then, so tightening a connection's scope list takes effect on the **next connection**, not
the next call. Closing that would require re-establishing the connection, which no MCP hook
can do.

**There is no revocation push.** Revocation is detected by asking, within
`agent_status_ttl`. `Plugin.InvalidateVerdicts()` is the seam for an Okta event hook or a
shared-signals receiver, which would close that window. Nothing calls it today.

**`act` and `sub_profile` are not in Okta's published developer documentation.** They were
verified empirically by decoding real tokens from a live tenant, and they behave
consistently. Do not present them as documented behaviour, and do not build assertions or
alerting on their shape as though it were a contract.

**Tokens are bearer tokens.** No DPoP, no sender constraint. They are protected by being
short-lived and re-checked, not by being unstealable.

**There is no per-object authorization.** A scope can say an agent may dispatch. It cannot
say whether it may dispatch *this particular* vehicle. That needs a fine-grained
authorization layer above this one.

**Nothing here is an Okta product.** It is sample code demonstrating an integration path,
and it carries no support commitment.

---

## Where to go next

| For | Read |
|---|---|
| Why the design is shaped this way, and what to look at in review | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| Config keys, one by one | [`README.md`](../README.md#config-reference) |
| Okta setup, click by click | `fleetops-bifrost-demo/docs/RUNBOOK.md` |
| Demonstrating it to a sceptic | `fleetops-bifrost-demo/docs/PROVING-IT.md` |
