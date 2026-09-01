# Integrating the plugin into your own Bifrost

This document is for a team that already runs Bifrost and is deciding whether, and how, to
adopt `okta-agent-identity` into that deployment.

It assumes you have a working Bifrost, your own MCP servers, and your own Okta tenant, and
that **nothing in your environment is named the way the reference demo names things.** Every
example value here is a placeholder for that reason.

It is deliberately not a second copy of the reference material. These already exist and are
not repeated:

| Read | For |
|---|---|
| [`README.md`](../README.md) in this repo | what the plugin does and why, and the design rationale |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | where the plugin can act, the three-step exchange, trust boundaries |
| `fleetops-bifrost-demo/docs/RUNBOOK.md` | **the Okta build, click by click**, with the console paths and the console-only steps |
| `fleetops-bifrost-demo/docs/TROUBLESHOOTING.md` | symptom-first diagnosis once something is already broken |
| `fleetops-bifrost-demo/docs/PROVING-IT.md` | how to show the enforcement is real rather than asserted |

The Okta side in particular is **not** duplicated here. [Stage 3](#stage-3-create-the-okta-objects)
gives you the shape and the traps so you can map it onto your own conventions; `RUNBOOK.md`
gives you the fields to fill in. Work through it there and come back.

What none of them answer is the question you are actually asking: **what changes in our
deployment, what do we have to own afterwards, and how do we get there without a single
cutover.** That is what follows, in the order a real team hits it.

**This is unsupported sample code.** It is not an Okta product, it carries no SLA, and
nothing about it is covered by an Okta support contract. Adopting it means adopting the
maintenance of it. Read [the prerequisites](#five-things-that-must-be-true-before-any-of-this-works)
and then [Stage 0](#stage-0-decide-whether-you-are-taking-on-a-bifrost-build) before you spend
engineering time anywhere else.

---

## Five things that must be true before any of this works

Items 1 to 3 are hard constraints on your tenant and your environment, and **two of the three
do not announce themselves.** A deployment that fails 2 or 3 can be configured completely and
correctly and still not work. Items 4 and 5 are costs to accept rather than facts to check. Go
through all five before reading on.

### 1. Your Okta org is entitled to Okta for AI Agents

Check before anything else, because it cannot be worked around by configuring anything and it
is an account question rather than an engineering one. Two places tell you: **Directory > AI
Agents** appears in the admin console navigation, and **Settings > Features** contains a toggle
called **Secure AI A2A Servers**. If either is missing, the org is not entitled and nothing here
will work. Take it to your Okta contact first. `RUNBOOK.md` opens with the same check and a
little more detail.

### 2. Every MCP server you want governed must be reachable over streamable HTTP

The MCP client must be `"connection_type": "http"`. **`stdio` and `sse` cannot work with this
plugin, and configuring them produces no error.**

The reason is not the plugin's. In Bifrost, `needs_session_stickiness` is only consulted for
`connection_type: http`. For any other connection type the client is treated as **sticky
regardless of what the field says**, because SSE binds its session to an open stream and STDIO
needs a persistent subprocess. A sticky client holds one long-lived shared connection.

Follow that through, because the failure is silent and total:

- The connect hook fires **once**, at startup, where there is no inbound request and therefore
  no caller token.
- With `allow_connect_without_caller: true` that connect is permitted and **no `Authorization`
  header is attached**, which is correct and deliberate.
- The per-call hook then works fine and permits legitimate calls, because it reads the caller's
  token off the inbound request regardless of stickiness.
- Every call is nonetheless rejected by your upstream, forever, because the shared connection it
  travels over never carried a credential. Or worse, if your upstream does **not** validate,
  every call succeeds with nothing having been enforced.

Either way you get a gateway whose authorization decisions have no effect, and no denial in the
Bifrost log to explain it, because the plugin did its job. **If your MCP servers are stdio, put
them behind an HTTP MCP server, or do not use this plugin.**

### 3. Your callers must present their own Okta access token to the gateway

The plugin delegates *from* the caller. It reads the caller's `Authorization: Bearer` header
straight off the inbound request to the gateway and submits it to Okta as the exchange subject.
That needs no `auth_type` configuration and no credential brokering, but it does need the header
to be there. **There is no fallback:** a tool call with no caller token is denied, and the
plugin never mints on the agent's own authority alone, because that would be a broader grant
than the one being requested.

That token has to be an **access token from a custom authorization server, addressed to the
acting agent**. An ID token, or a token from the org authorization server, is refused by Okta
with `'subject_token' is invalid`. Whatever calls your gateway has to be able to obtain one.
See [Stage 3](#stage-3-create-the-okta-objects) for what mints it.

### 4. You must be able to build and ship your own Bifrost image

Standing obligation, not a one-off. This is the biggest reason to decline, and it is
[Stage 0](#stage-0-decide-whether-you-are-taking-on-a-bifrost-build).

### 5. Okta must be treated as a hard dependency of your tool-call path

The call path is **unconditionally fail-closed**, and `fail_open` does not change that. See
[`fail_open` does less than its name suggests](#fail_open-does-less-than-its-name-suggests).
If your tool calls cannot be allowed to depend on an external identity provider's
availability, this design is not for you.

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
it prints is what the binary was actually built with rather than what any file claims. If your
image puts the binary somewhere other than `/app/main`, the target says so and exits; edit the
path in the `compat` recipe.

**Both printed values are inputs, and it is easy to use only the second one.** The `core:`
line sets `BIFROST_CORE`. The `go:` line sets `GO_IMAGE`, which is the container the plugin is
compiled in, and a mismatch there fails to load exactly as loudly as a `core` mismatch does,
which is to say silently.

```bash
make pin BIFROST_CORE=v1.8.3                  # the core: value it printed
make plugin GO_IMAGE=golang:1.27 PLATFORM=linux/amd64   # the go: value it printed
```

Set `GO_IMAGE` to the tag matching the printed Go version. If `make compat` prints a Go
version this repo's `GO_IMAGE` default does not match, **change `GO_IMAGE`, not the image**:
the Bifrost binary is the fixed point and the plugin is the thing that has to agree with it.

`make pin` also runs `go mod tidy`, so the indirect dependency set is re-resolved against
that core version. That is the point: the constraint is not only `bifrost/core`, it is the
whole graph underneath it.

### Run `compat` against the image you built, not the published one

`BIFROST_IMAGE` defaults to `maximhq/bifrost:latest`, which is the **statically linked
published** image. Inspecting that tells you about a binary you are not going to run, and its
core version can differ from the ref you cloned. Always pass your own tag.

That creates an ordering dependency worth planning for: you need your image before you can pin
the plugin against it. Two ways round it, and the first is better.

1. Build your Bifrost image first, which is
   [Phase 1](#phase-1-the-dynamic-binary-with-no-plugin) of the rollout anyway, then run
   `make compat` against it.
2. Or read the core version straight out of the Bifrost source you are about to build, from
   `transports/go.mod` at the ref you pinned, before building anything.

Pin the Bifrost ref explicitly either way. `Dockerfile.dynamic` uses
`BIFROST_REF=transports/v2.0.0`, and the `bifrost/core` version a transports tag depends on is
the number the plugin has to match. Building from a moving branch means the number can change
underneath a plugin build that still looks fine.

**The failure mode here is silence.** A mismatched plugin does not crash Bifrost and does
not produce an obvious error. It fails to load, Bifrost carries on, and the first thing you
notice is that nothing is being authorized. Make [Tier 1 of the verification](#tier-1-the-plugin-loaded-and-initialised)
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

### A rebuilt `.so` does nothing until the process restarts

Go's `plugin.Open` is called once per path, and **a second open of the same path returns the
already-loaded handle rather than reading the file again.** Bifrost calls it during plugin load
at startup.

Two consequences, and both have burned time:

- **Overwriting the `.so` in place changes nothing** in the running gateway. Not on the next
  call, not on a config reload through the admin API. The old code stays mapped for the life of
  the process. To pick up a rebuild you have to replace the process, and per
  [Never restart, always recreate](#never-restart-always-recreate) you want to replace it
  rather than restart it.
- **Inspecting the file on disk tells you nothing about what is running.** A checksum, a
  timestamp, `file`, `go version -m`: all of them describe the bytes on disk, which after any
  rebuild are not the bytes the process loaded. The only trustworthy statement about the
  running plugin comes from the gateway's own startup log, which is
  [Tier 1](#tier-1-the-plugin-loaded-and-initialised).

This is the mechanism behind the stale-artifact trap in the box above. It is also why a
deployment that mounts the `.so` from a shared volume and rebuilds into it does not behave like
a code deploy, and should not be treated as one.

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

### There is nowhere to register Bifrost, and that is the design

You will go looking for this, so it is worth answering before the object list rather than
after. **Okta has no object representing the gateway.** No app, no client, no service
principal. Nothing in your tenant knows Bifrost exists.

Bifrost authenticates to Okta **as the agent**, using the agent's private key via
`private_key_jwt`. The client assertion the plugin builds sets both `iss` and `sub` to the
agent's workload principal id, and neither token request sends a `client_id` of its own. From
Okta's side there is one client on the wire and it is the agent.

Four consequences, and the first two are the reason to like it:

- **Swapping the gateway needs no Okta change.** Move the plugin and the key to a different
  Bifrost, or replace Bifrost with something else that performs the same exchange, and the
  tenant is untouched. The audit trail is continuous across the swap because it was never about
  the gateway.
- **The audit trail names the agent and the caller, not the gateway.** That is usually what you
  want, and it is worth saying out loud to whoever asks for gateway-level attribution: they
  will not get it from Okta, and the place to get it is your own gateway logs.
- **There is nothing gateway-shaped to revoke.** Turning off access means deactivating the
  agent or its connection. You cannot revoke "this Bifrost" while leaving the agent live.
- **Whatever holds the agent's private key is the agent.** The key is the whole of the
  gateway's authority, so protecting it is protecting the agent's identity, not protecting a
  service credential. Treat it accordingly, and see [Key material](#key-material).

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

### Where the boundary falls, and which value goes where

Okta holds the decisions. The plugin config holds only **pointers at them**, plus the key that
proves who is asking. Nothing in the plugin config grants anything, which is why a reviewer can
read it without needing to trust it: change a scope there and Okta refuses, it does not comply.

Carry this table across when you fill in your own values. Every left-hand item is created in
Stage 3, and the right-hand column is the only place its identifier appears again.

| In Okta | What it decides | Plugin config key it lands in |
|---|---|---|
| Tenant hostname | Which org is asked | `okta_domain` |
| The agent registration (`wlp...`) | Who the gateway acts as, and whose key signs | `agent_id` |
| The agent's registered JWK | Whether the assertion verifies at all | `private_key_jwk_file` (the **private** half) |
| The agent registered as a **resource**, its resource URL | What the caller's inbound token must be addressed to | `agent_resource_url` |
| Target's custom authorization server (`aus...`) | Which server honours the assertion, and holds the scopes and policy | `bindings.<client>.authorization_server_id` |
| Target's resource URL | What within that server is addressed, and the `aud` your resource server should check | `bindings.<client>.target_resource_url` |
| The agent's **connection** to the target, and its scope list | Whether these scopes are grantable at all | `bindings.<client>.scopes` names them; Okta decides |
| Nothing in Okta | Which tools this lane may serve | `bindings.<client>.tools` (gateway-side only) |
| Agent or connection **status** | Whether anything is permitted right now | Not configured. Re-asked per call |

Two rows are worth dwelling on because they are where people put effort in the wrong place.

**`scopes` is a request, not a grant.** The values you list are what the plugin asks for. What
makes them grantable is the agent's **connection** to the target in Okta, and the authorization
server's policy rule. Widening the list in plugin config without widening the connection
produces `invalid_scope` and nothing else. That asymmetry is the property worth having: the
config is not a place privilege can be added.

**`tools` has no counterpart in Okta.** It is gateway-side only, so it is defence in depth
rather than authorization, and it is the one column an attacker who reaches your config could
widen. Do not let it be the only thing separating a read lane from a command lane: separate
those by **scope**, on **different authorization servers**, so Okta refuses too. See
[Where a command-shaped tool belongs](#where-a-command-shaped-tool-belongs).

---

## Stage 4. Bifrost configuration

Everything in this section is **Bifrost's** behaviour rather than the plugin's, which is why
none of it is configurable from the plugin side and why it has to be got right first. Each item
was either hit for real during the reference build or read out of Bifrost's own source.

### The two settings that look wrong and are not

```json
"auth_type": "none",
"needs_session_stickiness": false
```

Set on **every** MCP client the plugin governs.

**`auth_type: "none"` is not a placeholder and not the absence of a choice. It is the only
value that neither overwrites the plugin nor fails the connect.**

The mechanism is header composition order, and it is worth knowing rather than taking on
trust, because it is what makes the rule non-negotiable. On the connect path Bifrost:

1. builds the connect request from the client's static config headers,
2. runs the plugin's `PreMCPConnectionHook`, which is where this plugin sets `Authorization`,
3. **then** resolves the `auth_type`'s own headers and copies them **on top**.

Step 3 wins. Whatever the resolver returns replaces the same key from step 2. So:

| `auth_type` | What its resolver returns | Effect on the plugin |
|---|---|---|
| `none` | always empty | **nothing overwritten. The only safe value** |
| `headers` | the `Authorization` from the client's `headers` block, if there is one | overwrites when one is present. Silently fine when not, which is worse |
| `oauth`, `per_user_oauth`, `token_exchange` | a bearer token it obtains itself | overwrites, or errors the connect when no OAuth provider is configured |
| `per_user_headers` | pre-stored per-caller header values | errors the connect when there are none, and there are none to store |

When an overwrite happens, the plugin mints correctly, the header is replaced, and the upstream
rejects a credential the plugin never sent. It presents as a minting bug and is not one.

> **Omitting `auth_type` does not give you `none`.** An empty or absent value normalises to
> `headers`, matching Bifrost's own database default. That happens to work for as long as the
> client's `headers` block contains no `Authorization` key, and breaks the moment anyone adds
> one, for a reason that will look nothing like the edit that caused it. Set `none`
> explicitly on every governed client. An omitted field here is a latent trap, not a default.

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

**It is only honoured for `connection_type: "http"`.** Set it to `false` on an `sse` or
`stdio` client and Bifrost treats that client as sticky anyway, without complaint. That is not
a configuration problem you can fix from here, it is a
[prerequisite](#2-every-mcp-server-you-want-governed-must-be-reachable-over-streamable-http),
and it is the one that silently produces a gateway that authorizes correctly and delivers
nothing.

The direct consequence, stated here so it is not a surprise in
[capacity planning](#what-to-watch): because connections are per-call, the connect-time mint
runs **per call**. That is two Okta token requests per tool call, and it is unrelated to the
verdict cache TTL.

A second consequence is easy to mistake for an intrusion. Per-call clients hold no persistent
connection for Bifrost to health-check, so Bifrost keeps their tool list fresh with a
**periodic ephemeral connect, `tools/list`, disconnect**. The cadence adapts: `tool_sync_interval`
while the client is healthy, which defaults to 10 minutes, and a fixed 10 seconds while it is
not. That cycle runs the plugin's connect hook with **no inbound request and therefore no caller
token**, exactly like startup does. Two things follow:

- Your MCP server sees an unauthenticated connect and a `tools/list` from the gateway on a
  timer, forever. That is Bifrost, not a caller, and not a leak.
- `allow_connect_without_caller` has to stay `true` for the **life of the process**, not just
  long enough to boot. See [Stage 5](#allow_connect_without_caller-must-be-true-and-it-is-not-a-bypass).

It costs no Okta requests: with no caller token there is nothing to exchange, so the plugin
attempts no mint. Do not count these toward your token endpoint budget.

### Name rules, which Bifrost enforces silently

**Hyphens in MCP client or tool names make Bifrost skip the client.** No error, no warning,
the tool is simply not there. Use underscores: `fleetops_read`, not `fleetops-read`. No
spaces, no leading digit.

### `tools_to_execute` and `bindings[].tools` take different forms

In the same file:

| Field | Form | Example |
|---|---|---|
| Bifrost's `tools_to_execute` | **bare** tool name | `get_telemetry` |
| The plugin's `bindings[].tools` | **namespaced**, `<client>-<tool>` | `fleetops_read-get_telemetry` |

This is the nastiest inconsistency in the setup. The hyphen in the namespaced form is
Bifrost's own separator and is fine there; the ban on hyphens applies to the names **you**
declare.

Get it wrong in the plugin's direction, by using bare names in `bindings[].tools`, and **every
call to that client is denied** with:

```
tool "fleetops_read-get_telemetry" is not served by the binding for client "fleetops_read"
```

The denial names the namespaced form it was given and your config names the bare one, so the
two strings in front of you do not match and the reason is legible once you know to compare
them. Nothing about it says "wrong form".

**Do not derive these names by hand.** Ask the gateway what it actually registered, after the
client is up and before you write the binding:

```bash
curl -s -X POST http://your-gateway:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | grep -o '"name":"[^"]*"'
```

Those are the exact strings `bindings[].tools` matches on, and copying them verbatim removes
the whole class of mistake. Note the `Accept` header covers both content types: Bifrost's `/mcp`
endpoint needs it, and omitting it is its own confusing failure.

Do **not** read the names from `GET /api/mcp/clients` instead. That endpoint reports the
**bare** names, which is the wrong form here, and it reads from Bifrost's sqlite store rather
than the live registry, so it can also be reporting tools that no longer exist. See
[Never restart, always recreate](#never-restart-always-recreate).

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

[`README.md`](../README.md#config-reference) describes what each key means. This section is the
same surface described by **what breaks when it is wrong**, which is the version you need while
fitting it to a deployment nothing in this repo has ever seen.

### The whole thing, with nothing environment-specific in it

Every value below is a placeholder. There is no hidden key: this is the complete schema, and
**an unrecognised key is rejected** rather than ignored, so anything you add that is not here
fails startup.

```json
{
  "enabled": true,
  "name": "okta-agent-identity",
  "path": "/etc/bifrost/plugins/okta-agent-identity-amd64.so",
  "placement": "pre_builtin",
  "config": {
    "okta_domain": "TENANT.okta.com",
    "agent_id": "wlpXXXXXXXXXXXX",
    "agent_resource_url": "https://YOUR-AGENT.example",
    "private_key_jwk_file": "/secrets/agent-key.jwk",
    "agent_status_ttl": "10s",
    "fail_open": false,
    "allow_connect_without_caller": true,
    "bindings": {
      "YOUR_MCP_CLIENT": {
        "authorization_server_id": "ausXXXXXXXXXXXX",
        "target_resource_url": "https://YOUR-TARGET.example",
        "scopes": ["your.scope"],
        "tools": ["YOUR_MCP_CLIENT-your_tool"]
      }
    }
  }
}
```

The three outer keys that are not `config` are Bifrost's, not the plugin's:

| Key | Notes |
|---|---|
| `name` | Must be exactly `okta-agent-identity`. It is how the plugin is addressed, and it is the string that appears in the startup status line |
| `path` | Absolute path to the `.so`, **architecture-correct**. Reopening the same path never re-reads the file, see [above](#a-rebuilt-so-does-nothing-until-the-process-restarts) |
| `placement` | Use `pre_builtin` so the check runs before Bifrost's own plugins. The default is `post_builtin` |

### What breaks if each key is wrong

| Key | Required | If wrong |
|---|---|---|
| `okta_domain` | yes | Hostname only. Including a scheme is **rejected at startup** with `okta_domain must be a hostname without a scheme`. A wrong-but-valid hostname is a DNS or TLS error on the first mint, not a config error |
| `agent_id` | yes | The `wlp...` id. Wrong value means the assertion is signed for a principal that is not the key's owner, and Okta answers `invalid_client`, which reads like a key problem |
| `agent_resource_url` | yes | Validated as present and **read nowhere else**. See [below](#agent_resource_url-is-required-but-currently-unused) before you spend time on it |
| `private_key_jwk_file` | one of | Unreadable path or malformed JWK fails `Init`, so the plugin loads but never initialises, and in that state **it denies everything**. A public JWK gives the specific error `this looks like a public key` |
| `private_key_jwk` | one of | Same, plus the key is now in your gateway config. Setting **both** is rejected at startup. Prefer the file, see [Key material](#key-material) |
| `bindings` | yes | Empty is rejected. A client present in Bifrost but **absent here is refused**, never passed through, which is what makes adoption per instance rather than per server |
| `agent_status_ttl` | no | Default `10s`. An unparseable duration is rejected at startup. Raising it widens the revocation window, see [below](#agent_status_ttl-is-your-revocation-staleness-bound) |
| `fail_open` | no | Default `false`. Leave it. It does much less than the name suggests, see [below](#fail_open-does-less-than-its-name-suggests) |
| `allow_connect_without_caller` | no | Default `false`, and **`false` breaks the gateway completely**: zero tools discovered, everything `tool not found`. You need `true`, see [below](#allow_connect_without_caller-must-be-true-and-it-is-not-a-bypass) |

Per binding, keyed by the **Bifrost MCP client name** exactly as it appears in the `mcp` block:

| Key | Required | If wrong |
|---|---|---|
| the key itself | yes | A name that matches no MCP client is dead config that fails nothing and protects nothing. A client whose name is missing here is refused entirely |
| `authorization_server_id` | yes | The `aus...` protecting the target. Empty is rejected at startup. Pointing at the wrong server gives `access_denied, policy evaluation failed`, because the agent is not a listed client there |
| `target_resource_url` | yes | Empty is rejected at startup. A value with no **ACTIVE** connection matching it gives `invalid_target`, which reads like a typo and often is one. Byte-compare it against Okta |
| `scopes` | yes | Empty is rejected at startup. A scope the connection does not grant fails the **whole** request with `invalid_scope`. Okta does not narrow, so an over-broad list breaks the binding rather than degrading it |
| `tools` | no | Omitted means **every** tool on that client. Present means **namespaced** names, and a bare name denies every call. Gateway-side only, so it is not authorization, see [the boundary table](#where-the-boundary-falls-and-which-value-goes-where) |

### Two startup behaviours that shape how you debug this

**A typo in a key name fails startup rather than being ignored.** Config is decoded with
unknown fields disallowed, so `fail_close: true` or `agent_status_tll` is a hard `Init` error,
not a setting that silently did not apply. This is the behaviour you want, and it means you
never have to wonder whether a key took effect: if the plugin came up, every key you wrote was
a real one.

**A failed `Init` denies everything rather than passing through.** The `.so` is loaded but has
no initialised instance behind it, and every hook refuses:

```
okta-agent-identity is not initialised, so no call can be authorized.
Check Bifrost's logs for a plugin Init failure.
```

If you see that string, the problem is in this config or in the key file, not in Okta and not
in your bindings. Nothing has reached Okta yet.

### `allow_connect_without_caller` must be `true`, and it is not a bypass

**Bifrost registers MCP clients, and discovers their tools, at startup.** There is no
inbound HTTP request at that moment, so there is no caller token to delegate from.

Leave this `false` and the connect is refused, registration fails, **zero tools are
discovered**, and every later call fails with `tool not found` rather than with anything
resembling an authorization error. The gateway is unusable for a reason that looks nothing
like its cause, and the only hint is an empty tools array.

**It is not only startup.** Bifrost re-runs the same tokenless discovery on a timer for the
life of the process, because a per-call client has no persistent connection to health-check.
Setting this `false` therefore does not merely break boot: it makes the client fail its
periodic check, drop to the unstable state, and retry the refused connect every 10 seconds
indefinitely. Treat `true` as a permanent requirement of this design rather than a startup
concession you might later withdraw. Details in
[Stage 4](#the-two-settings-that-look-wrong-and-are-not).

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

Take one thing out of this phase for the next one: run `make compat` against the image you just
built and **record the Go and core versions with the image tag.** That pair is what the plugin
has to match, it is only knowable once the image exists, and it changes every time you rebuild.
See [Stage 1](#run-compat-against-the-image-you-built-not-the-published-one).

### Phase 2. A shadow instance, synthetic traffic

Stand up a **second** Bifrost instance from the same image, with the plugin loaded, one MCP
client bound, and no production traffic. Drive it with synthetic calls.

What you are proving, in this order, because each one is unreadable while the one above it is
broken:

- **The live tool registry is populated.** [Tier 0](#tier-0-the-live-tool-registry-is-populated).
  Do this before anything else, and take your real namespaced tool names from its output.
- **The `.so` loaded and initialised.** [Tier 1](#tier-1-the-plugin-loaded-and-initialised).
  The version-and-architecture check, and the one most likely to fail first.
- **A call actually reaches the upstream with a delegated token.**
  [Tier 2](#tier-2-the-upstream-received-a-token-the-caller-never-held).
- **Okta's objects are wired correctly end to end,** including the parts of `RUNBOOK.md` that
  are console-only and therefore not in your infrastructure-as-code.
- **The refusal path works,** and its wording is legible to your operators.

Deliberately break things here, while it is free:

- Point a binding at a scope the connection does not grant, and confirm you get `invalid_scope`
  naming that scope.
- Deactivate the agent, and confirm the call stops. Note it comes back as `invalid_client`,
  which reads like a key problem.
- Put a **bare** tool name in `bindings[].tools`, so your operators have seen
  `is not served by the binding` once before it happens for real.
- Restart the gateway rather than recreating it, and watch `/api/mcp/clients` keep reporting
  tools that `tools/list` says are gone. Fifteen seconds now, against hours later.

All four are cheap now and expensive later.

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
| `plugin status: okta-agent-identity - active` | Bifrost startup log | Proves the `.so` loaded **and** `Init` succeeded. Assert on it in your deploy, do not eyeball it |
| `plugin status: okta-agent-identity - error` | Bifrost startup log | Page on this. Bifrost starts anyway and exits zero, so nothing else will tell you |
| `okta denied "<tool>" on "<client>"` | Bifrost log | The **per-call** hook fired. This is the strong claim |
| `okta refused to issue a token for` | Bifrost log | The **connect-time** path. Also correct, weaker: it proves the session could not start, not that a call was gated |
| `is not served by the binding for client` | Bifrost log | Not an Okta decision at all. Almost always bare tool names in `bindings[].tools` |
| `is not initialised, so no call can be authorized` | Bifrost log | `Init` failed. Nothing has reached Okta. Config or key file |
| `tool not found` on everything | Bifrost log | Either `allow_connect_without_caller` is false, or something restarted instead of being recreated |
| `app.oauth2.token.grant.id_jag` | Okta System Log | Step 2 of the exchange, at the source |
| `app.oauth2.as.token.grant.access_token` | Okta System Log | Step 3, the token that went upstream |
| Token endpoint request rate | Okta | **Two token requests per tool call at steady state,** plus two more whenever the per-call check misses the verdict cache. Bifrost's periodic tokenless discovery adds none. Check your tenant's token endpoint rate limits against your peak tool-call rate before you assume headroom |
| Denial rate by binding | Bifrost log | A binding denying steadily usually means a connection scope list, not an agent problem |

> **Denials are logged at `info`, not `warn` or `error`.** They arrive as a normal MCP tool
> handler message, so a collector filtering at warn and above ships none of them, and the shape
> is `[mcp-server] tool handler error tool="..." error=okta denied ...`. If your alerting is
> severity-based you will see every operational failure of this plugin and none of its security
> decisions. Match on the strings above, not on level.

Do not build alerting on `act` or `sub_profile` claim shapes. See
[the accuracy note below](#what-not-to-say-about-this-internally-or-to-your-auditors).

---

## Stage 7. Verify it in your own environment

Adapted from `PROVING-IT.md`, which is written for demonstrating to a sceptic. This version
is written for convincing yourself.

Five checks. Each rules out a different way of fooling yourself, and they get progressively
harder to fake. Tier 0 is not about the plugin at all, and it comes first because everything
above it is unreadable while it is failing.

### Tier 0. The live tool registry is populated

```bash
curl -s -X POST http://your-gateway:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | grep -o '"name":"[^"]*"' | wc -l
```

Expect your tool count. **`"tools":[]` means nothing below this line will work,** and no amount
of reading the plugin, Okta or your bindings will explain it, because none of them is at fault.
Fix it by recreating the gateway, see
[Never restart, always recreate](#never-restart-always-recreate).

**This is the only trustworthy MCP readiness check, and substituting a convenient one is the
mistake.** Specifically:

- **Not `GET /api/mcp/clients`.** It reads from Bifrost's sqlite store, so it happily reports a
  full tool list and a healthy client while the live in-memory registry is empty. It is the
  most convincing wrong answer available.
- **Not an HTTP status code.** The endpoint answers regardless.
- **Not the admin console,** which is reading the same store.

Put this in your deploy gate. It is one request, it needs no credential, and it is the
difference between a broken gateway you find in seconds and one you find after two hours in the
wrong component.

### Tier 1. The plugin loaded and initialised

```bash
<your log query> | grep "plugin status: okta-agent-identity"
```

```
plugin status: okta-agent-identity - active
```

**`- active` is a stronger claim than it looks.** Bifrost sets that status only after the
plugin has been opened, its symbols resolved, **and its `Init` returned without error**. So one
line covers the whole of what could have gone wrong on your side: the `.so` matched on Go
version, dependency versions and architecture; every config key was recognised; and the private
key parsed. Seeing it means you can stop looking at [Stage 1](#stage-1-pin-the-three-axes) and
[Stage 5](#stage-5-plugin-configuration) entirely.

The failure shape is a pair of lines, and it names its own cause:

```
failed to load plugin okta-agent-identity: <reason>
plugin status: okta-agent-identity - error
```

Read the `<reason>`. `plugin.Open: Dynamic loading not supported` is
[Stage 0](#stage-0-decide-whether-you-are-taking-on-a-bifrost-build), a statically linked host.
`plugin was built with a different version of package ...` is
[Stage 1](#stage-1-pin-the-three-axes). `failed to cast <symbol> to expected signature` means
the plugin was built against a Bifrost whose hook signatures differ from the host's, which is
also Stage 1. Anything mentioning config or a key is [Stage 5](#stage-5-plugin-configuration).

**Bifrost starts anyway, and exits zero.** A plugin that fails to load is logged and skipped,
not fatal. The gateway comes up, registers its MCP clients, discovers tools, and serves. So the
absence of a crash is not evidence of anything, and this check has to be an assertion in your
deploy rather than something a human notices.

One useful line precedes the status, and it settles the stale-artifact question directly:

```
loading custom plugin from path /etc/bifrost/plugins/okta-agent-identity-arm64.so
```

That is the path and therefore the **architecture actually loaded**, which is the one place the
truth is visible. Compare it against what you meant to ship.

> **If the plugin is in `error` state and your tool calls still succeed, stop and fix that
> first.** It means your upstream MCP server is not validating the token it receives, so it
> would have accepted an unauthenticated call all along. None of the tiers below can measure
> anything until that is true. See
> [What your resource server must still do](#what-your-resource-server-must-still-do).

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

**First, work out whether Okta was asked at all.** Three denials never leave the gateway, and
looking for them in the Okta System Log wastes the trip:

| The gateway says | Means | Look at |
|---|---|---|
| `no okta binding configured for mcp client "x"` | That client is in Bifrost's `mcp` block and not in `bindings`. Refused, never passed through | Add the binding, or take the client off this instance |
| `tool "x" is not served by the binding for client "y"` | The tool is not in that binding's `tools` list | Almost always **bare** names where namespaced ones belong. Compare against `tools/list` |
| `is not initialised, so no call can be authorized` | `Init` failed at startup | The plugin config and the key file. Nothing has been asked of Okta |

Everything below is Okta's own wording, relayed verbatim:

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

**Okta does not audit the gateway, because Okta has no idea the gateway exists.** The System
Log records token requests attributed to the **agent** and naming the **caller**. It cannot tell
you which Bifrost asked, or that a Bifrost asked at all, and it does not see a tool call that
was answered from the verdict cache. Gateway-level attribution comes from your gateway's logs
and nowhere else. This is a consequence of the design being a feature, see
[Stage 3](#there-is-nowhere-to-register-bifrost-and-that-is-the-design), but it is easy to
promise an auditor something Okta cannot produce.

**Do not claim `resource` determines `aud`.** The observation is that they match. The mechanism
is unresolved and the reference setup cannot distinguish the two candidate explanations. The
safe form is "we validate `aud` against the resource URL we requested, which is correct under
either explanation." See
[Validate `aud` against the resource URL](#validate-aud-against-the-resource-url).

**`bindings[].tools` is not an authorization control.** It exists only in gateway config, has no
counterpart in Okta, and Okta will happily mint for a tool that list excludes. It is a useful
second fence and it is the wrong thing to point at when asked what enforces least privilege.
Point at the scope on the connection.

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
| What each config key means, rather than what breaks | [`README.md`](../README.md#config-reference) |
| **Okta setup, click by click. Do this part there, not here** | `fleetops-bifrost-demo/docs/RUNBOOK.md` |
| Diagnosis once something is already broken, organised by symptom | `fleetops-bifrost-demo/docs/TROUBLESHOOTING.md` |
| Demonstrating it to a sceptic | `fleetops-bifrost-demo/docs/PROVING-IT.md` |
| Threat model, and what the gateway is deliberately not trusted with | [`SECURITY.md`](../SECURITY.md) |
