# From demo to production

> **Status: unsupported sample code, not an Okta product.** No SLA, no support commitment, no
> patch channel that reaches your deployment. See
> [SECURITY.md](../SECURITY.md#support-status-and-reporting-a-vulnerability).

This document is the honest distance between the reference demo and something you would run.
It is written on the assumption that you will run it anyway, so it is a work list rather than a
warning.

The demo proves the integration path works. It is not hardened, not monitored, and not
supported. Everything below is what "not hardened" actually means in specifics.

**Contents**

1. [Demo-only settings, and what they should be](#1-demo-only-settings-and-what-they-should-be)
2. [What is genuinely missing](#2-what-is-genuinely-missing)
3. [Okta rate limits](#3-okta-rate-limits)
4. [Operational runbook](#4-operational-runbook)
5. [The build pipeline burden](#5-the-build-pipeline-burden)
6. [Minimum bar before production](#6-minimum-bar-before-production)

---

## 1. Demo-only settings, and what they should be

### Plugin configuration

| Setting | Demo value | Production | Why |
|---|---|---|---|
| `agent_status_ttl` | `10s` (also the code default) | **A number you chose deliberately.** See the tradeoff below | It is the revocation staleness bound *and* the cache lifetime. One number, two jobs |
| `fail_open` | `false` | **`false`.** Keep it | See [SECURITY.md](../SECURITY.md#fail_open). At connect time it permits an uncredentialed connection, which is an authorization bypass against any upstream that does not validate independently. At the per-call hook it currently does nothing at all, which is a discrepancy you should read before relying on either behaviour |
| `allow_connect_without_caller` | `true` | **`true`.** Same value, and it is not a bypass | Bifrost discovers tools at startup, where there is no caller. Left false, no tools are discovered and every call fails with `tool not found`. The compensating control is that your upstream must validate the token itself |
| `private_key_jwk_file` | a mounted file | **A file, from your secret manager**, with `0400` or `0600` permissions and correct ownership | The plugin performs no permission check. Never use the inline `private_key_jwk` form, and never an environment variable |
| `bindings[].scopes` | `["agent.invoke", "task.read"]` and `["agent.invoke", "task.dispatch"]` | One lane per risk class, as narrow as the lane needs | Okta does not down-scope. An over-broad ask fails the whole request, which is a clean failure and a design constraint |
| `bindings[].tools` | explicit namespaced lists | **Keep them explicit.** Empty means every tool on the client | An empty list is an implicit allow for any tool a server later adds. Naming them makes a new upstream tool fail closed |
| `bindings[].authorization_server_id` | **one authorization server shared by both bindings** | **Separate authorization servers per lane** | This is the biggest structural shortcut in the demo. Sharing one server means the read and command lanes are separated by scope alone, so a policy mistake on that server affects both lanes at once. Separate servers make an over-broad request fail at the lane boundary |
| `bindings[].target_resource_url` | **the same URL for both bindings** | **One resource URL per lane** | Sharing one resource indicator across lanes makes Okta's resource lookup ambiguous, and it is the reason the `aud` question in [SECURITY.md](../SECURITY.md#open-question-what-determines-aud) cannot be settled from this demo |

#### Choosing `agent_status_ttl`

There is no correct value, only a tradeoff you have to make explicitly.

- **Lower** means a deactivation bites faster and more traffic reaches Okta. At high call
  volumes this is the hazard described in [Okta rate limits](#3-okta-rate-limits), and it is not
  theoretical.
- **Higher** means less traffic and a proportionally wider window in which a deactivated agent
  still passes the gate. Raising it from `10s` to `60s` buys you load and costs you fifty
  seconds of revocation latency.
- **The per-call minting cost does not change either way.** Bifrost's connections are per call,
  so the connect-time mint runs per call regardless of the TTL. Lowering the TTL does not add
  the minting cost, and raising it does not remove it. What the TTL controls is only the
  *authorization check*, at most once per TTL per distinct binding.

| | Frequency | Driven by |
|---|---|---|
| The authorization check | at most once per TTL per distinct binding | `agent_status_ttl` |
| The mint | two token requests per call | Bifrost's per-call connection model. Nothing to do with the TTL |

So the honest statement to an operator is: the TTL is a revocation-latency setting whose side
effect is check traffic, and the bulk of your Okta traffic is the mint, which you cannot tune
here at all.

### Bifrost configuration

These are the host's settings, not the plugin's, and the demo's values are demo values.

| Setting | Demo value | Production |
|---|---|---|
| `client.allowed_origins` | `["*"]` | The origins you actually serve. `*` is a demo convenience |
| `client.enable_logging` | `true` | Keep request logging on, and then **decide where it goes and who can read it**. Bifrost's logs are the only record of a plugin denial, so they are now security-relevant records with a retention requirement |
| `auth_type` on every MCP client | `none` | **`none`.** This is not a placeholder and not the absence of a choice. Any other value makes Bifrost resolve upstream headers of its own, which overwrite the `Authorization` header the plugin set, and the upstream then rejects a credential the plugin never sent |
| `needs_session_stickiness` | `false` | **`false`** on every MCP client. Anything else gives one shared connection with no caller context, and the plugin has nothing to delegate from |
| `config_store` | sqlite at `/app/data/bifrost.db` in a Docker volume | Per-instance state you must account for in your deployment. See [High availability](#high-availability-with-more-than-one-gateway-instance) |
| The admin console | stubbed out of the reference `Dockerfile.dynamic` with a placeholder file | If you build the real console in, work out who can reach it and whether it renders plugin configuration. That is a question about your build, and you should answer it rather than take an answer from this document |

### Log verbosity

The plugin itself emits **nothing**: no logs, no metrics, no traces. Verified by inspection of
`plugin/`. Every observable event comes from Bifrost, from the resource server, or from Okta's
System Log.

That has two production consequences:

- **You cannot turn the plugin's logging down, because there is none.** There is also nothing to
  turn up, which is the problem in [What is genuinely missing](#2-what-is-genuinely-missing).
- **Bifrost's own logs now carry authorization decisions**, including denial reasons that quote
  Okta's error text and name scopes and resource URLs. Treat them as sensitive operational
  records: scope who can read them, and set a retention period on purpose rather than by
  default. They do not contain tokens; the plugin never logs credentials and never puts them in
  error messages.

### Okta tenant configuration

| Setting | Demo value | Production |
|---|---|---|
| Policy rule `people.groups` | `EVERYONE` | **Tighten this.** An agent is a workload principal, not a user, so it will never match a specific user group, which is why the demo uses `EVERYONE`. That is permissive and it is the tenant-side shortcut most worth revisiting |
| Managed connection scopes | granted for read, deliberately not granted for dispatch | Per lane, minimum necessary. Scopes are enforced on the managed **connection**, not only on the authorization server's policy. Publishing a scope on the server is not enough |
| Agent owners | Console-only to assign; the API returns 405 | Okta recommends at least two owners. Assign them |
| Token lifetimes | tenant defaults | Set them deliberately. Access token lifetime is the outer bound on how long a stolen or post-revocation credential is usable, and the per-call check only narrows that to the TTL for calls that go *through the gateway* |

### The demo's own rough edges

Not settings, but things you would meet immediately and should not carry forward:

- **The reference demo expects the agent key under two different filenames**, because the
  gateway path and the driver targets disagree. That is a pending cleanup in the demo repo, not
  a pattern to copy.
- **The demo resource server holds fleet state in memory** and resets with the container.
- **The demo's own credentials are scoped `agent.invoke` only**, so `GET /api/v1/logs` returns
  401 for them. That is correct behaviour for a demo client, and it means System Log evidence
  needs Admin Console access.

---

## 2. What is genuinely missing

This is not a list of nice-to-haves. Each of these is something you will need and will have to
build.

### Metrics and alerting on denial rates

**There are no metrics.** No counters, no histograms, no health endpoint from the plugin. What
you need and do not have:

| Signal | Why it matters | Where you would have to get it today |
|---|---|---|
| Denial rate, split by Okta error code | A rising `invalid_scope` rate is a misconfiguration or a probing agent. A rising `invalid_client` rate is a key or lifecycle problem. Collapsing them into "denials" loses the distinction that makes them actionable | Parse Bifrost's tool-handler error lines and classify on the quoted Okta code |
| Mint latency and mint failure rate | The plugin has a 30 second timeout, no retry and no circuit breaker. A degrading Okta shows up as tool calls getting slower before it shows up as failures | Not available. You would need to instrument the plugin |
| Cache hit rate | Tells you what your TTL is actually buying, which you currently have to infer | Not available |
| "The plugin is loaded" as a continuous check | A `.so` that fails to load leaves Bifrost serving traffic with no enforcement. This is the highest-consequence gap in the list | A log-line check at startup, and nothing continuous. See the runbook |

**Alert on the invariant, not just the errors.** The alarming condition is not a spike in
denials. It is denials dropping to zero when they never used to, which is what an unloaded
plugin looks like.

For the wording that distinguishes a per-call denial from a connect-time refusal, which is what
tells you the per-call gate is the thing that fired, see
[the runbook](#is-the-plugin-actually-loaded-and-deciding).

### What happens when Okta is unreachable

Today: **every tool call is denied**, and this is unconditional at the per-call hook regardless
of `fail_open`. Read [SECURITY.md](../SECURITY.md#fail_open) for exactly why, because the
config documentation says something different from what the code does.

What is missing around that:

- **No retry and no backoff.** One request, one chance. A transient network blip is a denied
  tool call.
- **No circuit breaker.** With Okta down and the TTL expired, every call pays the full timeout
  before failing.
- **The timeout is 30 seconds and is not configurable.** That is long for a request-path
  dependency and longer than many client timeouts, so the symptom your users report is a hang,
  not a refusal. If you change one number in this plugin before production, consider this one.
- **No degraded mode worth having.** The only alternative to fail-closed on offer is
  `fail_open`, which at connect time means an uncredentialed connection. There is no "trust the
  last known good answer for a bounded grace period" behaviour, which is what you would actually
  want, and it is not implemented.

### Rate limiting

**The plugin implements none, in either direction.**

- **Nothing limits how much traffic the plugin sends to Okta.** Load is a direct function of
  tool-call volume: two token requests per call, plus a check per TTL per binding. See
  [Okta rate limits](#3-okta-rate-limits).
- **Nothing limits how much an individual agent can do.** A permitted agent can call a permitted
  tool as fast as the gateway will carry it. If your threat model includes an agent looping, that
  control is not here. Bifrost may offer its own; this plugin does not.

### Cache behaviour under load

The verdict cache is correct and small, and it has two behaviours worth knowing before a load
test surprises you.

- **No request coalescing.** On TTL expiry, concurrent calls for the same binding all miss and
  each fires its own mint, because no lock is held across the Okta call. The load spike at
  expiry is proportional to your concurrency, not to one. With a short TTL and high concurrency
  this is a periodic thundering herd against Okta's token endpoint. Single-flight is the obvious
  fix and is not implemented.
- **Denials are cached symmetrically**, for the same TTL. Restoring a permission is therefore
  also up to one TTL stale, which trips up operators testing a fix immediately after making it.

The good news, stated because a reviewer will look for it: the cache is **bounded by your
binding count**, because keys derive from configuration rather than from request content. It is
not attacker-growable and it is not a memory exhaustion vector.

### High availability with more than one gateway instance

Nothing here prevents running several Bifrost instances. Four things change when you do.

- **The verdict cache is per process.** Each instance has its own independent TTL window. A
  deactivation is uniform across the fleet only after the *last* instance's window expires, so
  your effective revocation bound is still one TTL, but you cannot observe it from one place.
- **`InvalidateVerdicts()` is process-local.** It is the seam for an Okta event hook or a
  shared-signals receiver, **nothing calls it today**, and a future receiver would need to fan
  out to every instance rather than being handled by one. Plan for that shape if you build it.
- **Every instance holds the same agent private key**, so your key blast radius is the whole
  fleet. Consider whether each instance should be its own Okta agent principal instead, which
  gives per-instance revocation and per-instance attribution at the cost of more tenant objects.
- **Each instance has its own config store and its own tool discovery.** Tools are discovered
  only on **first** registration. On a restart, Bifrost reloads MCP clients from its store
  *without re-running discovery*, and the result is an instance that reports its tools correctly
  over the admin API while its live in-memory registry is empty and every call 404s with
  `tool not found`. There is no log line saying discovery was skipped. In a rolling deploy this
  can produce a fleet where some instances work and some do not, with no signal distinguishing
  them. **Replace instances with fresh state rather than restarting them in place**, and health
  check by executing a real tool call, not by process liveness.

### Key rotation

Rotation today is a **restart**. The key file is read once, in `NewClient`, during `Init`. A
replaced file is not noticed until the process restarts.

To rotate with zero downtime you need overlap: a period in which both the old and the new key
are acceptable to Okta, so instances can be replaced one at a time.

- **First establish whether your tenant permits more than one active signing key on a single
  agent.** We have not verified this, and the answer determines your whole procedure. Do not
  assume it either way.
- **If it does:** register the new key, roll instances onto it one at a time, confirm the old
  key is no longer in use, then remove it.
- **If it does not:** the honest sequence is to stand up a second agent principal with the new
  key, move instances onto it, then retire the first. That gives you overlap at the cost of a
  second identity, and it changes what appears in the `act` chain during the transition, which
  matters if anything downstream keys off the agent id.
- **Either way, rehearse it.** The failure symptom is `invalid_client` on every call, which is
  the same symptom as a mismatched key and as a deactivated agent, so a rotation gone wrong is
  ambiguous exactly when you are under pressure.
- Note that Okta rejects an agent JWK registration whose `use` is not `"sig"`, with a specific
  error to that effect. Worth knowing before you generate keys in a hurry.

### Everything else

- **No trace propagation.** A tool call cannot be followed from client through gateway to Okta
  to resource server on a single trace.
- **No configuration hot reload.** Every plugin config change is a restart, and per the note
  above a restart is really a replace.
- **No per-object authorization layer.** See [SECURITY.md](../SECURITY.md#no-per-object-authorization).
  If your policy needs to say "this vehicle" rather than "dispatch", that layer is above this
  one and does not exist here.

---

## 3. Okta rate limits

This deserves its own section because the failure mode is genuinely misleading.

### What the plugin's request path actually hits

Two OAuth token endpoints per mint:

1. `POST https://{domain}/oauth2/v1/token`, the **org** authorization server, for the ID-JAG.
2. `POST https://{domain}/oauth2/{asId}/v1/token`, the **target** authorization server, to redeem
   it.

Plus the authorization check, which is the same pair of requests, at most once per TTL per
distinct binding.

These are token endpoints with their own limits. **We have not measured them, and this document
will not quote a figure for them.** Read the rate limits published for your own org type, and
watch your tenant's rate-limit dashboard during a load test rather than reasoning about it.

### The AI Agent APIs share one org-wide bucket

Separately, and importantly: **Okta's AI Agent APIs share a single org-wide rate limit bucket
rather than having per-agent limits.** Fan-out across many agents draws down one shared
allowance. We have observed that bucket at 100 requests per minute; confirm the current figure
for your org type against Okta's published limits, because limits differ by org type and change.

**Exhaustion does not present as throttling. It presents as absence.** A rate-limited response
surfaces as an object appearing not to exist, so the symptom you chase is "this agent is not
there" or "this connection is missing" rather than "we are being throttled". Anyone debugging
that without knowing about the shared bucket will look at their tenant configuration first, and
find nothing wrong with it.

Two consequences:

- **Your administrative traffic competes with itself.** Agent import and sync, connection
  management, and any inventory or reconciliation job you build all draw on that one bucket. A
  well-meaning "reconcile every agent every minute" job can exhaust it on its own, and then your
  tooling reports agents as missing.
- **Do not "optimise" the per-call check into a status-API lookup.** It is a tempting change:
  read the agent's status from the management API instead of attempting a mint. It would move the
  hot path onto the shared AI Agent API bucket, where exhaustion looks like the agent not
  existing, which the plugin would have to interpret as some kind of denial. Attempting the mint
  keeps the check on the token endpoints, and it has the independent virtue that the grant *is*
  the decision, exercising the same policy path the real call depends on rather than a status
  field that could drift from it.

### Why a too-low TTL under load is a real hazard

Putting the two halves together: the mint is per call and you cannot tune it, and the check is
per TTL per binding and you can. Under load, dropping the TTL to shorten revocation latency
adds check traffic on top of an already per-call mint load, and the thundering herd at expiry
(no single-flight, see above) makes that traffic bursty rather than smooth.

The practical guidance: pick the TTL from your revocation requirement, then **load test at your
expected peak concurrency and watch the tenant's rate-limit dashboard**. If you are near a
limit, the lever that helps most is not the TTL. It is reducing tool-call volume or adding the
request coalescing the plugin does not have.

---

## 4. Operational runbook

### Is the plugin actually loaded, and deciding

Three questions, not one. A plugin can be present in the config, loaded into the process, and
still not be the thing making decisions.

**1. Did the `.so` load?**

```bash
docker compose logs bifrost | grep "plugin status"
```

```
plugin status: okta-agent-identity - active
```

Anything else, or nothing, means the `.so` did not load and **Bifrost is serving traffic with no
enforcement**. Go back to [the build section](#5-the-build-pipeline-burden). A silent
non-failure here is the usual outcome of a Go version, dependency version, or architecture
mismatch.

**2. Is it deciding per call, or only at connect time?**

Read the wording of a denial. It is load-bearing.

| Denial text | What it proves |
|---|---|
| `okta denied "<tool>" on "<client>"` | The **per-call** hook ran, on this call. This is the strong claim |
| `okta refused to issue a token for "<client>"` | The **connect-time** path. Also correct, and it only proves the session could not start |
| `okta-agent-identity is not initialised` | `Init` failed. The plugin is loaded and refusing everything. Look for an Init error earlier in the log |

Denials carry HTTP **403**, type `access_denied`, and code `okta_agent_denied` (or
`okta_plugin_uninitialised`), with `AllowFallbacks` false. Those are stable strings to alert on.

**3. Is the plugin the only thing supplying credentials?**

This is the only test that proves it, and it is the one people skip.

Set `"enabled": false` on the plugin entry, bring the stack down with `down -v` rather than
restarting, and call a tool. It must fail **completely**, with no `Authorization` header reaching
the upstream server at all:

```
tools/call get_telemetry DENIED: no Authorization header reached this server
```

If the call still succeeds, something else is authenticating and every other test you have run
was measuring the wrong thing. Run this negative control once per environment, and again after
any change to the upstream server's own configuration.

**4. Is delegation happening, or is the caller's token being forwarded?**

Compare the caller's token against the token the upstream received. They must differ in three
ways:

| | Caller's token | Token the upstream received |
|---|---|---|
| `aud` | the agent's resource URL | the **target's** resource URL |
| `scp` | the caller's own scope | the **target** scope |
| `act` | absent | **present**, naming the agent |

The same token in both columns means the gateway is forwarding rather than exchanging, and
nothing has been delegated. Note that `act` is not documented by Okta; treat its shape as
observed behaviour, per [SECURITY.md](../SECURITY.md#9-undocumented-okta-behaviour-this-depends-on).

### When calls start failing, check in this order

Ordered by likelihood and by how cheap the check is, not by how interesting the cause would be.

**1. Is it `tool not found` on everything?** Then it is almost certainly **not** an
authorization problem, and looking at Okta will waste an hour. Two causes:

- Something restarted in place instead of being replaced, so tool discovery never re-ran. The
  admin API will still report the tools correctly from the config store while the live registry
  is empty. Replace with fresh state.
- `allow_connect_without_caller` is false, so registration failed at startup.

**2. Is the plugin loaded?** Question 1 above. Especially if anything was deployed, rebuilt, or
upgraded recently.

**3. Read the Okta error code in the denial.** The plugin passes Okta's own words through, and
they distinguish cases that look identical from outside. See the denial table in
[SECURITY.md](../SECURITY.md#reading-a-denial). In short: `invalid_scope` naming a scope is a
permission decision; `invalid_client` is a key mismatch or a deactivated agent; `invalid_target`
means no ACTIVE connection matches the resource; `'subject_token' is invalid` means the caller
sent the wrong kind of token.

**4. Did anything just rotate?** `invalid_client` on every call, starting abruptly, is a key
that no longer matches what is registered on the agent. It is also what a deactivated agent
looks like, so check both.

**5. Is the upstream rejecting a token the plugin clearly minted?** Then it is not a denial at
all. Check `auth_type` is `none` on that MCP client: any other value makes Bifrost overwrite the
plugin's `Authorization` header, and the upstream refuses a credential the plugin never sent.
Also check the resource server's audience configuration against the resource URL actually sent.

**6. Is TLS interception in play?** An unknown-authority error on the plugin's Okta calls looks
identical whether you configured no CA bundle or configured a path that does not exist inside
the container. Confirm the bundle is present *inside* the container and contains the public roots
as well as your interception root, because it replaces the default trust store rather than adding
to it.

**7. Take the gateway out of the picture.** The reference demo ships a driver that calls the
plugin's **own** exchange code with no gateway in the way, so a passing run is direct evidence
about the code that ships. Use it to see Okta's own answer rather than a gateway's
interpretation of one. This is the fastest way to separate "Okta is refusing" from "the gateway
is misconfigured".

**8. Read the resource server's denial, if the call got that far.** It distinguishes no header,
token rejected, and wrong scope, and it prints the scopes the token actually carried. If the call
was refused at the gateway it will not appear there at all, and that absence is itself the
answer.

### Evidence for an incident review

- **Bifrost's log** is the enforcement point speaking for itself: one decision line per tool
  call.
- **The resource server's log** carries the accepted call with its scope, the delegation chain,
  and the token id, written after it validated the token independently.
- **Okta's System Log**, via Admin Console, Reports > System Log. Filter
  `app.oauth2.token.grant.id_jag` and `app.oauth2.as.token.grant.access_token`, and read
  `outcome.result` and `outcome.reason`. **Confirm for yourself, before you need it, whether a
  refused grant appears as its own discrete event in your tenant.** A granted-token event and a
  refused-grant event are not guaranteed to be logged the same way, and finding that out during
  an incident is the wrong time.

Do not compare gateway success counts against resource-server received counts across whole
container lifetimes. The two start at different times, so the windows differ and the naive
comparison produces an alarming-looking discrepancy that is entirely pre-restart traffic. If you
need that integrity check, restrict it to calls after the later process started.

---

## 5. The build pipeline burden

This is a real, permanent operational cost, and it belongs in the decision about whether to take
the plugin route at all.

### You must build and maintain your own Bifrost

**Bifrost's published images are statically linked and cannot load any Go plugin.** Not this one,
not any. Go's plugin system requires a dynamically-linked host binary. This is
[documented behaviour on Maxim's side](https://docs.getbifrost.ai/plugins/building-dynamic-binary),
not a defect and not something to file a bug about.

So running this plugin means owning a Bifrost build. That means:

- **A fork or a patched build of a third-party gateway** in your pipeline, tracking upstream
  releases yourself. The only required change is dropping `-extldflags '-static'` from the link
  step; the rest of the build is theirs. The reference demo has a working
  `bifrost/Dockerfile.dynamic`.
- **Fail the build if the output comes out static.** The reference Dockerfile does this
  deliberately, because the runtime symptom is `plugin.Open: Dynamic loading not supported`,
  which does not obviously point at a linker flag.
- **A decision about the admin console.** The reference build stubs `bifrost-http/ui` with a
  placeholder file, because the console is pulled in with `//go:embed all:ui` so the directory
  must be non-empty. That keeps an npm and React stage out of the build. If you want the console,
  you build it as their Dockerfile does, and then you own the question of who can reach it.
- **Your own vulnerability management for that build.** You are now the distributor of the
  gateway binary you run.

### The plugin must match the host exactly, on three axes

| Must match | Why |
|---|---|
| Go version | Go refuses to load a plugin built by a different toolchain version |
| **Every** shared dependency version | `bifrost/core` v1.8.4 against a v1.8.3 host does not load. Patch versions count |
| Architecture | An arm64 `.so` will not load into an amd64 host |

**Do not guess any of them.** Read them out of the image you are loading into:

```bash
make compat BIFROST_IMAGE=your-bifrost:tag
make pin BIFROST_CORE=<the core version it printed>
make plugin PLATFORM=linux/amd64
```

The build runs in a pinned container, because building on a developer's own toolchain is the
single most reliable way to produce a plugin that will not load. No local Go install is needed.

The plugin depends on **nothing outside the Go standard library**, and that is a deliberate
consequence of this constraint rather than minimalism for its own sake: every library added is
another version that must match the host. It is also why the RS256 signing is hand-rolled on
`crypto/rsa` rather than pulled from a JWT package.

### What this means for your release process

- **Every Bifrost upgrade is a coordinated plugin rebuild.** You cannot upgrade the gateway and
  the plugin independently. A Bifrost patch release can require a plugin rebuild and redeploy,
  and if you deploy the gateway without it, the plugin **silently fails to load** and Bifrost
  serves traffic with no enforcement.
- **Gate the deploy on the plugin loading.** Not on the container starting. The container will
  start happily either way. Make the `plugin status: okta-agent-identity - active` line, or a
  real tool call, the readiness condition.
- **The architecture mismatch has a failure mode worse than not loading.** On a clean checkout
  the two sides disagree and the plugin simply fails to load, which is at least loud. On a
  machine where a `.so` of the *other* architecture already exists, the build **succeeds while
  being wrong**: the artifact nobody loads is rebuilt, the stale file already on disk is loaded,
  and a source change looks applied when it is not. If a change appears to have no effect, check
  which architecture is in `bin/` and which one your config names. Build artefact names carry the
  architecture for exactly this reason.
- **Windows is not an option.** Go plugins do not work there. Linux or macOS.
- **There is no update channel.** A fix in this repository reaches you only when you rebuild
  against your own Bifrost and redeploy. Nothing notifies you.

---

## 6. Minimum bar before production

A checklist, in the order we would want to see it done. Nothing here is optional if the answer
to "is this enforcing anything" needs to be yes on a bad day.

**Configuration**

- [ ] `fail_open` is `false`, and everyone who might turn it on has read
      [SECURITY.md](../SECURITY.md#fail_open).
- [ ] `agent_status_ttl` chosen from a stated revocation requirement, and that requirement is
      written down somewhere.
- [ ] Separate authorization server and separate target resource URL per lane, not the demo's
      shared pair.
- [ ] `bindings[].tools` explicitly listed on every binding, so a new upstream tool fails closed.
- [ ] Okta policy `people.groups` narrowed from `EVERYONE`.
- [ ] The key is a file from your secret manager, `0400` or `0600`, correct owner, never inline
      and never in an environment variable.
- [ ] Core dumps disabled on the gateway process.

**Verification, run in your environment rather than trusted from this document**

- [ ] The negative control passed: plugin disabled, clean restart, call fails with no
      `Authorization` header reaching the upstream.
- [ ] Delegation confirmed: the upstream received a token differing from the caller's in `aud`,
      `scp`, and the presence of `act`.
- [ ] Every upstream MCP server validates tokens independently, with `RS256` pinned, and issuer,
      audience, expiry and per-tool scope checked. **Test one with a deliberately bad token**,
      because this path has never been observed firing in a live run.
- [ ] Revocation measured end to end: deactivate an agent, call a tool, record the actual
      staleness against your configured TTL. **This has never been demonstrated end to end**, so
      you are the first to measure it.
- [ ] Load tested at expected peak concurrency, watching your Okta tenant's rate-limit dashboard.

**Operations**

- [ ] "The plugin is loaded" is a monitored invariant and a deploy gate, not a build-time
      assumption.
- [ ] Alert on denials falling to zero, not only on denials spiking.
- [ ] Denial rate broken out by Okta error code, so `invalid_scope` and `invalid_client` are
      distinguishable.
- [ ] Bifrost logs shipped, access-controlled, and given a deliberate retention period. They are
      your only record of a gateway denial.
- [ ] Instances replaced rather than restarted in place, with health checks that execute a real
      tool call.
- [ ] Key rotation procedure written and rehearsed, including whether your tenant permits two
      active keys on one agent.
- [ ] Someone named owns rebuilding the plugin on every Bifrost upgrade.
