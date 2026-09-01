# Architecture

For an engineer who has to reason about this plugin, review it, or extend it.

The design is small, and almost all of it is forced. One constraint does most of the work,
and the rest of the code is consequences of it. This document leads with that constraint,
because reading the hooks without it makes several choices look arbitrary or wrong.

For adoption mechanics see [`INTEGRATION.md`](INTEGRATION.md). For the config reference see
[`README.md`](../README.md).

**This is unsupported sample code, not an Okta product.**

---

## The constraint everything follows from

Two facts, neither of which is negotiable, and which point in opposite directions.

**1. An MCP request carries no headers.** `BifrostMCPRequest` has no headers field. Bifrost
exposes mutable headers only on the **connect** request, `BifrostMCPConnectRequest`. So a
credential can be attached exactly once, when the connection is established, and never on an
individual call.

**2. An issued bearer token cannot be withdrawn.** That is not a limitation of Okta. It is
how access tokens work everywhere: the token is a signed statement that was true when it was
made, and nothing can reach out and un-say it. Deactivating an agent stops Okta issuing
**new** tokens instantly, and leaves the one already in flight working until it expires.

Put those together and you get an asymmetry that shapes the whole plugin:

> **The only place a credential can be attached is the one place that does not run per call.
> The only place that runs per call cannot attach a credential.**

So a per-call check has exactly one power available to it: **refusal**. It cannot mint a
fresher credential and swap it in, because there is nowhere to put it. It can only decide
whether the call proceeds at all.

That is why the per-call hook exists, and why it is the reason the plugin exists rather than
an optimisation layered on top of it. Without it, an agent deactivated in Okta keeps working
for as long as its already-issued token is valid, and the gateway is a pass-through with
extra steps.

It is also why this is a **gateway** plugin rather than a library. Closing that gap needs
something that keeps asking, gating every call on a recent answer instead of checking once
per session. The only component that sees every call is the gateway.

### What the asymmetry costs

The consequences are not incidental, and each one is a limitation you should be able to state
without looking it up:

| Consequence | Why it follows |
|---|---|
| The per-call check catches an agent being **switched off** | Okta refuses to mint, and the refusal is what stops the call |
| It does **not** catch scopes being **narrowed** | The token in flight was minted at connect and still carries the scopes granted then. Narrowing takes effect on the next connection, not the next call. Closing that would need the connection re-established, which no MCP hook can do |
| The cache TTL is simultaneously the **revocation staleness bound** | See [the verdict cache](#the-verdict-cache) |
| Revocation is detected by **asking**, never by being told | There is no push. `Plugin.InvalidateVerdicts()` is the seam for an event hook or a shared-signals receiver. Nothing calls it today |

---

## The shape, end to end

```
   +----------------------+
   |   Calling service    |  Not an agent, deliberately: registered agents are
   |  (scheduler, API,    |  not permitted the client_credentials grant at all,
   |   front door)        |  only token-exchange and jwt-bearer.
   +----------+-----------+
              |
   step 1     |  client_credentials at the ACTING AGENT'S OWN authorization
   (outside   |  server, resource = the acting agent's resource URL.
    the       |  Result: an access token addressed TO the agent, which is what
    plugin)   |  makes the grant specific to invoking this agent rather than
              |  ambient authority the service can spend anywhere.
              v
      Authorization: Bearer <caller token>
              |
              v
+-------------+------------------------------------------------------+
|                          B I F R O S T                             |
|                    policy ENFORCEMENT point                        |
|                       holds no policy of its own                   |
|                                                                    |
|  +--------------------------------------------------------------+  |
|  |               okta-agent-identity plugin                     |  |
|  |                                                              |  |
|  |  PreMCPConnectionHook   mint, set Authorization    ACTS       |  |
|  |  PreMCPHook             re-ask, refuse or pass     ACTS       |  |
|  |  PostMCPConnectionHook  pass through                          |  |
|  |  PostMCPHook            pass through                          |  |
|  |                                                              |  |
|  |  verdict cache: keyed on the WHOLE question,                 |  |
|  |  TTL = agent_status_ttl = revocation staleness bound          |  |
|  +---------------------------+----------------------------------+  |
|                              |                                     |
+------------------------------|-------------------------------------+
        steps 2 and 3          |          Authorization: Bearer
                               |          <minted token, carries act>
                               v                        v
    +--------------------------------+   +------------------------------+
    |              OKTA              |   |     Upstream MCP server      |
    |     policy DECISION point      |   |                              |
    |                                |   |  Validates the token ITSELF: |
    |  org AS   /oauth2/v1/token     |   |    RSA sig vs Okta's JWKS    |
    |    step 2  -> ID-JAG           |   |    RS256 pinned              |
    |                                |   |    iss / aud / exp           |
    |  target AS                     |   |    scope required by THIS    |
    |    /oauth2/{aus}/v1/token      |   |      tool                    |
    |    step 3  -> access token     |   |                              |
    |               carrying act     |   |  Takes the gateway's word    |
    |                                |   |  for nothing.                |
    +--------------------------------+   +------------------------------+
```

---

## Where the plugin can act

It implements two Bifrost interfaces, `schemas.MCPPlugin` and
`schemas.MCPConnectionPlugin`, which is four exported hook methods. **Two of them act. Two
are pass-throughs.**

### `PreMCPConnectionHook`: attach

The only place headers are mutable, so the only place a credential can be attached.

1. Resolve the binding for `req.ClientName`. **No binding is a refusal, never a
   pass-through**, so an MCP server nobody configured cannot be reached through the gateway
   unmanaged.
2. Extract the caller's token from the request context.
3. Mint, and set `req.Headers["Authorization"]`.

`ConnectionString`, `StdioCommand` and `StdioArgs` are left untouched. The hook changes one
header and nothing else.

**The tokenless-connect case is the interesting one.** Bifrost registers MCP clients, and
discovers their tools, at **startup**, where there is no inbound HTTP request and therefore no
caller token. Refusing that connect registers **zero** tools, and every later call then fails
with `tool not found` rather than anything resembling an authorization error, which is a
failure that looks nothing like its cause.

`AllowConnectWithoutCaller` permits it, and the permission is safe because of a pairing, not
because of a judgement call:

- **No credential is attached, and no mint is attempted.** The upstream validates
  independently, so it rejects any tool call arriving over that connection.
- **`PreMCPHook` still denies execution** without a caller token and a live mint, and is
  completely unaffected by this setting.

`TestTokenlessConnectAllowedButExecuteDenied` pins both halves, including the assertions that
no `Authorization` header appears and that the Okta client was called zero times. Changing one
half without the other fails the test. **If you are reviewing a change to either, that test is
the thing to read first.**

### `PreMCPHook`: refuse

The only hook that runs per call, and therefore the only place the standing decision can be
re-checked.

It gates exactly three request types: `MCPRequestTypeExecuteTool`,
`MCPRequestTypeChatToolCall`, `MCPRequestTypeResponsesToolCall`. Everything else, notably
`Ping` and `ListTools`, passes through.

**Discovery is deliberately not gated.** A listed tool still cannot run without passing the
check, so hiding names buys no control and makes the server harder to work with. Gating it
would additionally break tool registration, per the connect case above. Expect to be asked
why an agent can see a tool it may not use; that is the answer.

Then, in order: resolve the binding, check the tool is served by that binding, ask whether
Okta would still issue.

### `PostMCPHook` and `PostMCPConnectionHook`: nothing

Both return their arguments unchanged. This is not an omission.

By the time either runs, the decision has been made and, on the success path, the credential
has already been spent upstream. Neither hook can gate anything, so the only thing they could
add is observation. They are implemented because the interfaces require them, and left inert
because a hook that looks like it does something and does not is worse than one that plainly
does not.

**If you extend the plugin, these are where audit belongs.** They are the natural place to
emit a structured record of what was decided and what came back, and doing it there keeps the
decision path free of I/O.

### On ordering

The relative ordering of the connect hook and the call hook within a single request is
Bifrost's internal business and was **not** directly instrumented. What is observed in the
reference environment is that denials surfaced from the per-call hook and not from the connect
path, 36 to 0, which is recorded in `PROVING-IT.md`. Read that as evidence about which hook is
the operative gate, not as a claim about Bifrost's call graph.

The distinction shows up in the log wording, and it is worth being able to read:

| Log wording | Which hook | What it proves |
|---|---|---|
| `okta denied "<tool>" on "<client>"` | `PreMCPHook` | The check ran **on this call**. The strong claim |
| `okta refused to issue a token for "<client>"` | `PreMCPConnectionHook` | The session could not start. Correct, but weaker |

---

## The three-step exchange

The plugin performs the **last two** steps of a three-step machine-context exchange.

| Step | Who | What | Endpoint |
|---|---|---|---|
| 1 | the **calling service** | `client_credentials`, `resource` = the acting agent's resource URL | the **acting agent's own** authorization server |
| 2 | the **plugin** | token-exchange for an **ID-JAG** | the **org** authorization server, `https://{domain}/oauth2/v1/token` |
| 3 | the **plugin** | jwt-bearer, redeeming the ID-JAG for the access token that goes upstream | the **target's** authorization server, `https://{domain}/oauth2/{aus}/v1/token` |

**Step 1 cannot happen in the plugin.** Registered agents are not permitted the
`client_credentials` grant at all, only token-exchange and jwt-bearer. That is why something
which is not an agent has to start the chain, and it is a feature rather than an
inconvenience: the caller's grant is addressed to this specific agent, so it is not ambient
authority.

**Note the org authorization server in step 2.** Its token endpoint has no authorization
server id in its path. That is the only place an ID-JAG can be obtained. Exchanging at a
custom authorization server instead is the mistake that makes a gateway look like it supports
delegation when it only supports a single hop.

### Details that are easy to get wrong

**`audience` on step 2 must be the target server's ISSUER url,** `https://{domain}/oauth2/{aus}`,
not its token endpoint. `audience` selects which authorization server should honour the
assertion; `resource` selects what within it is being addressed.

**The client assertion differs between the two steps.** Both authenticate the agent with
`private_key_jwt`, and the assertion's `aud` is the endpoint being called, so step 2 and step
3 need separate assertions rather than one reused across both. `iss` and `sub` are both the
agent's workload principal id. A `jti` is included so Okta can reject replay.

**RS256 is hand-rolled on `crypto/rsa`.** Not for cleverness: the plugin depends on nothing
outside the standard library and `bifrost/core/schemas`, because a Go plugin must match its
host on **every** shared dependency version, so each added library is another way for the
`.so` to refuse to load in someone else's Bifrost build. RS256 is a SHA-256 digest and a
PKCS#1 v1.5 signature, both of which the standard library provides. **Keep that property if
you extend this.**

**CRT values are recomputed, not trusted.** `parseRSAPrivateJWK` reads only `n`, `e`, `d`,
`p`, `q` and calls `Precompute()`, so a JWK carrying stale `dp`/`dq`/`qi` cannot produce
silently invalid signatures. It also rejects a JWK with no `d` with an error that says the
private key is required, because handing over a public key by mistake is common and the
default error would not say so.

### `Exchange` returns both artifacts, and a partial result on failure

`Exchange` returns the ID-JAG **and** the access token, not only the one that goes on the
wire. The ID-JAG is the assertion that actually asserts the delegation; the access token is
merely what that assertion was redeemed for. Discarding it means a redemption failure cannot
be distinguished from an exchange failure by inspection.

More importantly, when the assertion is obtained but **redemption** fails, `Exchange` returns
a non-nil result carrying only `IDJAG`, alongside the error. That is deliberate, and it
distinguishes two failures with different fixes:

- **Okta would not assert this delegation.** Step 2 failed. Look at the caller, the agent, and
  the delegation.
- **Okta asserted it and the target authorization server refused to honour it.** Step 3
  failed. Look at the target's policy and the connection.

**The contract, because it is a trap:** on a non-nil error the result may be nil or partial.
Check the error first, and treat `AccessToken` as present only when `err` is nil. Never treat
a non-nil result as success. `MintResourceToken` is the narrow wrapper the hooks use, which
only ever needs the token that goes upstream, and
`TestMintResourceTokenIgnoresPartialResults` pins that it is not fooled by one.

Both fields are live credentials. Neither is logged.

### What is not verified about `aud`

**Do not state that `aud` comes from the `resource` parameter.** It is not established, and it
is easy to conclude wrongly from a setup that works.

**Observed:** the issued access token's `aud` equals the `resource` value sent on the
exchange. Verified repeatedly against a live tenant.

**Why that is not proof:** in the reference demo both bindings share **one** authorization
server. If that server's configured `audiences` holds the same string, then `resource` and
`audiences` predict the **same** `aud`, and no observation in that topology can tell them
apart. A matching `aud` is consistent with `resource` being authoritative. It does not
demonstrate it.

Settling it needs either reading the target server's configured `audiences`, confirming it
differs from the resource URL sent, and seeing which one `aud` follows; or sending a
`resource` the server's `audiences` does not contain and seeing which wins.

The `resource` parameter's documentation status is thin: Okta's published docs mention it on
the `client_credentials` call that produces the caller's token, and omit it from the parameter
table for this exchange. It is nevertheless sent, because a verified-working implementation
sends it and removing a parameter on the strength of documentation alone is the worse risk. An
unrecognised parameter is normally ignored.

**The operational instruction is unaffected:** validate `aud` against the resource URL. That
is correct under either explanation.

### `act` and `sub_profile`

The access token from step 3 carries an `act` claim naming both parties, with a `sub_profile`
on each level typing it `service` or `ai_agent`. Two distinct principals on one credential:
the service that asked, and the agent that acted. That is the claim the whole integration
exists to make, and it is what lets a receiving system attribute a call to a specific agent
rather than to a shared robot account.

> **`act` and `sub_profile` are not in Okta's published developer documentation.** They were
> verified empirically by decoding real tokens from a live tenant. They behave consistently.
> Do not present them as documented behaviour, and if you assert on them, treat their shape as
> observed behaviour that could change rather than as a contract.

---

## Why minting is the authorization question

The plugin asks "would Okta issue this token right now" instead of reading agent status from a
management API. That is a deliberate choice, for three reasons, and it is worth understanding
before anyone proposes replacing it with a status lookup.

**The grant is the decision.** A status field is a *description* of policy state. A successful
mint is policy state being *evaluated*. Everything relevant is folded in: the agent's status,
the connection's status, the connection's scope list, the authorization server's policy, and
the caller's standing as a listed client. No status endpoint returns the conjunction of those,
so reading one means reimplementing Okta's evaluation and keeping it in step.

**It exercises the same path the real call depends on.** A status field can drift from the
policy that actually governs issuance. The mint cannot, because it *is* that path. This is the
difference between checking a health endpoint and serving a request.

**It needs no second credential.** A management API call would require the gateway to hold
admin-scoped credentials in addition to the agent's key, widening the blast radius of a
gateway compromise for no gain. The gateway holds exactly one credential, the agent's key, and
can do exactly one thing with it.

The cost is that the check is a real round trip, which is what the verdict cache is for.

**One consequence to be precise about:** because the per-call check mints, and the minted
token cannot be attached to the call, that token is **deliberately discarded**. It existed only
to make Okta answer. The `verdict` struct retains the outcome and never the token, so no code
path can later find a credential lying around and use it somewhere it does not belong.

---

## Why a denial is a short-circuit and never an error

**Bifrost treats an error returned from a hook as non-blocking.**

So denying by returning an error would let the call through, and would do it while looking
like a denial in the code. The security posture would be silently inverted, and every test
that checked "the hook returned an error" would pass.

Every refusal is therefore a `*schemas.MCPPluginShortCircuit` or
`*schemas.MCPConnectionShortCircuit` carrying a `BifrostError` with HTTP 403, type
`access_denied`, code `okta_agent_denied`, and `AllowFallbacks` explicitly false. The third
return value is `nil` on every denial path.

`TestDenialIsNeverReturnedAsError` asserts exactly this, and its comment calls it the single
most important property in the package. **That is not hyperbole: it is the one bug in this
design that would not look like a bug.** If you change how refusals are constructed, that test
is the one that has to keep passing.

Two related fail-closed choices:

- **An uninitialised plugin denies.** If `Init` never ran or failed, nothing has authorized
  anything, so `main.go` short-circuits with `okta_plugin_uninitialised` rather than passing
  through.
- **Unknown config keys are rejected.** `Init` uses `DisallowUnknownFields`, so a typo in a key
  name fails startup instead of quietly leaving a setting at its default. A misspelled
  `fail_open` that silently defaulted would be a security-relevant typo.

### The `fail_open` discrepancy, stated because a reviewer will find it

`fail_open` reaches the connect hook and, as the code stands, **not** the per-call hook.

`stillPermitted` returns a denial *verdict* rather than an *error* when a mint fails: all of
its return paths pass `nil` as the error. The `if err != nil { if p.cfg.FailOpen {...} }`
branch in `PreMCPHook` is therefore unreachable. An Okta failure denies the call regardless of
the setting.

The effect errs safe, and the field's documented intent is broader than its behaviour. Two
things follow for anyone operating this:

- **Okta reachability is a hard dependency of the tool-call path.** There is no configuration
  that changes that today.
- **A mint failure is recorded in the verdict cache** as a denial, so a transient Okta failure
  continues denying for up to `agent_status_ttl` after Okta recovers.

---

## The verdict cache

An in-memory `map[string]verdict` guarded by a `sync.RWMutex`. It holds only the outcome, the
reason, and when it was decided. **Never a token.** It dies with the process, which is why
`Cleanup()` has nothing to release.

`agent_status_ttl` bounds how long an answer is reused. Default and shipped value `10s`.

### The TTL is not a performance dial

It is doing two jobs at once. It is the cache lifetime, **and it is the revocation staleness
bound.** Raising it widens the window in which a deactivated agent still passes. Choose it
against how fast a deactivation must bite, not against latency.

Lowering it does not add the minting cost, and raising it does not remove it, because the mint
is driven by something else entirely:

| | Frequency | Driven by |
|---|---|---|
| The authorization **check** | at most once per TTL per distinct question | the cache |
| The **mint** | two token requests, per connection | Bifrost's per-call connection model, `needs_session_stickiness: false` |

With per-call connections the connect-time mint runs per call, so the steady-state cost is two
Okta token requests per tool call, plus another two whenever the per-call check misses the
cache.

**Both hooks write to the same cache** through `record()`. So in the steady state the
connect-time mint is refreshing the verdict the call hook reads, and the effective staleness is
often well under the TTL. The TTL is a **bound**, not a typical value. Do not lean on the
typical value: the bound is what a deactivation is measured against.

### The collision it used to have

The key was originally the **authorization server id alone**. Two bindings on one
authorization server therefore shared a verdict.

That is exactly the reference topology: two lanes on one authorization server, separated only
by scope. The observable symptom was a call being refused with a message naming a scope it had
never requested, which reads as though the plugin is confused rather than as a cache artifact.

It failed in both directions, and they are not equally bad:

- **A cached success answering for a different binding** made a refusal permissive. Masked in
  practice, because connect-time minting still refused, which is worse than it sounds: the
  behaviour looked correct from outside while resting on a *second* mechanism instead of on
  this one being right.
- **A cached denial answering for a different binding** made an allowed call fail, with a
  message citing a scope that binding never asked for. It also made behaviour
  order-dependent: the same call succeeded or failed depending on what ran before it and how
  recently.

### Why the key must be the whole question

`Binding.verdictKey()` keys on the authorization server id, the target resource URL, and the
**sorted** scope set, NUL-joined.

The principle is general: **the cache key must be the entire question that was put to Okta.**
Anything less lets the cache answer a question it was never asked, and that is the worst
failure available to an authorization check, because it does not look like a failure.

Each element earns its place:

| Element | Without it |
|---|---|
| Authorization server id | Bindings on different servers collide |
| Target resource URL | Two bindings on one server, differing only in target, collide |
| Scope set | The reference topology's two lanes, differing only in scope, collide |
| **Sorting** the scopes | The same set written in a different order splits into two verdicts, silently doubling calls to Okta |
| **NUL** as the separator | No combination of values can be concatenated into a collision, because NUL cannot occur in an Okta id, a URL, or an OAuth scope token |

The binding's own slice is **copied** before sorting, so reading the key does not reorder the
caller's configuration. A method that reads like a getter must not have a side effect on the
config, and `TestVerdictKeyIgnoresScopeOrderButNotScopeContent` asserts that too.

Three tests cover the key. Two of them are recorded as **mutation-tested**, the first and the
third below: reverting the key to the authorization server id alone makes them fail, so they
actually bite rather than passing for unrelated reasons.

| Test | Asserts |
|---|---|
| `TestVerdictIsNotSharedAcrossBindingsOnOneAuthorizationServer` | A cached success does not answer for another binding |
| `TestDenialOnOneBindingDoesNotPoisonAnotherOnTheSameAuthorizationServer` | A cached denial does not refuse another binding |
| `TestVerdictKeyIgnoresScopeOrderButNotScopeContent` | Order shares a key, content does not, and the slice is not mutated |

The cache is read concurrently, so `make race` is part of the check set rather than optional.

---

## Trust boundaries

### What Okta is trusted for

Everything about the decision. Okta holds the policy and answers one question. **The gateway
holds no policy of its own,** and there is no local allow-list that could drift from the
tenant. `bindings[].scopes` is not policy: it is what the gateway *asks for*, and Okta decides
whether to grant it. An over-broad `scopes` list produces a clean refusal, not a wider grant.

### What the gateway is trusted for

Three things, and it is worth being able to say them separately:

1. **Attaching the right credential to the connection.** Nobody else can, because nobody else
   sees the connect request.
2. **Refusing calls Okta would not authorize.** This is the per-call gate, and it is the only
   mitigation for the un-withdrawable token.
3. **Holding the agent's private key.** This is the real boundary, and it should be stated
   plainly: the gateway can mint any token its configured bindings permit. **A compromised
   gateway is a compromised agent identity.**

The blast radius of (3) is bounded, and the bound is meaningful: it is the union of the
bindings in the gateway's config, further bounded by the scope lists on the agent's managed
connections in Okta. Every token it can mint is short-lived, is attributed to that specific
agent, and stops being issuable the moment the agent is deactivated. That is a materially
better position than a shared static credential in a config file. **It is not zero**, and a
security review should size it rather than skip it.

### What the gateway is deliberately not trusted with

**The caller's credential does not leave the gateway.** The plugin reads the caller's token
from `BifrostContextKeyRequestHeaders` to use as the exchange subject, and it deliberately does
**not** read `BifrostContextKeyMCPExtraHeaders`, because enabling the header there would also
forward the caller's raw token to the upstream MCP server. That is a credential leak with no
upside: the plugin wants to *read* the caller's token, not pass it on.

`BifrostContextKeyMCPInboundBearer` is checked first, because its declaration says exactly
"the caller's validated identity-provider token, used as the subject of delegated token
exchange". On open-source Bifrost it is **never populated**: nothing writes it outside tests,
and both readers are admin console handlers where the subject is the signed-in admin's own
token. Verified empirically as absent at every hook, in every configuration tried, including
when the caller demonstrably sent the header. Whether a non-OSS auth layer populates it is
untested, which is why it is tried first rather than dropped.

The caller's token is never logged, never placed in an error message, and never returned to the
caller. `TestSubjectTokenErrorNeverContainsTheToken` pins that.

**A non-Bearer scheme is refused outright** rather than passed through as an opaque value, so a
Basic or Negotiate credential cannot be smuggled into a token exchange as though it were a
bearer token. The `Bearer` prefix itself is matched case-insensitively, per RFC 7235, because a
caller sending lowercase `bearer` should not fail closed in a way indistinguishable from a
missing header.

### What the resource server must still verify for itself

**The resource server must not take the gateway's word for anything.** If it does, the
gateway becomes a single point of bypass and the whole model rests on network placement.

It has to do, itself:

- **Verify the RSA signature** against Okta's published keys.
- **Pin `RS256`**, so a token claiming `alg: none` is rejected.
- **Check `iss`, `aud` and `exp`.** Validate `aud` against the **resource URL**, per
  [the note above](#what-is-not-verified-about-aud).
- **Check the scope required by the specific tool being called.** The gateway's binding decides
  what to *ask* for. Only the resource server knows what this tool *requires*.
- **Make any per-object decision itself.** The token says an agent may dispatch. It does not
  say which vehicle.

The property you want is that going around the gateway does not get you in, it just means no
token. The demo's `server/auth.go` is a working reference.

### One boundary the plugin documents but does not enforce

`agent_resource_url` is validated as present at startup and is **not read anywhere else in the
current code.** The inbound-audience check its documentation describes, that the caller's token
is addressed to this agent, is **not performed by the plugin**.

The check is not absent from the system: the caller's token goes to Okta as `subject_token`,
and Okta refuses one from the wrong server or of the wrong type with
`'subject_token' is invalid`. So it is enforced at Okta rather than at the gateway. If your
threat model wants the gateway to reject a wrongly-addressed caller token locally, before an
Okta round trip, that is a small addition you would have to make.

---

## The loader shim, and why `main.go` looks redundant

Bifrost's `.so` loader resolves plugins as **free functions looked up by name**, not as a type
satisfying an interface. So `main.go` exports the symbols the loader looks for and forwards
them to `./plugin`, which is an ordinary testable package with no plugin machinery in it. That
split is what makes the hooks testable without a Bifrost.

A signature mismatch in that shim is a **runtime** failure: the loader reports "failed to cast
&lt;symbol&gt; to expected signature", and it surfaces only when someone starts Bifrost. So
`main.go` pins every exported signature in a `var` block of function-typed assertions, turning
a would-be production failure into a build failure here. `plugin.go` does the same for the two
interfaces with `_ schemas.MCPPlugin = (*Plugin)(nil)`.

**If you add or change a hook, add the assertion in the same commit.** It is the only thing
standing between an interface change upstream and a customer's gateway failing to load.

---

## Out of scope by design

Stated plainly, because someone who believes a wider claim and later finds the narrower reality
will trust none of it.

| Not done | Why, and what would be needed |
|---|---|
| **Per-object authorization** | A scope can say an agent may dispatch. It cannot say whether it may dispatch *this particular* vehicle. That belongs in a fine-grained authorization layer above this one |
| **Sender-constrained tokens (DPoP)** | Not implemented. Tokens are **bearer** tokens: anyone holding one can use it. They are protected by being short-lived and re-checked, not by being unstealable |
| **Catching scope narrowing per call** | The in-flight token carries the scopes granted at connect. Would need the connection re-established, which no MCP hook can do |
| **Revocation push** | Detected by asking, within `agent_status_ttl`. `InvalidateVerdicts()` is the seam for an Okta event hook or a shared-signals receiver. Nothing calls it |
| **Audit emission** | The Post hooks are inert. Okta's System Log and Bifrost's own log are the record today |
| **A local inbound-audience check** | See [above](#one-boundary-the-plugin-documents-but-does-not-enforce) |
| **Observe-only mode** | There is none. `fail_open` is not one. Shadowing means a parallel instance, see [`INTEGRATION.md`](INTEGRATION.md#phase-2-a-shadow-instance-synthetic-traffic) |

---

## If you are reviewing a change

The four properties most worth protecting, in order:

1. **A denial is never a returned error.** `TestDenialIsNeverReturnedAsError`. The one bug here
   that would not look like a bug.
2. **The verdict key is the whole question.** The three key tests, two of them mutation-tested.
3. **Tokenless connect is permitted while tokenless execute is denied.**
   `TestTokenlessConnectAllowedButExecuteDenied` pins both halves as a pair.
4. **No dependency outside the standard library and `bifrost/core/schemas`.** Each addition is
   another version that must match the host exactly, and therefore another way for the artifact
   to refuse to load in a customer's Bifrost.
