// Package oktabifrost is a Bifrost MCP plugin that makes Okta the policy decision
// point for agent access to MCP servers, with Bifrost as the enforcement point.
//
// It does two things, at the two places Bifrost allows them:
//
//   - At connection time it mints a short-lived, agent-scoped token from Okta and sets
//     it as the upstream Authorization header. That token names both the calling
//     service and the acting agent, so the upstream server can attribute the call.
//
//   - At every tool call it re-asks Okta whether it would still issue that token, and
//     refuses the call if the answer is no.
//
// The second is not redundant. Bifrost's MCP request carries no headers, so a token
// can only be attached when the connection is established, and an issued bearer token
// cannot be withdrawn. The per-call check is therefore the only thing standing between
// a deactivated agent and a connection holding a still-valid token. That is the entire
// reason this plugin exists.
//
// Asking Okta to mint is deliberately used as the authorization question rather than
// reading agent status from the management API. The grant IS the decision, it needs no
// second admin credential, and it exercises the same policy path the real call depends
// on rather than a status field that could diverge from it.
package oktabifrost

import (
	"fmt"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// PluginName is the name Bifrost uses to address this plugin in configuration.
const PluginName = "okta-agent-identity"

// Compile-time proof that the plugin satisfies the interfaces it claims. If Bifrost
// changes a hook signature, this fails at build time rather than in production.
var (
	_ schemas.MCPPlugin           = (*Plugin)(nil)
	_ schemas.MCPConnectionPlugin = (*Plugin)(nil)
)

// OktaClient is the Okta-facing surface the plugin depends on. It is an interface so
// the hooks can be tested without a tenant, and so the exchange can be adjusted as
// Okta's supported subject types evolve.
type OktaClient interface {
	// MintResourceToken performs the agent's half of the machine-context exchange and
	// returns an access token for the binding's target, with its expiry.
	//
	// The full flow is three steps; the plugin performs only the last two:
	//
	//  1. The CALLING SERVICE mints its own token via client_credentials at this
	//     agent's authorization server, with resource set to the agent's own A2A
	//     resource URL. That happens outside this plugin, and the result is what
	//     arrives as the inbound bearer. It cannot happen here: registered agents are
	//     not permitted the client_credentials grant at all, only token-exchange and
	//     jwt-bearer.
	//
	//  2. Exchange that token at the ORG authorization server for an ID-JAG, with the
	//     target's authorization server as audience and the target's resource URL as
	//     resource. Both are required; audience selects the server, resource selects
	//     what within it is addressed. The issued token is observed to carry an aud
	//     equal to the resource value, though what determines aud is an open question:
	//     see the note on exchangeForIDJAG in okta.go before relying on the mechanism.
	//
	//  3. Redeem the ID-JAG at the TARGET authorization server for the final access
	//     token, which carries the nested act chain.
	//
	// Both plugin-side steps authenticate the agent with private_key_jwt, and the
	// assertion audience differs between them because the endpoints differ.
	//
	// Errors should carry Okta's own message where there is one. Okta's refusals are
	// more precise than anything this plugin could invent, and they are what makes a
	// denial legible to whoever is looking at it.
	MintResourceToken(subjectToken string, b Binding) (token string, expiresAt time.Time, err error)
}

// Plugin is the Bifrost plugin.
type Plugin struct {
	cfg  Config
	okta OktaClient

	mu sync.RWMutex
	// keyed by Binding.verdictKey, which is the whole question put to Okta rather than
	// just the authorization server. See that method for why the difference matters.
	verdicts map[string]verdict
}

// verdict caches the outcome of the most recent mint for a binding. Only the outcome
// is retained, never the token: the token minted at connect is the one in flight, and
// keeping later ones would invite using them somewhere they cannot be used.
type verdict struct {
	permitted bool
	reason    string
	decidedAt time.Time
}

// New constructs the plugin, validating configuration eagerly so a misconfigured
// deployment fails at startup rather than on its first tool call.
func New(cfg Config, okta OktaClient) (*Plugin, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if okta == nil {
		return nil, fmt.Errorf("okta plugin: OktaClient must not be nil")
	}
	return &Plugin{
		cfg:      cfg,
		okta:     okta,
		verdicts: make(map[string]verdict),
	}, nil
}

// GetName satisfies schemas.BasePlugin.
func (p *Plugin) GetName() string { return PluginName }

// Cleanup satisfies schemas.BasePlugin. Nothing to release: the plugin holds only an
// in-memory verdict cache, which dies with the process.
func (p *Plugin) Cleanup() error { return nil }

// PreMCPConnectionHook mints the upstream token and attaches it to the connection.
//
// Headers are mutable only on the connect request, which is why minting happens here
// rather than per call. ConnectionString, StdioCommand and StdioArgs are left alone.
//
// WHY A CONNECT WITH NO CALLER TOKEN IS PERMITTED, when AllowConnectWithoutCaller is
// set. Please read this before "fixing" it back into an unconditional deny.
//
// Bifrost registers MCP clients, and discovers their tools, at STARTUP. There is no
// inbound HTTP request at that point, so there is no caller token to delegate from.
// Denying that connect means no tools are ever registered, and every later tool call
// fails with "tool not found" rather than with anything resembling an authorization
// error. The gateway is then completely unusable for a reason that looks nothing like
// its cause, and the only hint is an empty tools array.
//
// Permitting it does not make anything executable, for two independent reasons, both
// covered by TestTokenlessConnectAllowedButExecuteDenied:
//
//  1. No Authorization header is attached, so the upstream server refuses any tool call
//     over such a connection. It validates independently of this gateway.
//  2. PreMCPHook still denies every execute, chat_tool_call and responses_tool_call
//     without a caller token and a live Okta mint, and is unaffected by this setting.
//     Discovery needs only initialize and tools/list, which that hook deliberately does
//     not gate.
//
// That pairing, connect permitted while execute denied, is the invariant. Changing
// either half without the other breaks it.
func (p *Plugin) PreMCPConnectionHook(
	ctx *schemas.BifrostContext,
	req *schemas.BifrostMCPConnectRequest,
) (*schemas.BifrostMCPConnectRequest, *schemas.MCPConnectionShortCircuit, error) {
	if req == nil {
		return req, nil, nil
	}

	binding, err := p.cfg.bindingFor(req.ClientName)
	if err != nil {
		// An unbound client is a configuration error, not a pass-through. Refuse the
		// connection so an unmanaged MCP server cannot be reached through this gateway.
		return req, connectDenied(err.Error()), nil
	}

	subject, err := subjectTokenFrom(ctx)
	if err != nil {
		// Bifrost registers MCP clients, and discovers their tools, at startup: there is
		// no inbound request at that point and so no caller token. Refusing here means no
		// tools are ever registered and every later call fails as "tool not found".
		//
		// Allowing it attaches no credential, so the upstream server refuses any tool
		// call over this connection, and PreMCPHook still gates execution on a caller
		// token and a live Okta mint regardless of this setting.
		if p.cfg.AllowConnectWithoutCaller {
			return req, nil, nil
		}
		return req, connectDenied(err.Error()), nil
	}

	token, _, err := p.okta.MintResourceToken(subject, binding)
	p.record(binding, err)
	if err != nil {
		if p.cfg.FailOpen {
			return req, nil, nil
		}
		return req, connectDenied(fmt.Sprintf("okta refused to issue a token for %q: %v", req.ClientName, err)), nil
	}

	if req.Headers == nil {
		req.Headers = map[string]string{}
	}
	req.Headers["Authorization"] = "Bearer " + token

	return req, nil, nil
}

// PostMCPConnectionHook passes the connect outcome through unchanged.
func (p *Plugin) PostMCPConnectionHook(
	_ *schemas.BifrostContext,
	resp *schemas.BifrostMCPConnectResponse,
	bifrostErr *schemas.BifrostError,
) (*schemas.BifrostMCPConnectResponse, *schemas.BifrostError, error) {
	return resp, bifrostErr, nil
}

// PreMCPHook gates every tool call against Okta.
//
// Denial is returned as a short-circuit, never as an error. Bifrost treats a returned
// error from a hook as non-blocking, so denying by error would let the call through
// and silently invert the security posture.
func (p *Plugin) PreMCPHook(
	ctx *schemas.BifrostContext,
	req *schemas.BifrostMCPRequest,
) (*schemas.BifrostMCPRequest, *schemas.MCPPluginShortCircuit, error) {
	if req == nil {
		return req, nil, nil
	}

	// Ping and list_tools reuse the established transport and execute nothing. Gating
	// them would break discovery without adding control, since a listed tool still
	// cannot run without passing the check below.
	switch req.RequestType {
	case schemas.MCPRequestTypeExecuteTool,
		schemas.MCPRequestTypeChatToolCall,
		schemas.MCPRequestTypeResponsesToolCall:
	default:
		return req, nil, nil
	}

	binding, err := p.cfg.bindingFor(req.ClientName)
	if err != nil {
		return req, callDenied(err.Error()), nil
	}

	// GetToolName is used rather than the embedded tool-call structs, which are
	// deprecated and due to be replaced by BifrostMCPExecuteToolRequest.
	tool := req.GetToolName()
	if !binding.permitsTool(tool) {
		return req, callDenied(fmt.Sprintf("tool %q is not served by the binding for client %q", tool, req.ClientName)), nil
	}

	permitted, reason, err := p.stillPermitted(ctx, binding)
	if err != nil {
		if p.cfg.FailOpen {
			return req, nil, nil
		}
		return req, callDenied(fmt.Sprintf("could not confirm standing with okta: %v", err)), nil
	}
	if !permitted {
		if reason == "" {
			reason = "okta declined to issue a token for this agent"
		}
		return req, callDenied(fmt.Sprintf("okta denied %q on %q: %s", tool, req.ClientName, reason)), nil
	}

	return req, nil, nil
}

// PostMCPHook passes the tool result through unchanged.
func (p *Plugin) PostMCPHook(
	_ *schemas.BifrostContext,
	resp *schemas.BifrostMCPResponse,
	bifrostErr *schemas.BifrostError,
) (*schemas.BifrostMCPResponse, *schemas.BifrostError, error) {
	return resp, bifrostErr, nil
}

// stillPermitted asks whether Okta would issue a token for this binding right now,
// reusing a recent answer if one is within the TTL.
//
// KNOWN LIMITATION, stated rather than hidden: this catches revocation, because a
// deactivated agent or a deactivated connection makes Okta refuse. It does NOT catch
// scope NARROWING, because the token already in flight was minted at connect and
// still carries the scopes it was granted then. Tightening a connection's scopes
// takes effect on the next connection, not the next call. Closing that gap needs the
// connection re-established, which this hook cannot do.
func (p *Plugin) stillPermitted(ctx *schemas.BifrostContext, b Binding) (bool, string, error) {
	ttl := p.cfg.StatusTTL()
	key := b.verdictKey()

	p.mu.RLock()
	cached, ok := p.verdicts[key]
	p.mu.RUnlock()
	if ok && time.Since(cached.decidedAt) < ttl {
		return cached.permitted, cached.reason, nil
	}

	subject, err := subjectTokenFrom(ctx)
	if err != nil {
		return false, err.Error(), nil
	}

	// The minted token is intentionally discarded. It cannot be attached to this call,
	// since MCP requests carry no headers, so it exists only to make Okta answer.
	_, _, mintErr := p.okta.MintResourceToken(subject, b)
	p.record(b, mintErr)

	if mintErr != nil {
		return false, mintErr.Error(), nil
	}
	return true, "", nil
}

// record stores the outcome of a mint so the next call within the TTL can reuse it.
func (p *Plugin) record(b Binding, mintErr error) {
	v := verdict{permitted: mintErr == nil, decidedAt: time.Now()}
	if mintErr != nil {
		v.reason = mintErr.Error()
	}
	p.mu.Lock()
	p.verdicts[b.verdictKey()] = v
	p.mu.Unlock()
}

// InvalidateVerdicts drops every cached answer so the next call re-asks Okta
// immediately instead of waiting out the TTL. This is the seam for an Okta event hook
// or shared signals receiver, which is the gap Bifrost has no answer for today.
func (p *Plugin) InvalidateVerdicts() {
	p.mu.Lock()
	p.verdicts = make(map[string]verdict)
	p.mu.Unlock()
}

func callDenied(msg string) *schemas.MCPPluginShortCircuit {
	return &schemas.MCPPluginShortCircuit{Error: denial(msg)}
}

func connectDenied(msg string) *schemas.MCPConnectionShortCircuit {
	return &schemas.MCPConnectionShortCircuit{Error: denial(msg)}
}

func denial(msg string) *schemas.BifrostError {
	status := 403
	errType := "access_denied"
	code := "okta_agent_denied"
	allowFallbacks := false

	return &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &status,
		Type:           &errType,
		AllowFallbacks: &allowFallbacks,
		Error: &schemas.ErrorField{
			Type:    &errType,
			Code:    &code,
			Message: msg,
		},
	}
}
