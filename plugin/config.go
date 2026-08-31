package oktabifrost

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Config is the plugin's configuration, supplied through Bifrost's PluginConfig.Config
// field. Nothing here is environment-specific in the repo: every value is expected to
// arrive from the host's configuration or environment. No tenant domain, agent id,
// authorization server id, or key material is ever committed.
type Config struct {
	// OktaDomain is the tenant hostname without scheme, e.g. "example.oktapreview.com".
	OktaDomain string `json:"okta_domain"`

	// AgentID is the Okta workload principal id for the agent this Bifrost instance
	// acts as, e.g. "wlp...". The plugin authenticates as this agent using private_key_jwt.
	AgentID string `json:"agent_id"`

	// AgentResourceURL is this agent's own A2A resource URL, from its dual-citizenship
	// registration. The caller's inbound token must carry this as its audience, which
	// is what makes the caller's grant specific to this agent rather than ambient.
	//
	// Registering an agent as a resource is Console-only; the API returns 405. The
	// resource URL cannot be edited afterwards, only deleted and recreated, so it is
	// worth choosing deliberately. This field is used to verify the inbound audience,
	// not to mint anything.
	AgentResourceURL string `json:"agent_resource_url"`

	// PrivateKeyJWK is the agent's private key in JWK form, used to build the client
	// assertion. Secret.
	//
	// Prefer PrivateKeyJWKFile. Putting a JWK inline means the key ends up in the
	// gateway's config, which then has to be treated as a secret everywhere it is
	// stored, rendered, or backed up. It also has to survive JSON escaping and, in
	// practice, whatever shell renders the config, which is a reliable source of
	// corrupted keys.
	PrivateKeyJWK string `json:"private_key_jwk,omitempty"`

	// PrivateKeyJWKFile is a path to a file containing the agent's private key as a
	// JWK. Read once, at startup.
	//
	// This is the recommended form: the config stays non-secret, the key lives in
	// exactly one place with its own file permissions, and nothing has to escape it.
	// Exactly one of PrivateKeyJWK or PrivateKeyJWKFile must be set.
	PrivateKeyJWKFile string `json:"private_key_jwk_file,omitempty"`

	// Bindings maps a Bifrost MCP client name to the Okta authorization server that
	// protects it. One entry per upstream MCP server. Splitting read and command
	// scopes across two authorization servers means an over-broad request fails at
	// the lane boundary rather than being silently narrowed.
	Bindings map[string]Binding `json:"bindings"`

	// AgentStatusTTL bounds how long an agent's Okta status is trusted between checks.
	// This is the knob that decides how stale a revocation can be. Keep it short: the
	// whole point of the per-call check is that an already-minted bearer token cannot
	// be withdrawn, so the check is the only thing standing between a deactivated
	// agent and a live connection. Defaults to 10s.
	AgentStatusTTL string `json:"agent_status_ttl,omitempty"`

	// FailOpen allows tool calls through when Okta cannot be reached. Defaults to
	// false, and should stay false. It exists only so the failure mode is an explicit,
	// auditable choice rather than an accident of implementation.
	FailOpen bool `json:"fail_open,omitempty"`
}

// Binding ties one Bifrost MCP client to one Okta authorization server.
type Binding struct {
	// AuthorizationServerID is the Okta custom authorization server id protecting the
	// target, e.g. "aus...". This is the lane: read scopes and command scopes live on
	// separate authorization servers so an over-broad request fails at the boundary.
	AuthorizationServerID string `json:"authorization_server_id"`

	// TargetResourceURL is the target's resource URL, sent as `resource` on the
	// exchange alongside `audience`. Both are required: audience selects the
	// authorization server, resource selects what within it is being addressed.
	TargetResourceURL string `json:"target_resource_url"`

	// Scopes are requested on the token minted for this client.
	//
	// Okta does not down-scope a token-exchange request. A scope the agent's managed
	// connection does not grant fails the WHOLE request rather than yielding the
	// grantable subset, so there is no partial success to accidentally accept.
	//
	// Note the scope list is enforced on the managed CONNECTION, not only on the
	// authorization server's policy rule. Updating the authorization server alone is
	// not sufficient and is a common misconfiguration.
	Scopes []string `json:"scopes"`

	// Tools optionally restricts which tool names this binding may serve. Empty means
	// every tool on the client. Names are matched exactly against the MCP tool name.
	Tools []string `json:"tools,omitempty"`
}

const (
	defaultAgentStatusTTL = 10 * time.Second

	// redactedPlaceholder is what RedactConfig substitutes for secret values.
	redactedPlaceholder = "***REDACTED***"
)

// Validate checks the configuration is coherent before the plugin starts serving.
// It deliberately fails on a missing binding rather than defaulting to allow, so a
// typo in a client name cannot quietly turn into an ungoverned MCP server.
func (c *Config) Validate() error {
	var problems []string

	if strings.TrimSpace(c.OktaDomain) == "" {
		problems = append(problems, "okta_domain is required")
	}
	if strings.Contains(c.OktaDomain, "://") {
		problems = append(problems, "okta_domain must be a hostname without a scheme")
	}
	if strings.TrimSpace(c.AgentID) == "" {
		problems = append(problems, "agent_id is required")
	}
	inline := strings.TrimSpace(c.PrivateKeyJWK) != ""
	fromFile := strings.TrimSpace(c.PrivateKeyJWKFile) != ""
	switch {
	case inline && fromFile:
		problems = append(problems, "set only one of private_key_jwk or private_key_jwk_file, not both")
	case !inline && !fromFile:
		problems = append(problems, "one of private_key_jwk or private_key_jwk_file is required")
	}
	if strings.TrimSpace(c.AgentResourceURL) == "" {
		problems = append(problems, "agent_resource_url is required (the agent's dual-citizenship resource URL)")
	}
	if len(c.Bindings) == 0 {
		problems = append(problems, "at least one entry in bindings is required")
	}

	for name, b := range c.Bindings {
		if strings.TrimSpace(b.AuthorizationServerID) == "" {
			problems = append(problems, fmt.Sprintf("bindings[%q].authorization_server_id is required", name))
		}
		if strings.TrimSpace(b.TargetResourceURL) == "" {
			problems = append(problems, fmt.Sprintf("bindings[%q].target_resource_url is required", name))
		}
		if len(b.Scopes) == 0 {
			problems = append(problems, fmt.Sprintf("bindings[%q].scopes must not be empty", name))
		}
	}

	if c.AgentStatusTTL != "" {
		if _, err := time.ParseDuration(c.AgentStatusTTL); err != nil {
			problems = append(problems, fmt.Sprintf("agent_status_ttl %q is not a valid duration", c.AgentStatusTTL))
		}
	}

	if len(problems) > 0 {
		return errors.New("okta plugin config invalid: " + strings.Join(problems, "; "))
	}
	return nil
}

// StatusTTL returns the configured agent status TTL, or the default.
func (c *Config) StatusTTL() time.Duration {
	if c.AgentStatusTTL == "" {
		return defaultAgentStatusTTL
	}
	d, err := time.ParseDuration(c.AgentStatusTTL)
	if err != nil || d <= 0 {
		return defaultAgentStatusTTL
	}
	return d
}

// bindingFor resolves the binding for a Bifrost MCP client name.
// A missing binding is an error, never an implicit allow.
func (c *Config) bindingFor(clientName string) (Binding, error) {
	b, ok := c.Bindings[clientName]
	if !ok {
		return Binding{}, fmt.Errorf("no okta binding configured for mcp client %q", clientName)
	}
	return b, nil
}

// permitsTool reports whether this binding may serve the named tool.
// An empty Tools list means every tool on the client is in scope for the binding.
func (b Binding) permitsTool(tool string) bool {
	if len(b.Tools) == 0 {
		return true
	}
	for _, t := range b.Tools {
		if t == tool {
			return true
		}
	}
	return false
}
