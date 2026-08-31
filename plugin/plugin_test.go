package oktabifrost

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// fakeOkta stands in for a tenant. mintErr is what Okta is pretending to say.
type fakeOkta struct {
	mintErr error
	calls   int
}

func (f *fakeOkta) MintResourceToken(_ string, _ Binding) (string, time.Time, error) {
	f.calls++
	if f.mintErr != nil {
		return "", time.Time{}, f.mintErr
	}
	return "minted-token", time.Now().Add(5 * time.Minute), nil
}

const (
	readClient  = "fleetops-read"
	cmdClient   = "fleetops-command"
	readLaneAS  = "aus-read-lane"
	cmdLaneAS   = "aus-command-lane"
	readResURL  = "https://fleetops.atko.example/telemetry"
	cmdResURL   = "https://fleetops.atko.example/dispatch"
	agentResURL = "https://fleetops.atko.example/agent"
)

func testConfig() Config {
	return Config{
		OktaDomain:       "example.oktapreview.com",
		AgentID:          "wlpTESTAGENT",
		AgentResourceURL: agentResURL,
		PrivateKeyJWK:    `{"kty":"RSA","n":"x","e":"AQAB","d":"y","p":"p","q":"q"}`,
		Bindings: map[string]Binding{
			readClient: {
				AuthorizationServerID: readLaneAS,
				TargetResourceURL:     readResURL,
				Scopes:                []string{"fleet.telemetry.read", "fleet.routes.read"},
			},
			cmdClient: {
				AuthorizationServerID: cmdLaneAS,
				TargetResourceURL:     cmdResURL,
				Scopes:                []string{"fleet.dispatch.command"},
				Tools:                 []string{"dispatch_vehicle"},
			},
		},
	}
}

func newTestPlugin(t *testing.T, cfg Config, okta OktaClient) *Plugin {
	t.Helper()
	p, err := New(cfg, okta)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// toolCall builds an execute-tool request naming a tool on a client.
func toolCall(client, tool string) *schemas.BifrostMCPRequest {
	name := tool
	return &schemas.BifrostMCPRequest{
		RequestType: schemas.MCPRequestTypeChatToolCall,
		ClientName:  client,
		ChatAssistantMessageToolCall: &schemas.ChatAssistantMessageToolCall{
			Function: schemas.ChatAssistantMessageToolCallFunction{Name: &name},
		},
	}
}

func mustDeny(t *testing.T, sc *schemas.MCPPluginShortCircuit, wantSubstr string) {
	t.Helper()
	if sc == nil {
		t.Fatalf("expected a denial, got none")
	}
	if sc.Error == nil || sc.Error.Error == nil {
		t.Fatalf("denial carried no error payload")
	}
	if got := sc.Error.Error.Message; !strings.Contains(got, wantSubstr) {
		t.Fatalf("denial message %q does not contain %q", got, wantSubstr)
	}
	if sc.Error.StatusCode == nil || *sc.Error.StatusCode != 403 {
		t.Fatalf("expected HTTP 403 on denial, got %v", sc.Error.StatusCode)
	}
}

// A denial must never be delivered as a returned error. Bifrost treats hook errors as
// non-blocking, so denying by error would let the call through. This is the single most
// important property in the package.
func TestDenialIsNeverReturnedAsError(t *testing.T) {
	p := newTestPlugin(t, testConfig(), &fakeOkta{mintErr: errors.New("access_denied")})

	_, sc, err := p.PreMCPHook(nil, toolCall(cmdClient, "dispatch_vehicle"))
	if err != nil {
		t.Fatalf("hook returned an error, which Bifrost would ignore: %v", err)
	}
	mustDeny(t, sc, "")
}

func TestDeniesUnboundClient(t *testing.T) {
	p := newTestPlugin(t, testConfig(), &fakeOkta{})

	_, sc, err := p.PreMCPHook(nil, toolCall("some-unmanaged-server", "anything"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustDeny(t, sc, "no okta binding configured")
}

func TestDeniesToolOutsideBinding(t *testing.T) {
	p := newTestPlugin(t, testConfig(), &fakeOkta{})

	// read_telemetry is a real tool, but the command binding only serves dispatch_vehicle.
	_, sc, err := p.PreMCPHook(nil, toolCall(cmdClient, "read_telemetry"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustDeny(t, sc, "is not served by the binding")
}

// With no caller token there is nothing to delegate from, so the call must be refused
// rather than falling back to the agent's own authority.
func TestDeniesWhenCallerPresentedNoToken(t *testing.T) {
	p := newTestPlugin(t, testConfig(), &fakeOkta{})

	_, sc, err := p.PreMCPHook(nil, toolCall(readClient, "read_telemetry"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustDeny(t, sc, "no caller identity token")
}

// Okta's own words must survive to the caller. "invalid_scope, the following scopes are
// not allowed" is a permission refusal; "invalid_target" is a misconfiguration. Losing
// that distinction makes a denial unreadable.
func TestOktaRefusalReachesTheCallerVerbatim(t *testing.T) {
	cfg := testConfig()
	oktaSays := &OktaError{
		StatusCode:  400,
		Code:        "invalid_scope",
		Description: "The following scopes are not allowed for this request: [fleet.dispatch.command].",
	}
	p := newTestPlugin(t, cfg, &fakeOkta{})

	// Seed the verdict cache as though a mint had just been refused.
	p.record(cfg.Bindings[cmdClient], oktaSays)

	_, sc, err := p.PreMCPHook(nil, toolCall(cmdClient, "dispatch_vehicle"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustDeny(t, sc, "fleet.dispatch.command")
	mustDeny(t, sc, "invalid_scope")
}

func TestAllowsWhenOktaWouldStillIssue(t *testing.T) {
	cfg := testConfig()
	p := newTestPlugin(t, cfg, &fakeOkta{})
	p.record(cfg.Bindings[readClient], nil)

	_, sc, err := p.PreMCPHook(nil, toolCall(readClient, "read_telemetry"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc != nil {
		t.Fatalf("expected the call to pass, got denial: %v", sc.Error.Error.Message)
	}
}

// Revocation is the headline: a previously permitted agent must be refused once Okta
// stops issuing, without the connection being touched.
func TestRevocationFlipsAPermittedAgentToDenied(t *testing.T) {
	cfg := testConfig()
	p := newTestPlugin(t, cfg, &fakeOkta{})
	binding := cfg.Bindings[cmdClient]
	call := toolCall(cmdClient, "dispatch_vehicle")

	// Okta is issuing: the call goes through.
	p.record(binding, nil)
	if _, sc, _ := p.PreMCPHook(nil, call); sc != nil {
		t.Fatalf("agent should be permitted before revocation, got: %s", sc.Error.Error.Message)
	}

	// The agent is deactivated in Okta, so the next mint is refused. Nothing about the
	// connection changed, and the token it holds has not expired. The refusal alone is
	// what has to stop the call.
	p.record(binding, &OktaError{
		StatusCode:  403,
		Code:        "access_denied",
		Description: "Policy evaluation failed for this request.",
	})

	_, sc, err := p.PreMCPHook(nil, call)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustDeny(t, sc, "access_denied")
}

// Discovery must keep working: gating list_tools would break clients without adding
// control, since a listed tool still cannot execute.
func TestPingAndListToolsAreNotGated(t *testing.T) {
	p := newTestPlugin(t, testConfig(), &fakeOkta{mintErr: errors.New("okta is down")})

	for _, rt := range []schemas.MCPRequestType{schemas.MCPRequestTypePing, schemas.MCPRequestTypeListTools} {
		req := &schemas.BifrostMCPRequest{RequestType: rt, ClientName: readClient}
		_, sc, err := p.PreMCPHook(nil, req)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", rt, err)
		}
		if sc != nil {
			t.Fatalf("%s should not be gated, got denial", rt)
		}
	}
}

func TestFailOpenIsOptInAndOff(t *testing.T) {
	cfg := testConfig()
	if cfg.FailOpen {
		t.Fatal("fail_open must default to false")
	}
}

func TestConfigValidationCatchesMissingFields(t *testing.T) {
	cases := map[string]func(*Config){
		"okta_domain":        func(c *Config) { c.OktaDomain = "" },
		"agent_id":           func(c *Config) { c.AgentID = "" },
		"private_key_jwk":    func(c *Config) { c.PrivateKeyJWK = "" },
		"agent_resource_url": func(c *Config) { c.AgentResourceURL = "" },
		"bindings":           func(c *Config) { c.Bindings = nil },
		"scheme in domain":   func(c *Config) { c.OktaDomain = "https://example.oktapreview.com" },
		"target_resource_url": func(c *Config) {
			b := c.Bindings[readClient]
			b.TargetResourceURL = ""
			c.Bindings[readClient] = b
		},
		"empty scopes": func(c *Config) {
			b := c.Bindings[readClient]
			b.Scopes = nil
			c.Bindings[readClient] = b
		},
	}

	for name, break_ := range cases {
		cfg := testConfig()
		break_(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected validation to fail, it passed", name)
		}
	}
}

// The client assertion is what identifies the agent to Okta. If the JWK parsing or the
// RS256 signing is wrong, every exchange fails with an opaque client error, so this is
// worth proving locally rather than discovering against a tenant.
func TestClientAssertionIsAValidRS256JWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	jwk := map[string]string{
		"kty": "RSA",
		"kid": "test-kid",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		"d":   base64.RawURLEncoding.EncodeToString(key.D.Bytes()),
		"p":   base64.RawURLEncoding.EncodeToString(key.Primes[0].Bytes()),
		"q":   base64.RawURLEncoding.EncodeToString(key.Primes[1].Bytes()),
	}
	raw, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}

	cfg := testConfig()
	cfg.PrivateKeyJWK = string(raw)

	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	const audience = "https://example.oktapreview.com/oauth2/v1/token"
	assertion, err := c.clientAssertion(audience)
	if err != nil {
		t.Fatalf("clientAssertion: %v", err)
	}

	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("expected three JWT segments, got %d", len(parts))
	}

	// Header carries RS256 and the kid, so Okta can select the registered public key.
	var hdr map[string]any
	decodeSegment(t, parts[0], &hdr)
	if hdr["alg"] != "RS256" {
		t.Errorf("alg = %v, want RS256", hdr["alg"])
	}
	if hdr["kid"] != "test-kid" {
		t.Errorf("kid = %v, want test-kid", hdr["kid"])
	}

	// iss and sub must both be the agent, and aud the endpoint being called.
	var claims map[string]any
	decodeSegment(t, parts[1], &claims)
	if claims["iss"] != cfg.AgentID || claims["sub"] != cfg.AgentID {
		t.Errorf("iss/sub = %v/%v, want %s for both", claims["iss"], claims["sub"], cfg.AgentID)
	}
	if claims["aud"] != audience {
		t.Errorf("aud = %v, want %s", claims["aud"], audience)
	}
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Error("jti must be present so Okta can reject replay")
	}

	// The signature must actually verify against the public half.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestRejectsAPublicKeyMistakenForPrivate(t *testing.T) {
	pub := `{"kty":"RSA","n":"abc","e":"AQAB"}`
	if _, _, err := parseRSAPrivateJWK(pub); err == nil {
		t.Fatal("expected a public key to be rejected")
	} else if !strings.Contains(err.Error(), "PRIVATE key is required") {
		t.Errorf("error should say the private key is required, got: %v", err)
	}
}

func decodeSegment(t *testing.T, seg string, out any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("unmarshal segment: %v", err)
	}
}
