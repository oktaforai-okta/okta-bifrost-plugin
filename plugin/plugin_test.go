package oktabifrost

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
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

// Two bindings sharing ONE authorization server must not share a cached verdict.
//
// This is the shape the demo tenant actually has: both lanes are served by the same
// authorization server and are separated only by scope. Keyed on the authorization
// server alone, the read lane's success answered for the command lane, so the cache
// reported "permitted" for a request Okta had never been asked about. Connect-time
// minting still refused, so the behaviour looked correct from outside, which is what
// made this worth a test rather than an observation: correctness rested on a second
// mechanism instead of on this one being right.
func TestVerdictIsNotSharedAcrossBindingsOnOneAuthorizationServer(t *testing.T) {
	const sharedAS = "aus-one-lane-for-both"

	cfg := testConfig()
	for _, name := range []string{readClient, cmdClient} {
		b := cfg.Bindings[name]
		b.AuthorizationServerID = sharedAS
		cfg.Bindings[name] = b
	}

	// Okta refuses everything it is actually asked. The only "yes" available is the one
	// seeded into the cache below, so if the command lane is permitted it can only be
	// because it read the read lane's answer.
	oktaSays := &OktaError{
		StatusCode:  400,
		Code:        "invalid_scope",
		Description: "The following scopes are not allowed for this request: [fleet.dispatch.command].",
	}
	p := newTestPlugin(t, cfg, &fakeOkta{mintErr: oktaSays})

	// A caller token has to be present, or a cache miss is refused for the missing
	// subject before a mint is ever attempted, and the test would pass for the wrong
	// reason.
	ctx := ctxWith(schemas.BifrostContextKeyRequestHeaders, map[string]string{
		"authorization": "Bearer caller.tok.en",
	})

	// The read lane was permitted a moment ago, well inside the TTL.
	p.record(cfg.Bindings[readClient], nil)

	// The command lane asks for a scope that was never granted. Its refusal must stand.
	_, sc, err := p.PreMCPHook(ctx, toolCall(cmdClient, "dispatch_vehicle"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustDeny(t, sc, "invalid_scope")

	// And the converse: recording the command lane's refusal must not clobber the read
	// lane's standing answer.
	_, sc, err = p.PreMCPHook(ctx, toolCall(readClient, "read_telemetry"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc != nil {
		t.Fatalf("the read lane's own verdict was overwritten by another binding: %v",
			sc.Error.Error.Message)
	}
}

// The other direction, and the damaging one: a DENIAL on one binding must not refuse a
// call on another binding that shares the authorization server.
//
// This is worse than the masking direction it mirrors. Masking makes a refusal permissive,
// which connect-time minting still catches. This makes an ALLOWED call fail, and fail with
// a message naming a scope that binding never requested, so it reads as though the plugin
// is confused rather than as a cache artifact. It also makes behaviour order-dependent:
// the same call succeeds or fails depending on what ran before it and how long ago.
func TestDenialOnOneBindingDoesNotPoisonAnotherOnTheSameAuthorizationServer(t *testing.T) {
	const sharedAS = "aus-one-lane-for-both"

	cfg := testConfig()
	for _, name := range []string{readClient, cmdClient} {
		b := cfg.Bindings[name]
		b.AuthorizationServerID = sharedAS
		cfg.Bindings[name] = b
	}

	// Okta issues happily for anything it is actually asked. The only "no" in play is the
	// one seeded into the cache below, so a refusal here can only have come from there.
	p := newTestPlugin(t, cfg, &fakeOkta{})

	ctx := ctxWith(schemas.BifrostContextKeyRequestHeaders, map[string]string{
		"authorization": "Bearer caller.tok.en",
	})

	// The command lane was refused a moment ago, well inside the TTL.
	p.record(cfg.Bindings[cmdClient], &OktaError{
		StatusCode:  400,
		Code:        "invalid_scope",
		Description: "The following scopes are not allowed for this request: [fleet.dispatch.command].",
	})

	// The read lane asks only for scopes it holds. It must not inherit that refusal.
	for _, tool := range []string{"read_telemetry", "list_routes"} {
		_, sc, err := p.PreMCPHook(ctx, toolCall(readClient, tool))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tool, err)
		}
		if sc != nil {
			t.Fatalf("%s was refused by another binding's cached denial: %s",
				tool, sc.Error.Error.Message)
		}
	}
}

// The key is the whole question, so scope ORDER must not matter while scope CONTENT must.
// Without the sort, reordering a scope list in configuration would silently split one
// verdict into two and double the calls to Okta; without the content sensitivity, two
// genuinely different requests would share an answer.
func TestVerdictKeyIgnoresScopeOrderButNotScopeContent(t *testing.T) {
	base := Binding{
		AuthorizationServerID: "aus1",
		TargetResourceURL:     "https://example.test/tasking",
		Scopes:                []string{"task.read", "agent.invoke"},
	}

	reordered := base
	reordered.Scopes = []string{"agent.invoke", "task.read"}
	if base.verdictKey() != reordered.verdictKey() {
		t.Errorf("same scopes in a different order must share a verdict key")
	}

	// Reading the key must not reorder the caller's own configuration.
	if base.Scopes[0] != "task.read" {
		t.Errorf("verdictKey sorted the binding's slice in place, got %v", base.Scopes)
	}

	differentScopes := base
	differentScopes.Scopes = []string{"task.read", "task.dispatch"}
	if base.verdictKey() == differentScopes.verdictKey() {
		t.Errorf("different scope sets must not share a verdict key")
	}

	differentResource := base
	differentResource.TargetResourceURL = "https://example.test/intake"
	if base.verdictKey() == differentResource.verdictKey() {
		t.Errorf("different target resources must not share a verdict key")
	}

	differentAS := base
	differentAS.AuthorizationServerID = "aus2"
	if base.verdictKey() == differentAS.verdictKey() {
		t.Errorf("different authorization servers must not share a verdict key")
	}
}

// The invariant behind AllowConnectWithoutCaller, asserted as a pair because each half
// is worthless without the other.
//
// Bifrost registers MCP clients, and discovers their tools, at startup, where there is
// no inbound request and so no caller token. Denying that connect means no tools are
// ever registered and every later call fails as "tool not found", which looks nothing
// like an authorization problem. So a tokenless CONNECT must be permitted.
//
// It must also stay harmless, and that rests on two things this test pins: no
// Authorization header is attached to the connection, and a tokenless EXECUTE is still
// refused. If someone ever makes the connect deny again, or lets the execute through,
// one half of this fails.
func TestTokenlessConnectAllowedButExecuteDenied(t *testing.T) {
	cfg := testConfig()
	cfg.AllowConnectWithoutCaller = true
	okta := &fakeOkta{}
	p := newTestPlugin(t, cfg, okta)

	// Connect, with no caller token anywhere on the context.
	req, connSC, err := p.PreMCPConnectionHook(nil, &schemas.BifrostMCPConnectRequest{ClientName: readClient})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if connSC != nil {
		t.Fatalf("tokenless connect must be permitted so discovery can run, got denial: %v",
			connSC.Error.Error.Message)
	}
	if got, ok := req.Headers["Authorization"]; ok {
		t.Fatalf("tokenless connect must attach no credential, got Authorization %q", got)
	}
	if okta.calls != 0 {
		t.Fatalf("tokenless connect must not attempt a mint, got %d call(s)", okta.calls)
	}

	// Execute over that same tokenless connection is still refused.
	_, callSC, err := p.PreMCPHook(nil, toolCall(readClient, "read_telemetry"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustDeny(t, callSC, "no caller identity token")
}

// The permission above is opt-in. Left at its default, a tokenless connect is refused,
// so nothing changes for a deployment that never sets the flag.
func TestTokenlessConnectDeniedByDefault(t *testing.T) {
	p := newTestPlugin(t, testConfig(), &fakeOkta{})

	_, sc, err := p.PreMCPConnectionHook(nil, &schemas.BifrostMCPConnectRequest{ClientName: readClient})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc == nil {
		t.Fatalf("expected a tokenless connect to be denied when the flag is unset")
	}
	if sc.Error == nil || sc.Error.Error == nil ||
		!strings.Contains(sc.Error.Error.Message, "no caller identity token") {
		t.Fatalf("denial did not name the missing caller token: %+v", sc.Error)
	}
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

// --- caller token extraction ---
//
// These matter because the purpose-built context key is empty on open-source Bifrost, so
// the fallback is not a nicety, it is the only path that works. A regression here fails
// closed and every tool call is refused, which looks like an Okta problem rather than a
// context-reading problem.

func ctxWith(key schemas.BifrostContextKey, val any) *schemas.BifrostContext {
	return schemas.NewBifrostContextWithValue(context.Background(), time.Now().Add(time.Minute), key, val)
}

func TestSubjectTokenFromRequestHeaders(t *testing.T) {
	ctx := ctxWith(schemas.BifrostContextKeyRequestHeaders, map[string]string{
		"authorization": "Bearer abc.def.ghi",
		"content-type":  "application/json",
	})

	tok, err := subjectTokenFrom(ctx)
	if err != nil {
		t.Fatalf("expected the header to be found: %v", err)
	}
	if tok != "abc.def.ghi" {
		t.Errorf("token = %q, want the value with the Bearer prefix stripped", tok)
	}
}

// The scheme is case-insensitive per RFC 7235, and a lowercase "bearer" must not fail
// closed in a way that is indistinguishable from a missing header.
func TestSubjectTokenBearerPrefixIsCaseInsensitive(t *testing.T) {
	for _, prefix := range []string{"Bearer ", "bearer ", "BEARER ", "BeArEr "} {
		ctx := ctxWith(schemas.BifrostContextKeyRequestHeaders, map[string]string{
			"authorization": prefix + "tok.en.value",
		})
		tok, err := subjectTokenFrom(ctx)
		if err != nil {
			t.Errorf("%q: %v", prefix, err)
			continue
		}
		if tok != "tok.en.value" {
			t.Errorf("%q: token = %q", prefix, tok)
		}
	}
}

// The purpose-built key wins when something actually populates it, so that a Bifrost build
// with a real auth layer does not silently keep using the fallback.
func TestSubjectTokenPrefersTheInboundBearerKey(t *testing.T) {
	ctx := ctxWith(schemas.BifrostContextKeyMCPInboundBearer, "Bearer preferred.tok.en").
		WithValue(schemas.BifrostContextKeyRequestHeaders, map[string]string{
			"authorization": "Bearer fallback.tok.en",
		})

	tok, err := subjectTokenFrom(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "preferred.tok.en" {
		t.Errorf("token = %q, want the inbound-bearer key to take precedence", tok)
	}
}

func TestSubjectTokenDeniesWhenNothingUsable(t *testing.T) {
	cases := map[string]*schemas.BifrostContext{
		"nil context":       nil,
		"no keys at all":    ctxWith(schemas.BifrostContextKey("unrelated"), "x"),
		"no auth header":    ctxWith(schemas.BifrostContextKeyRequestHeaders, map[string]string{"host": "x"}),
		"empty auth header": ctxWith(schemas.BifrostContextKeyRequestHeaders, map[string]string{"authorization": "   "}),
		"bearer with no token": ctxWith(schemas.BifrostContextKeyRequestHeaders,
			map[string]string{"authorization": "Bearer "}),
		"wrong type on key": ctxWith(schemas.BifrostContextKeyRequestHeaders, []string{"nope"}),
	}

	for name, ctx := range cases {
		if _, err := subjectTokenFrom(ctx); err == nil {
			t.Errorf("%s: expected a denial, got a token", name)
		}
	}
}

// A denial must never leak the credential it was looking at.
func TestSubjectTokenErrorNeverContainsTheToken(t *testing.T) {
	const secret = "super.secret.value"
	ctx := ctxWith(schemas.BifrostContextKeyRequestHeaders, map[string]string{
		"authorization": "Basic " + secret, // wrong scheme, so it is not usable as a bearer
	})

	_, err := subjectTokenFrom(ctx)
	if err == nil {
		t.Skip("Basic auth was accepted as a bearer; that is a separate bug")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("the error message contains the credential")
	}
}

// --- Exchange's partial-result contract ---
//
// When redemption fails, Exchange returns the assertion alongside the error. That is the
// case where seeing it matters most: it distinguishes "Okta would not assert this
// delegation" from "Okta asserted it and the target refused to honour it". These are
// different problems, and a caller that cannot tell them apart misdirects whoever is
// debugging.

// newTestClient points a Client at a TLS test server, which works because endpoints are
// built from the domain and the server's own client trusts its certificate.
func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()

	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return &Client{
		domain:  strings.TrimPrefix(srv.URL, "https://"),
		agentID: "wlpTESTAGENT",
		key:     key,
		keyID:   "test-kid",
		http:    srv.Client(),
	}, srv
}

func TestExchangeReturnsTheAssertionWhenRedemptionFails(t *testing.T) {
	const assertion = "eyJhbGciOiJSUzI1NiJ9.aXQtaXMtYW4tYXNzZXJ0aW9u.sig"

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/oauth2/v1/token") {
			// Org authorization server: hand back an ID-JAG.
			_, _ = w.Write([]byte(`{"access_token":"` + assertion + `","token_type":"N_A","expires_in":300}`))
			return
		}
		// Target authorization server: refuse to honour it.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_scope","error_description":"The following scopes are not allowed for this request: [task.dispatch]."}`))
	})

	res, err := c.Exchange("caller-subject-token", Binding{
		AuthorizationServerID: "ausTARGET",
		TargetResourceURL:     "api://sentinel-tasking",
		Scopes:                []string{"task.dispatch"},
	})

	if err == nil {
		t.Fatal("expected redemption to fail")
	}
	if res == nil {
		t.Fatal("expected a partial result carrying the assertion, got nil")
	}
	if res.IDJAG != assertion {
		t.Errorf("IDJAG = %q, want the assertion that was actually obtained", res.IDJAG)
	}
	if res.AccessToken != "" {
		t.Errorf("AccessToken = %q, want empty: nothing was issued", res.AccessToken)
	}
	// The refusal must still name the scope, or a caller cannot tell why.
	if !strings.Contains(err.Error(), "task.dispatch") {
		t.Errorf("error lost Okta's wording: %v", err)
	}
	// And it must be attributable to redemption rather than to the exchange.
	if !strings.Contains(err.Error(), "redemption") {
		t.Errorf("error should identify which call failed: %v", err)
	}
}

func TestExchangeReturnsNoResultWhenTheAssertionItselfFails(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"kid is invalid"}`))
	})

	res, err := c.Exchange("caller-subject-token", Binding{
		AuthorizationServerID: "ausTARGET",
		TargetResourceURL:     "api://sentinel-tasking",
		Scopes:                []string{"task.read"},
	})

	if err == nil {
		t.Fatal("expected the exchange to fail")
	}
	// Nothing was asserted, so there is nothing partial to hand back.
	if res != nil {
		t.Errorf("expected nil result when nothing was asserted, got %+v", res)
	}
	if !strings.Contains(err.Error(), "exchange") {
		t.Errorf("error should identify which call failed: %v", err)
	}
}

// MintResourceToken must not be fooled by a non-nil partial result.
func TestMintResourceTokenIgnoresPartialResults(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/oauth2/v1/token") {
			_, _ = w.Write([]byte(`{"access_token":"assertion.value.here","expires_in":300}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"access_denied","error_description":"Policy evaluation failed for this request."}`))
	})

	tok, expiry, err := c.MintResourceToken("caller-subject-token", Binding{
		AuthorizationServerID: "ausTARGET",
		TargetResourceURL:     "api://sentinel-tasking",
		Scopes:                []string{"task.dispatch"},
	})

	if err == nil {
		t.Fatal("expected an error")
	}
	if tok != "" {
		t.Errorf("token = %q, want empty on failure", tok)
	}
	if !expiry.IsZero() {
		t.Errorf("expiry = %v, want zero on failure", expiry)
	}
}

func TestExchangeSucceedsAndReturnsBothArtifacts(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/oauth2/v1/token") {
			_, _ = w.Write([]byte(`{"access_token":"the.id.jag","token_type":"N_A","expires_in":300}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"the.access.token","token_type":"Bearer","expires_in":3600}`))
	})

	res, err := c.Exchange("caller-subject-token", Binding{
		AuthorizationServerID: "ausTARGET",
		TargetResourceURL:     "api://sentinel-tasking",
		Scopes:                []string{"task.read"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IDJAG != "the.id.jag" {
		t.Errorf("IDJAG = %q", res.IDJAG)
	}
	if res.AccessToken != "the.access.token" {
		t.Errorf("AccessToken = %q", res.AccessToken)
	}
	if time.Until(res.ExpiresAt) < 50*time.Minute {
		t.Errorf("ExpiresAt = %v, expected roughly an hour out from expires_in 3600", res.ExpiresAt)
	}
}
