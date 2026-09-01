package oktabifrost

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client is the default OktaClient, speaking to an Okta org over HTTPS.
//
// It deliberately depends on nothing outside the standard library. Native Go plugins
// are .so shared objects that must match the host binary on every shared dependency,
// so each library this plugin adds is another way for it to refuse to load inside
// someone else's Bifrost build. That is why the JWT signing below is hand-rolled
// rather than pulled from a JWT package: RS256 is a SHA-256 hash and a PKCS#1 v1.5
// signature, which crypto/rsa already provides.
type Client struct {
	domain  string
	agentID string
	key     *rsa.PrivateKey
	keyID   string
	http    *http.Client
}

// NewClient builds a Client from the plugin config. The private key is parsed once,
// at construction, so a malformed key fails at startup rather than on first use.
func NewClient(cfg Config) (*Client, error) {
	raw := cfg.PrivateKeyJWK
	source := "private_key_jwk"

	if f := strings.TrimSpace(cfg.PrivateKeyJWKFile); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("okta plugin: private_key_jwk_file %q: %w", f, err)
		}
		raw = string(b)
		source = "private_key_jwk_file " + f
	}

	key, kid, err := parseRSAPrivateJWK(raw)
	if err != nil {
		return nil, fmt.Errorf("okta plugin: %s: %w", source, err)
	}
	return &Client{
		domain:  strings.TrimSuffix(cfg.OktaDomain, "/"),
		agentID: cfg.AgentID,
		key:     key,
		keyID:   kid,
		http:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// orgTokenEndpoint is where the ID-JAG is minted. Note the absence of an
// authorization server id in the path: this is the org authorization server, and it is
// the only place an ID-JAG can be obtained. Exchanging at a custom authorization
// server instead is the mistake that makes a gateway look like it supports delegation
// when it only supports a single hop.
func (c *Client) orgTokenEndpoint() string {
	return fmt.Sprintf("https://%s/oauth2/v1/token", c.domain)
}

// casTokenEndpoint is the target custom authorization server's token endpoint, where
// the ID-JAG is redeemed for the access token that actually goes upstream.
func (c *Client) casTokenEndpoint(authorizationServerID string) string {
	return fmt.Sprintf("https://%s/oauth2/%s/v1/token", c.domain, authorizationServerID)
}

// casIssuer is the audience value naming the target authorization server on the
// ID-JAG request.
func (c *Client) casIssuer(authorizationServerID string) string {
	return fmt.Sprintf("https://%s/oauth2/%s", c.domain, authorizationServerID)
}

// ExchangeResult carries both artifacts the exchange produces, not just the one that
// goes on the wire.
//
// The ID-JAG matters to anyone trying to understand or debug a delegation: it is the
// assertion that actually asserts the delegation, and the access token is only what that
// assertion was redeemed for. Discarding it means a failure at redemption cannot be told
// apart from a failure at exchange by inspection, and an operator has no way to see what
// was asserted on their behalf.
//
// Both fields are live credentials. Do not log them.
type ExchangeResult struct {
	// IDJAG is the short-lived, single-use assertion from the org authorization server.
	IDJAG string

	// AccessToken is what the target authorization server issued for it, and the only
	// one of the two that is sent upstream.
	AccessToken string

	// ExpiresAt applies to AccessToken.
	ExpiresAt time.Time
}

// Exchange runs the two agent-side steps and returns both artifacts.
// See the OktaClient interface for why step one happens elsewhere.
//
// PARTIAL RESULT ON ERROR: when the assertion is obtained but redemption fails, this
// returns a non-nil result carrying only IDJAG, alongside the error. That is deliberate.
// Redemption failing is the case where seeing the assertion matters most, because it is
// the difference between "Okta would not assert this delegation" and "Okta asserted it and
// the target authorization server refused to honour it", which are different problems with
// different fixes. Discarding it forces a caller to infer that the exchange succeeded
// rather than show what was actually asserted.
//
// So: on a non-nil error, the result may be nil or partial. Check the error first, and
// treat AccessToken as present only when err is nil. Never treat a non-nil result as
// success.
func (c *Client) Exchange(subjectToken string, b Binding) (*ExchangeResult, error) {
	idJAG, err := c.exchangeForIDJAG(subjectToken, b)
	if err != nil {
		// Nothing was asserted, so there is no partial result to hand back.
		return nil, err
	}

	token, expiresIn, err := c.redeemIDJAG(idJAG, b)
	if err != nil {
		return &ExchangeResult{IDJAG: idJAG}, err
	}

	return &ExchangeResult{
		IDJAG:       idJAG,
		AccessToken: token,
		ExpiresAt:   time.Now().Add(time.Duration(expiresIn) * time.Second),
	}, nil
}

// MintResourceToken satisfies OktaClient. It is the narrow form the hooks use, which only
// ever needs the token that goes upstream. Callers that want to show or inspect the
// delegation should use Exchange instead.
func (c *Client) MintResourceToken(subjectToken string, b Binding) (string, time.Time, error) {
	res, err := c.Exchange(subjectToken, b)
	if err != nil {
		return "", time.Time{}, err
	}
	return res.AccessToken, res.ExpiresAt, nil
}

// exchangeForIDJAG is step two: the caller's token becomes an ID-JAG assertion
// targeting the binding's authorization server and resource.
//
// audience selects which authorization server should honour the assertion, and must be
// the server's ISSUER url (https://domain/oauth2/{asId}), not its token endpoint.
//
// PARTLY SETTLED: whether `resource` belongs on this request at all.
//
// Okta's published docs mention `resource` exactly once, on the client_credentials call
// that produces the caller's token, and omit it from every documented parameter table
// for this exchange. By those docs the final token's aud comes from the audience
// configured on the target authorization server in the Admin Console.
//
// Against that: a live, working implementation in a sibling tenant sends `resource`
// here, and its issued tokens carried an aud matching the resource url rather than the
// authorization server's configured audiences value.
//
// WHAT IS NOW OBSERVED, from decoding real tokens issued through this code:
// the access token's aud is exactly the `resource` value sent here. Verified repeatedly
// against this tenant.
//
// WHY THAT DOES NOT YET SETTLE IT, which is the trap to avoid: the two bindings in the
// reference demo share ONE authorization server, so if that server's configured
// audiences happens to hold the same string, both candidate sources predict the same
// aud and the observation cannot distinguish them. Matching aud is therefore consistent
// with `resource` being authoritative, but is not proof of it.
//
// TO ACTUALLY SETTLE IT, do one of:
//   - read the target authorization server's configured `audiences` and check whether it
//     differs from the resource url. If it differs and aud still matches resource, then
//     resource is authoritative and this comment can go.
//   - or send a resource url that the server's audiences value does NOT contain, on a
//     connection that permits it, and see which one aud follows.
//
// Until then the parameter stays. Removing a parameter that a verified-working
// implementation includes, on the strength of documentation alone, is the worse risk,
// and an unrecognised parameter is normally ignored.
func (c *Client) exchangeForIDJAG(subjectToken string, b Binding) (string, error) {
	assertion, err := c.clientAssertion(c.orgTokenEndpoint())
	if err != nil {
		return "", err
	}

	form := url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":         {subjectToken},
		"subject_token_type":    {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type":  {"urn:ietf:params:oauth:token-type:id-jag"},
		"audience":              {c.casIssuer(b.AuthorizationServerID)},
		"resource":              {b.TargetResourceURL},
		"scope":                 {strings.Join(b.Scopes, " ")},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}

	var out tokenResponse
	if err := c.post(c.orgTokenEndpoint(), form, &out); err != nil {
		return "", fmt.Errorf("id-jag exchange: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("id-jag exchange returned no assertion")
	}
	return out.AccessToken, nil
}

// redeemIDJAG is step three: the assertion is redeemed at the target authorization
// server for the access token that carries the nested act chain.
func (c *Client) redeemIDJAG(idJAG string, b Binding) (string, int, error) {
	endpoint := c.casTokenEndpoint(b.AuthorizationServerID)

	// The assertion audience is the endpoint being called, so it differs from step two.
	assertion, err := c.clientAssertion(endpoint)
	if err != nil {
		return "", 0, err
	}

	form := url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":             {idJAG},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}

	var out tokenResponse
	if err := c.post(endpoint, form, &out); err != nil {
		return "", 0, fmt.Errorf("id-jag redemption: %w", err)
	}
	if out.AccessToken == "" {
		return "", 0, fmt.Errorf("id-jag redemption returned no access token")
	}

	expiresIn := out.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 300
	}
	return out.AccessToken, expiresIn, nil
}

type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	IssuedTokenType string `json:"issued_token_type"`
	Scope           string `json:"scope"`
}

// OktaError carries Okta's own refusal verbatim. Okta's messages are more precise than
// anything this plugin could invent, and they are what makes a denial legible: the
// difference between "the scopes are not allowed for this request" and "'resource' is
// invalid or not supported" is the difference between a permission decision and a
// misconfiguration, and only Okta knows which one happened.
type OktaError struct {
	StatusCode  int
	Code        string
	Description string
}

func (e *OktaError) Error() string {
	switch {
	case e.Description != "" && e.Code != "":
		return fmt.Sprintf("%s: %s (HTTP %d)", e.Code, e.Description, e.StatusCode)
	case e.Code != "":
		return fmt.Sprintf("%s (HTTP %d)", e.Code, e.StatusCode)
	default:
		return fmt.Sprintf("okta returned HTTP %d", e.StatusCode)
	}
}

// post submits a form-encoded request and decodes either the success body or Okta's
// error body. The request body is never logged: it carries a live subject token.
func (c *Client) post(endpoint string, form url.Values, out any) error {
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Identifies this plugin in Okta's system log, so an operator can tell which
	// component made a call without correlating by timestamp.
	req.Header.Set("User-Agent", "okta-bifrost-plugin/0.1")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)

	if resp.StatusCode >= 400 {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
			ErrorCode   string `json:"errorCode"`
			Summary     string `json:"errorSummary"`
		}
		// A body that will not decode is not worth failing differently on; the status
		// code alone is still a usable answer.
		_ = dec.Decode(&e)

		code := e.Error
		if code == "" {
			code = e.ErrorCode
		}
		desc := e.Description
		if desc == "" {
			desc = e.Summary
		}
		return &OktaError{StatusCode: resp.StatusCode, Code: code, Description: desc}
	}

	return dec.Decode(out)
}

// clientAssertion builds the private_key_jwt this agent authenticates with.
//
// iss and sub are both the agent's workload principal id, and aud is the endpoint
// being called, which is why a fresh assertion is needed for each step of the
// exchange rather than one reused across both.
func (c *Client) clientAssertion(audience string) (string, error) {
	now := time.Now()

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	if c.keyID != "" {
		header["kid"] = c.keyID
	}

	jti, err := randomID()
	if err != nil {
		return "", err
	}

	claims := map[string]any{
		"iss": c.agentID,
		"sub": c.agentID,
		"aud": audience,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := b64(headerJSON) + "." + b64(claimsJSON)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing client assertion: %w", err)
	}

	return signingInput + "." + b64(sig), nil
}

func b64(in []byte) string {
	return base64.RawURLEncoding.EncodeToString(in)
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// rsaPrivateJWK is the subset of a JWK needed to reconstruct an RSA private key.
type rsaPrivateJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	D   string `json:"d"`
	P   string `json:"p"`
	Q   string `json:"q"`
}

// parseRSAPrivateJWK turns an RSA private JWK into an *rsa.PrivateKey.
//
// Only n, e, d, p and q are read. The CRT precomputed values (dp, dq, qi) are
// recomputed rather than trusted from the JWK, so a JWK with stale or wrong
// precomputed values cannot produce silently invalid signatures.
func parseRSAPrivateJWK(raw string) (*rsa.PrivateKey, string, error) {
	var jwk rsaPrivateJWK
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &jwk); err != nil {
		return nil, "", fmt.Errorf("not valid JSON: %w", err)
	}
	if jwk.Kty != "" && jwk.Kty != "RSA" {
		return nil, "", fmt.Errorf("unsupported key type %q, expected RSA", jwk.Kty)
	}
	if jwk.D == "" {
		return nil, "", fmt.Errorf("missing private exponent: this looks like a public key, the agent's PRIVATE key is required")
	}

	n, err := b64uint(jwk.N)
	if err != nil {
		return nil, "", fmt.Errorf("field n: %w", err)
	}
	e, err := b64uint(jwk.E)
	if err != nil {
		return nil, "", fmt.Errorf("field e: %w", err)
	}
	d, err := b64uint(jwk.D)
	if err != nil {
		return nil, "", fmt.Errorf("field d: %w", err)
	}
	p, err := b64uint(jwk.P)
	if err != nil {
		return nil, "", fmt.Errorf("field p: %w", err)
	}
	q, err := b64uint(jwk.Q)
	if err != nil {
		return nil, "", fmt.Errorf("field q: %w", err)
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	if err := key.Validate(); err != nil {
		return nil, "", fmt.Errorf("key failed validation: %w", err)
	}
	key.Precompute()

	return key, jwk.Kid, nil
}

func b64uint(s string) (*big.Int, error) {
	if s == "" {
		return nil, fmt.Errorf("is empty")
	}
	// JWK uses base64url without padding.
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, fmt.Errorf("is not valid base64url: %w", err)
	}
	return new(big.Int).SetBytes(raw), nil
}

// Compile-time proof the default client satisfies the interface.
var _ OktaClient = (*Client)(nil)
