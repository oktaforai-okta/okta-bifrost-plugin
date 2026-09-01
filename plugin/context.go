package oktabifrost

import (
	"errors"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

// errNoSubjectToken is returned when the caller presented no identity-provider token.
//
// This is a deny, not a fallback. Without a caller token there is nothing to delegate
// from, so any token minted would represent the agent acting on its own authority,
// which is a different and much broader grant than the one being requested.
var errNoSubjectToken = errors.New(
	"no caller identity token on this request: the MCP client must send its " +
		"identity-provider access token as an Authorization: Bearer header to the gateway",
)

// subjectTokenFrom extracts the caller's identity-provider access token from the Bifrost
// context, for use as the subject of the token exchange.
//
// Two sources are tried, in order of how much they ought to be the right one.
//
// BifrostContextKeyMCPInboundBearer is the key whose declaration says "the caller's
// validated identity-provider token, used as the subject of delegated token exchange".
// That is exactly our use case, so it is tried first. But on an open-source Bifrost it is
// never populated: nothing writes it outside tests, and both of its readers are admin
// console handlers for verifying an MCP client's OAuth configuration, where the subject is
// explicitly "the signed-in admin's own identity-provider token". So it is a key scoped to
// an authenticated dashboard session, not to callers on the /mcp data path. Verified
// empirically: absent at every hook, in every configuration tried, including when the
// caller demonstrably sent an Authorization header. Whether a non-OSS auth layer populates
// it is untested, which is why it is still checked first rather than dropped.
//
// BifrostContextKeyRequestHeaders is the source that actually works. It carries every
// request header with lowercased keys, needs no configuration at all, and was confirmed to
// round-trip the caller's token intact.
//
// Note the deliberate choice NOT to read BifrostContextKeyMCPExtraHeaders, which also
// carries the header but only when `allowed_extra_headers` includes it. Allowing it there
// additionally forwards the caller's raw token to the upstream MCP server, which is a
// credential leak we have no reason to accept: this plugin wants to READ the caller's token
// as an exchange subject, not pass it on. Reading from request headers keeps the caller's
// credential inside the gateway.
//
// The value is a live credential. It is never logged, never placed in an error message,
// and never returned to the caller.
func subjectTokenFrom(ctx *schemas.BifrostContext) (string, error) {
	if ctx == nil {
		return "", errNoSubjectToken
	}

	if tok, ok := bearerFromInboundKey(ctx); ok {
		return tok, nil
	}
	if tok, ok := bearerFromRequestHeaders(ctx); ok {
		return tok, nil
	}
	return "", errNoSubjectToken
}

// bearerFromInboundKey reads the purpose-built key, which is empty on OSS builds.
func bearerFromInboundKey(ctx *schemas.BifrostContext) (string, bool) {
	raw, ok := ctx.Value(schemas.BifrostContextKeyMCPInboundBearer).(string)
	if !ok {
		return "", false
	}
	return normaliseBearer(raw)
}

// bearerFromRequestHeaders reads the Authorization header off the inbound request.
// Keys are lowercased by Bifrost, so no case-insensitive lookup is needed.
func bearerFromRequestHeaders(ctx *schemas.BifrostContext) (string, bool) {
	headers, ok := ctx.Value(schemas.BifrostContextKeyRequestHeaders).(map[string]string)
	if !ok {
		return "", false
	}
	return normaliseBearer(headers["authorization"])
}

// normaliseBearer strips an optional Bearer prefix and rejects anything empty.
//
// The prefix is matched case-insensitively because the scheme is case-insensitive per
// RFC 7235, and a caller sending "bearer" lowercase should not silently fail closed in a
// way that looks like a missing header.
func normaliseBearer(raw string) (string, bool) {
	tok := strings.TrimSpace(raw)
	if tok == "" {
		return "", false
	}

	if scheme, rest, hasScheme := strings.Cut(tok, " "); hasScheme {
		// An explicit scheme is present. Only Bearer means anything here. A Basic or
		// Negotiate credential must not be smuggled into a token exchange as though it
		// were a bearer token, so anything else is refused outright rather than passed
		// through as an opaque value.
		if !strings.EqualFold(scheme, "bearer") {
			return "", false
		}
		tok = strings.TrimSpace(rest)
	} else if strings.EqualFold(tok, "bearer") {
		// "Bearer" with nothing after it is a scheme, not a credential. Worth handling
		// explicitly: trimming whitespace first turns "Bearer " into a bare word, which
		// a naive prefix check then mistakes for the token itself.
		return "", false
	}

	if tok == "" {
		return "", false
	}
	return tok, true
}
