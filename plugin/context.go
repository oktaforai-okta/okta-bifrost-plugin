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
	"no caller identity token on the request: the MCP client must present its " +
		"identity-provider access token, which requires the Bifrost client to be in " +
		"'headers' or 'both' auth mode rather than 'oauth' mode",
)

// subjectTokenFrom extracts the caller's identity-provider access token from the
// Bifrost context, for use as the subject of the token exchange.
//
// Bifrost stamps this on BifrostContextKeyMCPInboundBearer via its upstream auth
// layer. Two constraints carried over from Bifrost's own implementation notes:
//
//   - It must be a genuine OAuth access token, not an ID token. Okta rejects an ID
//     token as a type mismatch when declared access_token, and rejects the id_token
//     subject type outright at a custom authorization server. The org authorization
//     server does accept an ID token subject, but that is the human-delegated path,
//     not the machine one this plugin implements.
//
//   - The value is a live credential. It is never logged, never placed in an error
//     message, and never returned to the caller.
func subjectTokenFrom(ctx *schemas.BifrostContext) (string, error) {
	if ctx == nil {
		return "", errNoSubjectToken
	}

	raw := ctx.Value(schemas.BifrostContextKeyMCPInboundBearer)
	if raw == nil {
		return "", errNoSubjectToken
	}

	token, ok := raw.(string)
	if !ok {
		return "", errNoSubjectToken
	}

	token = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(token), "Bearer "))
	if token == "" {
		return "", errNoSubjectToken
	}

	return token, nil
}
