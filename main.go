// Command okta-agent-identity is the loadable Bifrost plugin.
//
// Bifrost's .so loader resolves free functions by name rather than a type satisfying
// an interface, so this file is a thin shim: it exports the symbols the loader looks
// up and forwards them to the implementation in ./plugin, which is an ordinary,
// testable package with no plugin machinery in it.
//
// The exported signatures here must match what framework/plugins/soloader.go type
// asserts, exactly. A mismatch is not a compile error: the loader fails at runtime
// with "failed to cast <symbol> to expected signature". The var block below pins each
// signature at build time so that cannot happen silently.
//
// Build with `make plugin`, never a local toolchain. See the Makefile for why.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/maximhq/bifrost/core/schemas"

	oktabifrost "github.com/oktaforai-okta/okta-bifrost-plugin/plugin"
)

// instance is set by Init and read by every hook. Bifrost calls Init once, before any
// hook, so this needs no locking of its own; the plugin's internal state is guarded.
var instance *oktabifrost.Plugin

// Compile-time assertions that each exported symbol has the signature the loader
// asserts. If Bifrost changes a hook shape, this fails the build here rather than
// failing to load in a customer's Bifrost.
var (
	_ func(config any) error = Init
	_ func() string          = GetName
	_ func() error           = Cleanup

	_ func(*schemas.BifrostContext, *schemas.BifrostMCPRequest) (*schemas.BifrostMCPRequest, *schemas.MCPPluginShortCircuit, error)                 = PreMCPHook
	_ func(*schemas.BifrostContext, *schemas.BifrostMCPResponse, *schemas.BifrostError) (*schemas.BifrostMCPResponse, *schemas.BifrostError, error) = PostMCPHook

	_ func(*schemas.BifrostContext, *schemas.BifrostMCPConnectRequest) (*schemas.BifrostMCPConnectRequest, *schemas.MCPConnectionShortCircuit, error)             = PreMCPConnectionHook
	_ func(*schemas.BifrostContext, *schemas.BifrostMCPConnectResponse, *schemas.BifrostError) (*schemas.BifrostMCPConnectResponse, *schemas.BifrostError, error) = PostMCPConnectionHook
)

// Init receives the `config` object from this plugin's entry in Bifrost's plugin
// configuration. It arrives as a decoded JSON value, so it is re-marshalled and
// decoded into a typed Config rather than reached into with type assertions.
//
// Every failure here is returned rather than tolerated. A plugin that loads with a
// broken config would fail open on the first tool call, which is the outcome this
// whole component exists to prevent.
func Init(config any) error {
	if config == nil {
		return fmt.Errorf("%s: no config supplied", oktabifrost.PluginName)
	}

	raw, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("%s: could not re-encode config: %w", oktabifrost.PluginName, err)
	}

	var cfg oktabifrost.Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // a typo in a key must not silently disable a setting
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("%s: invalid config: %w", oktabifrost.PluginName, err)
	}

	client, err := oktabifrost.NewClient(cfg)
	if err != nil {
		return err
	}

	p, err := oktabifrost.New(cfg, client)
	if err != nil {
		return err
	}

	instance = p
	return nil
}

// GetName is required by the loader.
func GetName() string { return oktabifrost.PluginName }

// Cleanup is required by the loader.
func Cleanup() error {
	if instance == nil {
		return nil
	}
	return instance.Cleanup()
}

// PreMCPConnectionHook mints the upstream token and attaches it to the connection.
func PreMCPConnectionHook(
	ctx *schemas.BifrostContext,
	req *schemas.BifrostMCPConnectRequest,
) (*schemas.BifrostMCPConnectRequest, *schemas.MCPConnectionShortCircuit, error) {
	if instance == nil {
		return req, refuseConnect(), nil
	}
	return instance.PreMCPConnectionHook(ctx, req)
}

// PostMCPConnectionHook passes the connect outcome through.
func PostMCPConnectionHook(
	ctx *schemas.BifrostContext,
	resp *schemas.BifrostMCPConnectResponse,
	bifrostErr *schemas.BifrostError,
) (*schemas.BifrostMCPConnectResponse, *schemas.BifrostError, error) {
	if instance == nil {
		return resp, bifrostErr, nil
	}
	return instance.PostMCPConnectionHook(ctx, resp, bifrostErr)
}

// PreMCPHook gates every tool call.
func PreMCPHook(
	ctx *schemas.BifrostContext,
	req *schemas.BifrostMCPRequest,
) (*schemas.BifrostMCPRequest, *schemas.MCPPluginShortCircuit, error) {
	if instance == nil {
		return req, refuseCall(), nil
	}
	return instance.PreMCPHook(ctx, req)
}

// PostMCPHook passes the tool result through.
func PostMCPHook(
	ctx *schemas.BifrostContext,
	resp *schemas.BifrostMCPResponse,
	bifrostErr *schemas.BifrostError,
) (*schemas.BifrostMCPResponse, *schemas.BifrostError, error) {
	if instance == nil {
		return resp, bifrostErr, nil
	}
	return instance.PostMCPHook(ctx, resp, bifrostErr)
}

// An uninitialised plugin denies rather than passes through. Reaching a hook with a nil
// instance means Init never ran or failed, and in that state nothing has authorized
// anything, so allowing the call would be worse than refusing it.
func uninitialised() *schemas.BifrostError {
	status := 403
	errType := "access_denied"
	code := "okta_plugin_uninitialised"
	allowFallbacks := false
	return &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &status,
		Type:           &errType,
		AllowFallbacks: &allowFallbacks,
		Error: &schemas.ErrorField{
			Type:    &errType,
			Code:    &code,
			Message: oktabifrost.PluginName + " is not initialised, so no call can be authorized. Check Bifrost's logs for a plugin Init failure.",
		},
	}
}

func refuseCall() *schemas.MCPPluginShortCircuit {
	return &schemas.MCPPluginShortCircuit{Error: uninitialised()}
}

func refuseConnect() *schemas.MCPConnectionShortCircuit {
	return &schemas.MCPConnectionShortCircuit{Error: uninitialised()}
}

func main() {
	// Required so the file is a main package, which -buildmode=plugin needs. Bifrost
	// loads the .so and calls the exported symbols; this never runs.
}
