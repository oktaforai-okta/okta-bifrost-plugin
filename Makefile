# Bifrost loads native Go plugins as .so shared objects, and Go refuses to load one
# unless the plugin and the host binary agree on the Go version AND on every shared
# dependency version. Building on a developer's local toolchain is therefore the single
# most common reason a plugin silently fails to load.
#
# So the build runs in a pinned container. GO_IMAGE is the one knob that matters: set it
# to match the Go version of the Bifrost build you are loading into. Bifrost core v1.8.4
# declares go 1.27.0.
#
# Nothing here needs a local Go install.

GO_IMAGE     ?= golang:1.27
PLUGIN_NAME  ?= okta-agent-identity

# BIFROST_CORE must equal the core version the target Bifrost binary was built with,
# not merely a compatible-looking one. Go plugin loading compares every shared
# dependency, so core v1.8.4 against a v1.8.3 host fails to load.
#
# Do not guess this. Run `make compat` and it will tell you.
BIFROST_CORE  ?= v1.8.3
BIFROST_IMAGE ?= maximhq/bifrost:latest

# A .so must match the host's ARCHITECTURE as well as its Go version. Docker on Apple
# Silicon defaults to arm64, which will not load into an amd64 Bifrost. Set PLATFORM to
# match wherever Bifrost runs:
#
#   make plugin PLATFORM=linux/amd64   # most EC2, ECS on x86
#   make plugin PLATFORM=linux/arm64   # Graviton, or local arm64 testing
#
# The artifact name carries the arch so two builds cannot be confused for each other.
PLATFORM ?= linux/amd64
ARCH      = $(notdir $(PLATFORM))
OUT      ?= bin/$(PLUGIN_NAME)-$(ARCH).so

DOCKER ?= docker
RUN     = $(DOCKER) run --rm --platform $(PLATFORM) -v "$(CURDIR)":/src -w /src $(GO_IMAGE)

.DEFAULT_GOAL := check

.PHONY: check
check: fmt-check vet test ## Run every check the CI would

.PHONY: plugin
plugin: ## Build the loadable .so into bin/
	@mkdir -p bin
	$(RUN) go build -buildmode=plugin -trimpath -o $(OUT) .
	@echo "built $(OUT)"
	@echo "load it by pointing a Bifrost plugin config entry's 'path' at this file"

.PHONY: test
test: ## Run the test suite
	$(RUN) go test ./...

.PHONY: test-v
test-v: ## Run the test suite verbosely
	$(RUN) go test -v ./...

.PHONY: race
race: ## Run tests under the race detector (the verdict cache is read concurrently)
	$(RUN) go test -race ./...

.PHONY: vet
vet: ## Static analysis
	$(RUN) go vet ./...

.PHONY: fmt
fmt: ## Format in place
	$(RUN) gofmt -w .

.PHONY: fmt-check
fmt-check: ## Fail if anything is unformatted
	@out=$$($(RUN) gofmt -l .); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

.PHONY: tidy
tidy: ## Reconcile go.mod / go.sum
	$(RUN) go mod tidy

.PHONY: compat
compat: ## Report which bifrost/core version $(BIFROST_IMAGE) requires
	@echo "inspecting $(BIFROST_IMAGE) ..."
	@cid=$$(docker create $(BIFROST_IMAGE)) ; \
	tmp=$$(mktemp -d) ; \
	docker cp "$$cid:/app/main" "$$tmp/main" >/dev/null 2>&1 || { \
		echo "could not find /app/main in the image; adjust the path in this target" >&2 ; \
		docker rm -f "$$cid" >/dev/null ; exit 1 ; } ; \
	docker rm -f "$$cid" >/dev/null ; \
	$(DOCKER) run --rm --platform $(PLATFORM) -v "$$tmp":/x $(GO_IMAGE) \
		sh -c 'echo "  go:   $$(go version -m /x/main | head -1 | awk "{print \$$2}")"; \
		       echo "  core: $$(go version -m /x/main | grep "bifrost/core" | awk "{print \$$3}")"' ; \
	rm -rf "$$tmp" ; \
	echo ; \
	echo "Set BIFROST_CORE to the core version above, then: make pin && make plugin"

.PHONY: pin
pin: ## Re-pin bifrost/core to $(BIFROST_CORE)
	$(RUN) go get github.com/maximhq/bifrost/core@$(BIFROST_CORE)
	$(RUN) go mod tidy
	@echo "pinned bifrost/core to $(BIFROST_CORE); rebuild the plugin and re-run tests"

.PHONY: clean
clean: ## Remove build output
	rm -rf bin

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
