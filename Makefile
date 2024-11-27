.PHONY: help
help: ## Displays this help
	@awk 'BEGIN {FS = ":.*##"; printf "$(MAKEFILE_NAME)\nUsage:\n  make \033[1;36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[1;36m%-25s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the project
	cd crates/shielder-circuits
	@cargo build --release

.PHONY: test
test: ## Run tests
	cd crates/shielder-circuits
	@cargo test --release

.PHONY: bench
bench: ## Run benches
	cd crates/shielder-circuits
	@cargo bench

.PHONY: lint
lint: ## Run fmt and clippy
	cd crates/shielder-circuits
	@cargo +nightly fmt --all
	@cargo clippy --release -- -D warnings
