# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root director for licensing
# and copyright information.

.PHONY: all clean clean-cargo-lock default doc fmt clippy nitro test-collateral runtime-manager-enclave

default: all

WORKSPACE_DIR = $(abspath ..)
OUT_DIR ?= $(WORKSPACE_DIR)/nitro-host/test-collateral
ARCH = $(shell uname -m)

include $(WORKSPACE_DIR)/common.mk
include $(WORKSPACE_DIR)/shared.mk

all: nitro

nitro: runtime_manager.eif PCR0

PCR0: runtime_manager.eif
	cat measurements.json | jq -r '.Measurements.PCR0' > PCR0

runtime_manager.eif: target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/runtime-manager-enclave crates/runtime-manager/dockerdir/Dockerfile
	rm -rf docker
	mkdir -p docker
	cp target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/runtime-manager-enclave docker
	cp crates/runtime-manager/dockerdir/Dockerfile docker
	perl -i -pe "s/x86_64/$(ARCH)/" docker/Dockerfile
	nitro-cli build-enclave --docker-dir docker --docker-uri runtime_manager --output-file runtime_manager.eif > measurements.json
	rm -rf docker

target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/runtime-manager-enclave: runtime-manager-enclave

runtime-manager-enclave:
	rustup target add $(ARCH)-unknown-linux-musl
	cargo build --target $(ARCH)-unknown-linux-musl $(PROFILE_FLAG) $(V_FLAG)
	strip target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/runtime-manager-enclave

doc:
	cargo doc

clippy:
	rustup target add $(ARCH)-unknown-linux-musl
	cargo clippy --target $(ARCH)-unknown-linux-musl $(PROFILE_FLAG) $(V_FLAG) \
		-p nitro-runtime -p runtime-manager -p execution-engine \
		-p session-manager -p policy-utils -p platform-services \
		-- --no-deps

fmt:
	cargo fmt

clean:
	@cargo clean
	@rm -f PCR0

clean-cargo-lock:
	rm -f Cargo.lock
