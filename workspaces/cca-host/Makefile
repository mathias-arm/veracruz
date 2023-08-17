# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.

.PHONY: all build install clean clean-cargo-lock default doc fmt clippy \
	test-dependencies test-collateral test-server test-client veracruz-test \
	tests

default: build

tests: test-server test-client veracruz-test

WORKSPACE_DIR = $(abspath ..)
include $(WORKSPACE_DIR)/common.mk

OUT_DIR ?= $(abspath test-collateral)
RUNTIME_ENCLAVE_BINARY_PATH = $(WORKSPACE_DIR)/cca-runtime/initrd.cpio
MEASUREMENT_FILE = $(RUNTIME_ENCLAVE_BINARY_PATH)
MEASUREMENT_PARAMETER = --css-file $(MEASUREMENT_FILE)
include $(WORKSPACE_DIR)/shared.mk

SIMULATION ?= 0
ifeq ($(SIMULATION),1)
	TARGET =--target $(shell uname -m)-unknown-linux-gnu
	SIMULATION_FEATURE = --features veracruz-server/simulation
endif

TEST_PARAMETERS = VERACRUZ_POLICY_DIR=$(OUT_DIR) \
	VERACRUZ_TRUST_DIR=$(OUT_DIR) \
	VERACRUZ_PROGRAM_DIR=$(OUT_DIR) \
	VERACRUZ_DATA_DIR=$(OUT_DIR) \
	VERACRUZ_CCA_KERNEL_PATH=$(WORKSPACE_DIR)/cca-runtime/Image \
	VERACRUZ_CCA_INITRD_PATH=$(RUNTIME_ENCLAVE_BINARY_PATH)

CLIPPY_OPTIONS = --no-deps -A clippy::type_complexity -A clippy::module_inception -D warnings

all: build test-collateral

build:
	cargo build $(PROFILE_FLAG) $(V_FLAG) $(TARGET) $(SIMULATION_FEATURE)

install:
	# create full names
	cp -f target/$(PROFILE_PATH)/veracruz-client $(BIN_DIR)
	cp -f target/$(PROFILE_PATH)/veracruz-server $(BIN_DIR)
	# create short names
	ln -sf $(BIN_DIR)/veracruz-server $(BIN_DIR)/vc-server
	ln -sf $(BIN_DIR)/veracruz-client $(BIN_DIR)/vc-client

test-dependencies: test-collateral $(RUNTIME_ENCLAVE_BINARY_PATH)

CARGO_TEST = RUNTIME_ENCLAVE_BINARY_PATH=$(RUNTIME_ENCLAVE_BINARY_PATH) \
	$(TEST_PARAMETERS) cargo test $(PROFILE_FLAG) $(TARGET) --features cca $(SIMULATION_FEATURE)

test-server: test-dependencies
	$(CARGO_TEST) -p tests --no-run -- --nocapture
	RUST_LOG="server_test=info,error" \
		$(CARGO_TEST) -p tests --test server_test -- --test-threads=1 --nocapture

test-client: test-dependencies
	$(CARGO_TEST) -p veracruz-client --lib -- --test-threads=1

veracruz-test: test-dependencies
	$(CARGO_TEST) -p tests --no-run
	RUST_LOG="integration_test=info,error" \
		$(CARGO_TEST) -p tests --test integration_test -- --test-threads=1

$(RUNTIME_ENCLAVE_BINARY_PATH):
	$(MAKE) -C ../cca-runtime SIMULATION=$(SIMULATION) cca

clippy: $(RUNTIME_ENCLAVE_BINARY_PATH)
	# workspace members and relevant dependencies
	$(COMPILERS) \
		cargo clippy $(PROFILE_FLAG) $(V_FLAG) \
		-p veracruz-client \
		-p veracruz-server -p io-utils -p transport-protocol \
		-p psa-attestation -p veracruz-utils  \
		-- $(CLIPPY_OPTIONS)
	# workspace testing crates
	$(COMPILERS) $(TEST_PARAMETERS) \
		cargo clippy --tests \
		$(PROFILE_FLAG) -p tests \
		-- $(CLIPPY_OPTIONS)

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean
	rm -rf $(OUT_DIR)

clean-cargo-lock:
	rm -f Cargo.lock
