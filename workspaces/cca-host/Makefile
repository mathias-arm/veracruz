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

QEMU ?= 0
ifeq ($(QEMU),1)
	COMPILERS = CC_x86_64_unknown_linux_gnu=gcc CC_aarch64_unknown_linux_gnu=gcc
	TARGET =
	QEMU_FEATURE = --features veracruz-server/icecap-qemu
else
	COMPILERS = CC_aarch64_unknown_linux_gnu=/usr/bin/aarch64-linux-gnu-gcc \
		LD_aarch64_unknown_linux_gnu=/usr/bin/aarch64-linux-gnu-gcc
	TARGET = --target aarch64-unknown-linux-gnu
	QEMU_FEATURE = --features veracruz-server/icecap-lkvm
endif

TEST_PARAMETERS = VERACRUZ_POLICY_DIR=$(OUT_DIR) \
	VERACRUZ_TRUST_DIR=$(OUT_DIR) \
	VERACRUZ_PROGRAM_DIR=$(OUT_DIR) \
	VERACRUZ_DATA_DIR=$(OUT_DIR) \
	VERACRUZ_CCA_KERNEL_PATH=$(WORKSPACE_DIR)/cca-runtime/Image.guest \
	VERACRUZ_CCA_INITRD_PATH=$(RUNTIME_ENCLAVE_BINARY_PATH)

CLIPPY_OPTIONS = --no-deps -A clippy::type_complexity -A clippy::module_inception -D warnings

all: build test-collateral

build:
	$(COMPILERS) \
		cargo build $(PROFILE_FLAG) $(V_FLAG) $(TARGET) \
		-p proxy-attestation-server \
		-p veracruz-client -p veracruz-server \
		--features proxy-attestation-server/cca \
		--features veracruz-client/cca \
		--features veracruz-server/cca \
		--features veracruz-server/vsock \
		--features cli $(QEMU_FEATURE)

install:
	# create full names
	cp -f target/$(PROFILE_PATH)/proxy-attestation-server $(BIN_DIR)
	cp -f target/$(PROFILE_PATH)/veracruz-client $(BIN_DIR)
	cp -f target/$(PROFILE_PATH)/veracruz-server $(BIN_DIR)
	# create short names
	ln -sf $(BIN_DIR)/proxy-attestation-server $(BIN_DIR)/vc-pas
	ln -sf $(BIN_DIR)/veracruz-server $(BIN_DIR)/vc-server
	ln -sf $(BIN_DIR)/veracruz-client $(BIN_DIR)/vc-client

test-dependencies: test-collateral $(RUNTIME_ENCLAVE_BINARY_PATH)

CARGO_TEST = RUNTIME_ENCLAVE_BINARY_PATH=$(RUNTIME_ENCLAVE_BINARY_PATH) \
	$(COMPILERS) \
	$(TEST_PARAMETERS) \
		cargo test $(PROFILE_FLAG) $(TARGET) \
			--features cca --features veracruz-server/vsock $(QEMU_FEATURE)

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
	$(MAKE) -C ../cca-runtime QEMU=$(QEMU) cca

clippy: $(RUNTIME_ENCLAVE_BINARY_PATH)
	# workspace members and relevant dependencies
	$(COMPILERS) \
		cargo clippy $(PROFILE_FLAG) $(V_FLAG) \
		-p proxy-attestation-server -p veracruz-client \
		-p veracruz-server -p io-utils -p transport-protocol \
		-p psa-attestation -p veracruz-utils  \
		--features proxy-attestation-server/cca \
		--features veracruz-client/cca \
		--features veracruz-server/cca \
		--features io-utils/cca \
		--features psa-attestation/cca \
		--features veracruz-utils/cca \
		-- $(CLIPPY_OPTIONS)
	# workspace testing crates
	$(COMPILERS) $(TEST_PARAMETERS) \
		cargo clippy --tests \
		$(PROFILE_FLAG) -p tests \
		--features veracruz-test/cca \
		--features veracruz-server-test/cca \
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
