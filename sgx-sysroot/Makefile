OUTDIR ?= out
SYSROOT_PATH = lib/rustlib/x86_64-unknown-linux-sgx/lib

all: $(OUTDIR)/$(SYSROOT_PATH)/libstd.rlib

$(OUTDIR)/$(SYSROOT_PATH)/libstd.rlib: target/x86_64-unknown-linux-sgx/release/libstd.rlib
	rm -rf $(OUTDIR)
	mkdir -p $(OUTDIR)/$(SYSROOT_PATH)
	cp -r target/x86_64-unknown-linux-sgx/release/deps/* $(OUTDIR)/$(SYSROOT_PATH)

target/x86_64-unknown-linux-sgx/release/libstd.rlib: x86_64-unknown-linux-sgx.json
	rustup component add rust-src
	perl -i -pe s/sgx/not_sgx/ x86_64-unknown-linux-sgx.json
	__CARGO_DEFAULT_LIB_METADATA=sgx \
	RUST_TARGET_PATH=$(abspath .) \
		cargo build --release --target x86_64-unknown-linux-sgx \
		-Z build-std=core,alloc
	perl -i -pe s/not_sgx/sgx/ x86_64-unknown-linux-sgx.json

x86_64-unknown-linux-sgx.json: ../runtime-manager/x86_64-unknown-linux-sgx.json
	cp ../runtime-manager/x86_64-unknown-linux-sgx.json $@

clean:
	cargo clean
	rm -rf x86_64-unknown-linux-sgx.json Cargo.lock $(OUTDIR)
