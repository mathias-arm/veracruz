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

.PHONY: all clean clean-cargo-lock doc fmt clippy cca runtime-manager-enclave

default: all

WORKSPACE_DIR = $(abspath ..)

include $(WORKSPACE_DIR)/common.mk

all: cca

cca: runtime-manager-enclave initrd.cpio

COMPILERS = CC_aarch64_unknown_linux_musl=/work/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc \
	LD_aarch64_unknown_linux_musl=/work/aarch64-linux-musl-cross/bin/aarch64-linux-musl-ld

initrd.cpio: runtime-manager-enclave
	rm -rf initrd initrd.cpio
	mkdir initrd
	cp target/aarch64-unknown-linux-musl/$(PROFILE_PATH)/init initrd/init
	/work/aarch64-linux-musl-cross/bin/aarch64-linux-musl-strip initrd/init
	(cd initrd ; echo -n init | cpio --null --create -V --format=newc -O ../initrd.cpio)
	rm -rf initrd

.PHONY: run

run: cca Image
	qemu-system-aarch64 -machine virt -cpu cortex-a57 -smp 4 -m 3072 \
		-device vhost-vsock-pci,guest-cid=3 \
		-netdev user,id=netdev0 \
		-serial mon:stdio -nographic \
		-semihosting-config enable=on,target=native \
		-chardev socket,path=./socket,server=on,wait=off,id=charconsole0 \
    	-device virtio-serial-device -device virtconsole,chardev=charconsole0,id=console0 \
		-kernel Image.guest -initrd initrd.cpio

runtime-manager-enclave:
	rustup target add aarch64-unknown-linux-musl
	$(COMPILERS) cargo build $(PROFILE_FLAG) $(V_FLAG) \
		--target aarch64-unknown-linux-musl \
		--features cca --features vsock -p init

doc:
	cargo doc

clippy:
	cargo clippy $(PROFILE_FLAG) $(V_FLAG) \
		-p runtime_manager_enclave -p execution-engine \
		-p session-manager -p policy-utils -p platform-services \
		--features runtime_manager_enclave/cca \
		--features execution-engine/std \
		--features session-manager/std \
		--features policy-utils/std \
		--features platform-services/std \
		-- --no-deps

fmt:
	cargo fmt

clean:
	@cargo clean

clean-cargo-lock:
	rm -f Cargo.lock
