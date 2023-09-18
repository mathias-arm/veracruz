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
FAKE_HOST ?= 0

ifeq ($(FAKE_HOST), 0)
    FAKE_HOST_FEATURE =
else
    FAKE_HOST_FEATURE = --features fake-host
endif

include $(WORKSPACE_DIR)/common.mk

all: cca

cca: cca-runtime-manager initrd.cpio

initrd.cpio: cca-runtime-manager
	rm -rf initrd initrd.cpio
	mkdir initrd
	cp target/aarch64-unknown-linux-musl/$(PROFILE_PATH)/init initrd/init
	/work/aarch64-linux-musl-cross/bin/aarch64-linux-musl-strip initrd/init
	(cd initrd ; echo -n init | cpio --null --create -V --format=newc -O ../initrd.cpio)
	rm -rf initrd

.PHONY: run

Image.guest:
	echo "Copy Image.guest file"
	/bin/false

run: cca Image.guest
	qemu-system-aarch64 -machine virt -cpu cortex-a57 -smp 4 -m 3072 \
		-serial mon:stdio -nographic -nic none \
		-semihosting-config enable=on,target=native \
		-chardev socket,path=./socket,server=on,wait=off,id=charconsole0 \
		-device virtio-serial-device -device virtconsole,chardev=charconsole0,id=console0 \
		-kernel Image.guest -initrd initrd.cpio

cca-runtime-manager:
	cargo build $(PROFILE_FLAG) $(V_FLAG) $(FAKE_HOST_FEATURE)

doc:
	cargo doc

clippy:
	cargo clippy $(PROFILE_FLAG) $(V_FLAG) \
		-p cca-runtime-manager -p runtime-manager -p execution-engine \
		-p session-manager -p policy-utils -p platform-services
		-- --no-deps

fmt:
	cargo fmt

clean:
	@cargo clean

clean-cargo-lock:
	rm -f Cargo.lock
