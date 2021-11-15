# XXX: This is a WIP

# wasi sdk toolchain
WASI_SDK_SYSROOT=$(WASI_SDK_ROOT)/share/wasi-sysroot
CLANG_FLAGS=--target=wasm32-wasi
WASM_CC=$(WASI_SDK_ROOT)/bin/clang --sysroot=$(WASI_SDK_SYSROOT) $(CLANG_FLAGS)
WASM_CXX=$(WASI_SDK_ROOT)/bin/clang++ --sysroot=$(WASI_SDK_SYSROOT) $(CLANG_FLAGS)

CFLAGS=-Wall -Wno-unused-result -Wno-unknown-pragmas -Wfatal-errors -Wno-writable-strings -fPIC
#OPTS=-Ofast
OPTS=-O0 -g
CFLAGS+=$(OPTS)
LDFLAGS= -lm

all: build

build-environments: veracruz wasmtime-upstream wasmtime-veracruz 

build-workloads: polybench-c deep-learning-server video-object-detection


# Environments
##########################################################
veracruz:
	cd veracruz/sdk/freestanding-execution-engine/ && cargo build

wasmtime-upstream:
	cd wasmtime-upstream && cargo +nightly build --release

wasmtime-veracruz:
	cd wasmtime-veracruz && cargo +nightly build --release


# Workloads
##########################################################
polybench-c:
	cd polybench-c-4.2.1-beta && perl utilities/make-all.pl .

deep-learning-server:
	cd veracruz-examples/deep-learning-server && make

video-object-detection:
	cd veracruz-examples/video-object-detection && git submodule update --init && make && make yolo_detection


##########################################################
run-polybench-c:
	cd polybench-c-4.2.1-beta
