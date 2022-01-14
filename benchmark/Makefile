# XXX: This is a WIP

# wasi sdk toolchain
WASI_SDK_SYSROOT=$(WASI_SDK_ROOT)/share/wasi-sysroot
CLANG_FLAGS=--target=wasm32-wasi
WASM_CC=$(WASI_SDK_ROOT)/bin/clang --sysroot=$(WASI_SDK_SYSROOT) $(CLANG_FLAGS)
WASM_CXX=$(WASI_SDK_ROOT)/bin/clang++ --sysroot=$(WASI_SDK_SYSROOT) $(CLANG_FLAGS)

CFLAGS=-Wall -Wno-unused-result -Wno-unknown-pragmas -Wfatal-errors -Wno-writable-strings -fPIC -D_WASI_EMULATED_PROCESS_CLOCKS
#OPTS=-Ofast
OPTS=-O0 -g
CFLAGS+=$(OPTS)
LDFLAGS= -lm -lwasi-emulated-process-clock

all: build

build-environments: veracruz wasmtime-upstream wasmtime-veracruz 

build-workloads: polybench-c deep-learning-server video-object-detection


# Environments
##########################################################
veracruz:
	cd ../veracruz/sdk/freestanding-execution-engine/ && cargo build

wasmtime-upstream:
	cd ../wasmtime-upstream && cargo +nightly build --release

wasmtime-veracruz:
	cd ../wasmtime-veracruz && cargo +nightly build --release


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


benchmarking-build:
	DOCKER_BUILDKIT=1 docker build --build-arg USER=root --build-arg UID=0 --build-arg ARCH=$(shell uname -m) -t veracruz_benchmarking .

benchmarking-run: benchmarking-build
	docker run --init --rm --privileged -d \
		-v $(abspath .):/work/benchmark \
		-v $(abspath ..):/work/veracruz \
		-v $(abspath .)/wasmtime-0.27:/work/wasmtime-veracruz \
        	-v /usr/bin:/host/bin \
		-v $(HOME)/.cargo/registry/:/usr/local/cargo/registry \
        	-v /var/run/docker.sock:/var/run/docker.sock \
        	--name veracruz_benchmarking_test veracruz_benchmarking sleep inf

benchmarking-exec:
	docker exec -it veracruz_benchmarking_test /bin/bash

