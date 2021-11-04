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

all: bubble_sort

bubble_sort: bubble_sort.cpp
	$(CXX) $(CFLAGS) $< -o $@
	$(WASM_CXX) $(CFLAGS) $< -o $@.wasm
