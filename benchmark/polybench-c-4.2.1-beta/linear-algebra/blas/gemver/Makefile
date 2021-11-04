include ../../../config.mk

EXTRA_FLAGS=

gemver: gemver.c gemver.h
	${VERBOSE} ${WASM_CC} -o gemver.wasm gemver.c ${CFLAGS} -I. -I../../../utilities ../../../utilities/polybench.c ${EXTRA_FLAGS}
	${VERBOSE} ${CC} -o gemver gemver.c ${CFLAGS} -I. -I../../../utilities ../../../utilities/polybench.c ${EXTRA_FLAGS}

clean:
	@ rm -f gemver gemver.wasm

