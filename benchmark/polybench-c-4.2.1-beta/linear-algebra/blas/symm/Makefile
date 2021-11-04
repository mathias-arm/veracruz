include ../../../config.mk

EXTRA_FLAGS=

symm: symm.c symm.h
	${VERBOSE} ${WASM_CC} -o symm.wasm symm.c ${CFLAGS} -I. -I../../../utilities ../../../utilities/polybench.c ${EXTRA_FLAGS}
	${VERBOSE} ${CC} -o symm symm.c ${CFLAGS} -I. -I../../../utilities ../../../utilities/polybench.c ${EXTRA_FLAGS}

clean:
	@ rm -f symm symm.wasm

