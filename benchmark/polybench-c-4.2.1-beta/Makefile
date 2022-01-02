# wasi sdk toolchain
WASI_SDK_SYSROOT=$(WASI_SDK_ROOT)/share/wasi-sysroot
CLANG_FLAGS=--target=wasm32-wasi
WASM_CC=$(WASI_SDK_ROOT)/bin/clang --sysroot=$(WASI_SDK_SYSROOT) $(CLANG_FLAGS)
WASM_CXX=$(WASI_SDK_ROOT)/bin/clang++ --sysroot=$(WASI_SDK_SYSROOT) $(CLANG_FLAGS)
WASM_CXX=$(WASM_CC)
#CXX=$(CC)

CFLAGS=-Wall -Wno-unused-result -Wno-unknown-pragmas -Wfatal-errors -Wno-writable-strings -fPIC -DEXTRALARGE_DATASET
CFLAGS_WASM=$(CFLAGS) -msimd128 -D_WASI_EMULATED_PROCESS_CLOCKS
OPTS=-Ofast
#OPTS=-O0 -g

CFLAGS+=$(OPTS)

LDFLAGS= -lm

all: correlation covariance gemm gemver gesummv symm syr2k syrk trmm 2mm 3mm atax bicg doitgen mvt cholesky durbin gramschmidt ludcmp lu trisolv deriche floyd-warshall nussinov adi fdtd-2d heat-3d jacobi-1d jacobi-2d seidel-2d

correlation: datamining/correlation/correlation.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I datamining/correlation utilities/polybench.c datamining/correlation/correlation.c -DPOLYBENCH_TIME -o correlation.wasm
	$(CXX) $(CFLAGS) -I utilities -I datamining/correlation utilities/polybench.c datamining/correlation/correlation.c -DPOLYBENCH_TIME -o correlation
covariance: datamining/covariance/covariance.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I datamining/covariance utilities/polybench.c datamining/covariance/covariance.c -DPOLYBENCH_TIME -o covariance.wasm
	$(CXX) $(CFLAGS) -I utilities -I datamining/covariance utilities/polybench.c datamining/covariance/covariance.c -DPOLYBENCH_TIME -o covariance
gemm: linear-algebra/blas/gemm/gemm.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/blas/gemm utilities/polybench.c linear-algebra/blas/gemm/gemm.c -DPOLYBENCH_TIME -o gemm.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/blas/gemm utilities/polybench.c linear-algebra/blas/gemm/gemm.c -DPOLYBENCH_TIME -o gemm
gemver: linear-algebra/blas/gemver/gemver.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/blas/gemver utilities/polybench.c linear-algebra/blas/gemver/gemver.c -DPOLYBENCH_TIME -o gemver.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/blas/gemver utilities/polybench.c linear-algebra/blas/gemver/gemver.c -DPOLYBENCH_TIME -o gemver
gesummv: linear-algebra/blas/gesummv/gesummv.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/blas/gesummv utilities/polybench.c linear-algebra/blas/gesummv/gesummv.c -DPOLYBENCH_TIME -o gesummv.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/blas/gesummv utilities/polybench.c linear-algebra/blas/gesummv/gesummv.c -DPOLYBENCH_TIME -o gesummv
symm: linear-algebra/blas/symm/symm.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/blas/symm utilities/polybench.c linear-algebra/blas/symm/symm.c -DPOLYBENCH_TIME -o symm.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/blas/symm utilities/polybench.c linear-algebra/blas/symm/symm.c -DPOLYBENCH_TIME -o symm
syr2k: linear-algebra/blas/syr2k/syr2k.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/blas/syr2k utilities/polybench.c linear-algebra/blas/syr2k/syr2k.c -DPOLYBENCH_TIME -o syr2k.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/blas/syr2k utilities/polybench.c linear-algebra/blas/syr2k/syr2k.c -DPOLYBENCH_TIME -o syr2k
syrk: linear-algebra/blas/syrk/syrk.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/blas/syrk utilities/polybench.c linear-algebra/blas/syrk/syrk.c -DPOLYBENCH_TIME -o syrk.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/blas/syrk utilities/polybench.c linear-algebra/blas/syrk/syrk.c -DPOLYBENCH_TIME -o syrk
trmm: linear-algebra/blas/trmm/trmm.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/blas/trmm utilities/polybench.c linear-algebra/blas/trmm/trmm.c -DPOLYBENCH_TIME -o trmm.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/blas/trmm utilities/polybench.c linear-algebra/blas/trmm/trmm.c -DPOLYBENCH_TIME -o trmm
2mm: linear-algebra/kernels/2mm/2mm.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/kernels/2mm utilities/polybench.c linear-algebra/kernels/2mm/2mm.c -DPOLYBENCH_TIME -o 2mm.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/kernels/2mm utilities/polybench.c linear-algebra/kernels/2mm/2mm.c -DPOLYBENCH_TIME -o 2mm
3mm: linear-algebra/kernels/3mm/3mm.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/kernels/3mm utilities/polybench.c linear-algebra/kernels/3mm/3mm.c -DPOLYBENCH_TIME -o 3mm.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/kernels/3mm utilities/polybench.c linear-algebra/kernels/3mm/3mm.c -DPOLYBENCH_TIME -o 3mm
atax: linear-algebra/kernels/atax/atax.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/kernels/atax utilities/polybench.c linear-algebra/kernels/atax/atax.c -DPOLYBENCH_TIME -o atax.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/kernels/atax utilities/polybench.c linear-algebra/kernels/atax/atax.c -DPOLYBENCH_TIME -o atax
bicg: linear-algebra/kernels/bicg/bicg.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/kernels/bicg utilities/polybench.c linear-algebra/kernels/bicg/bicg.c -DPOLYBENCH_TIME -o bicg.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/kernels/bicg utilities/polybench.c linear-algebra/kernels/bicg/bicg.c -DPOLYBENCH_TIME -o bicg
doitgen: linear-algebra/kernels/doitgen/doitgen.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/kernels/doitgen utilities/polybench.c linear-algebra/kernels/doitgen/doitgen.c -DPOLYBENCH_TIME -o doitgen.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/kernels/doitgen utilities/polybench.c linear-algebra/kernels/doitgen/doitgen.c -DPOLYBENCH_TIME -o doitgen
mvt: linear-algebra/kernels/mvt/mvt.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/kernels/mvt utilities/polybench.c linear-algebra/kernels/mvt/mvt.c -DPOLYBENCH_TIME -o mvt.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/kernels/mvt utilities/polybench.c linear-algebra/kernels/mvt/mvt.c -DPOLYBENCH_TIME -o mvt
cholesky: linear-algebra/solvers/cholesky/cholesky.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/solvers/cholesky utilities/polybench.c linear-algebra/solvers/cholesky/cholesky.c -DPOLYBENCH_TIME -o cholesky.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/solvers/cholesky utilities/polybench.c linear-algebra/solvers/cholesky/cholesky.c -DPOLYBENCH_TIME -o cholesky
durbin: linear-algebra/solvers/durbin/durbin.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/solvers/durbin utilities/polybench.c linear-algebra/solvers/durbin/durbin.c -DPOLYBENCH_TIME -o durbin.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/solvers/durbin utilities/polybench.c linear-algebra/solvers/durbin/durbin.c -DPOLYBENCH_TIME -o durbin
gramschmidt: linear-algebra/solvers/gramschmidt/gramschmidt.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/solvers/gramschmidt utilities/polybench.c linear-algebra/solvers/gramschmidt/gramschmidt.c -DPOLYBENCH_TIME -o gramschmidt.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/solvers/gramschmidt utilities/polybench.c linear-algebra/solvers/gramschmidt/gramschmidt.c -DPOLYBENCH_TIME -o gramschmidt
ludcmp: linear-algebra/solvers/ludcmp/ludcmp.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/solvers/ludcmp utilities/polybench.c linear-algebra/solvers/ludcmp/ludcmp.c -DPOLYBENCH_TIME -o ludcmp.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/solvers/ludcmp utilities/polybench.c linear-algebra/solvers/ludcmp/ludcmp.c -DPOLYBENCH_TIME -o ludcmp
lu: linear-algebra/solvers/lu/lu.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/solvers/lu utilities/polybench.c linear-algebra/solvers/lu/lu.c -DPOLYBENCH_TIME -o lu.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/solvers/lu utilities/polybench.c linear-algebra/solvers/lu/lu.c -DPOLYBENCH_TIME -o lu
trisolv: linear-algebra/solvers/trisolv/trisolv.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I linear-algebra/solvers/trisolv utilities/polybench.c linear-algebra/solvers/trisolv/trisolv.c -DPOLYBENCH_TIME -o trisolv.wasm
	$(CXX) $(CFLAGS) -I utilities -I linear-algebra/solvers/trisolv utilities/polybench.c linear-algebra/solvers/trisolv/trisolv.c -DPOLYBENCH_TIME -o trisolv
deriche: medley/deriche/deriche.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I medley/deriche utilities/polybench.c medley/deriche/deriche.c -DPOLYBENCH_TIME -o deriche.wasm
	$(CXX) $(CFLAGS) -I utilities -I medley/deriche utilities/polybench.c medley/deriche/deriche.c -DPOLYBENCH_TIME -o deriche
floyd-warshall: medley/floyd-warshall/floyd-warshall.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I medley/floyd-warshall utilities/polybench.c medley/floyd-warshall/floyd-warshall.c -DPOLYBENCH_TIME -o floyd-warshall.wasm
	$(CXX) $(CFLAGS) -I utilities -I medley/floyd-warshall utilities/polybench.c medley/floyd-warshall/floyd-warshall.c -DPOLYBENCH_TIME -o floyd-warshall
nussinov: medley/nussinov/nussinov.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I medley/nussinov utilities/polybench.c medley/nussinov/nussinov.c -DPOLYBENCH_TIME -o nussinov.wasm
	$(CXX) $(CFLAGS) -I utilities -I medley/nussinov utilities/polybench.c medley/nussinov/nussinov.c -DPOLYBENCH_TIME -o nussinov
adi: stencils/adi/adi.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I stencils/adi utilities/polybench.c stencils/adi/adi.c -DPOLYBENCH_TIME -o adi.wasm
	$(CXX) $(CFLAGS) -I utilities -I stencils/adi utilities/polybench.c stencils/adi/adi.c -DPOLYBENCH_TIME -o adi
fdtd-2d: stencils/fdtd-2d/fdtd-2d.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I stencils/fdtd-2d utilities/polybench.c stencils/fdtd-2d/fdtd-2d.c -DPOLYBENCH_TIME -o fdtd-2d.wasm
	$(CXX) $(CFLAGS) -I utilities -I stencils/fdtd-2d utilities/polybench.c stencils/fdtd-2d/fdtd-2d.c -DPOLYBENCH_TIME -o fdtd-2d
heat-3d: stencils/heat-3d/heat-3d.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I stencils/heat-3d utilities/polybench.c stencils/heat-3d/heat-3d.c -DPOLYBENCH_TIME -o heat-3d.wasm
	$(CXX) $(CFLAGS) -I utilities -I stencils/heat-3d utilities/polybench.c stencils/heat-3d/heat-3d.c -DPOLYBENCH_TIME -o heat-3d
jacobi-1d: stencils/jacobi-1d/jacobi-1d.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I stencils/jacobi-1d utilities/polybench.c stencils/jacobi-1d/jacobi-1d.c -DPOLYBENCH_TIME -o jacobi-1d.wasm
	$(CXX) $(CFLAGS) -I utilities -I stencils/jacobi-1d utilities/polybench.c stencils/jacobi-1d/jacobi-1d.c -DPOLYBENCH_TIME -o jacobi-1d
jacobi-2d: stencils/jacobi-2d/jacobi-2d.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I stencils/jacobi-2d utilities/polybench.c stencils/jacobi-2d/jacobi-2d.c -DPOLYBENCH_TIME -o jacobi-2d.wasm
	$(CXX) $(CFLAGS) -I utilities -I stencils/jacobi-2d utilities/polybench.c stencils/jacobi-2d/jacobi-2d.c -DPOLYBENCH_TIME -o jacobi-2d
seidel-2d: stencils/seidel-2d/seidel-2d.c
	$(WASM_CXX) $(CFLAGS_WASM) -I utilities -I stencils/seidel-2d utilities/polybench.c stencils/seidel-2d/seidel-2d.c -DPOLYBENCH_TIME -o seidel-2d.wasm
	$(CXX) $(CFLAGS) -I utilities -I stencils/seidel-2d utilities/polybench.c stencils/seidel-2d/seidel-2d.c -DPOLYBENCH_TIME -o seidel-2d

clean:
	rm correlation covariance gemm gemver gesummv symm syr2k syrk trmm 2mm 3mm atax bicg doitgen mvt cholesky durbin gramschmidt ludcmp lu trisolv deriche floyd-warshall nussinov adi fdtd-2d heat-3d jacobi-1d jacobi-2d seidel-2d
	rm correlation.wasm covariance.wasm gemm.wasm gemver.wasm gesummv.wasm symm.wasm syr2k.wasm syrk.wasm trmm.wasm 2mm.wasm 3mm.wasm atax.wasm bicg.wasm doitgen.wasm mvt.wasm cholesky.wasm durbin.wasm gramschmidt.wasm ludcmp.wasm lu.wasm trisolv.wasm deriche.wasm floyd-warshall.wasm nussinov.wasm adi.wasm fdtd-2d.wasm heat-3d.wasm jacobi-1d.wasm jacobi-2d.wasm seidel-2d.wasm
