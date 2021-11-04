#!/bin/bash

csv_output="output.csv"

extract_time() {
	echo "$1" | sed -nr "s/^.*Normalized time: (.*)$/\1/p"
}

for i in datamining/correlation datamining/covariance linear-algebra/blas/gemm linear-algebra/blas/gemver linear-algebra/blas/gesummv linear-algebra/blas/symm linear-algebra/blas/syr2k linear-algebra/blas/syrk linear-algebra/blas/trmm linear-algebra/kernels/2mm linear-algebra/kernels/3mm linear-algebra/kernels/atax linear-algebra/kernels/bicg linear-algebra/kernels/doitgen linear-algebra/kernels/mvt linear-algebra/solvers/cholesky linear-algebra/solvers/durbin linear-algebra/solvers/gramschmidt linear-algebra/solvers/ludcmp linear-algebra/solvers/lu linear-algebra/solvers/trisolv medley/deriche medley/floyd-warshall medley/nussinov medley/nussinov stencils/adi stencils/fdtd-2d stencils/heat-3d stencils/jacobi-1d stencils/jacobi-2d stencils/seidel-2d; do
#for i in linear-algebra/blas/gemm; do
	kernel=`basename $i`

	ret=`bash utilities/time_benchmark.sh $i/$kernel`
	echo -e "$ret\n"
	time_native=`extract_time "$ret"`

	ret=`bash utilities/time_benchmark.sh wasmtime --dir=$i $i/$kernel.wasm`
	echo -e "$ret\n"
	time_wasmtime=`extract_time "$ret"`

	ret=`bash utilities/time_benchmark.sh /home/guibry01/Documents/Projects/Veracruz/veracruz/sdk/freestanding-execution-engine/target/debug/freestanding-execution-engine -p $i/$kernel.wasm -x jit -o true -c true`
	echo -e "$ret\n"
	time_fee=`extract_time "$ret"`

	# Dump to csv
	echo "$kernel;$time_native;$time_wasmtime;$time_fee" >> "$csv_output"
done
