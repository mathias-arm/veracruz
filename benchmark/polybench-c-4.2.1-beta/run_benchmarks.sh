#!/bin/bash

csv_output="output.csv"
fee_path="$HOME/Documents/Projects/Veracruz/veracruz/sdk/freestanding-execution-engine/target/debug/freestanding-execution-engine"

extract_time() {
	echo "$1" | sed -nr "s/^.*Normalized time: ([0-9.]+)$/\1/p"
}

# Empty if the SD threshold hasn't been reached
extract_std_dev() {
	echo "$1" | sed -nr "s/^.*RSD=([0-9.]+).*$/\1/p"
}

for i in datamining/correlation datamining/covariance linear-algebra/blas/gemm linear-algebra/blas/gemver linear-algebra/blas/gesummv linear-algebra/blas/symm linear-algebra/blas/syr2k linear-algebra/blas/syrk linear-algebra/blas/trmm linear-algebra/kernels/2mm linear-algebra/kernels/3mm linear-algebra/kernels/atax linear-algebra/kernels/bicg linear-algebra/kernels/doitgen linear-algebra/kernels/mvt linear-algebra/solvers/cholesky linear-algebra/solvers/durbin linear-algebra/solvers/gramschmidt linear-algebra/solvers/ludcmp linear-algebra/solvers/lu linear-algebra/solvers/trisolv medley/deriche medley/floyd-warshall medley/nussinov medley/nussinov stencils/adi stencils/fdtd-2d stencils/heat-3d stencils/jacobi-1d stencils/jacobi-2d stencils/seidel-2d; do
	kernel=`basename $i`

	ret=`bash utilities/time_benchmark.sh $i/$kernel`
	echo -e "$ret\n"
	time_native=`extract_time "$ret"`
	sd_native=`extract_std_dev "$ret"`

	ret=`bash utilities/time_benchmark.sh wasmtime --dir=$i $i/$kernel.wasm`
	echo -e "$ret\n"
	time_wasmtime_upstream=`extract_time "$ret"`
	sd_wasmtime_upstream=`extract_std_dev "$ret"`

	ret=`bash utilities/time_benchmark.sh ../wasmtime_vc/target/release/wasmtime --dir=$i $i/$kernel.wasm`
	echo -e "$ret\n"
	time_wasmtime_vc=`extract_time "$ret"`
	sd_wasmtime_vc=`extract_std_dev "$ret"`

	ret=`bash utilities/time_benchmark.sh "$fee_path" -p $i/$kernel.wasm -x jit -o true -c true`
	echo -e "$ret\n"
	time_fee=`extract_time "$ret"`
	sd_fee=`extract_std_dev "$ret"`

	# Dump to csv
	# TODO: Dump SD
	echo "$kernel;$time_native;$time_wasmtime_upstream;$time_wasmtime_vc;$time_fee" >> "$csv_output"
done
