# Benchmarking

## polybench-c
* Generate Makefiles for each example:
  ```
  perl utilities/makefile-gen.pl . -cfg
  ```
* Compile examples (WASM and native) and run their native version:
  ```
  perl utilities/run-all-native.pl
  ```
* Run the actual benchmark: 5 runs per example, the longest and shortest durations are ditched; warning if the variance is bigger than the threshold; save results to CSV
  ```
  bash ./run_benchmarks.sh
  ```
