# Benchmarking

## Docker

### Build image
```
DOCKER_BUILDKIT=1 docker build --build-arg USER=root --build-arg UID=0 -t veracruz_benchmarking .
```

### Run container
```
#docker run --rm --privileged -d -v $(abspath ..):/work \
docker run --rm --privileged -d \
	-v `realpath ..`/wasmtime-upstream:/work/wasmtime-upstream \
	-v `realpath ..`/wasmtime-veracruz:/work/wasmtime-veracruz \
	-v /home/guibry01/Documents/Projects/Veracruz/veracruz:/work/veracruz \
	-v `realpath ..`/polybench-c-4.2.1-beta:/work/polybench-c-4.2.1-beta \
	-v `realpath ..`/veracruz-examples:/work/veracruz-examples \
	-v /usr/bin:/host/bin \
	-v /var/run/docker.sock:/var/run/docker.sock \
	--name veracruz_benchmarking_test veracruz_benchmarking sleep inf
```

### Execute
```
docker exec -it veracruz_benchmarking_test /bin/bash
```



## Bare metal

### Prerequisites
* Install WASI SDK and set `WASI_SDK_ROOT` environment variable

### polybench-c
* Open the polybench directory:
  ```
  cd polybench-c-4.2.1-beta
  ```
* Generate Makefiles for each example:
  ```
  perl utilities/makefile-gen.pl . -cfg
  ```
* Compile examples (WASM and native):
  ```
  perl utilities/make-all.pl
  ```
* Run the actual benchmark: 5 runs per example, the longest and shortest durations are ditched; warning if the variance is bigger than the threshold; save results to CSV
  ```
  bash ./run_benchmarks.sh
  ```

### veracruz-examples
* Open the veracruz-examples directory:
  ```
  cd veracruz-examples
  ```
* Build the [deep learning server](https://github.com/veracruz-project/veracruz-examples/tree/main/deep-learning-server) following the README
* Build the video object detection example 
