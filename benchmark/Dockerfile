# docker image for benchmarking Veracruz on AWS Nitro Enclaves
# XXX: This is a WIP
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.
#
# NOTE: We try to follow the guide in https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
#       Each RUN contains a bundle of steps, which reduces the cache.

FROM veracruz/base:latest

ARG USER=root
ARG UID=0
ENV DEBIAN_FRONTEND noninteractive
# Use bash as the default
SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get install --no-install-recommends -y \
	imagemagick
#    curl && \
#    apt-get clean 
#    python-setuptools \
#    python3-setuptools \
#    python3 \
#    python3-pip \
#    musl-tools \
#    ca-certificates \
#    lxc \
#    iptables \
#    jq \
#    iproute2
#

WORKDIR /work

# Install wasi sdk 12
RUN wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-12/wasi-sdk-12.0-linux.tar.gz &&\
	tar xvf wasi-sdk-12.0-linux.tar.gz &&\
	rm -f wasi-sdk-12.0-linux.tar.gz

# Install rustc nightly (needed to compile upstream wasmtime)
RUN rustup toolchain add nightly

# TODO: initialize submodules in wasmtime upstream

#COPY Makefile /work/Makefile

ENV WASI_SDK_ROOT="/work/wasi-sdk-12.0/"
