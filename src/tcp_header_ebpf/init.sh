#!/bin/bash

# ubuntu 22.04
# install bcc https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source
sudo apt update
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf clang llvm
sudo apt install -y libbpf-dev # get bpf_helpers.h header file
sudo apt install -y linux-headers-$(uname -r) # get uapi/linux/bpf.h, in /usr/src/linux-headers.*.*.*/include/uapi/linux/bpf.h
git clone --recurse-submodules -j8 https://github.com/libbpf/libbpf-bootstrap.git
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build
cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd

#
sudo apt install python3-pip -y
sudo pip install pyroute2
