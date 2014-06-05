#!/bin/bash

TOOLCHAIN=$NDK/arm-toolchain
PATH=$TOOLCHAIN/bin/:$PATH

pushd android-tproxy
rm -rf $TOOLCHAIN
$NDK/build/tools/make-standalone-toolchain.sh --platform=$PLATFORM --install-dir=$TOOLCHAIN

# Configure using host parameters (cross compilation not supported)
make -f Makefile.arm
arm-linux-androideabi-strip tproxy
mkdir -p ../build/armv7
mv tproxy ../build/armv7/
rm -rf $TOOLCHAIN
make -f Makefile.arm clean
popd
