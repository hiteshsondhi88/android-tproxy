#!/bin/bash
TOOLCHAIN=$NDK/x86-toolchain
PATH=$TOOLCHAIN/bin/:$PATH
rm -rf $TOOLCHAIN
pushd android-tproxy
$NDK/build/tools/make-standalone-toolchain.sh --platform=$PLATFORM --install-dir=$TOOLCHAIN --arch=x86

# Configure using host parameters (cross compilation not supported)
make -f Makefile.x86
i686-linux-android-strip tproxy
mkdir -p ../build/x86/
mv tproxy ../build/x86/
rm -rf $TOOLCHAIN
make -f Makefile.x86 clean
popd
