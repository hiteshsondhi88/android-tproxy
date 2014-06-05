#!/bin/bash

export NDK=~/Android/ndk
export PLATFORM=android-9
rm -rf build
bash arm_build.sh
bash x86_build.sh
