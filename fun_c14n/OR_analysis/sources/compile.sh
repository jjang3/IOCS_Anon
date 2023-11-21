#!/bin/sh

PARENT_DIR=$(dirname $(dirname "$PWD"))
LIB_DIR=$(dirname "$PWD")/lib
RESULTS_DIR=$PWD/lib
PIN_VER=3.27

if [ ! -d "$LIB_DIR" ]; then
    mkdir $LIB_DIR
fi

export PIN_ROOT="$PARENT_DIR"/pin-"$PIN_VER"_build

make

mv obj-intel64/* $LIB_DIR
rm -rf obj-intel64