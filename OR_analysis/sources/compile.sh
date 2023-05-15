#!/bin/sh

ROOT_DIR=`pwd`
PARENT_DIR="$(dirname "$ROOT_DIR")"
RESULTS_DIR=$PARENT_DIR/lib
PIN_VER=3.27

if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

export PIN_ROOT="$PARENT_DIR"/pin-"$PIN_VER"_build

make