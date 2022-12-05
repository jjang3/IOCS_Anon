#!/bin/sh

BASE_DIR=$(pwd)
LIBDFT_DIR=$(pwd)/libdft64
SOURCE_DIR=$(pwd)/sources
RESULTS_DIR=$BASE_DIR/results
LIB_DIR=$LIBDFT_DIR/tools/obj-intel64/

cp $SOURCE_DIR/libdft-mod.cpp $LIBDFT_DIR/tools/
cd $LIBDFT_DIR/tools/ && make -j4

if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

mv $LIB_DIR/libdft-mod.so $RESULTS_DIR