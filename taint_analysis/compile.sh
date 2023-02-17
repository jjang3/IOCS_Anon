#!/bin/sh

BASE_DIR=$(pwd)
LIBDFT_DIR=$(pwd)/libdft64
SOURCE_DIR=$(pwd)/libdft64_files
RESULTS_DIR=$BASE_DIR/lib
LIB_DIR=$LIBDFT_DIR/tools/obj-intel64

cp $SOURCE_DIR/libdft-mod.cpp $SOURCE_DIR/libdft-default.cpp $LIBDFT_DIR/tools/
cd $LIBDFT_DIR/tools/ && make -j4

if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

mv $LIB_DIR/libdft-mod.so $LIB_DIR/libdft-default.so $RESULTS_DIR