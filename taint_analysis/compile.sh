#!/bin/sh

BASE_DIR=$(pwd)
LIBDFT_DIR=$(pwd)/libdft64
SOURCE_DIR=$(pwd)/libdft64_files
RESULTS_DIR=$BASE_DIR/lib
LIB_DIR=$LIBDFT_DIR/tools/obj-intel64
PIN_VER=3.20

cp $SOURCE_DIR/makefile.rules $LIBDFT_DIR/tools/ 
cp $SOURCE_DIR/libdft-OR.cpp $LIBDFT_DIR/tools/
cp $SOURCE_DIR/libdft-mod.cpp $LIBDFT_DIR/tools/
cp $SOURCE_DIR/libdft-default.cpp $LIBDFT_DIR/tools/
cd $LIBDFT_DIR/tools/ && export PIN_ROOT=$BASE_DIR/pin-"$PIN_VER"_build && echo $PIN_ROOT && make DEBUG=1

if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

#mv $LIB_DIR/libdft-OR.so $RESULTS_DIR
#$LIB_DIR/libdft-mod.so $LIB_DIR/libdft-default.so 