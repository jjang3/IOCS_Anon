#!/bin/sh

CFLAGS="-shared -fPIC -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng -v"

# Environment variables
BASE_DIR=$(pwd)
HOME_DIR="$(dirname "$(pwd)")"
LIB_DIR=$BASE_DIR/lib
SOURCE_DIR=$BASE_DIR/source
INCLUDE_DIR=$BASE_DIR/include
LIBUNWIND_DIR=$HOME_DIR/libunwind


echo "Building shroud library..."

if [ ! -d "$LIB_DIR" ]; then
    echo "Creating a lib directory"
    mkdir $LIB_DIR
fi

clang -L$LIBUNWIND_DIR/arm_build/lib -I$LIBUNWIND_DIR/arm_build/include $CFLAGS "$SOURCE_DIR/waterfall.c" -Wall -o "$LIB_DIR/libuserwater.so"
#clang -c -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng  "$SOURCE_DIR/waterfall.c" -o "$LIB_DIR/userwaterfall_static.o"
#ar rc "$LIB_DIR/userwaterfall_static.a" "$LIB_DIR/userwaterfall_static.o"
