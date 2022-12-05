#!/bin/sh
#CC=/home/jay/gcc-10.3/bin/aarch64-none-linux-gnu-gcc

CC=clang
CFLAGS="-shared -fPIC -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng -v"
LIBFLAGS="-I/home/jay/Waterfall/libunwind/arm_build/include -L/home/jay/Waterfall/libunwind/arm_build/lib"

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

$CC $CFLAGS $LIBFLAGS "$SOURCE_DIR/waterfall.c" -Wall -o "$LIB_DIR/libuserwater.so"
#clang $CFLAGS "$SOURCE_DIR/waterfall.c" -Wall -o "$LIB_DIR/libuserwater.so"
#clang -c -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng  "$SOURCE_DIR/waterfall.c" -o "$LIB_DIR/userwaterfall_static.o"
#ar rc "$LIB_DIR/userwaterfall_static.a" "$LIB_DIR/userwaterfall_static.o"
#/home/jay/gcc-10.3/bin/aarch64-none-linux-gnu-gcc -I/home/jay/Waterfall/libunwind/arm_build/include -L/home/jay/Waterfall/libunwind/arm_build/lib libunwind_example.c -o libunwind_example -lunwind