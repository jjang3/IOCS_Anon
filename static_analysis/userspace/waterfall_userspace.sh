#!/bin/sh

# CFLAGS
CC=/home/jay/gcc-10.3/bin/aarch64-none-linux-gnu-gcc
CFLAGS="-target aarch64-linux-gnu -march=armv8.5-a+memtag+rng -v"
#CFLAGS="-march=armv8.5-a+memtag+rng -v"
DEBUGFLAGS="-S -emit-llvm"

# Environment variables
BASE_DIR=$(pwd)
HOME_DIR="$(dirname "$(pwd)")"
BIN_DIR=$BASE_DIR/bin
LIBUNWIND_DIR=$HOME_DIR/libunwind
WATERFALL_DIR=$BASE_DIR/lib/userwaterfall.so

echo -n "Source file to compile: "
read compile_target

COMPILE_SOURCE_FILE=$BASE_DIR/inputs/"$compile_target".c
EXECUTABLE_FILE=$BASE_DIR/bin/"$compile_target"
DEBUG_FILE=$BASE_DIR/debug/"$compile_target".ll

# Print the value of the variable
echo "Applying Shroud library on $COMPILE_SOURCE_FILE"

if [ ! -d "$BIN_DIR" ]; then
    echo "Creating a bin directory"
    mkdir $BIN_DIR
fi


#$CC $CFLAGS -L$LIBUNWIND_DIR/arm_build/lib -I$LIBUNWIND_DIR/arm_build/include -L$BASE_DIR/lib $COMPILE_SOURCE_FILE -Wall -o $EXECUTABLE_FILE -lunwind
clang $CFLAGS -L$BASE_DIR/lib $COMPILE_SOURCE_FILE -Wall -o $EXECUTABLE_FILE -luserwater
#clang $CFLAGS $DEBUGFLAGS -L$BASE_DIR/lib $COMPILE_SOURCE_FILE -Wall -o $DEBUG_FILE -luserwater