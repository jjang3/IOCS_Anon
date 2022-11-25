#!/bin/sh

# CFLAGS
CFLAGS="-target aarch64-linux-gnu -march=armv8.5-a+memtag+rng -v"
DEBUGFLAGS="-S -emit-llvm"

# Environment variables
BASE_DIR=$(pwd)
BIN_DIR=$BASE_DIR/bin
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


clang $CFLAGS -L$BASE_DIR/lib $COMPILE_SOURCE_FILE -Wall -o $EXECUTABLE_FILE -luserwater
#clang $CFLAGS $DEBUGFLAGS -L$BASE_DIR/lib $COMPILE_SOURCE_FILE -Wall -o $DEBUG_FILE -lshroud
