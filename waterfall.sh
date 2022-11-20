#!/bin/sh

# Variables needed
BASE_DIR=$(pwd)
LIB_DIR=$BASE_DIR/build
INPUT_FILE=$1.c
TESTING_DIR=$BASE_DIR/testing_inputs
SHROUD_FILENAME=$TESTING_DIR/shroud
SOURCE_DIR=$TESTING_DIR/sources
TEST_INPUT_DIR=$TESTING_DIR/$1
TEST_INPUT_SOURCE_FILE=$SOURCE_DIR/$1.c


echo $BASE_DIR $TESTING_DIR $TEST_INPUT_DIR $TEST_INPUT_SOURCE_FILE

if [ -f "$TEST_INPUT_SOURCE_FILE" ]; then
  #echo "$TEST_INPUT_SOURCE_FILE does exist"
  if [ ! -d "$TEST_INPUT_DIR" ]; then
    mkdir $TEST_INPUT_DIR
  fi
fi

if [ ! -f "$SHROUD_FILENAME.c" ]; then
  echo "Shroud file missing"
  exit 0
fi


clang -c -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng -fsanitize=memtag $SHROUD_FILENAME.c -o $TEST_INPUT_DIR/shroud.o
clang -emit-llvm -S -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng -fsanitize=memtag -o $TEST_INPUT_DIR/$1.ll $TEST_INPUT_SOURCE_FILE
clang -emit-llvm -c -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng -fsanitize=memtag -o $TEST_INPUT_DIR/$1.bc $TEST_INPUT_SOURCE_FILE

echo "Shroud in progress..."
sleep 0.5
echo "opt -load-pass-plugin $LIB_DIR/lib/"lib"$2.so -passes="$2" -S $TEST_INPUT_DIR/$1.bc -o $TEST_INPUT_DIR/"$1"_modified.ll"
opt -load-pass-plugin $LIB_DIR/lib/"lib"$2.so -passes="$2" -S $TEST_INPUT_DIR/$1.bc -o $TEST_INPUT_DIR/"$1"_modified.ll
#clang  -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng -fsanitize=memtag $TEST_INPUT_DIR/"$1"_modified.ll $TEST_INPUT_DIR/shroud.o -o  $TEST_INPUT_DIR/"$1"_shroud.out
#clang -g -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng -fsanitize=memtag $TEST_INPUT_DIR/$1.ll -o $TEST_INPUT_DIR/"$1"_mte.out
#clang  -target aarch64-linux-gnu $TEST_INPUT_DIR/$1.ll -o $TEST_INPUT_DIR/$1_orig.out