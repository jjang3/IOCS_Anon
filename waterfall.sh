#!/bin/sh

# Variables needed
BASE_DIR=$(pwd)
LIB_DIR=$BASE_DIR/build
INPUT_FILE=$1.c
INPUT_DIR=$BASE_DIR/inputs
INPUT_SOURCE_FILE=$INPUT_DIR/$1/$1.c
SHROUD_FILENAME=$BASE_DIR/sources/shroud
RESULTS_DIR=$BASE_DIR/results
RESULTS_INPUT_DIR=$RESULTS_DIR/$1

#echo $BASE_DIR $TESTING_DIR $TEST_INPUT_DIR $TEST_INPUT_SOURCE_FILE
if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

if [ -f "$INPUT_SOURCE_FILE" ]; then
  echo Input file "$INPUT_SOURCE_FILE does exist"
  if [ ! -d "$RESULTS_INPUT_DIR" ]; then
      mkdir $RESULTS_INPUT_DIR
  fi
else
  echo Input file "$INPUT_SOURCE_FILE does not exist"
fi

clang -c -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng $SHROUD_FILENAME.c -o $RESULTS_INPUT_DIR/shroud.o
clang -emit-llvm -S -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng -o $RESULTS_INPUT_DIR/$1.ll $INPUT_SOURCE_FILE
clang -emit-llvm -c -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng -o $RESULTS_INPUT_DIR/$1.bc $INPUT_SOURCE_FILE

echo "Waterfall in progress..."
sleep 0.5
#echo "opt -load-pass-plugin $LIB_DIR/lib/"lib"$2.so -passes="$2-pass" -S $RESULTS_INPUT_DIR/$1.bc -o $RESULTS_INPUT_DIR/"$1"_modified.ll"
opt -load $LIB_DIR/lib/"lib"$2.so -load-pass-plugin $LIB_DIR/lib/"lib"$2.so -passes="$2-pass" -S $RESULTS_INPUT_DIR/$1.bc  -taint $INPUT_DIR/$1/$1_list.out  -o $RESULTS_INPUT_DIR/"$1"_modified.ll
clang  -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng $RESULTS_INPUT_DIR/"$1"_modified.ll $RESULTS_INPUT_DIR/shroud.o  -o $RESULTS_INPUT_DIR/"$1"_waterfall.out
clang -g -target aarch64-linux-gnu -march=armv8.5-a+memtag+rng -fsanitize=memtag $RESULTS_INPUT_DIR/$1.ll -o $RESULTS_INPUT_DIR/"$1"_sanitized.out
clang  -target aarch64-linux-gnu $RESULTS_INPUT_DIR/$1.ll -o $RESULTS_INPUT_DIR/$1_orig.out