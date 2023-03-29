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
TAINT_DIR=$BASE_DIR/taint_analysis
TAINT_SCRIPTS_DIR=$TAINT_DIR/scripts
LLVM_BUILD_DIR=$HOME/llvm-project-13/llvm-arm-build

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

$LLVM_BUILD_DIR/bin/clang -emit-llvm -S -o $RESULTS_INPUT_DIR/$1.ll $INPUT_SOURCE_FILE
$LLVM_BUILD_DIR/bin/clang -emit-llvm -c -o $RESULTS_INPUT_DIR/$1.bc $INPUT_SOURCE_FILE

echo "Waterfall in progress..."
sleep 0.5
#echo "opt -load-pass-plugin $LIB_DIR/lib/"lib"$2.so -passes="$2-pass" -S $RESULTS_INPUT_DIR/$1.bc -o $RESULTS_INPUT_DIR/"$1"_modified.ll"
$LLVM_BUILD_DIR/bin/opt -load $LIB_DIR/lib/"lib"$2.so -load-pass-plugin $LIB_DIR/lib/"lib"$2.so -passes=waterfall -S $RESULTS_INPUT_DIR/$1.bc -taint $TAINT_SCRIPTS_DIR/$1/$1_list.out  -o $RESULTS_INPUT_DIR/"$1"_modified.ll
$LLVM_BUILD_DIR/bin/clang $RESULTS_INPUT_DIR/"$1"_modified.ll -o $RESULTS_INPUT_DIR/"$1"_waterfall.out
$LLVM_BUILD_DIR/bin/clang -g $RESULTS_INPUT_DIR/$1.ll -o $RESULTS_INPUT_DIR/"$1"_sanitized.out
$LLVM_BUILD_DIR/bin/clang $RESULTS_INPUT_DIR/$1.ll -o $RESULTS_INPUT_DIR/$1_orig.out

dot -Tpdf -O $RESULTS_INPUT_DIR/callgraph.dot
#sfdp -x -Tpng -O $RESULTS_INPUT_DIR/callgraph.dot
