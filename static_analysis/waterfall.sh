#!/bin/sh

# Variables needed
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
root_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
LIB_DIR=$current_path/build
INPUT_FILE=$1.c
INPUT_DIR=$current_path/inputs
INPUT_SOURCE_FILE=$INPUT_DIR/$1.c
RESULTS_DIR=$current_path/results
TAINT_DIR=$parent_path/taint_analysis/tests/results
RESULTS_INPUT_DIR=$RESULTS_DIR/$1
LLVM_BUILD_DIR=$LLVM_DIR

echo $current_path $RESULTS_DIR 
if [ ! -d "$RESULTS_DIR" ]; then
    echo "Directory doesn't exist"
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
echo "$LLVM_BUILD_DIR/bin/opt -load $LIB_DIR/lib/"lib"$2.so -load-pass-plugin $LIB_DIR/lib/"lib"$2.so -passes=waterfall -S $RESULTS_INPUT_DIR/$1.bc -taint $TAINT_SCRIPTS_DIR/$1/$1_list.out  -o $RESULTS_INPUT_DIR/"$1"_modified.ll"
$LLVM_BUILD_DIR/bin/opt -load $LIB_DIR/lib/"lib"$2.so -load-pass-plugin $LIB_DIR/lib/"lib"$2.so -passes=waterfall -S $RESULTS_INPUT_DIR/$1.bc -taint $TAINT_DIR/$1/$1_list.out  -o $RESULTS_INPUT_DIR/"$1"_modified.ll
