#!/bin/bash

#BASE_DIR=$(pwd)
CURR_DIR=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")
PARENT_DIR="$(dirname $CURR_DIR)"
echo $PARENT_DIR
E9BIN_DIR=$CURR_DIR/e9bin
OUTPUT_DIR=$CURR_DIR/outputs
echo $ISO_LIST
export PATH="$PATH:$PARENT_DIR/e9patch" # Change this to e9patch directory

e9compile.sh $CURR_DIR/src/$1.c

if [ ! -d "$E9BIN_DIR" ]; then
    mkdir $E9BIN_DIR
fi

mv $1 $E9BIN_DIR
rm $1.o
rm pkuapi.o
if [ ! -d "$OUTPUT_DIR" ]; then
    mkdir $OUTPUT_DIR
fi