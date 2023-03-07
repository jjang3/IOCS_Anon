#!/bin/bash

BASE_DIR=$(pwd)
PARENT_DIR="$(dirname $BASE_DIR)"
E9BIN_DIR=$BASE_DIR/e9bin
OUTPUT_DIR=$BASE_DIR/outputs
echo $ISO_LIST
export PATH="$PATH:$PARENT_DIR/e9patch" # Change this to e9patch directory

e9compile.sh $BASE_DIR/src/$1.c

if [ ! -d "$E9BIN_DIR" ]; then
    mkdir $E9BIN_DIR
fi

mv $1 $E9BIN_DIR
rm $1.o
rm pkuapi.o
if [ ! -d "$OUTPUT_DIR" ]; then
    mkdir $OUTPUT_DIR
fi