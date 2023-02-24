#!/bin/sh

BASE_DIR=$(pwd)
E9BIN_DIR=$BASE_DIR/e9bin
export PATH="$PATH:$HOME/e9patch" # Change this to e9patch directory

e9compile.sh $BASE_DIR/src/$1.c

if [ ! -d "$E9BIN_DIR" ]; then
    mkdir $E9BIN_DIR
fi

mv $1 $E9BIN_DIR
rm $1.o