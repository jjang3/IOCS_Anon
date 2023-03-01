#!/bin/sh

BASE_DIR=$(pwd)
PARENT_DIR="$(dirname $BASE_DIR)"
E9BIN_DIR=$BASE_DIR/e9bin
INPUT_DIR=$BASE_DIR/input
OUTPUT_DIR=$BASE_DIR/output
export PATH="$PATH:$PARENT_DIR/e9patch" # Change this to e9patch directory

e9compile.sh $BASE_DIR/src/$1.c

if [ ! -d "$E9BIN_DIR" ]; then
    mkdir $E9BIN_DIR
fi

mv $1 $E9BIN_DIR
rm $1.o

if [ ! -d "$OUTPUT_DIR" ]; then
    mkdir $OUTPUT_DIR
fi

#cd $E9BIN_DIR && e9tool -M 'call and target = &bar' -P 'before entry(offset,asm,"entry")@trampoline' -M 'call and target = &__cyg_profile_func_exit' -P 'before entry(offset,asm,"exit")@trampoline' $INPUT_DIR/$2.out
cd $E9BIN_DIR && e9tool -M 'call and target = &foo' -P 'before entry(offset,asm,"entry")@trampoline' -M 'call and target = &__cyg_profile_func_exit' -P 'before entry(offset,asm,"exit")@trampoline' $INPUT_DIR/$2.out
mv $E9BIN_DIR/a.out $OUTPUT_DIR/$2.out