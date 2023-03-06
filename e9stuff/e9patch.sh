#!/bin/sh

BASE_DIR=$(pwd)
PARENT_DIR="$(dirname $BASE_DIR)"
E9BIN_DIR=$BASE_DIR/e9bin
INPUT_DIR=$BASE_DIR/input
OUTPUT_DIR=$BASE_DIR/output
ISO_LIST=process_new_data,process_more_tainted_data
echo $ISO_LIST
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

#mov.+\(%rax.*
#cd $E9BIN_DIR && e9tool -M 'asm=/xor.+%rax.*/' -P 'after entry(offset,asm,"entry")@trampoline' $INPUT_DIR/$2.out
#cd $E9BIN_DIR && e9tool -M 'call and target = &__cyg_profile_func_enter' -P 'before entry(offset,asm,"entry")@trampoline' -M 'call and target = &__cyg_profile_func_exit' -P 'before entry(offset,asm,"exit")@trampoline' $INPUT_DIR/$2.out


PATCHING_TARGETS=""
for i in ${ISO_LIST//,/" "}
do
    PATCHING_TARGETS+="-M '\''call and target = &$i'\'' -P '\''before entry(offset,asm,\"entry\")@trampoline'\'' " 
done
PATCHING_TARGETS+="-M 'call and target = &__cyg_profile_func_exit' -P 'before entry(offset,asm,"exit")@trampoline'"
echo $PATCHING_TARGETS
#EQ="("
#EQ2=")"
#TEST_TARGET="-M \'call and target = &__cyg_profile_func_exit\' "-P" \'before entry${EQ}offset,asm,asm${EQ2}@trampoline\'"
#TEST="-M 'call and target = &__cyg_profile_func_exit' -P 'before entry(offset,asm,"exit")@trampoline"
#TEST=`-M "call and target = &__cyg_profile_func_exit" -P "before entry(offset,asm,"exit")@trampoline"`
#TEST_TEST="-M '\''call and target = &__cyg_profile_func_exit'\''"
#TEST_TEST_TEST="-P '\''before entry(offset,asm,asm)@trampoline'\''"
#TEST_2="-P \'before entry(offset,asm,"exit")@trampoline\'"
TEST_TARGET='-M '"call and target = &__cyg_profile_func_exit"''
TEST_PATCH='-P '"before entry(offset,asm,\"exit\")@trampoline"''

cd $E9BIN_DIR &&
e9tool \
"$TEST_TARGET" "$TEST_PATCH" \
for i in ${ISO_LIST//,/};
do
    echo $i
done
$INPUT_DIR/$2.out


#e9tool "$TEST" $INPUT_DIR/$2.out #"$TEST_2" 
#echo $TEST
#echo $PATCHING_TARGETS
#echo "e9tool $TEST_TARGET $INPUT_DIR/$2.out"
#e9tool $TEST_TARGET $INPUT_DIR/$2.out
exit
#$PATCHING_TARGETS
#-M 'call and target = &__cyg_profile_func_exit' -P 'before entry(offset,asm,"exit")@trampoline' \

mv $E9BIN_DIR/a.out $OUTPUT_DIR/$2.out
##-M 'call and target = &process_new_data' -P 'before entry(offset,asm,"entry")@trampoline' \