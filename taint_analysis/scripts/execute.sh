CURR_DIR=$(pwd)
PARENT_DIR="$(dirname "$CURR_DIR")"
RESULTS_DIR=$(pwd)/$1
LIB_DIR=$PARENT_DIR/lib
TEST_DIR=$PARENT_DIR/tests
SOURCE_DIR=$TEST_DIR/sources
CC=clang

usr_int(){

if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

mv dft.out $RESULTS_DIR

}

echo $RESULTS_DIR 
$CC $SOURCE_DIR/$1.c -o $TEST_DIR/$1
objdump -d $TEST_DIR/$1 &> $RESULTS_DIR/$1.objdump
pin -follow-execv -t $LIB_DIR/libdft-mod.so -- $TEST_DIR/$1

if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

mv dft.out $RESULTS_DIR