RESULTS_DIR=$(pwd)/$1
TEST_DIR=/home/jay/Waterfall/tests
SOURCE_DIR=/home/jay/Waterfall/tests/sources
CC=gcc

echo $RESULTS_DIR
$CC $SOURCE_DIR/$1.c -o $TEST_DIR/$1
objdump -d $TEST_DIR/$1 &> $RESULTS_DIR/$1.objdump
pin -follow-execv -t /home/jay/Waterfall/lib/libdft-mod.so -- /home/jay/Waterfall/tests/$1
if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

mv dft.out $RESULTS_DIR
