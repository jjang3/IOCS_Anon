ROOT_DIR=$
CURR_DIR=$(pwd)
PARENT_DIR="$(dirname "$CURR_DIR")"
RESULTS_DIR=$(pwd)/$1
PIN_DIR=$PARENT_DIR/pin-3.20_build
LIB_DIR=$PARENT_DIR/lib
TEST_DIR=$PARENT_DIR/tests
SOURCE_DIR=$TEST_DIR/sources
NGINX_DIR=$HOME/Downloads/nginx-1.3.9/install_x86_64
CC=clang

if [ $1 == 'nginx' ]
then
    echo $RESULTS_DIR 
    $PIN_DIR/pin -follow-execv -t $LIB_DIR/libdft-mod.so -- $NGINX_DIR/sbin/$1 -c $HOME/Downloads/nginx-1.3.9/conf/$1_taint.conf
    #-p $NGINX_DIR
    sleep 2
    ab -n 1 -c 1 http://127.0.0.1:8080/50x.html
elif [ $1 == 'execve' ]
then
    echo $RESULTS_DIR 
    $PIN_DIR/pin -follow-execv -t $LIB_DIR/libdft-mod.so -- $TEST_DIR/execve-test-overflow &
    sleep 2
    nc -u 127.0.0.1 9999
else
    echo $RESULTS_DIR 
    $CC $SOURCE_DIR/$1.c -o $TEST_DIR/$1
    objdump -d $TEST_DIR/$1 &> $RESULTS_DIR/$1.objdump
    $PIN_DIR/pin -follow-execv -t $LIB_DIR/libdft-mod.so -- $TEST_DIR/$1
fi

if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

mv dft.out $RESULTS_DIR

# Clean up
if [ $1 == 'nginx' ]
then
    kill $(lsof -t -i:8080)
fi
