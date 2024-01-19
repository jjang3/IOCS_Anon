#!/bin/bash

ROOT_DIR=$
#CURR_DIR=$(pwd)
CURR_DIR=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")
PARENT_DIR="$(dirname "$CURR_DIR")"
RESULTS_DIR=$CURR_DIR/$1
PIN_DIR=$PARENT_DIR/pin-3.27_build
LIB_DIR=$PARENT_DIR/taint_analysis/lib
TEST_DIR=$PARENT_DIR/tests
SOURCE_DIR=$TEST_DIR/sources
NGINX_DIR=$HOME/Downloads/nginx-1.3.9/install_x86_64
REDIS_DIR=$HOME/Downloads/redis-5.0.14/debug_build
CC=clang

if [ $1 == 'nginx' ]
then
    echo $RESULTS_DIR 
    $PIN_DIR/pin -follow-execv -t $LIB_DIR/libdft-OR.so -- $NGINX_DIR/sbin/$1 -c $HOME/Downloads/nginx-1.3.9/conf/$1_taint.conf
    #-p $NGINX_DIR
    sleep 2
    ab -n 1 -c 1 http://127.0.0.1:8080/50x.html
    #nm $NGINX_DIR/sbin/$1 &> $RESULTS_DIR/$1.nm
elif [ $1 == 'redis' ]
then
    echo $RESULTS_DIR
    #nm $REDIS_DIR/bin/redis-server &> $RESULTS_DIR/$1.nm
    $PIN_DIR/pin -follow-execv -t $LIB_DIR/libdft-mod.so -- $REDIS_DIR/bin/redis-server &
    sleep 2
    # $REDIS_DIR/bin/redis-benchmark -t set,get -q
elif [ $1 == 'epoll' ]
then
    echo $RESULTS_DIR 
    $PIN_DIR/pin -follow-execv -t $LIB_DIR/libdft-OR.so -- $TEST_DIR/epoll &
elif [ $1 == 'execve' ]
then
    echo $RESULTS_DIR
else
    echo $RESULTS_DIR 
    #$CC $SOURCE_DIR/$1.c -o $TEST_DIR/$1
    #objdump -d $TEST_DIR/$1 &> $RESULTS_DIR/$1.objdump
    $PIN_DIR/pin -follow-execv -t $LIB_DIR/libdft-mod.so -- $TEST_DIR/$1 1111
fi

if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

mv dft.out $RESULTS_DIR
rm dft.out
# Clean up
if [ $1 == 'nginx' ]
then
    kill $(lsof -t -i:8080)
elif [ $1 == 'epoll' ]
then
    #kill $(lsof -t -i:5000)
fi

