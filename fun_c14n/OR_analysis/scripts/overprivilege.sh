#!/bin/bash

ROOT_DIR=$
CURR_DIR=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")
PARENT_DIR="$(dirname "$CURR_DIR")"
RESULTS_DIR=$CURR_DIR/$1
PIN_DIR=$PARENT_DIR/pin-3.27_build
TEST_DIR=$PARENT_DIR/tests
SOURCE_DIR=$PARENT_DIR/sources
LIB_DIR=$SOURCE_DIR/obj-intel64
NGINX_DIR=$HOME/Downloads/nginx-1.3.9/install_x86_64
REDIS_DIR=$HOME/Downloads/redis-5.0.14/inst_build

if [ $1 == 'epoll' ]
then
    echo $RESULTS_DIR 
    $PIN_DIR/pin -follow-execv -t $LIB_DIR/dyn_OR.so -- $TEST_DIR/epoll
elif [ $1 == 'nginx' ]
then
    echo $RESULTS_DIR 
    $PIN_DIR/pin -follow-execv -t $LIB_DIR/dyn_OR.so -- $NGINX_DIR/sbin/$1 -c $HOME/Downloads/nginx-1.3.9/conf/$1_taint.conf
    sleep 2
    ab -n 1 -c 1 http://127.0.0.1:8080/50x.html
elif [ $1 == 'redis' ]
then
    echo $RESULTS_DIR
    #nm $REDIS_DIR/bin/redis-server &> $RESULTS_DIR/$1.nm
    $PIN_DIR/pin -follow-execv -t $LIB_DIR/dyn_OR.so -- $REDIS_DIR/bin/redis-server &
    #sleep 2
    #$REDIS_DIR/bin/redis-benchmark -t set,get -q
elif [ $1 == 'execve' ]
then
    echo $RESULTS_DIR
else
    echo $RESULTS_DIR 
    #objdump -d $TEST_DIR/$1 &> $RESULTS_DIR/$1.objdump
    $PIN_DIR/pin -follow-execv -t $LIB_DIR/dyn_OR.so -- $TEST_DIR/$1 1111
fi

if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi
