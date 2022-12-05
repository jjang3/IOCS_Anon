RESULTS_DIR=$(pwd)/execve

pin -follow-execv -t /home/jay/Waterfall/lib/libdft-mod.so -s 0 -f 0 -n 1 -- /home/jay/Waterfall/tests/execve-test-overflow &
#sleep 1
nc -u 127.0.0.1 9999
if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

mv dft.out $RESULTS_DIR