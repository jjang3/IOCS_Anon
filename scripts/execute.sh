RESULTS_DIR=$(pwd)/$1

echo $RESULTS_DIR
cd /home/jay/Waterfall/tests
pin -follow-execv -t /home/jay/Waterfall/lib/libdft-mod.so -s 0 -f 1 -n 1 -- /home/jay/Waterfall/tests/$1
if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

mv dft.out $RESULTS_DIR
