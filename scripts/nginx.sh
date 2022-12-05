RESULTS_DIR=$(pwd)/nginx

pin -follow-execv -t /home/jay/Waterfall/lib/libdft-mod.so -s 0 -f 0 -n 1  -- /home/jay/Downloads/nginx-1.3.9/install_x86_64/sbin/nginx -c /home/jay/Downloads/nginx-1.3.9/install_x86_64/conf/nginx.conf -p /home/jay/Downloads/nginx-1.3.9/install_x86_64 

sleep 2
ab -n 100 -c 10 http://localhost:8080/ 

if [ ! -d "$RESULTS_DIR" ]; then
    mkdir $RESULTS_DIR
fi

mv dft.out $RESULTS_DIR