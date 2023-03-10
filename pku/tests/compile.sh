gcc preload.c -o preload.so -fPIC -shared -ldl
gcc -g -T linker_temp.ld epoll_test.c -o epoll.out
