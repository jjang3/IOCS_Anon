cd .. && make clean && make
cd tests
make clean && make hello.out
objdump -d hello.out &> hello.objdump
