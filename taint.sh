#!bin/sh

ROOT_DIR="$PWD"
LIBDFT_DIR="$PWD"/libdft64
SOURCE_DIR="$PWD"/sources
git submodule init && git submodule update

#wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.20-98437-gf02b61307-gcc-linux.tar.gz
#tar -xvf pin-3.20-98437-gf02b61307-gcc-linux.tar.gz
#mv pin-3.20-98437-gf02b61307-gcc-linux pin-3.20
#rm pin-3.20-98437-gf02b61307-gcc-linux.tar.gz

export PIN_ROOT="$PWD"/pin-3.20
echo $PIN_ROOT

cd libdft64 && make -j4

cp $SOURCE_DIR/* $LIBDFT_DIR/tools/