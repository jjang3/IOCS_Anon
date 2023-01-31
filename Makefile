ROOT_DIR="$PWD"
LIBDFT_DIR="$PWD"/libdft64
SOURCE_DIR="$PWD"/sources
PIN_DIR="$PWD"/pin-3.20

.PHONY: clean update

PIN=pin-3.20-98437-gf02b61307-gcc-linux
SRC="https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.20-98437-gf02b61307-gcc-linux.tar.gz"

all: build 

build: ${PIN}_build ${LIBDFT}_build

${PIN}.tar.gz:
		wget ${SRC}

${PIN}: ${PIN}.tar.gz
		tar xvf ${PIN}.tar.gz

${PIN}_build: ${PIN}
		mv ${PIN} ${PIN}_build

${LIBDFT}_build: 
		cd libdft64 && \
		make -j4 && \
		cp $SOURCE_DIR/* ${LIBDFT}_build/tools/ && \
		cd ${LIBDFT}_build/tools/ && \
		make -j4

update:
		git submodule init
		git submodule update

${}

clean:
		rm -rf $LIBDFT_DIR
		rm -rf $PIN_DIR
