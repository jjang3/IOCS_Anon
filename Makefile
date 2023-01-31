ROOT_DIR="$PWD"
LIBDFT_DIR="$PWD"/libdft64
SOURCE_DIR="$PWD"/lib_sources
PIN_DIR="$PWD"/pin-3.20

.PHONY: clean build update

PIN=pin-3.20-98437-gf02b61307-gcc-linux
PIN_VER=pin-3.20
SRC="https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.20-98437-gf02b61307-gcc-linux.tar.gz"

all: build 

build: update ${PIN}_build ${LIBDFT}_build

${PIN}.tar.gz:
		wget ${SRC}

${PIN}: ${PIN}.tar.gz
		tar xvf ${PIN}.tar.gz

${PIN}_build: ${PIN}
		mv ${PIN} ${PIN_VER}_build
		rm ${SRC}

${LIBDFT}_build: 
		export PIN_ROOT="$PWD"/pin-3.20 && \
		cd libdft64 && \
		make -j4 && \
		cp $SOURCE_DIR/* ${LIBDFT}_build/tools/ && \
		cd ${LIBDFT}_build/tools/ && \
		make -j4

update:
		git submodule init
		git submodule update

clean:
		rm -rf ${LIBDFT}_build
		rm -rf ${PIN}_build
