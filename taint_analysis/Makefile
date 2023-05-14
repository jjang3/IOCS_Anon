ROOT_DIR=$(shell pwd)
LIB_DIR=${ROOT_DIR}/lib
LIBDFT_DIR=${ROOT_DIR}/libdft64
SOURCE_DIR=${ROOT_DIR}/libdft64_files
#PIN_BUILD=${ROOT_DIR}/pin-3.20_build
PIN_BUILD=${ROOT_DIR}/pin-3.27_build
PIN_VER=pin-3.27
LIBDFT=libdft64

#PIN=pin-3.20-98437-gf02b61307-gcc-linux
PIN=pin-3.27-98718-gbeaa5d51e-gcc-linux
PIN_DIR=${ROOT_DIR}/${PIN}

#SRC="https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.20-98437-gf02b61307-gcc-linux.tar.gz"
SRC="https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.27-98718-gbeaa5d51e-gcc-linux.tar.gz"

export PIN_ROOT := ${PIN_BUILD}

.PHONY: clean ${PIN_VER}_build ${LIBDFT}_build

all: build 

build: update ${PIN_VER}_build ${LIBDFT}_build compile

compile:
	bash compile.sh

${PIN}.tar.gz:
ifneq ($(PIN).tar.gz,"")
	wget ${SRC}
endif

${PIN}: ${PIN}.tar.gz
	if [ ! -d ${PIN_BUILD} ]; then \
		tar xvf ${PIN}.tar.gz; \
		mv ${PIN_DIR} ${PIN_BUILD};  \
	fi

${PIN_VER}_build: ${PIN}
	
${LIBDFT}_build: 
		echo ${PIN_ROOT} && \
		cd ${LIBDFT_DIR} && make && \
		echo ${SOURCE_DIR} && \
		cp -r ${SOURCE_DIR}/* ${LIBDFT_DIR}/tools/ && \
		cd ${LIBDFT_DIR}/tools && \
		make \
		
update:
		git submodule init
		git submodule update
		
clean:
		rm -rf ${PIN}
		rm -rf ${PIN_BUILD}
		rm -rf ${LIB_DIR}
		rm -rf ${LIBDFT_DIR}
		rm ${PIN}.tar.gz*
