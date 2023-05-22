ROOT_DIR=$(shell pwd)
LIB_DIR=${ROOT_DIR}/lib
PIN_BUILD=${ROOT_DIR}/pin-3.27_build
PIN_VER=pin-3.27

PIN=pin-3.27-98718-gbeaa5d51e-gcc-linux
PIN_DIR=${ROOT_DIR}/${PIN}

SRC="https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.27-98718-gbeaa5d51e-gcc-linux.tar.gz"

export PIN_ROOT := ${PIN_BUILD}

.PHONY: clean ${PIN_VER}_build 

all: build 

build: ${PIN_VER}_build

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
		
clean:
	rm -rf pin-3*
	rm -rf ${LIB_DIR}
