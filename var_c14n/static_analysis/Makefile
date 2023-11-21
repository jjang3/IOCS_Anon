ROOT_DIR=$(shell pwd)
# LLVM=llvm-project-13.0.1
LLVM=llvm-project-14.0.0
# LLVM_BUILD=${ROOT_DIR}/llvm-project-13.0.1.src
LLVM_BUILD=${ROOT_DIR}/llvm-project-14.0.0.src
# LLVM_DIR=${ROOT_DIR}/llvm-project-13
LLVM_DIR=${ROOT_DIR}/llvm-project-14
# SRC="https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.1/llvm-project-13.0.1.src.tar.xz"
SRC="https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.0/llvm-project-14.0.0.src.tar.xz"

all: build 

build: update ${LLVM}_build ${LLVM}_compile

${LLVM}_compile:
	cd ${LLVM_DIR} && \
	if [ ! -d llvm-build ]; then \
		mkdir llvm-build; \
		cd llvm-build; \
		CC=gcc CXX=g++ cmake -DCMAKE_CXX_FLAGS="-fPIC" -DCMAKE_INSTALL_PREFIX=${LLVM_DIR}/llvm-build -DLLVM_TARGETS_TO_BUILD="ARM;X86;AArch64" -DLLVM_ENABLE_PROJECTS="clang;lldb" -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" -DLLVM_ENABLE_ASSERTIONS=True -DCMAKE_BUILD_TYPE=Release -Wno-dev -G Ninja ../llvm; \
		ninja; \
		ninja install; \
	fi

${LLVM}.src.tar.xz:
ifneq ($(LLVM).src.tar.xz,"")
	wget ${SRC}
endif

${LLVM}: ${LLVM}.src.tar.xz
	if [ ! -d ${LLVM_DIR} ]; then \
		tar xvf ${LLVM}.src.tar.xz; \
		mv ${LLVM_BUILD} ${LLVM_DIR};  \
		rm ${LLVM}.src.tar.xz; \
	fi

${LLVM}_build: ${LLVM}

update:
		git submodule init
		git submodule update

clean:
		rm -rf ${LLVM_DIR}
		rm -rf SVF
		rm ${LLVM}.src.tar.xz