# Waterfall
Repository for the Waterfall project

## What's included

```
./
├── include
├── sources
|      ├── 
|      ├── 
|      └── 
├── SVF (submodule)
└── waterfall.sh
```
- `include` = contains header files for the waterfall pass
- `sources` = contains source files for the waterfall pass
- `waterfall.sh` = a script that will `waterfall` a source code.

## How to use (To-do)
1) `git submodule init && git submodule update`
  - Build a directory called `arm_build` inside of the `libunwind` directory, then run the command of `./configure --prefix=/home/jay/Waterfall/libunwind/arm_build --target=aarch64 --host=x86_64 CC=/home/jay/gcc-10.3/bin/aarch64-none-linux-gnu-gcc CXX=arm-none-linux-gnu-g++` 
2) Change `LT_LLVM_INSTALL_DIR` in `CMakeLists.txt` file to the full directory of where the built `LLVM` project exists.
3) From the root directory, `mkdir build && cd build`
4) `cmake .. && make`, this will first build the `SVF` library, then `waterfall`.
5) Insert an input file to `./inputs`
6) `bash waterfall.sh <source code name> waterfall (e.g., `bash waterfall.sh vuln_srv waterfall`)
