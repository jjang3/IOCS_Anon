# Waterfall
Repository for the Waterfall project

## What's included

```
./
├── sources
├── libdft64 (submodule)
└── taint.sh
```
- `sources` = contains taint analysis source file
- `libdft64` = libdft64 submodule
- `taint.sh` = a script for initialization

## How to use (To-do)
1) `bash taint.sh`
2) Change `LT_LLVM_INSTALL_DIR` in `CMakeLists.txt` file to the full directory of where the built `LLVM` project exists.
3) From the root directory, `mkdir build && cd build`
4) `cmake .. && make`, this will first build the `SVF` library, then `waterfall`.
5) Insert an input file to `./inputs`
6) `bash waterfall.sh <source code name> waterfall (e.g., `bash waterfall.sh vuln_srv waterfall`)