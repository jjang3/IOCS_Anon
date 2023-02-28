# Waterfall
Repository for the Waterfall project

## What's included

```
./
├── e9patch (sudmodule)
├── e9stuff
├── include
├── pku
├── sources
├── SVF (submodule)
├── taint_analysis (submodule)
└── waterfall.sh
```
- `e9stuff` = contains script files for the `e9patch`-related binary rewriting.
- `include` = contains header files for the waterfall LLVM pass
- `pku` = contains necessary files for the Intel Memory Protection Key (MPK)
- `sources` = contains source files for the waterfall LLVM pass
- `taint_analysis` = contains files for the taint analysis using Intel PIN
- `waterfall.sh` = a script that will `waterfall` a source code

## How to use (To-do)
1) `git submodule init && git submodule update`
2) `cd e9patch && bash build.sh` - This will build `e9patch` to be used later
3) `cd taint_analysis && make all`  
    - Sanity check: `cd scripts && bash execute.sh hello`
4) `export LLVM_DIR="/location/"` with your LLVM directory location.
5) From the `Waterfall` root directory, `mkdir build && cd build`
6) Install Z3: `sudo apt-get install z3 libz3-dev`
7) `cmake .. && make -j4`, this will first build the `SVF` library, then `waterfall`.
8) Insert an input file to `./inputs`
9) `bash waterfall.sh <source code name> waterfall (e.g., `bash waterfall.sh vuln_srv waterfall`)
