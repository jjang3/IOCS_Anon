# Waterfall
Repository for the Waterfall project

## What's included

```
./
├── include
├── sources
├── SVF (submodule)
├── taint_analysis  
└── waterfall.sh
```
- `include` = contains header files for the waterfall pass
- `sources` = contains source files for the waterfall pass
- `taint_analysis` = contains files for the taint  analysis
- `waterfall.sh` = a script that will `waterfall` a source code.

## How to use (To-do)
1-1) *Recommended*: `cd taint_analysis && make all`  - This is highly recommended. 
1-2) `git submodule init && git submodule update`
1) `export LLVM_DIR="/location/"` with your LLVM directory location.
2) From the `Waterfall` root directory, `mkdir build && cd build`
3) `cmake .. && make -j4`, this will first build the `SVF` library, then `waterfall`.
4) Insert an input file to `./inputs`
5) `bash waterfall.sh <source code name> waterfall (e.g., `bash waterfall.sh vuln_srv waterfall`)
