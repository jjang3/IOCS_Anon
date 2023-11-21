# Automatic Redirection Compartmentalization Systems (ARCS)
Repository for the ARCS project

## What's included

```
./
├── taint_analysis (used for both fun_c14n and var_c14n)
├── fun_c14n
|       ├── comp_analysis
|       |       ├── e9stuff         (script files for e9patch)
|       |       ├── pku             (PKU-related files)
|       |       ├── e9patch         (submodule)
|       |       ├── inst-gcc-plugin (submodule)
|       |       └── scripts/comp_analysis.sh
|       └── OR_analysis (OR = Overprivilege)
└── var_c14n
        ├── asm_rewriter
        |       ├── binary_patch.py (for individual source file)
        |       └── core.sh         (for coreutils)
        └── static_analysis (for alias analysis)
                ├── include         (header files for LLVM ARCS pass)
                ├── src             (source files for LLVM ARCS pass)
                ├── spdlog          (submodule)
                └── SVF             (submodule)
```

## How to use (To-do)
1) `git submodule init && git submodule update`
2) `cd e9patch && bash build.sh` - This will build `e9patch` to be used later
3) `cd taint_analysis && make all`  
    - Sanity check: `cd scripts && bash execute.sh hello`
4) `export LLVM_DIR="/location/"` with your LLVM directory location.
5) From the `Waterfall` root directory, `mkdir build && cd build`
6) Install Z3 version by `wget`ing: `https://github.com/Z3Prover/z3/archive/refs/tags/z3-4.8.8.zip` and then build using `cmake`.
     - Make sure to `EXPORT Z3_DIR=/path/to/z3-build`
7) `cmake .. && make -j4`, this will first build the `SVF` library, then `waterfall`.
8) Insert an input file to `./inputs`
9) `bash waterfall.sh <source code name> waterfall (e.g., `bash waterfall.sh vuln_srv waterfall`)

--- 
## LLVM build direction:
```
CC=gcc CXX=g++ cmake -DCMAKE_INSTALL_PREFIX=$HOME/llvm-project-13/llvm-arm-build -DLLVM_TARGETS_TO_BUILD="ARM;X86;AArch64" -DLLVM_ENABLE_PROJECTS="clang" -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" -DLLVM_ENABLE_ASSERTIONS=True -DCMAKE_BUILD_TYPE=Release -Wno-dev -G Ninja ../llvm
```