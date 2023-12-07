# Automatic Redirection Compartmentalization Systems (ARCS)
Repository for the ARCS project

## What's included

```
./
├── taint_analysis (used for both fun_c14n and var_c14n)
├── prepare.sh
├── useful_scripts
|       ├── dwarf_analysis.py
├── fun_c14n
|       ├── taint.sh
|       ├── comp_analysis
|       |       ├── e9stuff         (script files for e9patch)
|       |       ├── pku             (PKU-related files)
|       |       ├── e9patch         (submodule)
|       |       ├── inst-gcc-plugin (submodule)
|       |       └── scripts/comp_analysis.sh
|       └── OR_analysis (OR = Overprivilege)
└── var_c14n
        ├── taint.sh
        ├── arcs.sh
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
1) `git submodule init && git submodule update` - This will load all submodules per respective folders
2) `bash prepare.sh` - This will prepare everything needed for `fun_c14n` and `var_c14n`
3) `cd fun_c14n && cd comp_analysis && bash comp_analysis.sh epoll` - This will apply `fun_c14n` on the `epoll`
4) `cd var_c14n && bash arcs.sh epoll` - This will apply `ARCS` static pass on the `epoll`

---