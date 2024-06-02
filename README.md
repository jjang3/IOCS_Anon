# IBCS

## What's included

```
./
├── useful_scripts
|       ├── dwarf_analysis.py
└── var_c14n
        ├── arcs.sh
        ├── asm_rewriter
                ├── main.py (for individual source file)
                └── core.sh         (for coreutils)
```

## How to use (To-do)
1) `git submodule init && git submodule update` - This will load all submodules per respective folders
2) `bash prepare.sh` - This will prepare everything needed for `fun_c14n` and `var_c14n`
3) `cd fun_c14n && cd comp_analysis && bash comp_analysis.sh epoll` - This will apply `fun_c14n` on the `epoll`
4) `cd var_c14n && bash arcs.sh epoll` - This will apply `ARCS` static pass on the `epoll`

---