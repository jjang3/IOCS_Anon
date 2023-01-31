# Waterfall
Repository for the Waterfall project

## What's included

```
./
├── sources
├── tests
├── scripts
├── libdft64 (submodule)
├── compile.sh
└── Makefile
```
- `sources` = contains taint analysis source file
- `tests` = contains test input files 
- `scripts` = contains script files for test applications
- `libdft64` = libdft64 submodule
- `compile.sh` = a script for compiling a library

## How to use (To-do)
1) `make all` - This will initialize everyhting.
2) `bash compile.sh` - This will compile a library and store it in the new `lib` folder
3) `python3 function_analysis.py input-file` 