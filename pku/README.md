# PKU-related README

1. `make` from this directory will create `libpkuapi.so`
2. `cd tests && make hello.out` will create the test executable
3. `bash execute.sh $test_name` with updated `LD_LIBRARY_PATH` to the pku library folder will execute.
    - Example: `bash execute.sh hello`

`https://github.com/cyrus-and/gdb-dashboard.git` < Useful GDB tool >