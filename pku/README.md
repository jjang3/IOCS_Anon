# PKU-related README

> Input file (e.g., inputs/epoll.c) needs to be modified so that protected / untrusted sections are specifically designated.

1. `make lib` will create `libpkuapi.so`
2. `make /input/.out` will generate an executable with the isolated regions.
3. `bash execute.sh /output name/` to execute the application
    - Example: `bash execute.sh epoll`

`https://github.com/cyrus-and/gdb-dashboard.git` < Useful GDB tool >