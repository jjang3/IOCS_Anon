# Todo notes

## Tasks
| Task                            | Current Status  | Finished      | 
|----------------                 |---------------  |-----------    |
| Create an ICFG analysis pass | Completed | :white_check_mark: | 
| Create intra-procedural call graph (CG)| Completed | :white_check_mark: |
| Unwinding the stack to obtain the current function in runtime | In progress | :white_large_square: |
| Deterministic tagging per function (Instrumentation) | In progress | :white_large_square: |

## Notes
### File organization
- Separate each analysis pass into its own analysis file. Do not mix them.
  - ICFG analysis: `creates pseudo-inter-procedural graphs`
  - Compartmentalization analysis: `based on the input call graph and deterministic instrument a compartmentalization tag per each functions`

### Compartmentalization analysis
- [x] Use a `callGraphID` in the `callgraph` to determine whether it exceeds the count of 16 (ARM MTE limitation is 16 tags)
- [ ] Create a transfer relation table
  - [ ] 1) Need to unwind calls from a function (this will be used as an index)
    - [ ] `libunwind` -  I was able to successfully cross-compile a shared library into the `aarch64` architecture, but there is a problem with `glibc` which is preventing the execution of the test program.
    - [ ] `ELF utility` - Tried creating a test program by traversing through the secction names, but too complicated, hence abandoned.
    - [ ] `ARM specific unwind table` - Apparently there exists an `ARM` specific unwind table that can be used? Could not find any additional detail regarding it.
  - [ ] 2) Each function will generate its own unique encryption key (this will be used as a value to the key).
- [ ] Begin instrumenting deterministic tag entry point functions for all functions in a program
  - [x] Create a new instrumentation file for compartmentalization
  - [ ] Create a user-space version of instrumentation to test out the idea
    - [ ] Generate a random key at the entry point of the function.
      - Question, do I need to first generate index of all transfer relation, then store the key depending on the index value of the source fun? How to do this efficiently?
    - [ ] Create a transfer-relationship table with random key.
    - [ ] Tag everything in a target function with the same tag.
    - [ ] Retrieving the tag once you are in a different function.