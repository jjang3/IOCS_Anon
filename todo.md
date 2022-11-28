# TODO notes

## Tasks
| Task                            | Current Status  | Finished      | 
|----------------                 |---------------  |-----------    |
| Create an ICFG analysis pass | Completed | :white_check_mark: | 
| Create intra-procedural call graph (CG)| Completed | :white_check_mark: |
| Unwinding the stack to obtain the current function in runtime | In progress | :white_large_square: |
| Deterministic tagging per function (Instrumentation) | In progress | :white_large_square: |

<!---
Legend:
:white_check_mark: - Task finished
:white_large_square: - Task not finished
:o: - Progress finished
:x: - Failed
:recycle: - In-progress
:soon: - Next progress to be started
-->

### LLVM pass organization
- Separate each analysis pass into its own analysis file. Do not mix them.
  - ICFG analysis: `creating pseudo-inter-procedural graph / ID relationship to be passed through compartmentlization analysis`
  - Compartmentalization analysis: `based on the input call graph and deterministic instrument a compartmentalization tag per each functions`


## Progress

### ICFG analysis
- [x] :o: Use the [SVF](https://github.com/SVF-tools/SVF) tool to generate pseudo inter-proecdural graph.
  - [x] :o: Using a `callGraphID` in the `callgraph` to determine the transfer between functions and check whether it exceeds the count of 16 (ARM MTE limitation is 16 tags)

### Compartmentalization analysis
- [ ] :recycle: Create a transfer relation table
  - [ ] 1) :soon: Figure out how to implement lookup table - [Potential Solution](https://developer.arm.com/documentation/ka004546/latest) / [Potential Solution 2](https://www.oreilly.com/library/view/arm-assembly-language/9781800561274/video10_2.html)
    - [ ] :soon: Any potential alternatives? Do I really need to use a table? Can we reserve a register to be used for the caller to store its encryption key? How about utilizing `x#` register of `aarch64`? [Potential Solution](https://eclecticlight.co/2021/07/08/code-in-arm-assembly-moving-data-around/)
  - [ ] 2) :recycle: Need to unwind calls from a function (this will be used as an index) - [Solutions](https://stackoverflow.com/questions/3899870/print-call-stack-in-c-or-c)
    - [x] :x: `libunwind` -  I was able to successfully cross-compile a shared library into the `aarch64` architecture, but there is a problem with `glibc` which is preventing the execution of the test program.
    - [ ] :recycle: `ELF utility` - Tried creating a test program by traversing through the secction names, but too complicated, hence abandoned.
    - [ ] :recycle: `ARM specific unwind table` - Apparently there exists an `ARM` specific unwind table that can be used? Utilizing link register? - [Potential Solution](https://community.silabs.com/s/article/how-to-read-the-link-register-lr-for-an-arm-cortex-m-series-device?language=en_US#:~:text=Link%20Register-,On%20an%20ARM%20Cortex%20M%20series%20device%2C%20the%20link%20register,%2C%200xFFFFFFF9%2C%20or%200xFFFFFFFD) / [Potential Solution 2](https://minghuasweblog.wordpress.com/2013/04/05/arm-cc-software-stack-back-trace/)
  - [ ] :soon: 3) Each function will generate its own unique encryption key (this will be used as a value to the key).
    - [x] :o: Function to generate encryption key (derive it from `SHROUD`).
    - [ ] :soon: Upon generating the encryption key, insert this key into the table with unwind information
- [ ] :soon: Begin instrumenting deterministic tag entry point functions for all functions in a program
  - [x] Create a userspace deterministic tagging API
    - [x] :o: Tagging pointers in a target function with the same tag.
  - [ ] Create a full version of userspace instrumentation and test out the idea
    - [ ] Generate a random key at the entry point of the function.
      - Question, do I need to first generate index of all transfer relation, then store the key depending on the index value of the source fun? How to do this efficiently?
    - [ ] Create a transfer-relationship table with random key.
    - [ ] Retrieving the tag once you are in a different function.