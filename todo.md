# Todo notes

## Tasks
| Task                            | Current Status  | Finished      | 
|----------------                 |---------------  |-----------    |
| Create an ICFG analysis pass | Completed | :white_check_mark: | 
| Create intra-procedural call graph (CG)| Completed | :white_check_mark: |
| Deterministic tagging per function (Instrumentation) | In progress | :white_large_square: |

## Notes
### File organization
- Separate each analysis pass into its own analysis file. Do not mix them.
  - ICFG analysis: `creates pseudo-inter-procedural graphs`
  - Compartmentalization analysis: `based on the input call graph and deterministic instrument a compartmentalization tag per each functions`

### Compartmentalization analysis
- [x] Use a `callGraphID` in the `callgraph` to determine whether it exceeds the count of 16 (ARM MTE limitation is 16 tags)
- [x] Create a transfer relation table
- [ ] Begin instrumenting deterministic tag entry point functions for all functions in a program