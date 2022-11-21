# Todo notes

## Notes
- Separate each analysis pass into its own analysis file. Do not mix them.
  - ICFG analysis: `creates pseudo-inter-procedural graphs`
  - Compartmentalization analysis: `analyze graphs from above and instrument a fixed compartmentalization tag for each functions`

## Tasks
1. Create an ICFG analysis pass
2. This is interprocedural at the moment, is it possible to make this intraprocedural per function?