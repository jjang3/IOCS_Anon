#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include <iostream>

using namespace llvm;

// This is the actual analysis that will perform some operation
class waterfallAnalysis : public AnalysisInfoMixin<waterfallAnalysis> {
  // needed so that AnalysisInfoMixin<waterfallAnalysis> can access
  // private members of waterfallAnalysis
  friend AnalysisInfoMixin<waterfallAnalysis>;
  static AnalysisKey Key;

public:
  // You need to define a result. This can also be some other class.
  using Result = std::string;
  Result run(Module &M, ModuleAnalysisManager &MAM);
};

// This is the analysis pass that will be invocable via opt
class waterfallAnalysisPass : public AnalysisInfoMixin<waterfallAnalysisPass> {
  raw_ostream &OS;

public:
  explicit waterfallAnalysisPass(raw_ostream &OS) : OS(OS) {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};
