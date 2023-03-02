#include "../include/waterfall-struct.h"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

#include "SVF-LLVM/LLVMUtil.h"
#include "WPA/Andersen.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "Util/CallGraphBuilder.h"
#include "Util/Options.h"
#include "Graphs/ICFG.h"
#include "Graphs/SVFG.h"

#include <iostream>
#include <regex>

using namespace SVF;
using namespace SVFUtil;
using namespace llvm;

PTACallGraph *buildNonIntrinsicCG(SVFModule *input, ICFG *icfg);

class WaterfallICFGAnalysis
    : public llvm::AnalysisInfoMixin<WaterfallICFGAnalysis> {
// needed so that AnalysisInfoMixin<Main> can access
// private members of ICFG analysis
  // Provide a unique key, i.e., memory address to be used by the LLVM's pass
  // infrastructure.
  friend AnalysisInfoMixin<WaterfallICFGAnalysis>;
  static AnalysisKey Key; // NOLINT
public:
  // You need to define a result. This can also be some other class.
  //using Result = std::vector<std::pair<PTACallGraphNode*, SetVector<std::pair<int,int>>>>;
  using Result = std::vector<FunctionInfo>;
  Result run(Module &M, ModuleAnalysisManager &MAM);
};

// This is the analysis pass that will be invocable via opt
class WaterfallICFGAnalysisPass 
    : public AnalysisInfoMixin<WaterfallICFGAnalysisPass> {

public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};
