#include "llvm/ADT/SetVector.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Format.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"

#include "SVF-LLVM/LLVMUtil.h"
#include "WPA/Andersen.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "Util/CallGraphBuilder.h"
#include "Util/Options.h"
#include "Graphs/ICFG.h"
#include "Graphs/SVFG.h"

using namespace SVF;
using namespace SVFUtil;
using namespace llvm;

// This is the actual analysis that will perform some operation
class waterfallICFGAnalysis : public AnalysisInfoMixin<waterfallICFGAnalysis> {
  // needed so that AnalysisInfoMixin<waterfallAnalysis> can access
  // private members of waterfallAnalysis
  friend AnalysisInfoMixin<waterfallICFGAnalysis>;
  static AnalysisKey Key;

public:
  // You need to define a result. This can also be some other class.
  using Result = std::string;
  Result run(Module &M, ModuleAnalysisManager &MAM);
};

// This is the analysis pass that will be invocable via opt
class waterfallICFGAnalysisPass : public AnalysisInfoMixin<waterfallICFGAnalysisPass> {

public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};
