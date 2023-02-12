#include "../include/waterfall-ICFG.h"

#define DBG_FLAG 1

using namespace llvm;
using namespace std;

llvm::raw_ostream &icfg_dbg = llvm::errs();


AnalysisKey WaterfallICFGAnalysis::Key;

// Definition of the run function of the analysis.
// Here the actual stuff happens!!!
WaterfallICFGAnalysis::Result 
    WaterfallICFGAnalysis::run(Module &M, ModuleAnalysisManager &MM) 
{
    std::vector<FunctionInfo> AnalysisResult;
    #if DBG_FLAG
    icfg_dbg << "Waterfall ICFG Analysis\n";
    #endif
    return AnalysisResult;
}


// Definition of the run function of the analysis pass that
// will be invocable via opt. It uses the getResult<Analysis>()
// method of the ModuleAnalysisManager. This result will be the
// result defined in the waterfallAnalysis above.
PreservedAnalyses WaterfallICFGAnalysisPass::run(Module &M,
                                      ModuleAnalysisManager &MAM) {

    // Analysis should never change the LLVM IR code so all
    // results of other analyses are still valid!
    return PreservedAnalyses::all();
}