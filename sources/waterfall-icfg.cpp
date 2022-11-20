#include "../include/waterfall-icfg.h"

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include <iostream>

using namespace llvm;

AnalysisKey waterfallICFGAnalysis::Key;

// Definition of the run function of the analysis.
// Here the actual stuff happens!!!
std::string waterfallICFGAnalysis::run(Module &M, ModuleAnalysisManager &MAM) 
{
    // This analysis pass iterates over the module and build call graph
    // to build a pseudo-inter-procedural graph.

    std::string output;

    std::vector<std::string> moduleNameVec;
    auto fileName = M.getSourceFileName();
    auto bitcodeName = M.getModuleIdentifier();
    errs() << "Input file: " << bitcodeName << "\n";

    SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);
    svfModule->getAliasSet();

    return output;

}

// Definition of the run function of the analysis pass that
// will be invocable via opt. It uses the getResult<Analysis>()
// method of the ModuleAnalysisManager. This result will be the
// result defined in the waterfallAnalysis above.
PreservedAnalyses waterfallICFGAnalysisPass::run(Module &M,
                                      ModuleAnalysisManager &MAM) {

    // Analysis should never change the LLVM IR code so all
    // results of other analyses are still valid!
    return PreservedAnalyses::all();
}