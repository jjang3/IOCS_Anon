#include "../include/waterfall-analysis.h"

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include <iostream>

using namespace llvm;

AnalysisKey waterfallAnalysis::Key;

// Definition of the run function of the analysis.
// Here the actual stuff happens!!!
std::string waterfallAnalysis::run(Module &M, ModuleAnalysisManager &MAM) {

  // This pass just iterates over all instructions in all the
  // basic blocks of the function and appends their opcodes to
  // the output string.

  std::string output;

    auto fileName = M.getSourceFileName();
    auto bitcodeName = M.getModuleIdentifier();
    errs() << "Input file: " << bitcodeName << "\n";
  return output;
}

// Definition of the run function of the analysis pass that
// will be invocable via opt. It uses the getResult<Analysis>()
// method of the FunctionAnalysisManager. This result will be an
// std::string as we have defined the Result of MyAnalysis above.
// The result string is piped into the raw_ostream member
// of the MyAnalysisPass.
PreservedAnalyses waterfallAnalysisPass::run(Module &M,
                                      ModuleAnalysisManager &MAM) {


  // Analysis should never change the LLVM IR code so all
  // results of other analyses are still valid!
  return PreservedAnalyses::all();
}