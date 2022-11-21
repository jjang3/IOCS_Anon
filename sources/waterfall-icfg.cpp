#include "../include/waterfall-icfg.h"

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include <iostream>
#include <regex>

using namespace llvm;

AnalysisKey waterfallICFGAnalysis::Key;

// Definition of the run function of the analysis.
// Here the actual stuff happens!!!
std::string waterfallICFGAnalysis::run(Module &M, ModuleAnalysisManager &MAM) 
{
    // This analysis pass iterates over the module and build call graph
    // to build a pseudo-inter-procedural graph.

    std::string output;
    auto fileName = M.getSourceFileName();
    auto bitcodeName = M.getModuleIdentifier();
    auto resultName = std::regex_replace(bitcodeName, std::regex("\\/[a-z]*.bc"), "");
    auto graphName = resultName + "/callgraph";
    //errs() << "Input file: " << bitcodeName << "\n";

    SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule({bitcodeName});
    PTACallGraph* callgraph = new PTACallGraph();
    for (SVFModule::const_iterator F = svfModule->begin(), FE = svfModule->end(); F != FE; ++F)
    {
        bool nonIntrinsic = false;
        const SVFFunction *svfFun = *F;
        for (SVFFunction::const_iterator BB = svfFun->begin(), BE = svfFun->end(); BB != BE; ++BB)
        {
            const SVFBasicBlock *svfBB = *BB;
            for (SVFBasicBlock::const_iterator I = svfBB->begin(), IE = svfBB->end(); I != IE; ++I)
            {
                const SVFInstruction *svfI = *I;
                if (!isIntrinsicInst(svfI))
                {
                    nonIntrinsic = true;
                }
            }
        }
        if (nonIntrinsic)
        {
            callgraph->addCallGraphNode(*F);
        }
    }
    callgraph->dump(graphName);
    #if 0
    // Minimalistic example to get the call graph to work.
    // Build Program Assignment Graph (SVFIR)
    SVFIRBuilder builder(svfModule);
    SVFIR* pag = builder.build();
    /// Create Andersen's pointer analysis
    Andersen* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);
    /// Call Graph
    PTACallGraph* callgraph = ander->getPTACallGraph();
    PointerAnalysis::CallGraphSCC* callgraphSCC = new PointerAnalysis::CallGraphSCC(callgraph);
    //callgraph->dump(graphName);
    callgraphSCC->graph()->dump(graphName);
    #endif
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