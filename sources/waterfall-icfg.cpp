#include "../include/waterfall-icfg.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include <iostream>
#include <regex>

using namespace llvm;

AnalysisKey waterfallICFGAnalysis::Key;

PTACallGraph *buildNonintrinsicCG(SVFModule *input, ICFG *icfg)
{
    SmallVector<const SVFFunction*> nonIntrinsicList;
    PTACallGraph *output = new PTACallGraph();
    #if 1
    for (SVFModule::const_iterator F = input->begin(), FE = input->end(); F != FE; ++F)
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
             SVFUtil::errs() << "Insert " << svfFun->toString() << "\n";
            nonIntrinsicList.push_back(svfFun);
            output->addCallGraphNode(*F);
        }
    }
    for (SVFModule::const_iterator F = input->begin(), E = input->end(); F != E; ++F)
    {
        for (const SVFBasicBlock* svfbb : (*F)->getBasicBlockList())
        {
            for (const SVFInstruction* inst : svfbb->getInstructionList())
            {
                if (SVFUtil::isNonInstricCallSite(inst))
                {
                    const SVFFunction* callee = getCallee(inst);
                    for (auto item : nonIntrinsicList) {
                        if (item == callee) {
                            const CallICFGNode* callBlockNode = icfg->getCallICFGNode(inst);
                            output->addDirectCallGraphEdge(callBlockNode,*F,callee);
                            SVFUtil::errs() << "Found: " << inst->toString() << " " << inst->getFunction()->toString() << "\n";
                        }
                    }
                }
            }
        }
    }
    #endif
    return output;
}

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
    // Build Program Assignment Graph (SVFIR)
    SVFIRBuilder builder(svfModule);
    SVFIR* pag = builder.build();
    /// Create Andersen's pointer analysis
    Andersen* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);
    
    PTACallGraph* callgraph = new PTACallGraph();

    // Create graph nodes without intrinsic functions
    callgraph = buildNonintrinsicCG(svfModule, ander->getICFG());
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