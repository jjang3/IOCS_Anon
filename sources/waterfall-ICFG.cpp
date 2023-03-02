#include "../include/waterfall-ICFG.h"

#define DBG_FLAG 0

using namespace llvm;
using namespace std;

llvm::raw_ostream &icfg_dbg = llvm::errs();


AnalysisKey WaterfallICFGAnalysis::Key;
PTACallGraph *buildNonIntrinsicCG(SVFModule *input, ICFG *icfg)
{
    SmallVector<const SVFFunction*> nonIntrinsicList;
    PTACallGraph *output = new PTACallGraph();

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
            icfg_dbg << "Insert " << svfFun->toString() << "\n";
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
                            //icfg_dbg << "Found: " << inst->toString() << " " << inst->getFunction()->toString() << "\n";
                        }
                    }
                }
            }
        }
    }
    return output;
}

// Definition of the run function of the analysis.
// Here the actual stuff happens!!!
WaterfallICFGAnalysis::Result 
    WaterfallICFGAnalysis::run(Module &M, ModuleAnalysisManager &MM) 
{
    std::vector<FunctionInfo> AnalysisResult;
    FunctionInfo funInfo;
    #if DBG_FLAG
    icfg_dbg << "Waterfall ICFG Analysis\n";
    #endif
    
    auto fileName = M.getSourceFileName();
    auto bitcodeName = M.getModuleIdentifier();
    auto resultName = std::regex_replace(bitcodeName, std::regex("\\/[a-z,^\\_]*.bc"), "");
    auto graphName = resultName + "/callgraph";

    // Build Program Assignment Graph (SVFIR)
    PTACallGraph* callgraph = new PTACallGraph();
    SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule({bitcodeName});
    SVFIRBuilder builder(svfModule);
    SVFIR* pag = builder.build();

    /// Create Andersen's pointer analysis
    Andersen* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);
    
    // Create graph nodes without intrinsic functions
    callgraph = buildNonIntrinsicCG(svfModule, ander->getICFG());
    callgraph->dump(graphName);
    funInfo.resultGraph = callgraph;
    AnalysisResult.push_back(funInfo);
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