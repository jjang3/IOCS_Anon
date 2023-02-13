#include "../include/waterfall-ICFG.h"

#define DBG_FLAG 0

using namespace llvm;
using namespace std;

llvm::raw_ostream &icfg_dbg = llvm::errs();


AnalysisKey WaterfallICFGAnalysis::Key;


WaterfallICFGAnalysis::Result extractCallGraph(Module &M, PTACallGraph* inputCG)
{

}

PTACallGraph *buildDTAInputGraph(SVFModule *input, PTACallGraph *PTACG) 
{
    PTACallGraph *output = new PTACallGraph();
    
    auto &callInstToCGEdgesM = PTACG->getCallInstToCallGraphEdgesMap();
    for (auto mapIt = callInstToCGEdgesM.begin(); mapIt != callInstToCGEdgesM.end(); mapIt++) {
        auto *cbNode = mapIt->first;
        auto cgEdgeSet = mapIt->second;
        auto *caller = cbNode->getCaller();
        auto *callsite = cbNode->getCallSite();

        PTACallGraph::FunctionSet funSet;
        PTACG->getCallees(cbNode, funSet);

        for (auto funSetIt = funSet.begin(); funSetIt != funSet.end(); funSetIt++) {
            const SVFFunction *callee = *funSetIt;
            icfg_dbg << callee->getName().c_str() << "\n";
        }

        // iterate each ICFGNode on ICFG
        for(PTACallGraph::iterator i = PTACG->begin(); i != PTACG->end(); i++)
        {
            auto *n = i->second;
            
            //}
        }

    
    }
    #if 0
    for (SVFModule::const_iterator F = input->begin(), FE = input->end(); F != FE; ++F)
    {
        const SVFFunction *svfFun = *F;
        for (SVFFunction::const_iterator BB = svfFun->begin(), BE = svfFun->end(); BB != BE; ++BB)
        {
            const SVFBasicBlock *svfBB = *BB;
            for (SVFBasicBlock::const_iterator I = svfBB->begin(), IE = svfBB->end(); I != IE; ++I)
            {
                const SVFInstruction *svfI = *I;
            }
        }
        output->addCallGraphNode(*F);
    }
    #endif
    #if 0
    for (SVFModule::const_iterator F = input->begin(), E = input->end(); F != E; ++F)
    {
        for (const SVFBasicBlock* svfbb : (*F)->getBasicBlockList())
        {
            for (const SVFInstruction* inst : svfbb->getInstructionList())
            {
                if(isCallSite(inst))
                {
                    auto instCallSite = getSVFCallSite(inst);
                    auto instCallee  = getCallee(instCallSite);
                    const CallICFGNode* callBlockNode = icfg->getCallICFGNode(inst);
                    output->addDirectCallGraphEdge(callBlockNode, *F, instCallee);
                    icfg_dbg << "Found: " << inst->toString() << " " << inst->getFunction()->toString() << "\n";
                }
            }
        }
    }
    #endif
    return output;
}

// Definition of the run function of the analysis.
// Here the actual stuff happens!!!
WaterfallICFGAnalysis::Result 
    WaterfallICFGAnalysis::run(Module &M, ModuleAnalysisManager &MM) 
{
    std::vector<FunctionInfo> AnalysisResult;
    #if DBG_FLAG
    icfg_dbg << "Waterfall ICFG Analysis\n";
    #endif

    PTACallGraph* callgraph = new PTACallGraph();
    auto fileName = M.getSourceFileName();
    auto bitcodeName = M.getModuleIdentifier();
    // /home/jay/Waterfall_Full/results/scanf_ex/scanf_ex.bc -> /home/jay/Waterfall_Full/results/scanf_ex
    auto resultName = std::regex_replace(bitcodeName, std::regex("\\/[a-z,^\\_]*.bc"), "");

    auto graphName = resultName + "/callgraph";

    //exit(1);
    // Build Program Assignment Graph (SVFIR)
    SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule({bitcodeName});
    SVFIRBuilder builder(svfModule);
    SVFIR* pag = builder.build();
    ICFG *icfg = pag->getICFG();
    //icfg->dump(graphName);
    //pag->dump(graphName);
    // iterate each ICFGNode on ICFG
    for(ICFG::iterator inode = icfg->begin(); inode != icfg->end(); inode++)
    {
        ICFGNode *n = inode->second;
        //SVFUtil::outs() << n->toString() << "\n";
        // for(ICFGEdge* edge : n->getOutEdges()){
        //     SVFUtil::outs() << edge->toString() << "\n";
        // }
        if (SVFUtil::isa<FunEntryICFGNode>(n))
        {
            icfg_dbg << "Fun entry: " << n->toString().c_str() << "\n";
        }
        if (SVFUtil::isa<CallICFGNode>(n)) { 
            CallICFGNode* callNode =  SVFUtil::cast<CallICFGNode>(n);
            const SVFInstruction* svfInst = callNode->getCallSite();
            icfg_dbg << svfInst->toString().c_str() << "\n";
        }          
    }
    /// Create Andersen's pointer analysis
    //Andersen* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);
    //ander->getPTACallGraph()->dump(graphName);

    #if 0
    /// Sparse value-flow graph (SVFG)
    SVFGBuilder svfBuilder(true);
    //SVFG* svfg =
    auto svfg_build = svfBuilder.buildFullSVFG(ander);

    for(auto i = svfg_build->begin(); i != svfg_build->end(); i++)
    {
        icfg_dbg << i->second->Addr  << "\n";
    }
    #endif
    // Create graph nodes without intrinsic functions
    //callgraph = buildDTAInputGraph(svfModule, ander->getPTACallGraph());
    //callgraph->dump(graphName);
    //AnalysisResult = extractCallGraph(M, callgraph);
    
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