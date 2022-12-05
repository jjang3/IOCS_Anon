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

std::vector<FunctionInfo> extractCallGraph(PTACallGraph* inputCG)
{
    std::vector<FunctionInfo> extractedResults;
    SetVector<std::pair<int,int>> callerToCallee;
    SVFUtil::errs() << "\nTotal Node Number: " << inputCG->getTotalNodeNum() << "\n";
    for (auto F = inputCG->begin(), FE = inputCG->end(); F != FE; ++F)
    {
        auto cgNode = F->second;
        //SVFUtil::errs() << "Function: " << cgNode->getFunction()->getName() << "ID: " << cgNode->getId() << "\n";
        for (PTACallGraphNode::const_iterator it = cgNode->InEdgeBegin(), eit = cgNode->InEdgeEnd(); it != eit; ++it)
        {
            PTACallGraphEdge* callEdge = (*it);
            auto callerID = callEdge->getSrcNode()->getId();
            auto calleeID = callEdge->getDstNode()->getId();
            callerToCallee.insert(std::pair<int,int>(callerID,calleeID)); 
           
        }   
    }

    SetVector<std::pair<int,int>> relationVector;
    SetVector<int> dstIDs;
    FunctionInfo funInfo;
    #if 1
    for (auto F = inputCG->begin(), FE = inputCG->end(); F != FE; ++F)
    {
        funInfo.ID = F->first;
        funInfo.PTACGNode = F->second;
        for (auto CTCitem : callerToCallee)
        {
            if (F->first == (const unsigned int)CTCitem.first) 
            {   
                funInfo.dstIDs.insert(CTCitem.second);
            }
        }
        extractedResults.push_back(funInfo);
        dstIDs.clear();
        funInfo = (const struct FunctionInfo){ 0 };
    }   
    #endif
    #if 1
    for (auto ERitem : extractedResults) {
        
        SVFUtil::errs() << ERitem.PTACGNode->getFunction()->getName() << " ID: " << ERitem.ID << "\n";
        for (auto dstID : ERitem.dstIDs)
        {
            SVFUtil::errs() << ERitem.ID  << " -> " << dstID << "\n";
        }
        SVFUtil::errs() << "\n";
    }
    #endif
    return extractedResults;
}

PTACallGraph *buildNonIntrinsicCG(SVFModule *input, ICFG *icfg)
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
waterfallICFGAnalysis::Result waterfallICFGAnalysis::run(Module &M, ModuleAnalysisManager &MAM) 
{
    // This analysis pass iterates over the module and build call graph
    // to build a pseudo-inter-procedural graph.

    std::vector<FunctionInfo> analysisResults;
    PTACallGraph* callgraph = new PTACallGraph();
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

    // Create graph nodes without intrinsic functions
    callgraph = buildNonIntrinsicCG(svfModule, ander->getICFG());
    callgraph->dump(graphName);
    // Extract the generated call graph
    analysisResults = extractCallGraph(callgraph);
    return analysisResults;
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