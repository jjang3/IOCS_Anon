#include "../include/waterfall-compart.h"
#include <algorithm>

using namespace llvm;
using namespace std;

SetVector<Function*> funsInModule;

Function *findFun(StringRef targetFunName)
{
    Function *returnFun;
    for (auto &item : funsInModule)
    {
        //llvm::errs() << item->getName() << " - " << targetFunName << "\n";
        if (item->getName() == targetFunName)
        {
            llvm::errs() << "Function found\n\t" << item->getName() << "\n";
            returnFun = item;
            break;
        }
    }
    return returnFun;
}

void waterfallCompartmentalization(Module &M, 
            std::vector<FunctionInfo> analysisInput, std::vector<std::string> taintedFunctions)
{
    SVFUtil::errs() << "╔═══════════════════════════════════════════╗\n";
    SVFUtil::errs() << "║       Instrumentation Analysis            ║\n";
    SVFUtil::errs() << "╚═══════════════════════════════════════════╝\n";

    for (Function &fun : M)
    {
        //llvm::errs() << fun.getName() << "\n";
        funsInModule.insert(&fun);
    }

    for (auto item : taintedFunctions)
    {
        //llvm::errs() << item;
    }

    DataLayout *DL = new DataLayout(&M);
    LLVMContext& context = M.getContext(); 
    SetVector<BasicBlock*> visitedBBs;
    for (FunctionInfo analysisFun : analysisInput) 
    {
        auto *currFun = analysisFun.PTACGNode->getFunction(); 
        //SVFUtil::errs() << currFun->getName() << "\n";    
        Function *targetFun;   
    
        for (auto item : taintedFunctions)
        {
            //llvm::errs() << item << "\n";
            if (currFun->getName() == item)
            {
                //llvm::errs() << "Checking: " << currFun->getName() << "\n";
                targetFun = findFun(item);
            }
        }
        //auto finalBBInst = finalBB->getTerminator();
    }
}
