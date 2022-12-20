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

#include "../include/waterfall-struct.h"

using namespace SVF;
using namespace SVFUtil;
using namespace llvm;
using namespace std;

#define UNUSED(x) (void)(x);

class Compartmentalization : public InstVisitor<Compartmentalization> {
    public:
        void visitAllocaInst(AllocaInst &AI);
        //void visitBitCastInst(BitCastInst &BI);
        //void visitCallInst(CallInst &CI);
        //void visitGetElementPtrInst(GetElementPtrInst &GEPI);
        //void visitStoreInst(StoreInst &SI);
};

void waterfallCompartmentalization(Module &M, std::vector<FunctionInfo> analysisInput, 
                                    std::vector<std::pair<string, std::vector<string> >> taintedVulnFuns);
bool instrumentInst(BasicBlock &BB, std::vector<std::pair<FunctionCallee, std::string>> FV, 
                    DataLayout *DL, Instruction *finalBBInst, std::vector<string>  vulnFuns);