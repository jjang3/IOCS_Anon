#include "../include/waterfall-compart.h"

#include <algorithm>
#include "llvm/ADT/SetVector.h"
#include "llvm/Support/Casting.h"
#include <llvm/Support/raw_ostream.h>
//Instrumentation 
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"

#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Instrumentation.h"

#include "llvm/Analysis/LoopInfo.h"

using namespace llvm;
using namespace std;


std::map<GetElementPtrInst*, Value*> gep_access_bit;
std::map<Instruction*,AllocaInst*> alloc_to_patch;
std::map<Instruction*, StringRef> insts_patch_type;
std::map<Instruction*, Function*> insts_inter_funs;
SetVector<std::pair<CallInst*, int>> call_inst_to_op;
SetVector<Instruction*> insts_to_remove;
SetVector<Instruction*> custom_mallocs;
SetVector<std::pair<StringRef, AllocaInst*>> custom_allocs;

std::vector<std::pair<FunctionCallee, std::string>> initializeFuns(Module &M, Function *currFun) {

    LLVMContext& context = M.getContext();
    PointerType *int8Ptr = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
    PointerType *int8DoublePtr = PointerType::get(int8Ptr, 0);
    std::vector<Type*> charDoublePtrParamTypes = {int8DoublePtr};
    std::vector<Type*> charParamTypes = {int8Ptr};
    std::vector<Type*> irgParamTypes = {int8Ptr, IntegerType::get(M.getContext(), 64)};
    std::vector<Type*> stgParamTypes = {int8Ptr, int8Ptr};

    #if 1
    Type *retType = Type::getVoidTy(context);   
    Type *charPtrRetType = Type::getInt8PtrTy(context);   

    FunctionType *mteInitFunType = FunctionType::get(charPtrRetType, charParamTypes, false);
    #endif
    
    FunctionCallee mteInit = currFun->getParent()->getOrInsertFunction("mte_init", mteInitFunType);

    std::vector<std::pair<FunctionCallee, std::string>> funsVector;
    funsVector.push_back(std::pair<FunctionCallee, std::string>(mteInit, "mte_init"));
    return funsVector;
}

bool instrumentInst(BasicBlock &BB,
                    std::vector<std::pair<FunctionCallee, std::string>> FV, 
                    DataLayout *DL, Instruction *finalBBInst);

void waterfallCompartmentalization(Module &M, 
            std::vector<FunctionInfo> analysisInput, std::vector<std::pair<string, std::vector<string>>> taintedVulnFuns)
{
    SVFUtil::errs() << "╔═══════════════════════════════════════════╗\n";
    SVFUtil::errs() << "║       Instrumentation Analysis            ║\n";
    SVFUtil::errs() << "╚═══════════════════════════════════════════╝\n";
    DataLayout *DL = new DataLayout(&M);
    SetVector<BasicBlock*> visitedBBs;
    std::vector<std::pair<FunctionCallee, std::string>> funVectors;

    for (FunctionInfo analysisFun : analysisInput) 
    {
        Function *currFun = analysisFun.nodeFun; 
        auto bbList = &currFun->getBasicBlockList();
        auto finalBB = bbList->rbegin();
        auto finalBBInst = finalBB->getTerminator();
        funVectors = initializeFuns(M, currFun);
        for (auto item : taintedVulnFuns)
        {
            //llvm::errs() << item << "\n";
            if (currFun->getName() == item.first)
            {
                llvm::errs() << "=======" << currFun->getName() << "=======\n";
                for (auto &BB : *currFun) 
                {
                    if (!(visitedBBs.contains(&BB))){
                        instrumentInst(BB, funVectors, DL, finalBBInst);
                        visitedBBs.insert(&BB);
                    }
                }
            }
        }
    }
    
    for (auto inst : insts_to_remove)
    {
        //llvm::errs() << *Inst << "\n";
        inst->removeFromParent();
    }
}

bool instrumentInst (BasicBlock &BB,
                    std::vector<std::pair<FunctionCallee, std::string>> FV, 
                    DataLayout *DL, Instruction *finalBBInst) 
{
    // ======= Function initializations ======= //
    FunctionCallee mteInit;
     for (auto item : FV) 
     {
        if (item.second == "mte_init") {
            mteInit = item.first;
        }
     }
    auto currFunction = BB.getParent();
    auto currFunName = currFunction->getName();
    UNUSED(currFunName);

    LLVMContext& context = BB.getContext();
    Type *i8Type = Type::getInt8Ty(context);
    Type *i64Type = Type::getInt64Ty(context);

    for (auto &inst : BB) {
        llvm::IRBuilder<> mte_builder(&inst);
        Instruction *curr_I = &inst;

        #if 1
        // Beginning of alloca instruction check.
        if (auto curr_alloca_I = llvm::dyn_cast<AllocaInst>(curr_I)) {
            llvm::errs() << *curr_alloca_I << "\n";
            
        }
        #endif
    }
    return false;
}