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


/* ------------------------------- Helper functions related --------------------------------- */


bool isDoublePtr(const Value* V) {
    const Type* T = V->getType();
    if (T->getPointerElementType()->getPointerElementType()->isPointerTy()) {
        return true;
    } 
    else {
        return false;
    }
}
Instruction *recursiveFindAlloca (Instruction *I) {
    auto target_I = I;
    llvm::errs() << "Recursively finding alloca\t Current: " << *I << "\n";
    if (!llvm::dyn_cast<AllocaInst>(target_I)) {
        if (auto gep_I = llvm::dyn_cast<GetElementPtrInst>(target_I)) {
        auto gep_I_op = gep_I->getPointerOperand();
            return recursiveFindAlloca(llvm::dyn_cast<Instruction>(gep_I_op));
        } else if (auto zext_I = llvm::dyn_cast<ZExtInst>(target_I)) {
            auto zext_I_op = zext_I->getOperand(0);
            return recursiveFindAlloca(llvm::dyn_cast<Instruction>(zext_I_op));
        }
        else if (auto load_I = llvm::dyn_cast<LoadInst>(target_I)) {
            auto load_I_op = load_I->getPointerOperand();
            return recursiveFindAlloca(llvm::dyn_cast<Instruction>(load_I_op));
        }
        else if (auto ptr2int_I = llvm::dyn_cast<PtrToIntInst>(target_I)) {
            auto ptr2int_I_op = ptr2int_I->getPointerOperand();
            return recursiveFindAlloca(llvm::dyn_cast<Instruction>(ptr2int_I_op));
        }
        else if (auto store_I = llvm::dyn_cast<StoreInst>(target_I)) {
            auto store_I_op = store_I->getOperand(0);
            return recursiveFindAlloca(llvm::dyn_cast<Instruction>(store_I_op));
        }
    } 
    
    if (isDoublePtr(target_I)) {
        return NULL;
    }
    else {
        return target_I;
    }
}

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

/* ------------------------------- InstVisitor related --------------------------------- */

void Compartmentalization::visitAllocaInst(AllocaInst &AI) {
    llvm::errs() << "\n--------Visiting Alloca Started--------\n";
    llvm::errs() << "Visit Alloca: " << AI << "\n";
    for (auto *usr : AI.users()) {
        llvm::errs() << "\t» Usr: " << *usr << "\n";
        if (llvm::dyn_cast<BitCastInst>(usr)) {
            //allocaParent = true;
            visit(llvm::dyn_cast<Instruction>(usr));
        }
    }
    llvm::errs() << "--------Visiting Alloca Finished--------\n\n";
}


bool instrumentInst(BasicBlock &BB,
                    std::vector<std::pair<FunctionCallee, std::string>> FV, 
                    DataLayout *DL, Instruction *finalBBInst, std::vector<string> vulnFuns);

void waterfallCompartmentalization(Module &M, 
            std::vector<FunctionInfo> analysisInput, 
            std::vector<std::pair<string, std::vector<string>>> taintedVulnFuns)
{
    SVFUtil::errs() << "╔═══════════════════════════════════════════╗\n";
    SVFUtil::errs() << "║       Compartmentalization                ║\n";
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
                        instrumentInst(BB, funVectors, DL, finalBBInst, item.second);
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
                    DataLayout *DL, Instruction *finalBBInst, std::vector<string> vulnFuns) 
{
    Compartmentalization compartmentVisitor;
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
    #if 0
    for (auto item : vulnFuns)
    {
        llvm::errs() << "Fun: " << item << "\n";
    }
    #endif
    LLVMContext& context = BB.getContext();
    Type *i8Type = Type::getInt8Ty(context);
    Type *i64Type = Type::getInt64Ty(context);

    for (auto &inst : BB) {
        llvm::IRBuilder<> mte_builder(&inst);
        Instruction *curr_I = &inst;
        compartmentVisitor.visit(curr_I);
        #if 1
        // Beginning of alloca instruction check.
        if (auto curr_alloca_I = llvm::dyn_cast<AllocaInst>(curr_I)) {
            //llvm::errs() << *curr_alloca_I << "\n";
            for (auto user : curr_alloca_I->users())
            {

            }
        }
        #endif

        #if 1
         // Beginning of Call instruction check.
        if (auto curr_call_I = llvm::dyn_cast<CallInst>(curr_I)) {
            //errs() << *curr_call_I << "\n";
            auto curr_call_next = curr_call_I->getNextNode();
            UNUSED(curr_call_next);
            if (curr_call_I->getCalledFunction() != NULL) 
            {
                auto curr_call_fun_name = curr_call_I->getCalledFunction()->getName();
                if (std::find(vulnFuns.begin(), vulnFuns.end(), curr_call_fun_name) != vulnFuns.end())
                {
                    // If function is found, need to trace through each alloca and protect it
                    //llvm::errs() << "Function found: " << curr_call_fun_name << "\n";
                    // llvm::errs() << *curr_call_I << "\n";
                    //auto store_op = curr_call_I->getOperand();
                    //auto alloc_to_use = recursiveFindAlloca(llvm::dyn_cast<Instruction>(store_op));
                    //llvm::errs() << "Alloc found " << *alloc_to_use << "\n";
                    
                }
                
            }

        }
        #endif
    }
    return false;
}