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


SetVector<Instruction*> insts_to_remove;
SetVector<Instruction*> alloc_to_compartment;
SetVector<StringRef> structs;
llvm::SetVector<std::pair<llvm::Instruction*, int>> compartmentTargets;


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
    #if 0
    for (auto item : vulnFuns)
    {        llvm::errs() << item << "\n";    }
    #endif
    llvm::errs() << "\n--------Visiting Alloca Started--------\n";
    llvm::errs() << "Visit Alloca: " << AI << " | Type: " << *AI.getType()->getPointerElementType() << "\n";
    for (auto *usr : AI.users()) {
        llvm::errs() << "\t» Usr: " << *usr << "\n";
        if (llvm::dyn_cast<BitCastInst>(usr)) {
            allocaParent = true;
        }
        visit(llvm::dyn_cast<Instruction>(usr));
    }
    if (allocaCompartment == true)
    {
        if (AI.getType()->getPointerElementType()->isStructTy())
        {
            if (structs.contains(AI.getType()->getPointerElementType()->getStructName()))
            {
                //llvm::errs() << "Struct found, ignore\n";
                return;
            }
        }
        else
        {
            alloc_to_compartment.insert(llvm::dyn_cast<Instruction>(&AI));
        }
    }
    allocaCompartment = false;
    llvm::errs() << "--------Visiting Alloca Finished--------\n\n";
}


void Compartmentalization::visitBitCastInst(BitCastInst &BI) {
    if (allocaParent == false) {
        return;
    }
    llvm::errs() << "\n--------Visiting Bitcast Started--------\n";
    llvm::errs() << "Visit BitCast: " << BI << "\n";
    for (auto *usr : BI.users()) {
        llvm::errs() << "\t» Usr: " << *usr << "\n";
        if (llvm::dyn_cast<CallInst>(usr) && allocaParent == true){
            visit(llvm::dyn_cast<Instruction>(usr));
        }
    }
    llvm::errs() << "--------Visiting Bitcast Finished--------\n\n";
}


void Compartmentalization::visitLoadInst(LoadInst &LI) {
    //llvm::errs() << "\n--------Visiting Load Started--------\n";
    llvm::errs() << "Visit Load: " << LI << "\n";
    for (auto *usr : LI.users()) {
        llvm::errs() << "\t» Usr: " << *usr << "\n";
        if (auto usrCall = llvm::dyn_cast<CallInst>(usr)){
            mostRecentI = llvm::dyn_cast<Instruction>(&LI);
            if ( std::find(vulnFuns.begin(), vulnFuns.end(), usrCall->getCalledFunction()->getName()) != vulnFuns.end() )
            {
                visit(llvm::dyn_cast<Instruction>(usr));
            }
        }
    }
    //llvm::errs() << "--------Visiting Load Finished--------\n\n";
}


void Compartmentalization::visitCallInst(CallInst &CI){
    // Check if call instruction is indirect
    int targetArgNum;
    llvm::errs() << "\n--------Visiting Call Started--------\n";
    llvm::errs() << "Visit Call: " << CI << " " << CI.getNumArgOperands() << "\n";
    //llvm::errs() << "Most recent I: " << *mostRecentI << "\n";

    if (CI.getNumArgOperands() > 0) {
        for (auto &arg : CI.args())
        {
            if (arg == mostRecentI)
            {
                targetArgNum = arg.getOperandNo();
                // llvm::errs() << "Found argument\n";
                compartmentTargets.insert(std::pair<Instruction*,int>(llvm::dyn_cast<Instruction>(&CI), targetArgNum));
                allocaCompartment = true;
            }
        }
    }
    llvm::errs() << "--------Visiting Call Finished--------\n\n";
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

    for (auto item : M.getIdentifiedStructTypes())
    {
        llvm::errs() << *item << "\n";
        structs.insert(item->getStructName());
    }
    //exit(1);
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
                llvm::errs() << "======= " << currFun->getName() << " =======\n";
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
    compartmentVisitor.vulnFuns = vulnFuns;
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
        if (llvm::dyn_cast<AllocaInst>(curr_I))
        {
            compartmentVisitor.visit(curr_I);
            if (alloc_to_compartment.contains(curr_I))
            {
                llvm::errs() << "Compartmentalize: " << *curr_I << "\n";
            }
        }

        if (auto curr_call_I = llvm::dyn_cast<CallInst>(curr_I)) {
            for (auto item : compartmentTargets)
            {
                /*
                if (item.first == llvm::dyn_cast<Instruction>(curr_call_I))
                {
                    llvm::errs() << "Call inst needs to be patched\n";
                }
                */
            }
        }

    }
    return false;
}