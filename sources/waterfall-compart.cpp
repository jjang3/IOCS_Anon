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

#define DBG_OPTION 0 // 0 = disable | 1 = enable

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
    #if DBG_OPTION
    for (auto item : vulnFuns)
    {        llvm::errs() << item << "\n";    }
    
    llvm::errs() << "\n--------Visiting Alloca Started--------\n";
    llvm::errs() << "Visit Alloca: " << AI << " | Type: " << *AI.getType()->getPointerElementType() << "\n";
    #endif
    if (AI.getType()->getPointerElementType()->isStructTy())
    {
        if (structs.contains(AI.getType()->getPointerElementType()->getStructName()))
        {
            //llvm::errs() << "Struct found, ignore\n";
            return;
        }
    }
    for (auto *usr : AI.users()) {
        #if DBG_OPTION
        llvm::errs() << "\t» Usr: " << *usr << "\n";
        #endif
        if (llvm::dyn_cast<BitCastInst>(usr)) {
            allocaParent = true;
        }
        visit(llvm::dyn_cast<Instruction>(usr));
    }
    if (allocaCompartment == true)
    {
        //llvm::errs() << "Inserting: " << AI << "\n";
        
        alloc_to_compartment.insert(llvm::dyn_cast<Instruction>(&AI));
        allocaCompartment = false;
    }
    #if DBG_OPTION
    llvm::errs() << "--------Visiting Alloca Finished--------\n\n";
    #endif
}


void Compartmentalization::visitBitCastInst(BitCastInst &BI) {
    if (allocaParent == false) {
        return;
    }
    #if DBG_OPTION
    llvm::errs() << "\n--------Visiting Bitcast Started--------\n";
    llvm::errs() << "Visit BitCast: " << BI << "\n";
    #endif
    for (auto *usr : BI.users()) {
        #if DBG_OPTION
        llvm::errs() << "\t» Usr: " << *usr << "\n";
        #endif
        if (llvm::dyn_cast<CallInst>(usr) && allocaParent == true){
            visit(llvm::dyn_cast<Instruction>(usr));
        }
    }
    #if DBG_OPTION
    llvm::errs() << "--------Visiting Bitcast Finished--------\n\n";
    #endif
}


void Compartmentalization::visitLoadInst(LoadInst &LI) {
    //llvm::errs() << "\n--------Visiting Load Started--------\n";
    #if DBG_OPTION
    llvm::errs() << "Visit Load: " << LI << "\n";
    #endif
    for (auto *usr : LI.users()) {
        #if DBG_OPTION  
        llvm::errs() << "\t» Usr: " << *usr << "\n";
        #endif
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
    #if DBG_OPTION
    llvm::errs() << "\n--------Visiting Call Started--------\n";
    llvm::errs() << "Visit Call: " << CI << " " << CI.getNumArgOperands() << "\n";
    //llvm::errs() << "Most recent I: " << *mostRecentI << "\n";
    #endif
    if (CI.getNumArgOperands() > 0) {
        for (auto &arg : CI.args())
        {
            if (arg == mostRecentI)
            {
                //llvm::errs() << "Found argument\n";
                targetArgNum = arg.getOperandNo();
                compartmentTargets.insert(std::pair<Instruction*,int>(llvm::dyn_cast<Instruction>(&CI), targetArgNum));
                allocaCompartment = true;
            }
        }
    }
    #if DBG_OPTION
    llvm::errs() << "--------Visiting Call Finished--------\n\n";
    #endif
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
        //llvm::errs() << *item << "\n";
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
                llvm::errs() << "\n\n";
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
    Type *i8type = Type::getInt8Ty(context);
    Type *i64type = Type::getInt64Ty(context);

    for (auto &inst : BB) {
        llvm::IRBuilder<> mte_builder(&inst);
        Instruction *curr_I = &inst;
        if (auto curr_alloca_I = llvm::dyn_cast<AllocaInst>(curr_I))
        {
            compartmentVisitor.visit(curr_I);
            if (alloc_to_compartment.contains(curr_I)) // Initializing from alloca instruction
            {
                Type *c_array_ptr_elem_type = curr_alloca_I->getType()->getPointerElementType();
                llvm::errs() << "Compartmentalize: " << *curr_I << " Type: " << *c_array_ptr_elem_type << "\n";
                // Static array compartmentalization
                if (llvm::dyn_cast<ArrayType>(c_array_ptr_elem_type)) 
                {
                    llvm::errs() << "   > Compartmentment type: static array\n";
                    int c_array_length = curr_alloca_I->getAllocatedType()->getArrayNumElements();
                    Type *c_array_elem_type = curr_alloca_I->getType()->getPointerElementType()->getArrayElementType();
                    auto c_elem_size = ConstantInt::get(i8type, DL->getTypeAllocSize(c_array_elem_type));
                    int c_array_length_granule_remainder = c_array_length % 16;
                    if (c_array_length_granule_remainder != 0) {
                        int extension_size = 16 - c_array_length_granule_remainder;
                        c_array_length += extension_size;
                        llvm::errs() << "Array length: " << c_array_length << "\n"; 
                    }

                    auto c_array_size = ConstantInt::get(i64type, c_array_length);
                    auto c_alloc_size = ConstantExpr::getMul(c_elem_size, c_array_size);
                    auto custom_alloca_I = mte_builder.CreateAlloca(curr_alloca_I->getType()->getPointerElementType()->getArrayElementType()->getPointerTo() );
                    auto custom_malloc_I = llvm::CallInst::CreateMalloc(
                        mte_builder.GetInsertBlock(), 
                        i64type,
                        c_array_elem_type,
                        c_alloc_size,
                        nullptr,
                        nullptr,
                        ""
                    );
                }
                if (llvm::dyn_cast<PointerType>(c_array_ptr_elem_type))
                {
                    llvm::errs() << "   > Compartmentment type: dynamic array\n";
                    for (auto user : curr_alloca_I->users())
                    {
                        if (auto store_user_I = llvm::dyn_cast<StoreInst>(user))
                        {
                            mte_builder.SetInsertPoint(store_user_I->getNextNode());
                            auto custom_load_I = mte_builder.CreateLoad(curr_alloca_I->getType()->getPointerElementType(), curr_alloca_I);
                            mte_builder.SetInsertPoint(custom_load_I->getNextNode());
                            auto mte_init_I = mte_builder.CreateCall(mteInit, custom_load_I);
                            mte_builder.SetInsertPoint(mte_init_I->getNextNode());
                            auto mte_store_I = mte_builder.CreateStore(mte_init_I, curr_alloca_I);
                        }
                    }
                }
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