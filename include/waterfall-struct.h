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

using namespace llvm;

using namespace SVF;
using namespace SVFUtil;

#ifndef UNIQUE_IDENTIFIER_HERE
#define UNIQUE_IDENTIFIER_HERE

struct FunctionInfo {
    PTACallGraphNode* PTACGNode;
    uint32_t ID;
    SetVector<int> dstIDs;
};


#endif // ndef UNIQUE_IDENTIFIER_HERE
