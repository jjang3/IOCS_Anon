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

void waterfallCompartmentalization(Module &M, std::vector<FunctionInfo> analysisInput, std::vector<std::pair<string, std::vector<string>>> taintedVulnFuns);