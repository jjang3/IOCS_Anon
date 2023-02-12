#include "../include/waterfall-struct.h"

#include "llvm/ADT/SetVector.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Format.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"

using namespace llvm;
using namespace std;


namespace {

SetVector<Function*> buildWorklist(Module &M);

class WaterfallPass 
    : public PassInfoMixin<WaterfallPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MM);

private:
    SetVector<Function*> funsWorklist;

};

}