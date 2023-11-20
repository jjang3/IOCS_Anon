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

class ARCSPass 
    : public PassInfoMixin<ARCSPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MM);

private:
    SetVector<Function*> funsWorklist;
    std::vector<string> funsTainted;
};

}