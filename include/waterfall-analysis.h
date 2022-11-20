#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/ADT/SetVector.h"

#include "SVF-FE/LLVMUtil.h"
#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include "SVF-FE/SVFIRBuilder.h"
#include "Util/Options.h"

using namespace llvm;
using namespace SVF;

#define UNUSED(x) (void)(x);

namespace root {

struct WorklistAnalysis : public llvm::AnalysisInfoMixin<WorklistAnalysis> {
    using Result = std::vector<FunctionInfo>;
    //using worklistResult = std::map <Function*, int>;
    using worklistResult = std::vector<Function*>;
    Result run(Module &M, ModuleAnalysisManager &MAM);
    worklistResult buildWorklist(Module &M);
    static llvm::AnalysisKey Key;
    static bool isRequired() { return true; }
};

//------------------------------------------------------------------------------
// New PM interface for the printer pass
//------------------------------------------------------------------------------
class worklistInstrument : public llvm::PassInfoMixin<worklistInstrument> {
public:
  llvm::PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

}