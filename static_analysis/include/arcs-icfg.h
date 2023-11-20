#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/Path.h"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"

using namespace llvm;
using namespace std;

// This is the actual analysis that will perform some operation
class ARCSICFGAnalysis : public AnalysisInfoMixin<ARCSICFGAnalysis> {
  private:
    static AnalysisKey Key;
    static bool isRequired() { return true; }

  public:
    // You need to define a result. This can also be some other class.
    // using Result = std::vector<std::pair<PTACallGraphNode*, SetVector<std::pair<int,int>>>>;
    using Result = std::vector<std::string>;
    StringSet<>  analyzeICFG(Module &M, ModuleAnalysisManager &MAM);
    
};