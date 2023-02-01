#include "../include/waterfall-main.h"

#define DBG_FLAG 1

using namespace SVF;
using namespace SVFUtil;
using namespace llvm;
using namespace std;

llvm::raw_ostream &dbg = llvm::errs();

//===----------------------------------------------------------------------===//
// Command line options
//===----------------------------------------------------------------------===//
cl::opt<string> inputTaintFile("taint", cl::desc("<input file>"), cl::OneOrMore);


namespace {
    
SetVector<Function*> buildWorklist(Module &M)
{
    SetVector<Function*> Result;
    Triple Trip(M.getTargetTriple());
    TargetLibraryInfoImpl TLII(Trip);
    TargetLibraryInfo TLI(TLII);
    LibFunc intrinsicFuns;
    // Ignore intrinsic functions, only focus on local functions
    for (auto &F : M)
    {
        #if DBG_FLAG
        dbg << F.getName() << "\n";
        #endif
        if (!(TLI.getLibFunc(F, intrinsicFuns))) {
            Result.insert(&F);
        } 
    }   
    return Result;
}

PreservedAnalyses WaterfallPass::run(Module &M, 
                                  ModuleAnalysisManager &MM) {
    WaterfallPass waterfall;
    waterfall.funsWorklist = buildWorklist(M);
    return PreservedAnalyses::all();
}

} // end of anonymous namespace


// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "WaterfallPass", "v0.1", [](PassBuilder &PB) 
    {
      LoopAnalysisManager LAM;
      FunctionAnalysisManager FAM;
      CGSCCAnalysisManager CGAM;
      ModuleAnalysisManager MAM;
      PB.registerModuleAnalyses(MAM);
      PB.registerCGSCCAnalyses(CGAM);
      PB.registerFunctionAnalyses(FAM);
      PB.registerLoopAnalyses(LAM);
      PB.registerPipelineParsingCallback(
        [](StringRef Name, ModulePassManager &MPM,
        ArrayRef<PassBuilder::PipelineElement>) {
          if(Name == "waterfall"){
            MPM.addPass(WaterfallPass());
            return true;
          }
          return false;
        }
      );
    }
  };
}