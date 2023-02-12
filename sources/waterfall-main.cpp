#include "../include/waterfall-main.h"
#include "../include/waterfall-ICFG.h"

#define DBG_FLAG 0

using namespace llvm;
using namespace std;

//===----------------------------------------------------------------------===//
// Command line options
//===----------------------------------------------------------------------===//
cl::opt<string> inputTaintFile("taint", cl::desc("<input file>"), cl::OneOrMore);

llvm::raw_ostream &main_dbg = llvm::errs();

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
        main_dbg << F.getName() << "\n";
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
    auto waterfallAnalysisResult = MM.getResult<WaterfallICFGAnalysis>(M);
    return PreservedAnalyses::all();
}

} // end of anonymous namespace


void registerAnalyses(ModuleAnalysisManager &MAM) {
    MAM.registerPass([&] { return WaterfallICFGAnalysis(); });   
}

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "WaterfallPass", "v0.2", [](PassBuilder &PB) 
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
            MPM.addPass(WaterfallICFGAnalysisPass());
            return true;
          }
          return false;
        }
      );
      PB.registerAnalysisRegistrationCallback(registerAnalyses); 
    }
  };
}