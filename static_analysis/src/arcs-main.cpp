#include "../include/arcs-main.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>


#define DBG_FLAG 0

using namespace llvm;
using namespace std;

//===----------------------------------------------------------------------===//
// Command line options
//===----------------------------------------------------------------------===//
cl::opt<string> inputTaintFile("taint", cl::desc("<input file>"), cl::OneOrMore);

llvm::raw_ostream &main_dbg = llvm::errs();

namespace {

std::vector<string> parseTaintFile(std::ifstream &inputFile)
{
  SPDLOG_INFO("");
  std::vector<string> result;
  if ( inputFile.is_open() ){
    for( std::string line; getline( inputFile, line ); )
    {
      std::stringstream ss(line);
      while( ss.good() )
      {
        std::string substr;
        getline(ss, substr, ',');
        result.push_back(substr);
      }
      
      #if DBG_FLAG
      for (std::size_t i = 0; i < result.size(); i++)
        main_dbg << result[i] << "\n";
      #endif
    }
  }
  inputFile.close();
  return result;
}

SetVector<Function*> buildWorklist(Module &M)
{
    SPDLOG_INFO("");
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

PreservedAnalyses ARCSPass::run(Module &M, 
                                  ModuleAnalysisManager &MM) {
    /* spdlog-related settings */      
    spdlog::set_pattern("[%^%l%$] [%s:%#] [Fun: %!] %v");
    spdlog::set_level(spdlog::level::debug);
    spdlog::enable_backtrace(32);
    auto console = spdlog::stdout_color_mt("console");      
    auto err_logger = spdlog::stderr_color_mt("stderr");    
    // Parsing input list file:
    std::ifstream infile(inputTaintFile);
    ARCSPass arcs;
    arcs.funsWorklist   = buildWorklist(M);
    arcs.funsTainted    = parseTaintFile(infile);

    SPDLOG_INFO("Welcome to ARCS!");
    for (auto item : arcs.funsTainted)
    {
      main_dbg << item << "\n";
    }
    exit(1);
    // auto waterfallAnalysisResult = MM.getResult<WaterfallICFGAnalysis>(M);
    return PreservedAnalyses::all();
}

} // end of anonymous namespace


void registerAnalyses(ModuleAnalysisManager &MAM) {
    // MAM.registerPass([&] { return WaterfallICFGAnalysis(); });   
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
          if(Name == "arcs"){
            MPM.addPass(ARCSPass());
            // MPM.addPass(WaterfallICFGAnalysisPass());
            return true;
          }
          return false;
        }
      );
      PB.registerAnalysisRegistrationCallback(registerAnalyses); 
    }
  };
}