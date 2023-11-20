#include "../include/arcs-icfg.h"
#include "spdlog/spdlog.h"


using namespace llvm;
using namespace std;

StringSet<> ARCSICFGAnalysis::analyzeICFG(Module &M, ModuleAnalysisManager &MAM) 
{
    SPDLOG_INFO("");
    StringSet<> funResult;
    return funResult;
}