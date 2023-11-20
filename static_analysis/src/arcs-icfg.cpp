#include "../include/arcs-icfg.h"
#include "spdlog/spdlog.h"

using namespace llvm;
using namespace std;
using namespace SVF;

llvm::raw_ostream &icfg_dbg = llvm::errs();

StringSet<> ARCSICFGAnalysis::analyzeICFG(Module &M, ModuleAnalysisManager &MAM) 
{
    SPDLOG_INFO("");
    StringSet<> funResult;
    
    auto fileName = M.getSourceFileName();
    auto bitcodeName = M.getModuleIdentifier();
    // auto resultName = std::regex_replace(bitcodeName, std::regex("\\/[a-z,^\\_]*.bc"), "");
    
    // SPDLOG_DEBUG(fileName, resultName);

    // // Build Program Assignment Graph (SVFIR)
    // PTACallGraph* callgraph = new PTACallGraph();
    // SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule({bitcodeName});
    // SVFIRBuilder builder(svfModule);
    // SVFIR* pag = builder.build();
    
    /// Create Andersen's pointer analysis
    // Andersen* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);
    
    return funResult;
}