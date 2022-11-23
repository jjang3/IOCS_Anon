#include "../include/waterfall-compart.h"

using namespace llvm;

void waterfallCompartmentalization(Module &M, std::vector<FunctionInfo> analysisInput)
{
    SVFUtil::errs() << "╔═══════════════════════════════════════════╗\n";
    SVFUtil::errs() << "║       Instrumentation Analysis            ║\n";
    SVFUtil::errs() << "╚═══════════════════════════════════════════╝\n";
}
