//===-- sources/waterfall-worklist.h --===// -*- C++ -*-
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// This file is the root of waterfall project. It obtains the worklist from the
/// module level and work per cascading calls.
///
//===----------------------------------------------------------------------===//

#include "llvm/ADT/SetVector.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Format.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include <llvm/Analysis/AliasAnalysis.h>
#include "llvm/Analysis/LoopInfo.h"

using namespace llvm;

namespace {

    struct waterfallPass : public PassInfoMixin<waterfallPass> 
    {
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) 
        {
            auto fileName = M.getSourceFileName();
            auto bitcodeName = M.getModuleIdentifier();
            errs() << "Input file: " << bitcodeName << "\n";
            return PreservedAnalyses::all();
        }
    };

}











//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------

bool registerPipeline(StringRef Name, ModulePassManager &MPM,
                      ArrayRef<PassBuilder::PipelineElement>) {    
    if (Name == "waterfall-pass") {
        MPM.addPass(waterfallPass());
        return true;
    }
    return false;
}

llvm::PassPluginLibraryInfo getWorklistPluginInfo() 
{
    return {LLVM_PLUGIN_API_VERSION, "waterfallPass", LLVM_VERSION_STRING, [](PassBuilder &PB) 
                {
                    LoopAnalysisManager LAM;
                    FunctionAnalysisManager FAM;
                    CGSCCAnalysisManager CGAM;
                    ModuleAnalysisManager MAM;
                    PB.registerModuleAnalyses(MAM);
                    PB.registerCGSCCAnalyses(CGAM);
                    PB.registerFunctionAnalyses(FAM);
                    PB.registerLoopAnalyses(LAM);
                    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);
                    PB.registerPipelineParsingCallback(registerPipeline);
                }
           };
}

// This is the core interface for pass plugins. It guarantees that 'opt' will
// be able to recognize HelloWorld when added to the pass pipeline on the
// command line, i.e. via '-passes=instrument'
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() 
{
  return getWorklistPluginInfo();
}