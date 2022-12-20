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
#include "../include/waterfall-icfg.h"
#include "../include/waterfall-compart.h"
#include "../include/waterfall-struct.h"

#include "llvm/ADT/SetVector.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include <llvm/Analysis/AliasAnalysis.h>
#include "llvm/Analysis/LoopInfo.h"
#include <fstream>

using namespace llvm;
using namespace std;


//===----------------------------------------------------------------------===//
// Command line options
//===----------------------------------------------------------------------===//
cl::opt<string> inputTaintFile("taint", cl::desc("<input file>"), cl::OneOrMore);

//std::vector<string> taintedFuns;
std::vector<std::pair<string, std::vector<string>>> taintedVulnFuns;
std::vector<std::pair<string, llvm::SetVector<const char*>>> taintedVulnFunsSet;
namespace {

    struct waterfallPass : public PassInfoMixin<waterfallPass> 
    {
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) 
        {
            // Input taint file related
            std::string delimiter = ": ";
            std::string delimiter_2 = " ";
            std::ifstream infile(inputTaintFile);
            std::vector<string> vulnFuns;
            string taintedFunName;
            int count = 0;
            for( std::string line; getline( infile, line ); )
            {
                auto start = 0U;
                auto end = line.find(delimiter);
                while (end != std::string::npos)
                {
                    if (count == 0)
                    {
                        taintedFunName = line.substr(start, end - start);
                    }
                    else
                    {
                        if (line.substr(start, end - start) != "\0")
                        {
                            vulnFuns.push_back(line.substr(start, end - start));
                        }
                    }
                    //llvm::errs() << line.substr(start, end - start) << "\n";

                    start = end + delimiter_2.length();
                    end = line.find(delimiter_2, start);
                    count++;
                }    
                taintedVulnFuns.push_back(std::pair<string, std::vector<string>>(taintedFunName, vulnFuns));
                count = 0;
                vulnFuns.clear();
            }
            //exit(1);
            #if 0 
            for (auto item : taintedVulnFuns)
            {
                llvm::errs() << "\n" << item.first << ":\t";
                for (auto item_2 : item.second)
                {
                    llvm::errs() << item_2 << " ";
                }
            }
            
            for (auto item : taintedFuns) 
            {
                SVFUtil::errs() << item;
            }
            #endif

            auto waterfallAnalysisResult = MAM.getResult<waterfallICFGAnalysis>(M);
            
            waterfallCompartmentalization(M, waterfallAnalysisResult, taintedVulnFuns);
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
        MPM.addPass(waterfallICFGAnalysisPass());
        return true;
    }
    return false;
}

void registerAnalyses(ModuleAnalysisManager &MAM) {
    MAM.registerPass([&] { return waterfallICFGAnalysis(); });   
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
                    // register the pipeline to be used for opt
                    PB.registerAnalysisRegistrationCallback(registerAnalyses); 
                    // register the analysis to be used for getResult
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