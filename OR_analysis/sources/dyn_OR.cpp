/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*
 * This pintool is testing the libpindwarf.so library.
 * Pintool mode of operation:
 * The pintool does not actually use any instrumentations and does not run the application.
 * It runs its logic from the main() function and uses the API of libpindwarf.so directly.
 * The subprograms list returned from the library is dumped to a file in a specific format
 * that needs to match the format in the reference file since the files will be compared.
 * The reason for using a pintool for this purpose is because it is already linked with Pin CRT and is simple to use.
 * The pintool itself will only fail in case there is an error in retrieving the data.
 */

#include "pin.H"
#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <set>
#include <stack>
#include <string>
#include <regex> 
#include <list>

using namespace std;

using std::cerr;
using std::endl;
using std::string;

#define DBG_FLAG 0
#define ACT_FLAG 1

#define DW_PR_DUx "llx"
#define DW_PR_DSx "llx"
#define DW_PR_DUu "llu"
#define DW_PR_DSd "lld"

/*  Depending on the ABI we set INITIAL_VAL
    differently.  For ia64 initial value is
    UNDEF_VAL, for MIPS and others initial
    value is SAME_VAL.
    Here we'll set it UNDEF_VAL
    as that way we'll see when first set. */
#define UNDEF_VAL 2000
#define SAME_VAL 2001
#define CFA_VAL 2002
#define INITIAL_VAL UNDEF_VAL

#include "dwarf.h"
#include "libdwarf.h"

/* trace file */
FILE *trace;
std::ofstream TraceFile;

uintptr_t offset_addr;

std::map<uintptr_t, string> ptrToGVName;
//std::map<std::string, std::stack<std::string>> routineToInsts;
std::map<std::string, std::set<std::string>> routineToInsts;

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif

std::stack<std::string> routineStack;
std::set<std::string> routineSet;
std::string currRoutine;
// Create a map of three (string, int) pairs
std::map<std::string, std::set<std::map<int, std::string>>> patchLocalMap;

std::set<std::map<UINT64, std::string>> pinVarSet;
std::map<UINT64, std::string> localFunVarSet;
std::map<std::string, std::set<std::map<UINT64, std::string>>> pinVarMap;

#pragma region PIN_Related // start of pragma region
/* ===================================================================== */
// Helper functions/arrays
/* ===================================================================== */

std::string intrinFunList[]={
    "_init", ".plt", ".plt.got", "_start", "deregister_tm_clones", "register_tm_clones", "_dl_fini",
    "__do_global_dtors_aux", "frame_dummy", "__libc_csu_init", "__libc_csu_fini", "__libc_start_main", "_fini"};

const char* StripPath(const char* path)
{
    const char* file = strrchr(path, '/');
    if (file)
        return file + 1;
    else
        return path;
}

template<class T>
bool stackFind (stack<T> source, T target)
{
    while (!source.empty() && source.top() != target)
        source.pop();

    if (!source.empty())
         return true;

    return false;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

// analysis for memory read
VOID RecMemRead(ADDRINT ip, ADDRINT addr)
{
    uintptr_t read_computed_addr;
    read_computed_addr = addr-offset_addr;
    auto read_it = ptrToGVName.find(read_computed_addr);
    if (read_it != ptrToGVName.end()) {
        #if 1
        printf("\tread: %p | Name: %s\n", (void*)read_computed_addr, ptrToGVName.find(read_computed_addr)->second.c_str());
        #endif
        auto gvName = ptrToGVName.find(read_computed_addr)->second;
        std::string privStr = "Read " + gvName + "\n";
        #if 0
        if (stackFind(routineToInsts.find(currRoutine)->second, privStr)) 
            printf("Exists\n");
        else
            routineToInsts.find(currRoutine)->second.push(privStr);
        #endif
        routineToInsts.find(routineStack.top())->second.insert(privStr);
    }
    else
    {
       
        #if 1
        map<uintptr_t,string>::iterator i = localFunVarSet.find((uintptr_t)addr);

        if (i == localFunVarSet.end()) { /* Not found */ }
        else {         
            printf("\t%p read: %p name: %s\n", (void*)(ip-offset_addr),(void*)addr, i->second.c_str());

            std::string privStr = "Read " + i->second + "\n";
            routineToInsts.find(routineStack.top())->second.insert(privStr);
            
        /* Found, i->first is f, i->second is ++-- */ 
        }


        #endif
    }
}

// analysis for memory write
VOID RecMemWrite(VOID* ip, ADDRINT addr)
{
    uintptr_t write_computed_addr;
    write_computed_addr = addr-offset_addr;
    auto write_it = ptrToGVName.find(write_computed_addr);
    if (write_it != ptrToGVName.end()) {
        #if 1
        printf("\twrite: %p | Name: %s\n", (void*)write_computed_addr, ptrToGVName.find(write_computed_addr)->second.c_str());
        #endif
        auto gvName = ptrToGVName.find(write_computed_addr)->second;
        std::string privStr = "Write " + gvName + "\n";
        #if 0
        if (stackFind(routineToInsts.find(currRoutine)->second, privStr)) 
            printf("Exists\n");
        else
            routineToInsts.find(currRoutine)->second.push(privStr);
        #endif
        routineToInsts.find(routineStack.top())->second.insert(privStr);
    }
    else
    {
        #if 1
        map<uintptr_t,string>::iterator i = localFunVarSet.find((uintptr_t)addr);

        if (i == localFunVarSet.end()) { /* Not found */ }
        else {         
            printf("\t%p write: %p name: %s\n", (void*)(ip-offset_addr), (void*)addr, i->second.c_str());
            std::string privStr = "Write " + i->second + "\n";
            routineToInsts.find(routineStack.top())->second.insert(privStr);
        /* Found, i->first is f, i->second is ++-- */ 
        }


        #endif
    }
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */
VOID instruInst(INS ins, VOID *v)
{
    // must be valid and within bounds of the main executable.
    #if 0
    if(!INS_Valid(ins) || !main_executable_boundaries.is_in_bounds(INS_Address(ins))) {
        return;
    }
    #endif
    //printf("Instrument instruction\n");
    const UINT32 mem_operands = INS_MemoryOperandCount(ins);
    //printf("Instrumenting instructions\n");
    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < mem_operands; memOp++)
    {
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            //printf("Instrumenting: ");
            //cerr << INS_Disassemble(ins) << endl;
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(RecMemRead),
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }

        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            //printf("Instrumenting: ");
            //cerr << INS_Disassemble(ins) << endl;
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(RecMemWrite),
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
    }
}

// Pin calls this function every time a new rtn is executed
VOID routInst(RTN rtn, VOID* v)
{
    // The RTN goes away when the image is unloaded, so save it now
    // because we need it in the fini
    #if DBG_FLAG
    auto rtnAddr    = RTN_Address(rtn);
    #endif
    auto rtnName    = RTN_Name(rtn);
    auto rtnImage   = IMG_Name(SEC_Img(RTN_Sec(rtn)));
    const auto libStr = std::string(".so.");
    const auto vdsoStr = std::string("[vdso]");
    const auto pltStr = std::string("@plt");

    RTN_Open(rtn);
    #if ACT_FLAG
    if (rtnImage.find(libStr) == string::npos) {
        if (rtnImage.find(vdsoStr) == string::npos)
            if (rtnName.find(pltStr) == string::npos) {
                if (std::find(std::begin(intrinFunList), std::end(intrinFunList), rtnName) == std::end(intrinFunList))
                {
                    //routineStack=stack<std::string>();
                    routineSet.clear();
                    currRoutine = rtnName;
                    printf("Curr routine: %s\n", rtnName.c_str());
                    #if DBG_FLAG
                    printf("%p Routine: %s | Image: %s\n", (void*)rtnAddr, rtnName.c_str(), StripPath(rtnImage.c_str()));
                    #endif
                    //routineToInsts.insert(std::pair<std::string,std::stack<std::string>>(currRoutine, routineStack));
                    routineToInsts.insert(std::pair<std::string,std::set<std::string>>(currRoutine, routineSet));
                }
            }
                
    } 
       
    #endif
    RTN_Close(rtn);
}

 
VOID DynObjCheck(CHAR* name, ADDRINT size) { 
    #if 1
    printf("\tDyn object found | Curr routine: %s\n", currRoutine.c_str());
    //routineStack.push("Dyn object\n");
    #endif
    #if ACT_FLAG
    std::string privStr = "Dyn object\n";
    //routineToInsts.find(currRoutine)->second.push(privStr);
    routineToInsts.find(currRoutine)->second.insert(privStr);
    #endif
}


VOID RoutineCheck(CHAR* name) { 
    #if 1
    //printf("%s\n", name);
    pinVarSet.clear();
    const auto pltStr = std::string("@plt");
    const auto nameStr = std::string(name);
    if (std::find(std::begin(intrinFunList), std::end(intrinFunList), nameStr) == std::end(intrinFunList)) {      
        if (nameStr.find(pltStr) == string::npos)
        {
            #if DBG_FLAG
            printf("Routine check: %s\n", nameStr.c_str());
            #endif
            currRoutine = nameStr;
            routineStack.push(nameStr);
        }
    }

    #endif
}



VOID RoutineClear(CHAR* name) { 
    #if 1
    const auto pltStr = std::string("@plt");
    const auto nameStr = std::string(name);
    if (std::find(std::begin(intrinFunList), std::end(intrinFunList), nameStr) == std::end(intrinFunList)) {      
        if (nameStr.find(pltStr) == string::npos)
        {
            if (routineStack.size() != 1)
            {
                #if DBG_FLAG
                printf("Routine clear %s\n", nameStr.c_str());
                #endif
                routineStack.pop();
                routineSet.clear();
                localFunVarSet.clear();
            }
        }
    }
    #endif
}


// The input file - the binary for which we are extracting the dwarf data
KNOB< string > KnobBinary(KNOB_MODE_WRITEONCE, "pintool", "bin", "", "specify binary file name for dwarf parsing");
// The output file - where to dump the subroutines list
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify stdout file name");

static const int maxRecursionLevel = 100;

// According the documentation of libdWARF, isInfo should be TRUE for reading through .debug_info
// and FALSE for reading through DWARF4 .debug_types. Experiments showed the result is actually the same in this test.
static const Dwarf_Bool isInfo = TRUE;
static std::ofstream outfile;

void callUnwinding(ADDRINT callrtn_addr, char *dis)
{
	PIN_LockClient();
	RTN callRtn = RTN_FindByAddress(callrtn_addr);
	if (RTN_Valid(callRtn))
	{
		auto rtnName = RTN_Name(callRtn);
        const auto pltStr = std::string("@plt");
		RTN_Open(callRtn);
        if (std::find(std::begin(intrinFunList), std::end(intrinFunList), rtnName) == std::end(intrinFunList)) {      
            if (rtnName.find(pltStr) == string::npos)
            {
                #if DBG_FLAG
                cerr << hex << "\tCall " << RTN_Name(callRtn) << " Curr routine: " << routineStack.top() << endl;
                #endif
                std::string privStr = "Call " + rtnName + "\n";
                routineToInsts.find(routineStack.top())->second.insert(privStr);
            }
        }
		RTN_Close(callRtn);
	}
	PIN_UnlockClient();
}
 
VOID Taken(const CONTEXT* ctxt)
{

	PIN_LockClient();
    ADDRINT TakenIP = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);

	RTN takenRtn = RTN_FindByAddress(TakenIP);
	if (RTN_Valid(takenRtn))
	{
        auto rtnName = RTN_Name(takenRtn);
        if (std::find(std::begin(intrinFunList), std::end(intrinFunList), rtnName) == std::end(intrinFunList)) {   
            #if DBG_FLAG
            printf("\tReturn %s Curr routine: %s\n", currRoutine.c_str(), rtnName.c_str());
            #endif
            std::string privStr = "Return " +  rtnName + "\n";
            routineToInsts.find(currRoutine.c_str())->second.insert(privStr);
        }
    }
    PIN_UnlockClient();
}

// Stores the effective memory operand address of the current instruction.
UINT64 _currentMemoryOperandAddress;

// [Callback] Stores the memory operand address of the current instruction.
VOID StoreInstructionMemoryOperandAddress(UINT64 effectiveAddress, CHAR* name, VOID* ip)
{
    
	PIN_LockClient();
	RTN currentRTN = RTN_FindByAddress((ADDRINT)ip);
    const auto nameStr = std::string(name);
    auto it = patchLocalMap.find(nameStr);
    if(it != patchLocalMap.end()) {
        //cout << "Found\n";
        //printf("Address: %ld\n", address);
        //cout << it->first << "\n";
        for (auto var_map : it->second) {
            //cout << "j: " << j. << "\n";
            for (auto info : var_map) {
                if (info.first == (uintptr_t)ip-offset_addr) {
                    cout << "Fun: " << RTN_Name(currentRTN) << " Var: " << info.second << "\n";
                    localFunVarSet.insert(std::pair<UINT64, std::string>(effectiveAddress, info.second));
                }
            }
        }
    }
    //cerr << "Ins addr: " << hex << "0x" << (ip-offset_addr) << "\n";
    
    //printf("%s\n", name);
    cerr << "Memory address: " << hex << "0x" << effectiveAddress << "\n";
	_currentMemoryOperandAddress = effectiveAddress;
    PIN_UnlockClient();
}

VOID getMetadata(IMG img, void *v)
{
	// Global pointer (GP) of image, if a GP is used to address global data
	ADDRINT imgLoadOffset    	= IMG_LoadOffset(img);
    #if DBG_FLAG
	ADDRINT imgGlobalPt			= IMG_Gp(img);
	ADDRINT imgLowAddr    		= IMG_LowAddress(img);
	ADDRINT imgHighAddr   		= IMG_HighAddress(img);
	ADDRINT imgStartAddr  		= IMG_StartAddress(img);
	USIZE imgSizeMapping      	= IMG_SizeMapped(img);
    #endif
	bool isMainExecutable       = IMG_IsMainExecutable(img);
	if (isMainExecutable == true)
	{
        offset_addr = (uintptr_t)imgLoadOffset;
		#if DBG_FLAG
		printf ("image_globalPointer = 0x%zx \n",imgGlobalPt);
		printf ("image_loadOffset    = 0x%zx \n",imgLoadOffset);
		printf ("image_lowAddress    = 0x%zx \n",imgLowAddr);
		printf ("image_highAddress   = 0x%zx \n",imgHighAddr);
		printf ("image_startAddress  = 0x%zx \n",imgStartAddr);
		printf ("image_sizeMapped    = %lu \n",imgSizeMapping);
		#endif
		#if 1
        //  Find the malloc() function.
        RTN mallocRtn = RTN_FindByName(img, MALLOC);
        if (RTN_Valid(mallocRtn))
        {
            RTN_Open(mallocRtn);
            // Instrument malloc() to print the input argument value and the return value.

            RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)DynObjCheck, IARG_ADDRINT, MALLOC, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                        IARG_END);
            RTN_Close(mallocRtn);
        }
    
        // Find the free() function.
        RTN freeRtn = RTN_FindByName(img, FREE);
        if (RTN_Valid(freeRtn))
        {
            RTN_Open(freeRtn);
            // Instrument free() to print the input argument value.
            RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)DynObjCheck, IARG_ADDRINT, FREE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                        IARG_END);
            RTN_Close(freeRtn);
        }
		for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
		{
			string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
			RTN rtn = RTN_FindByAddress(imgLoadOffset + SYM_Value(sym));
			#if 1
			const char* UndecoratedFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY).c_str();
			std::cerr << "[*] " << hex << "0x" << (ADDRINT)RTN_Address(rtn)-offset_addr << "\t" << undFuncName << endl;
			#endif
			#if 1
			if (RTN_Valid(rtn))
			{	
				RTN_Open(rtn);
                //printf("Curr routine: %s\n", undFuncName.c_str());
				// For each instruction of the routine
                #if ACT_FLAG
				for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
				{
                    if (INS_IsMov(ins) && INS_IsMemoryWrite(ins)) {
                        auto it = patchLocalMap.find(undFuncName);
                        if(it != patchLocalMap.end()) {
                            //cout << "Found\n";
                            auto address = (ADDRINT)INS_Address(ins)-offset_addr;
                            //printf("Address: %ld\n", address);
                            //cout << it->first << "\n";
                            for (auto var_map : it->second) {
                                //cout << "j: " << j. << "\n";
                                for (auto info : var_map) {
                                    cout << "Var: " << info.second << "\tAddr: " << info.first << "\n";
                                    if (info.first == address) {
                                        printf("Found patching target inst\n");
                                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)StoreInstructionMemoryOperandAddress, 
                                            IARG_MEMORYWRITE_EA, IARG_ADDRINT, RTN_Name(rtn).c_str(), IARG_INST_PTR,
                                            IARG_END);
                                    }
                                }
                            }
                        }
                    }
                    std::cerr << "\t- " << hex << "0x" << (ADDRINT)INS_Address(ins)-offset_addr << " " << INS_Disassemble(ins) << "\n";
                    // Entry point instrumentation to push currRoutine
                    if (ins == RTN_InsHead(rtn)) 
                    {
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RoutineCheck,  IARG_ADDRINT, RTN_Name(rtn).c_str(), IARG_END);
                    }
                    #if DBG_FLAG
					string *instString = new string(INS_Disassemble(ins));
                    std::cerr << instString->c_str() << "\n";
                    #endif
                    if (INS_IsDirectCall(ins))
					{
                        // To capture direct function calls
						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)callUnwinding, IARG_BRANCH_TARGET_ADDR, IARG_PTR, IARG_INST_PTR, IARG_END);
					}
                    if (INS_IsRet(ins))
                    {
                        // instrument each return instruction.
                        // IPOINT_TAKEN_BRANCH always occurs last.
                        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)Taken, IARG_CONTEXT, IARG_END);
                    }
                    // Exit point instrumentation to pop currRoutine
                    if (ins == RTN_InsTail(rtn))
                    {
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RoutineClear,  IARG_ADDRINT, RTN_Name(rtn).c_str(), IARG_END);
                    }
				}
                #endif
				RTN_Close(rtn);
			}
			#endif

            
		}
        // cycle through all sections of the main executable.
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        {
            // get boundaries of the '.data' section
            if(SEC_Name(sec) == ".data") {
                const auto sec_address = (SEC_Address(sec)-imgLoadOffset);   
                printf("Data section boundaries: %p to %p\n", (void*)sec_address, (void*)(sec_address + SEC_Size(sec)));
            }
        }
		#endif
	}
}
#pragma endregion PIN_Related


INT32 Usage()
{
    std::cerr << "This tool gathers the metadata for Overprivilege Ratio (OR)." << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

 
VOID Fini(INT32 code, VOID* v) { 
    #if 1
    for (auto i : routineToInsts) {   // auto keyword 
		cout << i.first << ": " << endl;
        
        fprintf(trace, "%s:\n", i.first.c_str());
        #if 0
        while (!i.second.empty())
        {
            cout << "\t" << i.second.top();
            fprintf(trace, "\t%s", i.second.top().c_str());
            i.second.pop();
        }
        #endif 
        for (auto itr : i.second)
        {
            cout << itr << " ";
            fprintf(trace, "\t%s", itr.c_str());
        } 
        fprintf(trace,"\n");
        cout << endl;
        
    }
    fclose(trace);
    #endif
}

int main(int argc, char* argv[])
{
	/* initialize symbol processing */
	PIN_InitSymbols();

    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

	trace = fopen("OR.out", "w");
	if (trace != NULL)
	{
		//printf("Success\n");
		//fprintf(trace, "Output file\n");
	}
    
    IMG_AddInstrumentFunction(getMetadata, 0);
    INS_AddInstrumentFunction(instruInst, nullptr);
    RTN_AddInstrumentFunction(routInst, 0);

    printf("Input file: %s\n\n", argv[8]);
    // Register Instruction to be called to instrument instructions
	// define your file name
    #if 1 // move this to somewhere else as an init function, or make it happen in init
    // regex expression for pattern to be searched 
    regex regexp("(.*)(?=:)"); 
    // flag type for determining the matching behavior (in this case on string objects)
    smatch m; 
    fstream newfile;
    newfile.open("local_OR.out",ios::in); //open a file to perform read operation using file object
    if (newfile.is_open()){ //checking whether the file is open
        string tp;
        string funname;
        vector<string> gv_result;
        vector<string> result;
        std::map<int, std::string> var_to_addr;
        std::set<std::map<int, std::string>> var_to_addr_set;
        while(getline(newfile, tp)){ //read data from file object and put it into string.
            cout << tp << "\n"; //print the data of the string
            regex_search(tp, m, regexp); 

            if (m[1] == "last_fun_completed"){
                printf("Last one\n");
                patchLocalMap.insert(std::pair<std::string, std::set<std::map<int,std::string>>>(funname, var_to_addr_set));
                funname = "";
            }
            else if (m[1] == "global_completed") {
                printf("Global variable\n");
                for (auto i : var_to_addr_set){
                    for (auto j = i.begin(); j != i.end(); j++){
                        cout << j->first << "	 " << j->second  << endl;
                        int num = j->first;
                        std::string var_name = j->second;
                        ptrToGVName.insert(std::pair<uintptr_t, string>((uintptr_t)num, var_name));
                        }
                }
                funname = "";
                       // ptrToGVName.insert(std::pair<uintptr_t, string>((uintptr_t)num, var_name));
                
                    //printf("Inserting: %d\tName: %s\n", num, var_name.c_str());
            }
            else if (m[1] != "") {   
                patchLocalMap.insert(std::pair<std::string, std::set<std::map<int,std::string>>>(funname, var_to_addr_set));
                var_to_addr_set.clear();            
                cout << m[1] << endl;
                funname = m[1];

                printf("Here 1 %s\n", funname.c_str());
            }
            else {
                cerr << m[1] << endl;
                printf("Fun name: %s\n", funname.c_str());
                //cout << tp << endl;
                stringstream s_stream(tp); //create string stream from the string
                while(s_stream.good()) {
                    string substr;
                    getline(s_stream, substr, ','); //get first string delimited by comma
                    result.push_back(substr);
                }
                if (result.at(0) != "\n")
                {
                    int num;
                    string var_name;
                    for(int i = 0; i < (int)result.size(); i++) {    //print all splitted strings
                        if (i == 0){
                            num = std::stoi(result.at(i),nullptr,16);
                            //cout << "Addr: " << result.at(i) << " " << num << endl;
                        }
                        else if (i == 1){
                            var_name = result.at(i);
                            //cout << "Name: " << result.at(i) << endl;
                        }
                    }
                    printf("Addr: %x\tName: %s\n", num, var_name.c_str());
                    var_to_addr.insert(std::pair<int,std::string>(num, var_name));
                    var_to_addr_set.insert(var_to_addr);
                    var_to_addr.clear();
                }
                result.clear(); 
            }
            
        }
        newfile.close(); //close the file object.
        for (auto i : patchLocalMap) {   // auto keyword 
		    cout << i.first << "\n";
            for (auto var_map : i.second) {
                //cout << "j: " << j. << "\n";
                for (auto info : var_map) {
                    cout << "Var: " << info.first << "\tAddr: " << info.second << "\n";
                }
            }
        }
    }
    #endif
    // (.*)(?=:)

    #if 0
    BOOL succeeded = initDWARF(argv[8]);
    if (!succeeded)
    {
        PIN_ExitProcess(1);
    }
    #endif
    

    PIN_AddFiniFunction(Fini, 0);
	/* start Pin */
	PIN_StartProgram();

    return 0;
}
