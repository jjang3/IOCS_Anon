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

#pragma region DWARF_Related // start of pragma region


static int get_form_values(Dwarf_Debug dbg,
	Dwarf_Attribute attrib,
	Dwarf_Half *theform, Dwarf_Half *directform,
	Dwarf_Error *err)
{
	int res = 0;

	res = dwarf_whatform(attrib, theform, err);
	if (res != DW_DLV_OK) {
		return res;
	}
	res = dwarf_whatform_direct(attrib, directform, err);
	return res;
}

/*
 * Return TRUE if the retval passed is an error, and print the error. Return FALSE otherwise.
 */
static BOOL foundErr(const char* call_name, int retval, Dwarf_Error& error, const Dwarf_Debug& dbg)
{
    if (retval == DW_DLV_ERROR)
    {
        std::cerr << call_name << "() failed ";
        Dwarf_Unsigned dw_errno = dwarf_errno(error);
        char* dw_errmsg         = dwarf_errmsg(error);
        std::cerr << "; errno " << std::dec << dw_errno << " (" << dw_errmsg << ")" << std::endl;
        dwarf_dealloc_error(dbg, error);
        error = NULL;
        return TRUE;
    }
    return FALSE;
}

/*
 * Move to another node in the DWARF tree through one of the node's attributes.
 * In some cases an attribute is a link to another node in the tree.
 * For example, DW_AT_specification.
 * This function will follow the link and return the linked die.
 * In case of failure the function will return NULL.
 */
static Dwarf_Die getlinkedDIE(int attributeId, Dwarf_Die die, const Dwarf_Debug& dbg)
{
    Dwarf_Error error;
    Dwarf_Die ret_die       = NULL;
    Dwarf_Attribute attrib  = 0;
    Dwarf_Off attrib_offset = 0;
    
    int res = dwarf_attr(die, attributeId, &attrib, &error);
    foundErr("dwarf_attr", res, error, dbg);
    if (res == DW_DLV_OK)
    {
        res = dwarf_global_formref(attrib, &attrib_offset, &error);
        foundErr("dwarf_global_formref", res, error, dbg);
        if (res == DW_DLV_OK)
        {
            res = dwarf_offdie_b(dbg, attrib_offset, isInfo, &ret_die, &error);
            foundErr("dwarf_offdie_b", res, error, dbg);
        }
        dwarf_dealloc(dbg, attrib, DW_DLA_ATTR);
    }
    return ret_die;
}

/*
 * Read the name (short or mangled) of a subprogram from a DWARF node.
 * In some cases the name (DW_AT_name/DW_AT_linkage_name/DW_AT_MIPS_linkage_name)
 * will appear as part of the original die, and in other cases we will need to
 * travel through additional nodes to get the name. 
 * The function returns TRUE always because it is possible for a valid node not to have a mangled name for example.
 * However if a name is not found then the name argument will get a NULL value.
 */
static BOOL getSubprogName(int attributeId, char** name, Dwarf_Die die, const Dwarf_Debug& dbg)
{
    Dwarf_Error error;
    Dwarf_Die curr     = die;
    const int maxSteps = 3;
    *name              = NULL;
    for (int i = 0; i < maxSteps; i++)
    {
        int res = dwarf_die_text(curr, attributeId, name, &error);
        foundErr("dwarf_die_text", res, error, dbg);
        if (res == DW_DLV_OK)
        {
            return TRUE;
        }
        Dwarf_Die next = getlinkedDIE(DW_AT_abstract_origin, curr, dbg);
        if (next == NULL)
        {
            next = getlinkedDIE(DW_AT_specification, curr, dbg);
        }
        if (next == NULL) break;
        curr = next;
    }
    return TRUE;
}
#if 0
static BOOL getCIEInfo(Dwarf_Error *error, Dwarf_Debug dbg)
{
    Dwarf_Cie *cie_data = 0;
    Dwarf_Signed cie_count = 0;
    Dwarf_Fde *fde_data = 0;
    Dwarf_Signed fde_count = 0;
    int fres = 0;

    fres = dwarf_get_fde_list(dbg,&cie_data,&cie_count,
        &fde_data,&fde_count,error);
    if (fres != DW_DLV_OK) {
        return fres;
    }
    else {
        printf("Success\n");
    }
    /*  Do something with the lists*/
    dwarf_dealloc_fde_cie_list(dbg, cie_data, cie_count,
        fde_data,fde_count);
    return fres;
}
#endif
int example_locexprc(Dwarf_Debug dbg,Dwarf_Ptr expr_bytes,
    Dwarf_Unsigned expr_len,
    Dwarf_Half addr_size,
    Dwarf_Half offset_size,
    Dwarf_Half version,
    Dwarf_Error*error)
{
    Dwarf_Loc_Head_c head = 0;
    Dwarf_Locdesc_c locentry = 0;
    int res2 = 0;
    Dwarf_Unsigned rawlopc = 0;
    Dwarf_Unsigned rawhipc = 0;
    Dwarf_Bool debug_addr_unavail = FALSE;
    Dwarf_Unsigned lopc = 0;
    Dwarf_Unsigned hipc = 0;
    Dwarf_Unsigned ulistlen = 0;
    Dwarf_Unsigned ulocentry_count = 0;
    Dwarf_Unsigned section_offset = 0;
    Dwarf_Unsigned locdesc_offset = 0;
    Dwarf_Small lle_value = 0;
    Dwarf_Small loclist_source = 0;
    Dwarf_Unsigned i = 0;

    res2 = dwarf_loclist_from_expr_c(dbg,
        expr_bytes,expr_len,
        addr_size,
        offset_size,
        version,
        &head,
        &ulistlen,
        error);
    if (res2 != DW_DLV_OK) {
        return res2;
    }
    /*  These are a location expression, not loclist.
        So we just need the 0th entry. */
    res2 = dwarf_get_locdesc_entry_d(head,
        0, /* Data from 0th because it is a loc expr,
            there is no list */
        &lle_value,
        &rawlopc, &rawhipc, &debug_addr_unavail, &lopc, &hipc,
        &ulocentry_count, &locentry,
        &loclist_source, &section_offset, &locdesc_offset,
        error);
    if (res2 == DW_DLV_ERROR) {
        dwarf_dealloc_loc_head_c(head);
        return res2;
    } else if (res2 == DW_DLV_NO_ENTRY) {
        dwarf_dealloc_loc_head_c(head);
        return res2;
    }
    /*  ASSERT: ulistlen == 1 */
    for (i = 0; i < ulocentry_count;++i) {
        Dwarf_Small op = 0;
        Dwarf_Unsigned opd1 = 0;
        Dwarf_Unsigned opd2 = 0;
        Dwarf_Unsigned opd3 = 0;
        Dwarf_Unsigned offsetforbranch = 0;

        res2 = dwarf_get_location_op_value_c(locentry,
            i, &op,&opd1,&opd2,&opd3,
            &offsetforbranch,
            error);
        /* Do something with the expression operator and operands */
        if (res2 != DW_DLV_OK) {
            dwarf_dealloc_loc_head_c(head);
            return res2;
        }
    }
    dwarf_dealloc_loc_head_c(head);
    return DW_DLV_OK;
}
static Dwarf_Unsigned getLocInformation(Dwarf_Attribute *attrs, int i, Dwarf_Error *error, 
    uint8_t op, Dwarf_Debug dbg)
{
    Dwarf_Unsigned lcount = 0;
    Dwarf_Loc_Head_c loclist_head = 0;
    int lres = 0;
    int res;
    UNUSED(res);
    lres = dwarf_get_loclist_c(attrs[i],&loclist_head,
        &lcount,error);
        if (lres == DW_DLV_OK) {
        Dwarf_Unsigned j = 0;
        /*  Before any return remember to call
        dwarf_loc_head_c_dealloc(loclist_head); */
        for (j = 0; j < lcount; ++j) {
            Dwarf_Small loclist_lkind = 0;
            Dwarf_Small lle_value = 0;
            Dwarf_Unsigned rawval1 = 0;
            Dwarf_Unsigned rawval2 = 0;
            Dwarf_Bool debug_addr_unavailable = FALSE;
            Dwarf_Addr lopc = 0;
            Dwarf_Addr hipc = 0;
            Dwarf_Unsigned loclist_expr_op_count = 0;
            Dwarf_Locdesc_c locdesc_entry = 0;
            Dwarf_Unsigned expression_offset = 0;
            Dwarf_Unsigned locdesc_offset = 0;
            res = dwarf_get_locdesc_entry_d(loclist_head,
            j,
            &lle_value,
            &rawval1,&rawval2,
            &debug_addr_unavailable,
            &lopc,&hipc,
            &loclist_expr_op_count,
            &locdesc_entry,
            &loclist_lkind,
            &expression_offset,
            &locdesc_offset,
            error);
            if (lres == DW_DLV_OK) {
                Dwarf_Unsigned j = 0;
                int opres = 0;
                Dwarf_Small op = 0;

                for (j = 0; j < loclist_expr_op_count; ++j) {
                    Dwarf_Unsigned opd1 = 0;
                    Dwarf_Unsigned opd2 = 0;
                    Dwarf_Unsigned opd3 = 0;
                    Dwarf_Unsigned offsetforbranch = 0;
                    opres = dwarf_get_location_op_value_c(
                        locdesc_entry, j,&op,
                        &opd1,&opd2,&opd3,
                        &offsetforbranch,
                        error);
                    if (opres == DW_DLV_OK) {
                        /*  Do something with the operators.
                            Usually you want to use opd1,2,3
                            as appropriate. Calculations
                            involving base addresses etc
                            have already been incorporated
                            in opd1,2,3.  */
                        if (op == DW_OP_addr) {
                            printf("\tGlobal addr: %llx\n", opd1);
                            return opd1;
                        }
                        else if (op == DW_OP_fbreg) {
                            printf("\tLocal offset: %lld\n", opd1);
                            return opd1;
                        }
                        else if (op == DW_OP_call_frame_cfa) {
                            printf("\tFrame offset: %lld %lld %lld %lld %lld\n", 
                                    opd1, opd2, opd3, expression_offset, locdesc_offset);
                            return opd1;
                        }
                    } else {
                        dwarf_dealloc_loc_head_c(loclist_head);
                        /*Something is wrong. */
                        return opres;
                    }
                }
            }
        }
    }
    return TRUE;  
}


static BOOL getDIEAttrs(Dwarf_Die input_die, Dwarf_Error *error, Dwarf_Debug dbg, string strName)
{
    Dwarf_Attribute *attrs;
    Dwarf_Signed attrcount, i;
    Dwarf_Off offset = 0;
    Dwarf_Half tag = 0;
    Dwarf_Half theform = 0;
    Dwarf_Half directform = 0;
    Dwarf_Unsigned blen;
    Dwarf_Ptr bdata;
    Dwarf_Unsigned locAddr;
    int res = 0;
    const char *attrname = 0;
    const char *tagname = 0;
    Dwarf_Unsigned lcount = 0;
    Dwarf_Loc_Head_c loclist_head = 0;
    int lres = 0;
    /* Grab the DIEs attributes for display */
    if (dwarf_attrlist(input_die, &attrs, &attrcount, error) != DW_DLV_OK)
        return FALSE;
    for (i = 0; i < attrcount; ++i) {
        Dwarf_Half attrcode;
        if (dwarf_whatattr(attrs[i], &attrcode, error) != DW_DLV_OK)
            break;
        dwarf_get_AT_name(attrcode,&attrname);
        #if 1
        printf("Attribute[%ld], value %u name %s\n",
            (long int)i,attrcode,attrname);
        #endif
    
        switch (attrcode) {
            case DW_AT_decl_line:
                //dwarf_formudata(attrs[i], &offset, 0);
                //printf("\tLine Number: %lld\n", offset);
                break;
            case DW_AT_frame_base:
                res = dwarf_tag(input_die, &tag, error);
                if (res != DW_DLV_OK) {
                    printf("No tag\n");
                }
                if (get_form_values(dbg, attrs[i], &theform, &directform, error))
                    break;
                dwarf_get_FORM_name(theform, &tagname);
                printf("\tForm Tag: %s\n", tagname);
                if (theform == DW_FORM_data1 || theform == DW_FORM_data2 ||
                    theform == DW_FORM_data2 || theform == DW_FORM_data4 ||
                    theform == DW_FORM_data8 || theform == DW_FORM_udata) {
                    dwarf_formudata(attrs[i], &offset, 0);
                    printf("\tTag Number: %lld\n", offset); // DWARF2
                }
                else if (theform == DW_FORM_exprloc) {
                    if (dwarf_formexprloc(attrs[i], &blen, &bdata, error))
                        break;
                    uint8_t op = *((uint8_t *)bdata);
                    if (op == DW_OP_call_frame_cfa) {
                        printf("\tFound call frame cfa\n");
                        lres = dwarf_get_loclist_c(*attrs,&loclist_head,
                            &lcount,error);
                        if (lres == DW_DLV_OK) {
                            Dwarf_Unsigned i = 0;
                        }
                        else {
                            printf("loclist loaded\n");
                            locAddr = getLocInformation(attrs, i, error, op, dbg);
                        }
                    }
                }
                break;
            case DW_AT_type:
                dwarf_attr(input_die,attrcode,attrs,NULL);
                dwarf_global_formref(*attrs,&offset,NULL);
                dwarf_offdie_b(dbg,offset,1,&input_die,NULL);
                res = dwarf_tag(input_die, &tag, error);
                if (res != DW_DLV_OK) {
                    printf("No tag\n");
                }
                dwarf_get_TAG_name(tag, &tagname);
                printf("\tType Tag: %s\n", tagname);
                break;
            case DW_AT_location:
                if (get_form_values(dbg, attrs[i], &theform, &directform, error))
                    break;
                dwarf_get_FORM_name(theform, &tagname);
                printf("\tForm Tag: %s\n", tagname);
                if (theform == DW_FORM_exprloc) {
                    if (dwarf_formexprloc(attrs[i], &blen, &bdata, error))
                        break;
                    uint8_t op = *((uint8_t *)bdata);
                    if (op == DW_OP_addr) {
                        printf("\tFound global\n");
                        locAddr = getLocInformation(attrs, i, error, op, dbg);
                        ptrToGVName.insert(std::pair<uintptr_t, string>((uintptr_t)locAddr, strName));
                    }
                    else if (op == DW_OP_fbreg) {
                        printf("\tFound local\n");
                        locAddr = getLocInformation(attrs, i, error, op, dbg);
                        ptrToGVName.insert(std::pair<uintptr_t, string>((uintptr_t)locAddr, strName));
			    	}
                }
                break;
            default:
                continue;
        }
    }
    return TRUE;
}
#if 0
/* Simply shows the instructions at hand for this fde. */
static void
print_cie_instrs(Dwarf_Cie cie,Dwarf_Error *error)
{
    int res = DW_DLV_ERROR;
    Dwarf_Unsigned bytes_in_cie = 0;
    Dwarf_Small version = 0;
    char *augmentation = 0;
    Dwarf_Unsigned code_alignment_factor = 0;
    Dwarf_Signed data_alignment_factor = 0;
    Dwarf_Half   return_address_register_rule = 0;
    Dwarf_Small   *instrp = 0;
    Dwarf_Unsigned instr_len = 0;
    Dwarf_Half offset_size = 0;

    res = dwarf_get_cie_info_b(cie,&bytes_in_cie,
        &version, &augmentation, &code_alignment_factor,
        &data_alignment_factor, &return_address_register_rule,
        &instrp,&instr_len,&offset_size,error);
    if (res != DW_DLV_OK) {
        printf("Unable to get cie info!\n");
        exit(1);
    }
}

/* Dumping a dwarf-expression as a byte stream. */
static void
dump_block(char *prefix, Dwarf_Small *data, Dwarf_Unsigned len)
{
    Dwarf_Small *end_data = data + len;
    Dwarf_Small *cur = data;
    int i = 0;

    printf("%s", prefix);
    for (; cur < end_data; ++cur, ++i) {
        if (i > 0 && i % 4 == 0)
            printf(" ");
        printf("%02x", 0xff & *cur);

    }
}
#endif
/*
 * Print subprograms in a format expected by the comparison script.
 */
static BOOL printDIE(Dwarf_Die die, const Dwarf_Debug& dbg)
{
    Dwarf_Error error;
    Dwarf_Half tag = 0;
    int res;
    res = dwarf_tag(die, &tag, &error);
    if (foundErr("dwarf_tag", res, error, dbg)) 
        return FALSE;
    if (res == DW_DLV_NO_ENTRY)
    {
        std::cerr << "Dwarf_Die doesn't have a TAG value" << std::endl;
        return FALSE;
    }
    ASSERTX(res == DW_DLV_OK);
    const char *tagname;
    dwarf_get_TAG_name(tag, &tagname);
    // Skip all tags except DW_TAG_subprogram and DW_TAG_variable (to get global info)
    BOOL subprog = FALSE;
    BOOL variable = FALSE;
    switch (tag)
    {
        case DW_TAG_subprogram:
            subprog = TRUE;
            break;

        case DW_TAG_variable:
            variable = TRUE;
            break;

        default:
            return TRUE;
    }

    // low PC
    Dwarf_Addr lowPC = 0;
    res              = dwarf_lowpc(die, &lowPC, &error);
    if (foundErr("dwarf_lowpc", res, error, dbg)) 
        return FALSE;

    char* shortName = NULL;
    getSubprogName(DW_AT_name, &shortName, die, dbg);
    char* mangledName = NULL;
    if (subprog == true) {
        printf("Tag: %s\n", tagname);
        if (!getSubprogName(DW_AT_linkage_name, &mangledName, die, dbg))
        {
            getSubprogName(DW_AT_MIPS_linkage_name, &mangledName, die, dbg);
        }
        if ((shortName == NULL) && (mangledName == NULL))
        {
            return TRUE;
        }
        if (mangledName == NULL)
        {
            mangledName = shortName;
        }
        printf("Subprogram: %s\n", mangledName);
        getDIEAttrs(die, &error, dbg, shortName);
    }
    else if (variable == true) {
        string stringName(shortName);
        printf("Variable name: %s\n", stringName.c_str());
        getDIEAttrs(die, &error, dbg, shortName);
    }
    return TRUE;
}

/*
 * Traverse the tree and print its nodes.
 * The function will print the node passed as root, and then call this function for each of its children.
 */
static BOOL traverseDWARFTree(Dwarf_Die root, const Dwarf_Debug& dbg, int& recursionLevel)
{
    if (recursionLevel > maxRecursionLevel) // This is just a precaution in case the DWARF tree is invalid or has loops
    {
        std::cerr << "Recursion level exceeds " << std::dec << maxRecursionLevel << " DWARF may be invalid" << std::endl;
        return TRUE;
    }

    Dwarf_Error error;
    std::vector< Dwarf_Die > children;
    int res;

    // Print current node
    if (!printDIE(root, dbg))
    {
        return FALSE;
    }
    // Create list of children for current node
    Dwarf_Die child = NULL;
    res             = dwarf_child(root, &child, &error);
    if (foundErr("dwarf_child", res, error, dbg)) 
        return FALSE;
    if (res == DW_DLV_OK)
    {
        children.push_back(child);

        Dwarf_Die curr    = child;
        Dwarf_Die sibling = NULL;
        while (TRUE)
        {
            res = dwarf_siblingof_b(dbg, curr, isInfo, &sibling, &error);
            if (foundErr("dwarf_siblingof_b", res, error, dbg)) 
                return FALSE;
            if (res == DW_DLV_NO_ENTRY)
            {
                break;
            }
            ASSERTX(res == DW_DLV_OK);
            children.push_back(sibling);
            curr = sibling;
        }
    }
    // Release current node
    dwarf_dealloc(dbg, root, DW_DLA_DIE);

    // Iterate on the list of children and recurse into this function with child as root
    recursionLevel++;
    for (size_t i = 0; i < children.size(); i++)
    {
        if (!traverseDWARFTree(children[i], dbg, recursionLevel))
        {
            return FALSE;
        }
    }
    recursionLevel--;
    return TRUE;
}

/*
 * Iterate on the compilation units and for each one print the subprograms in it.
 */
static BOOL iterateCU(const Dwarf_Debug& dbg)
{
while (TRUE)
    {
        Dwarf_Unsigned cuHeaderLen;
        Dwarf_Half versionStamp;
        Dwarf_Off abbrevOffset;
        Dwarf_Half addressSize;
        Dwarf_Half lengthSize;
        Dwarf_Half extensionSize;
        Dwarf_Sig8 typeSignature;
        Dwarf_Unsigned typeOffset;
        Dwarf_Unsigned nextCuHeaderOffset;
        Dwarf_Half headerCuType;
        Dwarf_Error error;
        int res;

        res = dwarf_next_cu_header_d(dbg,                 // dw_dbg
                                     isInfo,              // dw_is_info
                                     &cuHeaderLen,        // dw_cu_header_length
                                     &versionStamp,       // dw_version_stamp
                                     &abbrevOffset,       // dw_abbrev_offset
                                     &addressSize,        // dw_address_size
                                     &lengthSize,         // dw_length_size
                                     &extensionSize,      // dw_extension_size
                                     &typeSignature,      // dw_type_signature
                                     &typeOffset,         // dw_typeoffset
                                     &nextCuHeaderOffset, // dw_next_cu_header_offset
                                     &headerCuType,       // dw_header_cu_type
                                     &error               // dw_error
        );

        if (foundErr("dwarf_next_cu_header_d", res, error, dbg)) 
            return FALSE;
        if (res == DW_DLV_NO_ENTRY) // no more compilation units, we're done
        {
            return TRUE;
        }
        ASSERTX(res == DW_DLV_OK);
        Dwarf_Die die = NULL;
        res           = dwarf_siblingof_b(dbg,    // dw_dbg,
                                NULL,   // dw_die
                                isInfo, // dw_is_info
                                &die,   // dw_return_sibling,
                                &error  // dw_error
        );

        if (foundErr("dwarf_siblingof_b", res, error, dbg)) 
            return FALSE;

        if (res == DW_DLV_NO_ENTRY) // this is not expected, it's an error
        {
            std::cerr << "Error: no die for compilation unit" << std::endl;
            return FALSE;
        }
        ASSERTX(res == DW_DLV_OK);
        int recursionLevel = 0;
        #if 1
        if (!traverseDWARFTree(die, dbg, recursionLevel))
        {
            std::cerr << "Failed\n";
            return FALSE;
        }
        #endif
        #if DBG_FLAG
        for (auto const& x : ptrToGVName)
        {
            std::cerr << x.first  // string (key)
                    << ": " 
                    << x.second.c_str() // string's value 
                    << std::endl;
        }
        #endif
        printf("\n");
    }
}

/* Frame related */


static void dump_block(char *prefix, Dwarf_Small *data, Dwarf_Unsigned len) {
  Dwarf_Small *end_data = data + len;
  Dwarf_Small *cur = data;
  int i = 0;

  printf("%s", prefix);
  for (; cur < end_data; ++cur, ++i) {
    if (i > 0 && i % 4 == 0)
      printf(" ");
    printf("%02x", 0xff & *cur);
  }
}

static Dwarf_Block dwblockzero;
static void print_fde_selected_regs(Dwarf_Fde fde) {
  Dwarf_Error oneferr = 0;
  static int selected_cols[] = {1, 3, 5};
  static int selected_cols_count =
      sizeof(selected_cols) / sizeof(selected_cols[0]);
  Dwarf_Signed k = 0;
  int fres = 0;

  Dwarf_Addr low_pc = 0;
  Dwarf_Unsigned func_length = 0;
  Dwarf_Small *fde_bytes = NULL;
  Dwarf_Unsigned fde_bytes_length = 0;
  Dwarf_Off cie_offset = 0;
  Dwarf_Signed cie_index = 0;
  Dwarf_Off fde_offset = 0;
  Dwarf_Fde curfde = fde;
  Dwarf_Cie cie = 0;
  Dwarf_Addr jsave = 0;
  Dwarf_Addr high_addr = 0;
  Dwarf_Addr next_jsave = 0;
  Dwarf_Bool has_more_rows = 0;
  Dwarf_Addr subsequent_pc = 0;
  Dwarf_Error error = 0;
  int res = 0;

  fres = dwarf_get_fde_range(curfde, &low_pc, &func_length, &fde_bytes,
                             &fde_bytes_length, &cie_offset, &cie_index,
                             &fde_offset, &oneferr);

  if (fres == DW_DLV_ERROR) {
    printf("FAIL: dwarf_get_fde_range err %" DW_PR_DUu " line %d\n",
           dwarf_errno(oneferr), __LINE__);
    exit(EXIT_FAILURE);
  }
  if (fres == DW_DLV_NO_ENTRY) {
    printf("No fde range data available\n");
    return;
  }
  res = dwarf_get_cie_of_fde(fde, &cie, &error);
  if (res != DW_DLV_OK) {
    printf("Error getting cie from fde\n");
    exit(EXIT_FAILURE);
  }

  high_addr = low_pc + func_length;
  for (jsave = low_pc; next_jsave < high_addr; jsave = next_jsave) {
    next_jsave = jsave + 1;
    printf("\n");
    for (k = 0; k < selected_cols_count; ++k) {
      Dwarf_Unsigned reg = 0;
      Dwarf_Unsigned offset_relevant = 0;
      int fires = 0;
      Dwarf_Small value_type = 0;
      Dwarf_Block block;
      Dwarf_Unsigned offset;
      Dwarf_Addr row_pc = 0;

      //block = dwblockzero;
      fires = dwarf_get_fde_info_for_reg3_b(
          curfde, selected_cols[k], jsave, &value_type, &offset_relevant, &reg,
          &offset, &block, &row_pc, &has_more_rows, &subsequent_pc, &oneferr);
      if (fires == DW_DLV_ERROR) {
        printf("FAIL: reading reg err %" DW_PR_DUu " line %d",
               dwarf_errno(oneferr), __LINE__);
        exit(EXIT_FAILURE);
      }
      if (fires == DW_DLV_NO_ENTRY) {
        continue;
      }
      #if 0
      print_fde_col(selected_cols[k], jsave, value_type, offset_relevant, reg,
                    offset, &block, row_pc, has_more_rows, subsequent_pc);
    #endif
      if (has_more_rows) {
        next_jsave = subsequent_pc;
      } else {
        next_jsave = high_addr;
      }
    }
  }
}

static int print_frame_instrs(Dwarf_Debug dbg,
                              Dwarf_Frame_Instr_Head frame_instr_head,
                              Dwarf_Unsigned frame_instr_count,
                              Dwarf_Error *error) {
  Dwarf_Unsigned i = 0;

  printf("\nPrint %" DW_PR_DUu " frame instructions\n", frame_instr_count);
  for (; i < frame_instr_count; ++i) {
    int res = 0;
    Dwarf_Unsigned instr_offset_in_instrs = 0;
    Dwarf_Small cfa_operation = 0;
    const char *fields = 0;
    Dwarf_Unsigned u0 = 0;
    Dwarf_Unsigned u1 = 0;
    Dwarf_Unsigned u2 = 0;
    Dwarf_Signed s0 = 0;
    Dwarf_Signed s1 = 0;
    Dwarf_Block expression_block;
    Dwarf_Unsigned code_alignment_factor = 0;
    Dwarf_Signed data_alignment_factor = 0;
    const char *op_name = 0;

    expression_block = dwblockzero;
    res = dwarf_get_frame_instruction_a(
        frame_instr_head, i, &instr_offset_in_instrs, &cfa_operation, &fields,
        &u0, &u1, &u2, &s0, &s1, &code_alignment_factor, &data_alignment_factor,
        &expression_block, error);
    res = dwarf_get_frame_instruction(
        frame_instr_head, i, &instr_offset_in_instrs, &cfa_operation, &fields,
        &u0, &u1, &s0, &s1, &code_alignment_factor, &data_alignment_factor,
        &expression_block, error);

    if (res != DW_DLV_OK) {
      if (res == DW_DLV_ERROR) {
        printf("ERROR reading frame instruction "
               "%" DW_PR_DUu "\n",
               frame_instr_count);
        if(error) {
          dwarf_dealloc_error(dbg, *error);
          *error = 0;
        }
      } else {
        printf("NO ENTRY reading frame instruction "
               " %" DW_PR_DUu "\n",
               frame_instr_count);
      }
      break;
    }
    dwarf_get_CFA_name(cfa_operation, &op_name);
    printf("[%2" DW_PR_DUu "]  %" DW_PR_DUu " %s ", i, instr_offset_in_instrs,
           op_name);
    switch (fields[0]) {
    case 'u': {
      if (!fields[1]) {
        printf("%" DW_PR_DUu "\n", u0);
      }
      if (fields[1] == 'c') {
        Dwarf_Unsigned final = u0 * code_alignment_factor;
        printf("%" DW_PR_DUu, final);
#if 0
                if (glflags.verbose) {
                    printf("  (%" DW_PR_DUu " * %" DW_PR_DUu,
                        u0,code_alignment_factor);

                }
#endif
        printf("\n");
      }
    } break;
    case 'r': {
      if (!fields[1]) {
        printf("r%" DW_PR_DUu "\n", u0);
        break;
      }
      if (fields[1] == 'u') {
        if (!fields[2]) {
          printf("%" DW_PR_DUu, u1);
          printf("\n");
          break;
        }
        if (fields[2] == 'd') {
          Dwarf_Signed final = (Dwarf_Signed)u0 * data_alignment_factor;
          printf("%" DW_PR_DUu, final);
          printf("\n");
        }
      }
      if (fields[1] == 'r') {
        printf("r%" DW_PR_DUu "\n", u0);
        printf(" ");
        printf("r%" DW_PR_DUu "\n", u1);
        printf("\n");
      }
      if (fields[1] == 's') {
        if (fields[2] == 'd') {
          Dwarf_Signed final = s1 * data_alignment_factor;
          printf("r%" DW_PR_DUu "\n", u0);
          printf("%" DW_PR_DSd, final);
#if 0
                    if (glflags.verbose) {
                        printf("  (%" DW_PR_DSd " * %" DW_PR_DSd,
                            s1,data_alignment_factor);
                    }
#endif
          printf("\n");
        }
      }
      if (fields[1] == 'b') {
        /* rb */
        printf("r%" DW_PR_DUu "\n", u0);
        printf("%" DW_PR_DUu, u0);
        printf(" expr block len %" DW_PR_DUu "\n", expression_block.bl_len);
        #if 0
        dump_block("    ", expression_block.bl_data,
                   (Dwarf_Signed)expression_block.bl_len);
        #endif
        printf("\n");
#if 0
                if (glflags.verbose) {
                    print_expression(dbg,die,&expression_block,
                        addr_size,offset_size,
                        version);
                }
#endif
      }
    } break;
    case 's': {
      if (fields[1] == 'd') {
        Dwarf_Signed final = s0 * data_alignment_factor;

        printf(" %" DW_PR_DSd, final);
#if 0
                if (glflags.verbose) {
                    printf("  (%" DW_PR_DSd " * %" DW_PR_DSd,
                        s0,data_alignment_factor);
                }
#endif
        printf("\n");
      }
    } break;
    case 'b': {
      if (!fields[1]) {
        printf(" expr block len %" DW_PR_DUu "\n", expression_block.bl_len);
        #if 0
        dump_block("    ", expression_block.bl_data,
                   (Dwarf_Signed)expression_block.bl_len);
        #endif
        printf("\n");
#if 0
                if (glflags.verbose) {
                    print_expression(dbg,die,&expression_block,
                        addr_size,offset_size,
                        version);
                }
#endif
      }
    } break;
    case 0:
      printf("\n");
      break;
    default:
      printf("UNKNOWN FIELD 0x%x\n", fields[0]);
    }
  }
  return DW_DLV_OK;
}

static void print_fde_instrs(Dwarf_Debug dbg, Dwarf_Fde fde,
                             Dwarf_Error *error) {
  int res;
  Dwarf_Addr lowpc = 0;
  Dwarf_Unsigned func_length = 0;
  Dwarf_Small *fde_bytes;
  Dwarf_Unsigned fde_byte_length = 0;
  Dwarf_Off cie_offset = 0;
  Dwarf_Signed cie_index = 0;
  Dwarf_Off fde_offset = 0;
  Dwarf_Addr arbitrary_addr = 0;
  Dwarf_Addr actual_pc = 0;
  Dwarf_Regtable3 tab3;
  int oldrulecount = 0;
  Dwarf_Small *outinstrs = 0;
  Dwarf_Unsigned instrslen = 0;
  Dwarf_Cie cie = 0;

  res = dwarf_get_fde_range(fde, &lowpc, &func_length, &fde_bytes,
                            &fde_byte_length, &cie_offset, &cie_index,
                            &fde_offset, error);
  if (res != DW_DLV_OK) {
    printf("Problem getting fde range \n");
    exit(EXIT_FAILURE);
  }

  arbitrary_addr = lowpc + (func_length / 2);
  printf("function low pc 0x%" DW_PR_DUx "  and length 0x%" DW_PR_DUx
         "  and midpoint addr we choose 0x%" DW_PR_DUx "\n",
         lowpc, func_length, arbitrary_addr);

  oldrulecount = dwarf_set_frame_rule_table_size(dbg, 1);
  dwarf_set_frame_rule_table_size(dbg, oldrulecount);

  tab3.rt3_reg_table_size = oldrulecount;
  tab3.rt3_rules = (struct Dwarf_Regtable_Entry3_s *)malloc(
      sizeof(struct Dwarf_Regtable_Entry3_s) * oldrulecount);
  if (!tab3.rt3_rules) {
    printf("Unable to malloc for %d rules\n", oldrulecount);
    exit(EXIT_FAILURE);
  }

  res = dwarf_get_fde_info_for_all_regs3(fde, arbitrary_addr, &tab3, &actual_pc,
                                         error);
  printf("function actual addr of row 0x%" DW_PR_DUx "\n", actual_pc);

  if (res != DW_DLV_OK) {
    printf("dwarf_get_fde_info_for_all_regs3 failed!\n");
    exit(EXIT_FAILURE);
  }
  //print_regtable(&tab3);

  res = dwarf_get_fde_instr_bytes(fde, &outinstrs, &instrslen, error);
  if (res != DW_DLV_OK) {
    printf("dwarf_get_fde_instr_bytes failed!\n");
    exit(EXIT_FAILURE);
  }
  res = dwarf_get_cie_of_fde(fde, &cie, error);
  if (res != DW_DLV_OK) {
    printf("Error getting cie from fde\n");
    exit(EXIT_FAILURE);
  }

  {
    Dwarf_Frame_Instr_Head frame_instr_head = 0;
    Dwarf_Unsigned frame_instr_count = 0;
    res = dwarf_expand_frame_instructions(cie, outinstrs, instrslen,
                                          &frame_instr_head, &frame_instr_count,
                                          error);
    if (res != DW_DLV_OK) {
      printf("dwarf_expand_frame_instructions failed!\n");
      exit(EXIT_FAILURE);
    }
    printf("Frame op count: %" DW_PR_DUu "\n", frame_instr_count);
    print_frame_instrs(dbg, frame_instr_head, frame_instr_count, error);

    dwarf_dealloc_frame_instr_head(frame_instr_head);
  }
  free(tab3.rt3_rules);
}

static void print_reg(int r) {
  switch (r) {
  case SAME_VAL:
    printf(" %d SAME_VAL ", r);
    break;
  case UNDEF_VAL:
    printf(" %d UNDEF_VAL ", r);
    break;
  case CFA_VAL:
    printf(" %d (CFA) ", r);
    break;
  default:
    printf(" r%d ", r);
    break;
  }
}
/*
 * Print the subporograms in 'binary'
 */
static BOOL initDWARF(const char* binary)
{
    Dwarf_Debug dbg = NULL;
    Dwarf_Error error;
    // Init
    int res = dwarf_init_path(binary,             // dw_path
                              NULL,               // dw_true_path_out_buffer
                              0,                  // dw_true_path_bufferlen,
                              DW_GROUPNUMBER_ANY, // dw_groupnumber
                              NULL,               // dw_errhand,
                              NULL,               // dw_errarg,
                              &dbg,               // dw_dbg
                              &error              // dw_error
    );

    if (foundErr("dwarf_init_path", res, error, dbg)) 
        return FALSE;

    // Initialize frame base at the initalization
    Dwarf_Cie *cie_data = 0;
    Dwarf_Signed cie_count = 0;
    Dwarf_Fde *fde_data = 0;
    Dwarf_Signed fde_count = 0;
    int fres = 0;
    fres = dwarf_get_fde_list_eh(dbg,&cie_data,&cie_count,
        &fde_data,&fde_count,&error);
    #if 1

    if (fres == DW_DLV_OK) {
        Dwarf_Fde myfde = 0;
        UNUSED(myfde);
        for (Dwarf_Signed fdenum = 0; fdenum < fde_count; ++fdenum) {
            Dwarf_Cie cie = 0;

            res = dwarf_get_cie_of_fde(fde_data[fdenum],&cie,&error);
            if (res != DW_DLV_OK) {
                printf("Error accessing cie of fdenum %" DW_PR_DSd " to get its cie\n",fdenum);
                exit(1);
            }
            printf("Print cie of fde %" DW_PR_DSd "\n",fdenum);
            //print_cie_instrs(cie,&error);
            #if 1
            print_fde_instrs(dbg,fde_data[fdenum],&error);
            //printf("Frame op count: %" DW_PR_DUu "\n",frame_instr_count);
            #endif
        }
    }
    #endif
    BOOL succeeded = iterateCU(dbg);
    res = dwarf_finish(dbg);
    if (foundErr("dwarf_finish", res, error, dbg)) 
        return FALSE;

    return succeeded;
}

#pragma endregion DWARF_Related

INT32 Usage()
{
    std::cerr << "This tool gathers the metadata for Overprivilege Ratio (OR)." << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

 
VOID Fini(INT32 code, VOID* v) { 
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

}
 

int main(int argc, char* argv[])
{
	/* initialize symbol processing */
	PIN_InitSymbols();

    if (PIN_Init(argc, argv))
    {
        return Usage();
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
        vector<string> result;
        std::map<int, std::string> var_to_addr;
        std::set<std::map<int, std::string>> var_to_addr_set;
        while(getline(newfile, tp)){ //read data from file object and put it into string.
            //cout << tp << "\n"; //print the data of the string
            regex_search(tp, m, regexp); 
            if (m[1] != "") {   
                patchLocalMap.insert(std::pair<std::string, std::set<std::map<int,std::string>>>(funname, var_to_addr_set));
                var_to_addr_set.clear();            
                cout << m[1] << endl;
                funname = m[1];
            }
            else if (m[1] == "last_fun_completed"){
                printf("Last one\n");
                patchLocalMap.insert(std::pair<std::string, std::set<std::map<int,std::string>>>(funname, var_to_addr_set));
            }
            else {
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
                    for(int i = 0; i<result.size(); i++) {    //print all splitted strings
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

    /*
    BOOL succeeded = initDWARF(argv[8]);
    if (!succeeded)
    {
        PIN_ExitProcess(1);
    }
    */

    //PIN_AddFiniFunction(Fini, 0);
	/* start Pin */
	PIN_StartProgram();

    return 0;
}
