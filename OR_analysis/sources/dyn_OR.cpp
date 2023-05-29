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

using namespace std;

using std::cerr;
using std::endl;
using std::string;

#define DBG_FLAG 0
#define ACT_FLAG 1

#include "dwarf.h"
#include "libdwarf.h"

uintptr_t offset_addr;

std::map<uintptr_t, string> ptrToGVName;
std::map<std::string, std::stack<std::string>> routineToInsts;


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
std::string currRoutine;

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
        #if DBG_FLAG
        printf("\tread: %p | Name: %s\n", (void*)read_computed_addr, ptrToGVName.find(read_computed_addr)->second.c_str());
        #endif
        #if ACT_FLAG
        auto gvName = ptrToGVName.find(read_computed_addr)->second;
        std::string privStr = "Read " + gvName + "\n";
        routineToInsts.find(currRoutine)->second.push(privStr);
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
        #if DBG_FLAG
        printf("\twrite: %p | Name: %s\n", (void*)write_computed_addr, ptrToGVName.find(write_computed_addr)->second.c_str());
        #endif
        #if ACT_FLAG
        auto gvName = ptrToGVName.find(write_computed_addr)->second;
        std::string privStr = "Write " + gvName + "\n";
        routineToInsts.find(currRoutine)->second.push(privStr);
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

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < mem_operands; memOp++)
    {
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(RecMemRead),
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }

        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(RecMemWrite),
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
    }
}


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
                routineStack=stack<std::string>();
                if (std::find(std::begin(intrinFunList), std::end(intrinFunList), rtnName) == std::end(intrinFunList))
                {
                    currRoutine = rtnName;
                    #if DBG_FLAG
                    printf("%p Routine: %s | Image: %s\n", (void*)rtnAddr, rtnName.c_str(), StripPath(rtnImage.c_str()));
                    #endif
                    routineToInsts.insert(std::pair<std::string,std::stack<std::string>>(currRoutine, routineStack));
                }
            }
                
    } 
       
    #endif
    RTN_Close(rtn);
}

 
VOID Arg1Before(CHAR* name, ADDRINT size) { 
    #if 1
    printf("\tDyn object found | Curr routine: %s\n", currRoutine.c_str());
    //routineStack.push("Dyn object\n");
    #endif
    #if ACT_FLAG
    std::string privStr = "Dyn object\n";
    routineToInsts.find(currRoutine)->second.push(privStr);
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

void callUnwinding(ADDRINT callrtn_addr, char *dis, ADDRINT ins_addr)
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
                cerr << hex << "\tCall " << RTN_Name(callRtn) << " Curr routine: " << currRoutine << endl;
                #endif
                #if ACT_FLAG
                std::string privStr = "Call " + rtnName + "\n";
                routineToInsts.find(currRoutine)->second.push(privStr);
                #endif
            }
        }
		RTN_Close(callRtn);
	}
	PIN_UnlockClient();
}


 
VOID Before(CONTEXT* ctxt)
{
    ADDRINT BeforeIP = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    cerr << "Before: IP = " << hex << BeforeIP-offset_addr << dec << endl;
}
 

VOID Taken(const CONTEXT* ctxt)
{

	PIN_LockClient();
    ADDRINT TakenIP = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    //baOutFile << "Taken: IP = " << hex << TakenIP << dec << endl;

	RTN takenRtn = RTN_FindByAddress(TakenIP);
	if (RTN_Valid(takenRtn))
	{
        auto rtnName = RTN_Name(takenRtn);
        if (std::find(std::begin(intrinFunList), std::end(intrinFunList), rtnName) == std::end(intrinFunList)) {   
            #if DBG_FLAG   
            printf("\tReturn %s Curr routine: %s\n", rtnName.c_str(), currRoutine.c_str());
            #endif
            #if ACT_FLAG
            std::string privStr = "Return " + rtnName + "\n";
            routineToInsts.find(currRoutine)->second.push(privStr);
            #endif
        }
    }
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

            RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_ADDRINT, MALLOC, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                        IARG_END);
            RTN_Close(mallocRtn);
        }
    
        // Find the free() function.
        RTN freeRtn = RTN_FindByName(img, FREE);
        if (RTN_Valid(freeRtn))
        {
            RTN_Open(freeRtn);
            // Instrument free() to print the input argument value.
            RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_ADDRINT, FREE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                        IARG_END);
            RTN_Close(freeRtn);
        }
		for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
		{
			string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
			RTN rtn = RTN_FindByAddress(imgLoadOffset + SYM_Value(sym));
			#if DBG_FLAG
			const char* UndecoratedFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY).c_str();
			std::cerr << "[*] " << hex << "0x" << (ADDRINT)RTN_Address(rtn)-offset_addr << "\t" << undFuncName << endl;
			#endif
			#if 1
			if (RTN_Valid(rtn))
			{	
				RTN_Open(rtn);
				// For each instruction of the routine
                #if ACT_FLAG
				for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
				{
					string *instString = new string(INS_Disassemble(ins));
                    #if DBG_FLAG
                    std::cerr << instString->c_str() << "\n";
                    #endif
                    if (INS_IsDirectCall(ins))
					{
						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)callUnwinding, IARG_BRANCH_TARGET_ADDR, IARG_PTR, instString->c_str(), IARG_INST_PTR, IARG_END);
					}
                    if (INS_IsCall(ins))
                    {
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Before, IARG_CONTEXT, IARG_END);
                    }
                    if (INS_IsRet(ins))
                    {
                        // instrument each return instruction.
                        // IPOINT_TAKEN_BRANCH always occurs last.
                        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)Taken, IARG_CONTEXT, IARG_END);
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

static Dwarf_Unsigned getLocInformation(Dwarf_Attribute *attrs, int i, Dwarf_Error *error, uint8_t op)
{
    Dwarf_Unsigned lcount = 0;
    Dwarf_Loc_Head_c loclist_head = 0;
    int lres = 0;
    int res = 0;
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
                        else if (op == DW_OP_fbreg){
                            printf("\tLocal offset: %lld\n", opd1);
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
            case DW_AT_frame_base:
                res = dwarf_tag(input_die, &tag, error);
                if (res != DW_DLV_OK) {
                    printf("No tag\n");
                }
                dwarf_get_FRAME_name(tag, &tagname);
                printf("\tFrame Tag: %s\n", tagname);
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
                        locAddr = getLocInformation(attrs, i, error, op);
                        ptrToGVName.insert(std::pair<uintptr_t, string>((uintptr_t)locAddr, strName));
                    }
                    else if (op == DW_OP_fbreg) {
                        printf("\tFound local\n");
                        locAddr = getLocInformation(attrs, i, error, op);
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
        printf("Tag: %s\n", tagname);
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
    outfile.close();

    for (auto i : routineToInsts) {   // auto keyword 
		cout << i.first << ": " << endl;
        while (!i.second.empty())
        {
            cout << "\t" << i.second.top();
            i.second.pop();
        }
        cout << endl;
    }
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
	

    outfile.open(KnobOutputFile.Value().c_str());
    if (!outfile.is_open())
    {
        std::cout << "Could not open " << KnobOutputFile.Value() << std::endl;
        exit(1);
    }
    BOOL succeeded = initDWARF(argv[8]);
    if (!succeeded)
    {
        PIN_ExitProcess(1);
    }

    PIN_AddFiniFunction(Fini, 0);
	/* start Pin */
	PIN_StartProgram();

    return 0;
}
