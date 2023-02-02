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

#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"
#include "ins_helper.h"

using namespace std;

using std::cerr;
using std::endl;

#define WORD_LEN	4	/* size in bytes of a word value */

/* default path for the log file (audit) */
#define LOGFILE_DFL	"libdft-dta.log"

/* default suffixes for dynamic shared libraries */
#define DLIB_SUFF	".so"
#define DLIB_SUFF_ALT	".so."
#define	TAG 	0x01U

#define DBG_FLAG 0

/* thread context */
extern thread_ctx_t *threads_ctx;

/* ins descriptors */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* set of interesting descriptors (sockets) */
static set<int> fdset;

/* log file path (auditing) */
static KNOB<string> logpath(KNOB_MODE_WRITEONCE, "pintool", "l",
		LOGFILE_DFL, "");

/* trace file */
FILE *trace;
std::ofstream TraceFile;

/* global values */
uintptr_t offset_addr;

stack<const char*> callStack;

// Print every instruction that is executed.
/*
 * read(2) handler (taint-source)
 */
static void
post_read_hook(THREADID tid, syscall_ctx_t *ctx)
{
	cerr << "Taint source: " << callStack.top() << endl;
	callStack.pop();
        /* read() was not successful; optimized branch */
        if (unlikely((long)ctx->ret <= 0))
                return;
	
	/* taint-source */
	if (fdset.find(ctx->arg[SYSCALL_ARG0]) != fdset.end())
        	/* set the tag markings */
	        tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret, TAG);
	else
        	/* clear the tag markings */
	        tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/*
 * readv(2) handler (taint-source)
 */
static void
post_readv_hook(THREADID tid, syscall_ctx_t *ctx)
{

	cerr << "Taint source: " << callStack.top() << endl;
	callStack.pop();
	/* iterators */
	int i;
	struct iovec *iov;
	set<int>::iterator it;

	/* bytes copied in a iovec structure */
	size_t iov_tot;

	/* total bytes copied */
	size_t tot = (size_t)ctx->ret;

	/* readv() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;
	
	/* get the descriptor */
	it = fdset.find((int)ctx->arg[SYSCALL_ARG0]);

	/* iterate the iovec structures */
	for (i = 0; i < (int)ctx->arg[SYSCALL_ARG2] && tot > 0; i++) {
		/* get an iovec  */
		iov = ((struct iovec *)ctx->arg[SYSCALL_ARG1]) + i;
		
		/* get the length of the iovec */
		iov_tot = (tot >= (size_t)iov->iov_len) ?
			(size_t)iov->iov_len : tot;
	
		/* taint interesting data and zero everything else */	
		if (it != fdset.end())
                	/* set the tag markings */
                	tagmap_setn((size_t)iov->iov_base, iov_tot, TAG);
		else
                	/* clear the tag markings */
                	tagmap_clrn((size_t)iov->iov_base, iov_tot);

                /* housekeeping */
                tot -= iov_tot;
        }
}

void printIp(ADDRINT v, char * dis)
{
	PIN_LockClient();
    //fprintf(stderr, "Ip: 0x%lx %s\n", (unsigned long)v, dis);
	#if DBG_FLAG
	cerr << "  > " << dis << " " << hex << RTN_Name(RTN_FindByAddress(v)) << endl;
	#endif
	RTN callRtn = RTN_FindByAddress(v);
	if (RTN_Valid(callRtn))
	{
		if (RTN_Name(callRtn) == ".plt.got" || RTN_Name(callRtn) == ".plt.sec")
			return;
		RTN_Open(callRtn);
		callStack.push(RTN_Name(RTN_FindByAddress(v)).c_str());
		/* read(2) */
		(void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
		/* readv(2) */
		(void)syscall_set_post(&syscall_desc[__NR_readv], post_readv_hook);

		cerr << RTN_Name(RTN_FindByAddress(v)) << endl;
		#if 0
		for (INS ins = RTN_InsHead(callRtn); INS_Valid(ins); ins = INS_Next(ins))
		{	
			if(INS_IsSyscall(ins)) {
				string *instString = new string(INS_Disassemble(ins));
				cerr << instString->c_str() << endl;
			}
		}
		#endif
		RTN_Close(callRtn);
	}
	PIN_UnlockClient();
}


VOID getOffsetAddr(IMG img, void *v)
{
	printf("Loading %s, Image id = %d \n", IMG_Name(img).c_str(), IMG_Id(img));

	ADDRINT image_entry         = IMG_Entry(img);
// Global pointer (GP) of image, if a GP is used to address global data
	ADDRINT image_globalPointer = IMG_Gp(img);
	ADDRINT image_loadOffset    = IMG_LoadOffset(img);
	ADDRINT image_lowAddress    = IMG_LowAddress(img);
	ADDRINT image_highAddress   = IMG_HighAddress(img);
	ADDRINT image_startAddress  = IMG_StartAddress(img);
	USIZE image_sizeMapped      = IMG_SizeMapped(img);
	bool isMainExecutable       = IMG_IsMainExecutable(img);
	offset_addr = image_startAddress;
	if (isMainExecutable == true)
	{
		printf ("   image_entry         = 0x%zx \n",image_entry);
		printf ("   image_globalPointer = 0x%zx \n",image_globalPointer);
		printf ("   image_loadOffset    = 0x%zx \n",image_loadOffset);
		printf ("   image_lowAddress    = 0x%zx \n",image_lowAddress);
		printf ("   image_highAddress   = 0x%zx \n",image_highAddress);
		printf ("   image_startAddress  = 0x%zx \n",image_startAddress);
		printf ("   image_sizeMapped    = %lu \n",image_sizeMapped);
		printf ("   isMainExecutable    = %s \n",isMainExecutable ? "true" : "false");
		
		// Walk through the symbols in the symbol table.
		#if 1
		for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
		{
			const char* undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY).c_str();
			UNUSED(undFuncName)++;
			RTN rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
			
			if (RTN_Valid(rtn))
			{
				#if DBG_FLAG
				cerr << "[*] " << hex << "0x" << RTN_Address(rtn)-image_loadOffset << "\t" << undFuncName << endl;
				#endif
				RTN_Open(rtn);
				 // For each instruction of the routine
				for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
				{
					
					if (INS_IsDirectCall(ins))
					{
						string *instString = new string(INS_Disassemble(ins));
						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printIp, IARG_BRANCH_TARGET_ADDR, IARG_PTR, instString->c_str(), IARG_END);
					}
					
				}
				RTN_Close(rtn);
			}
		}
		#endif
	}
}

/*
 * flag variables
 *
 * 0	: feature disabled
 * >= 1	: feature enabled
 */ 
/* track stdin (enabled by default) */
static KNOB<size_t> stdin_(KNOB_MODE_WRITEONCE, "pintool", "s", "1", "");

/* track fs (enabled by default) */
static KNOB<size_t> fs(KNOB_MODE_WRITEONCE, "pintool", "f", "1", "");

/* track net (enabled by default) */
static KNOB<size_t> net(KNOB_MODE_WRITEONCE, "pintool", "n", "1", "");

// store value got from entry handler
// will be used in exit handler
ADDRINT syscallNum = 0xffffffffffffffff;
UINT64 start = 0;
UINT fd = 0;
VOID SyscallEntryHandler(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
    // get syscall number
    syscallNum = PIN_GetSyscallNumber(ctx, std);

    // get buffer addr and fd if the syscall num is read(0)
    if(syscallNum == __NR_read)
    {
		#if DBG_FLAG
		cerr << "[*] syscall(" << syscallNum << ") " << hex << (void*)PIN_GetContextReg(ctx, REG_ESI) << " " << hex << v << " " << endl;
		#endif
        start = (UINT64)PIN_GetSyscallArgument(ctx,std,1);
        fd = (UINT)PIN_GetSyscallArgument(ctx,std,0);
    }
}


/* 
 * DTA
 *
 * used for demonstrating how to implement
 * a practical dynamic taint analysis (DTA)
 * tool using libdft
 */
int
main(int argc, char **argv)
{
	/* initialize symbol processing */
	PIN_InitSymbols();
	
	/* initialize Pin; optimized branch */
	if (unlikely(PIN_Init(argc, argv)))
		/* Pin initialization failed */
		goto err;

	/* initialize the core tagging engine */
	if (unlikely(libdft_init() != 0))
		/* failed */
		goto err;
	
	/* add stdin to the interesting descriptors set */
	if (stdin_.Value() != 0)
		fdset.insert(STDIN_FILENO);

	trace = fopen("dft.out", "w");
	if (trace != NULL)
	{
		printf("Success\n");
	}
	IMG_AddInstrumentFunction(getOffsetAddr, 0);
	PIN_AddSyscallEntryFunction(SyscallEntryHandler, NULL);
	/* read(2) */
	//(void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
	/* 
	 * install taint-sources
	 *
	 * all network-related I/O calls are
	 * assumed to be taint-sources; we
	 * install the appropriate wrappers
	 * for tagging the received data
	 * accordingly -- Again, for brevity
	 * I assume that all calls to
	 * syscall_set_post() are successful
	 */
	/* instrument call */
	//(void)ins_set_pre(&ins_desc[XED_ICLASS_SYSCALL],
	//					syscall_taint_source);


	/* start Pin */
	PIN_StartProgram();

	/* typically not reached; make the compiler happy */
	return EXIT_SUCCESS;

err:	/* error handling */

	/* detach from the process */
	libdft_die();

	/* return */
	return EXIT_FAILURE;
}