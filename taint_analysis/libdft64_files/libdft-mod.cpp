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

/* input file prefix */
#define FILE_NAME	"file.txt"

/* default suffixes for dynamic shared libraries */
#define DLIB_SUFF	".so"
#define DLIB_SUFF_ALT	".so."
#define	TAG 	0x01U

#define DBG_FLAG 0

#define findRTNName(Address) RTN_Name(RTN_FindByAddress(Address))

/* thread context */
extern thread_ctx_t *threads_ctx;

/* ins descriptors */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* set of interesting descriptors (sockets) */
static set<int> fdset;

/* trace file */
FILE *trace;
std::ofstream TraceFile;

/* global values */
uintptr_t offset_addr;

static stack<const char*> unwindStack;

/*
 * flag variables
 *
 * 0	: feature disabled
 * >= 1	: feature enabled
 */ 

/* track stdin (enabled by default) */
static KNOB<size_t> stdin_(KNOB_MODE_WRITEONCE, "pintool", "s", "1", "");

/* track fs (enabled by default) */
static KNOB<size_t> fs(KNOB_MODE_WRITEONCE, "pintool", "f", "0", "");

/* track net (enabled by default) */
static KNOB<size_t> net(KNOB_MODE_WRITEONCE, "pintool", "n", "1", "");

#if 1

void callUnwinding(ADDRINT callrtn_addr, char *dis, ADDRINT ins_addr)
{
	PIN_LockClient();
	RTN callRtn = RTN_FindByAddress(callrtn_addr);
	if (RTN_Valid(callRtn))
	{
		auto routineName = RTN_Name(callRtn);
		string pltName = "@plt";
		//if(strstr(routineName.c_str(),pltName.c_str()))
		//	return;
		RTN_Open(callRtn);
		//unwindStack.push(RTN_Name(callRtn).c_str());
		cerr << hex << ins_addr << " [*] " << RTN_Name(callRtn) << endl;
		RTN_Close(callRtn);
	}
	PIN_UnlockClient();
}

VOID getMetadata(IMG img, void *v)
{
	printf("Loading %s, Image id = %d \n", IMG_Name(img).c_str(), IMG_Id(img));

	ADDRINT imgEntry         	= IMG_Entry(img);
	// Global pointer (GP) of image, if a GP is used to address global data
	ADDRINT imgGlobalPt			= IMG_Gp(img);
	ADDRINT imgLoadOffset    	= IMG_LoadOffset(img);
	ADDRINT imgLowAddr    		= IMG_LowAddress(img);
	ADDRINT imgHighAddr   		= IMG_HighAddress(img);
	ADDRINT imgStartAddr  		= IMG_StartAddress(img);
	USIZE imgSizeMapping      	= IMG_SizeMapped(img);
	bool isMainExecutable       = IMG_IsMainExecutable(img);
	if (isMainExecutable == true)
	{
		printf ("   image_entry         = 0x%zx \n",imgEntry);
		printf ("   image_globalPointer = 0x%zx \n",imgGlobalPt);
		printf ("   image_loadOffset    = 0x%zx \n",imgLoadOffset);
		printf ("   image_lowAddress    = 0x%zx \n",imgLowAddr);
		printf ("   image_highAddress   = 0x%zx \n",imgHighAddr);
		printf ("   image_startAddress  = 0x%zx \n",imgStartAddr);
		printf ("   image_sizeMapped    = %lu \n",imgSizeMapping);
		#if 1
		for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
		{
			string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
			RTN rtn = RTN_FindByAddress(imgLoadOffset + SYM_Value(sym));
			#if 1
			//const char* UndecoratedFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY).c_str();
			cerr << "[*] " << hex << "0x" << RTN_Address(rtn) << "\t" << undFuncName << endl;
			#endif
			#if 1
			if (RTN_Valid(rtn))
			{	
				RTN_Open(rtn);
				// For each instruction of the routine
				for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
				{
					string *instString = new string(INS_Disassemble(ins));
					if (INS_IsDirectCall(ins))
					{
						//auto OffsetAddress = (ADDRINT)INS_DirectBranchOrCallTargetAddress(ins) - (ADDRINT)IMG_LoadOffset;
						//auto FindName = findRTNName(OffsetAddress);
						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)callUnwinding, IARG_BRANCH_TARGET_ADDR, IARG_PTR, instString->c_str(), IARG_INST_PTR, IARG_END);
					}
				}
				RTN_Close(rtn);
			}
			#endif
		}
		#endif
	}
}
#endif

#if 1
/*
 * read(2) handler (taint-source)
 */
static void
post_read_hook(THREADID tid, syscall_ctx_t *ctx)
{
	/* read() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
			return;

	/* taint-source */
	if (fdset.find(ctx->arg[SYSCALL_ARG0]) != fdset.end()){
		/* set the tag markings */ // << unwindStack.top() << " " << std::hex << ctx->arg[SYSCALL_ARG1]
		//hex << ctx->arg[SYSCALL_ARG1] << "fd: " << ctx->arg[SYSCALL_ARG0] << " " << std::hex 
		cerr << "\t► read(2) taint set " << endl;
		tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret, TAG);
	}
	else{
		/* clear the tag markings */
		cerr << "\t► read(2) taint clear " << endl;
		tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
	}
}

/*
 * readv(2) handler (taint-source)
 */
static void
post_readv_hook(THREADID tid, syscall_ctx_t *ctx)
{
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
		if (it != fdset.end()) { 
			/* set the tag markings */
			cerr << "\t► readv(2) taint set " << endl;
			tagmap_setn((size_t)iov->iov_base, iov_tot, TAG);
		}
		else {
			/* clear the tag markings */
			cerr << "\t► readv(2) taint clear " << endl;
			tagmap_clrn((size_t)iov->iov_base, iov_tot);
		}
		/* housekeeping */
		tot -= iov_tot;
        }
}
#endif

#if 1
/*
 * socket(2) syscall post hook(auxiliary)
 *
 * when socket(2) open INET fd, add the fd to the fdset
 */
static void 
post_socket_hook(THREADID tid, syscall_ctx_t *ctx) 
{
  /* sanity check */
	if (unlikely((long)ctx->ret < 0))
				return;

	/* add the socket fd to the socketset */
	if (likely(ctx->arg[SYSCALL_ARG0] == PF_INET || ctx->arg[SYSCALL_ARG0] == PF_INET6))
	{
		fdset.insert((int)ctx->ret);
		//printf("fdset insert\n");
	}
}

/*
 * accept() and accept4() syscall post hook(auxiliary)
 *
 * add the new INET fd to the fdset
 */
static void 
post_accept_hook(THREADID tid, syscall_ctx_t *ctx)
{
  /* sanity check */
	if (unlikely((long)ctx->ret < 0))
				return;
  /* add the socket fd to the socketset */
	if (likely(fdset.find(ctx->arg[SYSCALL_ARG0]) !=fdset.end()))
		fdset.insert((int)ctx->ret);
}

/*
 * recvfrom() syscall post hook(source)
 *
 * tag the buffer
 */
static void 
post_recvfrom_hook(THREADID tid, syscall_ctx_t *ctx)
{
  /* not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;
	
	/* taint-source */	
	if (fdset.find((int)ctx->arg[SYSCALL_ARG0]) != fdset.end())
	{
		/* set the tag markings */
		cerr << "\t► recvfrom(2) taint set " << unwindStack.top() << endl;
		tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret, TAG);
		//printf("tag the buffer\n");
	}
	else
		/* clear the tag markings */
		tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);

	/* sockaddr argument is specified */
	if ((void *)ctx->arg[SYSCALL_ARG4] != NULL)
	{
		/* clear the tag bits */
		tagmap_clrn(ctx->arg[SYSCALL_ARG4], *((int *)ctx->arg[SYSCALL_ARG5]));
				
		/* clear the tag bits */
		tagmap_clrn(ctx->arg[SYSCALL_ARG5], sizeof(int));
	}
}


/*
 * recvmsg() syscall post hook(source)
 *
 * tag the buffer
 */
static void 
post_recvmsg_hook(THREADID tid, syscall_ctx_t *ctx)
{
  /* message header; recvmsg(2) */
	struct msghdr *msg;

	/* iov bytes copied; recvmsg(2) */
	size_t iov_tot;

	/* iterators */
	size_t i;
	struct iovec *iov;
	set<int>::iterator it;
	
	/* total bytes received */
	size_t tot;
	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;

	/* get the descriptor */
	it = fdset.find((int)ctx->arg[SYSCALL_ARG0]);

	/* extract the message header */
	msg = (struct msghdr *)ctx->arg[SYSCALL_ARG1];

	/* source address specified */
	if (msg->msg_name != NULL) {
		/* clear the tag bits */
		tagmap_clrn((size_t)msg->msg_name,
			msg->msg_namelen);
		
		/* clear the tag bits */
		tagmap_clrn((size_t)&msg->msg_namelen,
				sizeof(int));
	}

	/* ancillary data specified */
	if (msg->msg_control != NULL) {
		/* taint-source */
		if (it != fdset.end()){
			/* set the tag markings */
			cerr << "\t► recvmsg(2) taint set " << unwindStack.top() << endl;
			tagmap_setn((size_t)msg->msg_control,
				msg->msg_controllen, TAG);
		}
		else
			/* clear the tag markings */
			tagmap_clrn((size_t)msg->msg_control,
				msg->msg_controllen);
			
		/* clear the tag bits */
		tagmap_clrn((size_t)&msg->msg_controllen,
				sizeof(int));
	}

	/* flags; clear the tag bits */
	tagmap_clrn((size_t)&msg->msg_flags, sizeof(int));	

	/* total bytes received */	
	tot = (size_t)ctx->ret;

	/* iterate the iovec structures */
	for (i = 0; i < msg->msg_iovlen && tot > 0; i++) {
		/* get the next I/O vector */
		iov = &msg->msg_iov[i];

		/* get the length of the iovec */
		iov_tot = (tot > (size_t)iov->iov_len) ?
				(size_t)iov->iov_len : tot;
		
		/* taint-source */	
		if (it != fdset.end()) {
			/* set the tag markings */
			cerr << "\t► recvmsg(2) taint set " << unwindStack.top() << endl;
			tagmap_setn((size_t)iov->iov_base,
						iov_tot, TAG);
		}
		else
			/* clear the tag markings */
			tagmap_clrn((size_t)iov->iov_base,
						iov_tot);

		/* housekeeping */
		tot -= iov_tot;
	}
	printf("tag the buffer\n");
}
#endif


#if 1
/* 
 * DTA/DFT alert
 *
 * @ins:	address of the offending instruction
 * @bt:		address of the branch target
 */
static void PIN_FAST_ANALYSIS_CALL
alert_branch(ADDRINT ins, BOOL isbt, ADDRINT bt)
{
	//cerr << "alert() " << isbt << endl;
}

/* 
 * Alert Function
 *
 * @buff:	address of sensitive information buffer
 * @buffsize: buffer size
 * @tag: tag of the buffer
 */
#if 0
static void 
alert(ADDRINT buff, size_t buffsize , tag_t tag)
{
	printf("Info Leakage Detected!\n");

}
#endif

/*
 * 64-bit register assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a register
 * for an indirect branch; returns a positive value
 * whenever the register value or the target address
 * are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_reg64(THREADID tid, uint64_t reg, ADDRINT addr)
{
	//printf("assert_reg64\n");
	/* 
	 * combine the register tag along with the tag
	 * markings of the target address
	 */
	tag_t tag = 0x00U;
	
	for(int i = 0; i < 7; i++)
	{
		tag |= threads_ctx[tid].vcpu.gpr[reg][i] | threads_ctx[tid].vcpu.gpr[reg][i+1];
	}
	return tag | tagmap_getn(addr, 8);
}

/*
 * 64-bit memory assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a memory
 * location for an indirect branch; returns a positive
 * value whenever the memory value (i.e., effective address),
 * or the target address, are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_mem64(ADDRINT paddr, ADDRINT taddr)
{
	return tagmap_getn(paddr, 8) | tagmap_getn(taddr, 8);
}

static void
dta_instrument_jmp_call(INS ins)
{
	/* temporaries */
	REG reg;
	/* 
	 * we care about indirect calls because of control-flow hijacking attacks 
	 */
	if (unlikely(INS_IsIndirectControlFlow(ins))) { //  optimized branch
		/* perform operand analysis */
		/* call via register */
		if (INS_OperandIsReg(ins, 0)) {
			/* extract the register from the instruction */
			reg = INS_OperandReg(ins, 0);
			/* size analysis */
			/* 64-bit register */
			if (REG_is_gr64(reg))
				/*
				 * instrument assert_reg64() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg64,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg),
					IARG_REG_VALUE, reg,
					IARG_END);
		}
		else {
		/* call via memory */
			/* size analysis */
			/* 64-bit */
			if (INS_MemoryReadSize(ins) == 2*WORD_LEN)
				/*
				 * instrument assert_mem64() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_mem64,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_BRANCH_TARGET_ADDR,
					IARG_END);
		}
		/*
		 * instrument alert() before branch;
		 * conditional instrumentation -- then
		 */
		#if 1
		INS_InsertThenCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)alert_branch,
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR,
			IARG_BRANCH_TAKEN,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);
		#endif
	}
}

/*
 * instrument the memory write instruction
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins: paddr = physical address | eaddr = effective address
 */
static void
dta_tainted_mem_write(ADDRINT paddr, ADDRINT eaddr)
{
	// print when addr is tagged.
	if (tagmap_getn(paddr, 8) | tagmap_getn(eaddr, 8))
	{
		#if DBG_FLAG
		printf("Tagged Mem Write (TMW)\n");
		#endif
		cerr << "\t▷ dta_mem_write() " << endl;
		//fprintf(trace, "\tTMW: %s | %p", rtn_name.c_str(), (void *)ip);
	}
}
#if 0
static void
dta_tainted_mem_read(ADDRINT paddr, ADDRINT eaddr)
{
	// print when addr is tagged.
	if (tagmap_getn(paddr, 8) | tagmap_getn(eaddr, 8))
	{
		#if DBG_FLAG
		printf("Tagged Mem Write (TMW)\n");
		#endif
		cerr << "\t▷ dta_mem_read()" << std::hex << " " << endl;
		//fprintf(trace, "\tTMW: %s | %p", rtn_name.c_str(), (void *)ip);
	}
}
#endif
#if 1
VOID Instruction(INS ins, VOID* v)
{
	UINT32 memOperands = INS_MemoryOperandCount(ins);
    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        // Note that in some architectures a single memory operand can be
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)dta_tainted_mem_write, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                                     IARG_END);
        }
		#if 0
		// Disabling this for now as there is no need to check on whether tagged memory is written.
		if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)dta_tainted_mem_read, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                                     IARG_END);
        }
		#endif 
    }
}
#endif

/*
 * instrument the ret instruction
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */
static void
dta_instrument_ret(INS ins)
{
	/* size analysis */	
	/* 64-bit */
	if (INS_MemoryReadSize(ins) == 2*WORD_LEN)
		/*
		 * instrument assert_mem64() before ret;
		 * conditional instrumentation -- if
		 */
		INS_InsertIfCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)assert_mem64,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);
	/*
	 * instrument alert() before ret;
	 * conditional instrumentation -- then
	 */
	INS_InsertThenCall(ins,
		IPOINT_BEFORE,
		(AFUNPTR)alert_branch,
		IARG_FAST_ANALYSIS_CALL,
		IARG_INST_PTR,
		IARG_BRANCH_TARGET_ADDR,
		IARG_END);
}


#endif

/*
 * auxiliary (helper) function
 *
 * whenever open(2)/creat(2) is invoked,
 * add the descriptor inside the monitored
 * set of descriptors
 *
 * NOTE: it does not track dynamic shared
 * libraries
 */
static void
post_open_hook(THREADID tid, syscall_ctx_t *ctx)
{
	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/* ignore dynamic shared libraries */
	if (strstr((char *)ctx->arg[SYSCALL_ARG0], DLIB_SUFF) == NULL &&
		strstr((char *)ctx->arg[SYSCALL_ARG0], DLIB_SUFF_ALT) == NULL)
		fdset.insert((int)ctx->ret);
}

/*
 * openat() syscall post hook(auxiliary)
 *
 * when openat() open the sensitive document
 * add the fd of the document to the fdset
 */
static void post_openat_hook(THREADID tid, syscall_ctx_t *ctx) 
{
  /* sanity check */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/* add the fd of the document to the fdset */
	if (strstr((char *)ctx->arg[SYSCALL_ARG1], FILE_NAME) != NULL)
		fdset.insert((int)ctx->ret);
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
	IMG_AddInstrumentFunction(getMetadata, 0);
	INS_AddInstrumentFunction(Instruction, 0);
	// ---------- Taint sources ---------- // 
	/* 
	 * For now, we are considering network input / user-input / open files
	 */ 
	#if 1
	/* read(2) */
	(void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);

	/* readv(2) */
	(void)syscall_set_post(&syscall_desc[__NR_readv], post_readv_hook);
	#endif

	#if 1
	/* socket(2), accept(2), recvfrom(2), recvmsg(2) */
	(void)syscall_set_post(&syscall_desc[__NR_socket], post_socket_hook);
	(void)syscall_set_post(&syscall_desc[__NR_accept] , post_accept_hook);
	(void)syscall_set_post(&syscall_desc[__NR_accept4] , post_accept_hook);
	(void)syscall_set_post(&syscall_desc[__NR_recvfrom] , post_recvfrom_hook);
	(void)syscall_set_post(&syscall_desc[__NR_recvmsg] , post_recvmsg_hook);
	#endif

	/* open(2), creat(2) */
	if (fs.Value() != 0) {
		(void)syscall_set_post(&syscall_desc[__NR_open],
				post_open_hook);
		(void)syscall_set_post(&syscall_desc[__NR_creat],
				post_open_hook);
		/* instrument openat(2) */
		(void)syscall_set_post(&syscall_desc[__NR_openat] , 
				post_openat_hook);
	}


	// ---------- Taint sinks ---------- //
	/* 
	 * handle control transfer instructions
	 *
	 * instrument the branch instructions, accordingly,
	 * for installing taint-sinks (DFT-logic) that check
	 * for tainted targets (i.e., tainted operands or
	 * tainted branch targets)
	 */
	#if 1
	/* instrument call */
	(void)ins_set_post(&ins_desc[XED_ICLASS_CALL_NEAR],
			dta_instrument_jmp_call);
	/* instrument jmp */
	(void)ins_set_post(&ins_desc[XED_ICLASS_JMP],
			dta_instrument_jmp_call);
	/* instrument ret */
	(void)ins_set_post(&ins_desc[XED_ICLASS_RET_NEAR],
			dta_instrument_ret);
	#endif

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