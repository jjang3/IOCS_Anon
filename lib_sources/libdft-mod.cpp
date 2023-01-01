#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <set>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <unordered_map>
using namespace std;
#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"
#include "ins_helper.h"

#define WORD_LEN	4	/* size in bytes of a word value */

/* default path for the log file (audit) */
#define LOGFILE_DFL	"/tmp/libdft-dta.log"

/* default suffixes for dynamic shared libraries */
#define DLIB_SUFF	".so"
#define DLIB_SUFF_ALT	".so."
#define	TAG 	0x01U

#define LIB_BASE 0x700000000000
#define ALLOCATED 1
#define FREED 2

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define SCANF "scanf"
#define ISOCSCANF "__isoc99_scanf"
#define FREE "free"
#define READ "read"
#define GETS "gets"
#define FGETS "fgets"
#define STRCPY "strcpy"
#define STRNCPY "strncpy"
#define MEMCPY "memcpy"
#define PRINTF "printf"
#define FPRINTF "fprintf"
#define SPRINTF "sprintf"
#define SNPRINTF "snprintf"
#define CLOSE "close"
#define CALLINS "call"
#endif

const CHAR* targetFuns[] = {MALLOC, SCANF, ISOCSCANF, FREE, READ, GETS, FGETS, STRCPY, STRNCPY, MEMCPY, PRINTF, FPRINTF, SPRINTF, SNPRINTF, CLOSE};

using std::cerr;
using std::endl;

/* trace file */
FILE *trace;
std::ofstream TraceFile;

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

/* map between target rtn names and address */
std::map<ADDRINT, string> rtn_to_addr;
std::map<ADDRINT, int> mem_addr_table;
std::map<ADDRINT, int> mem_alloc_table;
ADDRINT mem_addr = 0;


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

/* 
	Custom functions added
 */

void *offset_addr;

bool checkLibAddr(UINT64 addr) {
    if (addr > LIB_BASE) {
        return true;
    }
    return false;
}

void checkMallocMemWrite(ADDRINT addr, CONTEXT *ctx, ADDRINT raddr, ADDRINT waddr)
{
     //fprintf(LogFile, "%lx;%s;%lx,%lx,\n", addr, opcmap[addr].c_str(),
     //        raddr, waddr);
	void* rax_addr = (void*)PIN_GetContextReg(ctx, REG_RAX);
    if ((!checkLibAddr((UINT64)addr)) && rax_addr > offset_addr)
    {
		if ((uintptr_t)rax_addr < LIB_BASE)
		{
			fprintf(trace, "\tREG: %p\n", rax_addr);
		}
		
    }
    
}

VOID parse_funRtns(IMG img, void *v)
{
	if (IMG_IsMainExecutable(img))
	{
		// Calculating offset address
		offset_addr = (void*)IMG_LoadOffset(img);
		printf("Offset: %p\n", (void*)IMG_LoadOffset(img));

	}

	#if 1
	RTN mallocRtn = RTN_FindByName(img, MALLOC);
	if (RTN_Valid(mallocRtn))
	{
		RTN_Open(mallocRtn);

		// Instrument malloc() to print the input argument value and the return value.
		#if 0

		cerr << "Entering malloc" << endl;
		RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)RecordMalloc,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_END);
		RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)RecordMallocResult,
					IARG_INST_PTR,
					IARG_FUNCRET_EXITPOINT_VALUE, 
					//IARG_MEMORYWRITE_PTR,
					IARG_END);
		#endif
		//fprintf(trace, "Enttering malloc\n");
		
		for (INS ins = RTN_InsHead(mallocRtn); INS_Valid(ins); ins = INS_Next(ins))
		{
		}
		RTN_Close(mallocRtn);
		cerr << "Exiting malloc" << endl;
	}
	#endif
}
	
string invalid = "invalid_rtn";
const string *Target2String(ADDRINT target)
{
	//printf("Here\n");
    string name = RTN_FindNameByAddress(target);
    if (name == "")
        return &invalid;
    else
        return new string(name);
}


VOID RecordMemWrite(ADDRINT ip, ADDRINT addr)
{
	// print when addr is tagged.
	if (tagmap_getl(size_t(addr)))
	{
		string rtn_name = RTN_FindNameByAddress(ip);
		//printf("Tagged Mem Write (TMW)\n");

		cerr << "Write: " << std::hex << addr << endl;
		fprintf(trace, "\tTMW: %s | %p\n", rtn_name.c_str(), (void *)ip);
	}
}

VOID RecordMemRead(ADDRINT ip, ADDRINT addr)
{

	// print when addr is tagged.
	if (tagmap_getl(size_t(addr)))
	{
		string rtn_name = RTN_FindNameByAddress(ip);
		//printf("Tagged Mem Read (TMR)\n");

		cerr << "Read: " << std::hex << addr << endl;
		fprintf(trace, "\tTMR: %s | %p\n", rtn_name.c_str(), (void *)ip);
	}	
}
 
VOID Instruction(INS ins, VOID *v)
{
	// Calling plt.sec functions
	if (INS_IsCall(ins))
    {
        if (INS_IsDirectBranchOrCall(ins))
        {
			uintptr_t tag_addr = (uintptr_t)(INS_Address(ins) & ~(uintptr_t) 0xfffffffffffUL);
			tag_addr = tag_addr >> 44;
			if (tag_addr == 5)
			{
				const ADDRINT target = INS_DirectBranchOrCallTargetAddress(ins);

				uintptr_t exec_addr = (uintptr_t)target - (uintptr_t)offset_addr;

				//fprintf(trace, "%p > ", (void*)((uintptr_t)INS_Address(ins) - (uintptr_t)offset_addr));
				fprintf(trace, "\n%p > %p - [%s]\n", (void*)((uintptr_t)INS_Address(ins) - (uintptr_t)offset_addr), (void*)exec_addr, Target2String(target)->c_str());
				//fprintf(trace, "%p - [%s]\n", (void*)exec_addr, (Target2String(target)->c_str()));
			}
        }
    }

	if (INS_IsMemoryWrite(ins)) {

		//cerr << INS_Disassemble(ins)  <<  endl;
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)checkMallocMemWrite, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_MEMORYWRITE_PTR , IARG_END);
	}	 
	UINT32 memOperands = INS_MemoryOperandCount(ins);
	for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
		// Instructions have memory write
		if (INS_MemoryOperandIsWritten(ins, memOp)) {
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
					(AFUNPTR)RecordMemWrite, IARG_INST_PTR,
					IARG_MEMORYOP_EA, memOp, IARG_END);
		}	
		// Instructions have memory read
		if (INS_MemoryOperandIsRead(ins, memOp)) {
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
					(AFUNPTR)RecordMemRead, IARG_INST_PTR,
					IARG_MEMORYOP_EA, memOp, IARG_END);
		}
		
	}
}

VOID Fini(INT32 code, VOID *v)
{
//	fprintf(trace, "#eof\n");
	fclose(trace);
	
}

static void
post_openat_hook(THREADID tid, syscall_ctx_t *ctx)
{
	int fd;
	const char *fname = (char*)ctx->arg[SYSCALL_ARG1];

    if(strstr(fname, ".so") || strstr(fname, ".so.")) 
	{
		printf("Ignore shared library\n");
        return;
    }
	else 
	{
		fd = (int)ctx->ret;
		fdset.insert(fd);
	}
	printf("Opening %s at fd %u\n", fname, fd);
}


/* 
 * DTA/DFT alert
 *
 * @ins:	address of the offending instruction
 * @bt:		address of the branch target
 */
static void PIN_FAST_ANALYSIS_CALL
alert(ADDRINT ins, ADDRINT bt)
{
	/* log file */
	FILE *logfile;

	/* auditing */
	if (likely((logfile = fopen(logpath.Value().c_str(), "a")) != NULL)) {
		/* hilarious :) */
		(void)fprintf(logfile, " ____ ____ ____ ____\n");
		(void)fprintf(logfile, "||w |||o |||o |||t ||\n");
		(void)fprintf(logfile, "||__|||__|||__|||__||\t");
		(void)fprintf(logfile, "[%d]: 0x%08lx --> 0x%08lx\n",
							getpid(), ins, bt);

		(void)fprintf(logfile, "|/__\\|/__\\|/__\\|/__\\|\n");
		
		/* cleanup */
		(void)fclose(logfile);
	}
	else
		/* failed */
		LOG(string(__func__) +
			": failed while trying to open " +
			logpath.Value().c_str() + " (" +
			string(strerror(errno)) + ")\n");

	/* terminate */
	exit(EXIT_FAILURE);
}

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
 * 32-bit register assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a register
 * for an indirect branch; returns a positive value
 * whenever the register value or the target address
 * are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_reg32(THREADID tid, uint32_t reg, ADDRINT addr)
{
	/* 
	 * combine the register tag along with the tag
	 * markings of the target address
	 */
	tag_t tag = 0x00U;
	
	for(int i = 0; i < 3; i++)
	{
		tag |= threads_ctx[tid].vcpu.gpr[reg][i] | threads_ctx[tid].vcpu.gpr[reg][i+1];
	}
	return tag | tagmap_getn(addr, 4);
}

/*
 * 16-bit register assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a register
 * for an indirect branch; returns a positive value
 * whenever the register value or the target address
 * are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_reg16(THREADID tid, uint32_t reg, ADDRINT addr)
{
	/* 
	 * combine the register tag along with the tag
	 * markings of the target address
	 */
	tag_t tag = 0x00U;
	
	tag |= threads_ctx[tid].vcpu.gpr[reg][0] | threads_ctx[tid].vcpu.gpr[reg][1];
	return tag | tagmap_getn(addr, 2);
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

/*
 * 32-bit memory assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a memory
 * location for an indirect branch; returns a positive
 * value whenever the memory value (i.e., effective address),
 * or the target address, are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_mem32(ADDRINT paddr, ADDRINT taddr)
{
	return tagmap_getn(paddr, 4) | tagmap_getn(taddr, 4);
}

/*
 * 16-bit memory assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a memory
 * location for an indirect branch; returns a positive
 * value whenever the memory value (i.e., effective address),
 * or the target address, are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_mem16(ADDRINT paddr, ADDRINT taddr)
{
	return tagmap_getn(paddr, 2) | tagmap_getn(taddr, 2);
}

/*
 * instrument the jmp/call instructions
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */

static void
dta_instrument_jmp_call(INS ins)
{
	/* temporaries */
	REG reg;

	/* custom addition */
	#if 1
	if (INS_IsDirectCall(ins))
	{
		//int arg_num = 0;
		#if 0
		//printf("%p\n", (void*)INS_DirectBranchOrCallTargetAddress(ins) );
		if ((void*)INS_DirectBranchOrCallTargetAddress(ins) == target) {
			printf("Found\n");
		}
		#endif
		#if 0
    	std::string func = RTN_FindNameByAddress(INS_DirectBranchOrCallTargetAddress(ins));
		if (funcnames[INS_DirectBranchOrCallTargetAddress(ins)] != "") {
			printf("%s\n", funcnames[INS_DirectBranchOrCallTargetAddress(ins)].c_str());
		}
		if (strcmp(func.c_str(), "read") == 0)
		{
			printf("%s | %p\n", func.c_str(), (void *)INS_DirectBranchOrCallTargetAddress(ins));
		}
		#endif
	}
	#endif

	/* 
	 * we only care about indirect calls;
	 * optimized branch
	 */
	if (unlikely(INS_IsIndirectControlFlow(ins))) {
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
			/* 32-bit register */
			else if (REG_is_gr32(reg))
				/*
				 * instrument assert_reg32() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg32,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg),
					IARG_REG_VALUE, reg,
					IARG_END);
			else
				/* 16-bit register */
				/*
				 * instrument assert_reg16() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg16,
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
			/* 32-bit */
			else if (INS_MemoryReadSize(ins) == WORD_LEN)
				/*
				 * instrument assert_mem32() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_mem32,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_BRANCH_TARGET_ADDR,
					IARG_END);
			/* 16-bit */
			else
				/*
				 * instrument assert_mem16() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_mem16,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_BRANCH_TARGET_ADDR,
					IARG_END);
		}
		/*
		 * instrument alert() before branch;
		 * conditional instrumentation -- then
		 */
		INS_InsertThenCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)alert,
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);
	}
}

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
	/* 32-bit */
	else if (INS_MemoryReadSize(ins) == WORD_LEN)
		/*
		 * instrument assert_mem32() before ret;
		 * conditional instrumentation -- if
		 */
		INS_InsertIfCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)assert_mem32,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);
	/* 16-bit */
	else
		/*
		 * instrument assert_mem16() before ret;
		 * conditional instrumentation -- if
		 */
		INS_InsertIfCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)assert_mem16,
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
		(AFUNPTR)alert,
		IARG_FAST_ANALYSIS_CALL,
		IARG_INST_PTR,
		IARG_BRANCH_TARGET_ADDR,
		IARG_END);
}

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
        	/* set the tag markings */
			printf("\nTagging\n");
	        tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret, TAG);
	}
	else {
        	/* clear the tag markings */
			printf("\nClearing\n");
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

/*
 * socket(2) syscall post hook(auxiliary)
 *
 * when socket(2) open INET fd, add the fd to the fdset
 */
static void post_socket_hook(THREADID tid, syscall_ctx_t *ctx) 
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
static void post_accept_hook(THREADID tid, syscall_ctx_t *ctx)
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
static void post_recvfrom_hook(THREADID tid, syscall_ctx_t *ctx)
{
  /* not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;
	
	/* taint-source */	
	if (fdset.find((int)ctx->arg[SYSCALL_ARG0]) != fdset.end())
	{
		/* set the tag markings */
		tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret, TAG);
		printf("tag the buffer\n");
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
static void post_recvmsg_hook(THREADID tid, syscall_ctx_t *ctx)
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
				if (it != fdset.end())
					/* set the tag markings */
					tagmap_setn((size_t)msg->msg_control,
						msg->msg_controllen, TAG);
					
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
				if (it != fdset.end())
					/* set the tag markings */
					tagmap_setn((size_t)iov->iov_base,
								iov_tot, TAG);
				else
					/* clear the tag markings */
					tagmap_clrn((size_t)iov->iov_base,
								iov_tot);
		
				/* housekeeping */
				tot -= iov_tot;
			}
	printf("tag the buffer\n");
}

/*
 * auxiliary (helper) function
 *
 * duplicated descriptors are added into
 * the monitored set
 */
static void
post_dup_hook(THREADID tid, syscall_ctx_t *ctx)
{
	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/*
	 * if the old descriptor argument is
	 * interesting, the returned handle is
	 * also interesting
	 */
	if (likely(fdset.find((int)ctx->arg[SYSCALL_ARG0]) != fdset.end()))
		fdset.insert((int)ctx->ret);
}

/*
 * auxiliary (helper) function
 *
 * whenever close(2) is invoked, check
 * the descriptor and remove if it was
 * inside the monitored set of descriptors
 */
static void
post_close_hook(THREADID tid, syscall_ctx_t *ctx)
{
	/* iterator */
	set<int>::iterator it;

	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/*
	 * if the descriptor (argument) is
	 * interesting, remove it from the
	 * monitored set
	 */
	it = fdset.find((int)ctx->arg[SYSCALL_ARG0]);
	if (likely(it != fdset.end()))
		fdset.erase(it);
}

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
		strstr((char *)ctx->arg[SYSCALL_ARG0], DLIB_SUFF_ALT) == NULL) {
		fdset.insert((int)ctx->ret);
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

	
	trace = fopen("dft.out", "w");
	if (trace != NULL)
	{
		printf("Success\n");
	}
	IMG_AddInstrumentFunction(parse_funRtns, 0);

	/* initialize the core tagging engine */
	if (unlikely(libdft_init() != 0))
		/* failed */
		goto err;
	/* 
	 * handle control transfer instructions
	 *
	 * instrument the branch instructions, accordingly,
	 * for installing taint-sinks (DFT-logic) that check
	 * for tainted targets (i.e., tainted operands or
	 * tainted branch targets) -- For brevity I omitted
	 * checking the result of each instrumentation for
	 * success or failure
	 */

	/* instrument call pre */
	//(void)ins_set_pre(&ins_desc[XED_ICLASS_CALL_NEAR],
	//		dta_instrument_call);

	/* instrument call post */
	(void)ins_set_post(&ins_desc[XED_ICLASS_CALL_NEAR],
			dta_instrument_jmp_call);
	
	/* instrument jmp */
	(void)ins_set_post(&ins_desc[XED_ICLASS_JMP],
			dta_instrument_jmp_call);

	/* instrument ret */
	(void)ins_set_post(&ins_desc[XED_ICLASS_RET_NEAR],
			dta_instrument_ret);

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
	
	/* read(2) */
	(void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);

	/* readv(2) */
	(void)syscall_set_post(&syscall_desc[__NR_readv], post_readv_hook);

	/* socket(2), accept(2), recvfrom(2), recvmsg(2) */
	
	(void)syscall_set_post(&syscall_desc[__NR_socket], post_socket_hook);
	(void)syscall_set_post(&syscall_desc[__NR_accept] , post_accept_hook);
	(void)syscall_set_post(&syscall_desc[__NR_accept4] , post_accept_hook);
	(void)syscall_set_post(&syscall_desc[__NR_recvfrom] , post_recvfrom_hook);
	(void)syscall_set_post(&syscall_desc[__NR_recvmsg] , post_recvmsg_hook);


	/* dup(2), dup2(2) */
	(void)syscall_set_post(&syscall_desc[__NR_dup], post_dup_hook);
	(void)syscall_set_post(&syscall_desc[__NR_dup2], post_dup_hook);

	/* close(2) */
	(void)syscall_set_post(&syscall_desc[__NR_close], post_close_hook);
	
	/* open(2), creat(2) */
	if (fs.Value() != 0) {
		(void)syscall_set_post(&syscall_desc[__NR_open],
				post_open_hook);
		(void)syscall_set_post(&syscall_desc[__NR_creat],
				post_open_hook);
		(void)syscall_set_post(&syscall_desc[__NR_openat],
				post_openat_hook);
	}
	
	/* add stdin to the interesting descriptors set */
	if (stdin_.Value() != 0)
		fdset.insert(STDIN_FILENO);


    // Register Instruction to be called to instrument instructions
	// temp
	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddFiniFunction(Fini, 0);

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