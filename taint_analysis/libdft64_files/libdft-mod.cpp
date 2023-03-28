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

/* default path for the log file (audit) */
#define LOGFILE_DFL	"libdft-dta.log"

/* default suffixes for dynamic shared libraries */
#define DLIB_SUFF	".so"
#define DLIB_SUFF_ALT	".so."
#define	TAG 	0x01U

#define DBG_FLAG 1

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

static stack<const char*> unwindStack;
static stack<const char*> routineStack;
static stack<ADDRINT> addressStack;

bool taintSrc = false;

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

#if 1
void callUnwinding(ADDRINT callrtn_addr, char *dis, ADDRINT ins_addr)
{
	PIN_LockClient();
	RTN callRtn = RTN_FindByAddress(callrtn_addr);
	if (RTN_Valid(callRtn))
	{
		auto routineName = RTN_Name(callRtn);
		string pltName = "@plt";
		
		//cerr << routineName << endl;
		if(!(strstr(routineName.c_str(),pltName.c_str()))){
			unwindStack.push(RTN_Name(callRtn).c_str());
			addressStack.push(ins_addr);
		}
		else{
			routineStack.push(RTN_Name(callRtn).c_str());
			
			addressStack.push(ins_addr);
		}
		//	return;
		RTN_Open(callRtn);
		#if DBG_FLAG
		//cerr << hex << ins_addr << " [*] " << RTN_Name(callRtn) << endl;
		#endif
		RTN_Close(callRtn);
	}
	taintSrc = false;
	PIN_UnlockClient();
}

VOID getMetadata(IMG img, void *v)
{
	#if DBG_FLAG
	printf("Loading %s, Image id = %d \n", IMG_Name(img).c_str(), IMG_Id(img));
	#endif
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
		#if DBG_FLAG
		printf ("   image_entry         = 0x%zx \n",imgEntry);
		printf ("   image_globalPointer = 0x%zx \n",imgGlobalPt);
		printf ("   image_loadOffset    = 0x%zx \n",imgLoadOffset);
		printf ("   image_lowAddress    = 0x%zx \n",imgLowAddr);
		printf ("   image_highAddress   = 0x%zx \n",imgHighAddr);
		printf ("   image_startAddress  = 0x%zx \n",imgStartAddr);
		printf ("   image_sizeMapped    = %lu \n",imgSizeMapping);
		#endif
		offset_addr = (uintptr_t)(imgLoadOffset);
		#if 1
		for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
		{
			string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
			RTN rtn = RTN_FindByAddress(imgLoadOffset + SYM_Value(sym));
			#if DBG_FLAG
			//const char* UndecoratedFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY).c_str();
			//cerr << "[*] " << hex << "0x" << RTN_Address(rtn) << "\t" << undFuncName << endl;
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
		(void)fprintf(logfile, " ____ ____ ____ ____\n");
	}
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
	#if DBG_FLAG
	cerr << "read(2) fd: " << ctx->arg[SYSCALL_ARG0] << endl;
	#endif
	/* taint-source */
	if (fdset.find(ctx->arg[SYSCALL_ARG0]) != fdset.end())
	{
		/* set the tag markings */
		//cerr << "\t► read(2) taint set | " << unwindStack.top() << endl;
		taintSrc = true;
		// \nCurr Fun: %s\n\t  unwindStack.top()
		fprintf(trace, "Taint source read(2): 0x%lx\n", (uintptr_t)(addressStack.top()-offset_addr));
		//cerr << "\t - Routine: " << routineStack.top() << endl;
		tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret, TAG);
		unwindStack.pop();
	}
	else {
		/* clear the tag markings */
		#if DBG_FLAG
		printf("read(2) taint clear\n");
		#endif
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
			fprintf(trace, "Taint source readv(2): 0x%lx\n", (uintptr_t)(addressStack.top()-offset_addr));
			//cerr << "\t► readv(2) taint set | " << unwindStack.top() << endl;
			tagmap_setn((size_t)iov->iov_base, iov_tot, TAG);
		}
		else{
			#if DBG_FLAG
			cerr << "\t► readv(2) taint clear " << endl;
			#endif
			/* clear the tag markings */
			tagmap_clrn((size_t)iov->iov_base, iov_tot);
		}		
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

		#if DBG_FLAG
        cerr << "\t► socket(2) fd add " << (int)ctx->ret << endl;
		#endif
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
	if (likely(fdset.find(ctx->arg[SYSCALL_ARG0]) !=fdset.end())){
		#if DBG_FLAG
        cerr << "fd add accept\n";
		#endif
		// Fix this bug later
		//if ((int)ctx->ret < 8)
		fdset.insert((int)ctx->ret);
		//fdset.insert(8);
}}

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
        printf("Taint set recvfrom\n");
		fprintf(trace, "Taint source recvfrom(2): 0x%lx\n", (uintptr_t)(addressStack.top()-offset_addr));
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
		if (it != fdset.end()){
			/* set the tag markings */
			fprintf(trace, "Taint source recvmsg(2): 0x%lx\n", addressStack.top());
			//cerr << "\t► recvmsg(2) taint set | " << unwindStack.top() << endl;
			tagmap_setn((size_t)msg->msg_control,
				msg->msg_controllen, TAG);
		}
		else {
			#if DBG_FLAG
			cerr << "\t► recvmsg(2) taint clear " << endl;
			#endif
			/* clear the tag markings */
			tagmap_clrn((size_t)msg->msg_control,
				msg->msg_controllen);
		}
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
		if (it != fdset.end()){
			/* set the tag markings */
			fprintf(trace, "Taint source recvmsg(2): 0x%lx\n", addressStack.top());
			//cerr << "Taint set recvmsg\n";
			tagmap_setn((size_t)iov->iov_base,
						iov_tot, TAG);}
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
	if (likely(fdset.find((int)ctx->arg[SYSCALL_ARG0]) != fdset.end())){
		#if DBG_FLAG
        cerr << "fd add dup\n";
		#endif
		fdset.insert((int)ctx->ret);}
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

#if 0 // Temporarily disabled as this is causing segmentation fault in MIR machine
static void
post_open_hook(THREADID tid, syscall_ctx_t *ctx)
{
	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	#if DBG_FLAG
    cerr << "post open hook\n";
	#endif
	/* ignore dynamic shared libraries */
	if (strstr((char *)ctx->arg[SYSCALL_ARG0], DLIB_SUFF) == NULL &&
		strstr((char *)ctx->arg[SYSCALL_ARG0], DLIB_SUFF_ALT) == NULL)
		fdset.insert((int)ctx->ret);
}
#endif
#if 1
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
		//auto tag_val = tagmap_getn(paddr, 8) | tagmap_getn(eaddr, 8);
		#if DBG_FLAG
		printf("Tagged Mem Write (TMW)\n");
		#endif
		if (taintSrc == false){
			//cerr << "\t▷ dta_mem_write() " << endl;
			//printf("dta_mem_write\n");
			//fprintf(trace, "\tTaint sink: %s 0x%lx %d\n", routineStack.top(), addressStack.top(), tag_val);
			fprintf(trace, "\tTaint sink dta_mem_write(): 0x%lx\n", (uintptr_t)(addressStack.top()-offset_addr));
		}
		//fprintf(trace, "\tTMW: %s | %p", rtn_name.c_str(), (void *)ip);
	}
}
static void
dta_tainted_mem_read(ADDRINT paddr, ADDRINT eaddr)
{
	// print when addr is tagged.
	if (tagmap_getn(paddr, 8) | tagmap_getn(eaddr, 8))
	{
		//auto tag_val = tagmap_getn(paddr, 8) | tagmap_getn(eaddr, 8);
		#if DBG_FLAG
		printf("Tagged Mem Read (TMR)\n");
		#endif
		if (taintSrc == false){
			//cerr << "\t▷ dta_mem_read()" << std::hex << " " << endl;
			//printf("dta_mem_read\n");
			//fprintf(trace, "\tTaint sink: %s 0x%lx %d\n", routineStack.top(), addressStack.top(), tag_val);
			fprintf(trace, "\tTaint sink dta_mem_read(): 0x%lx\n",  (uintptr_t)(addressStack.top()-offset_addr));
		}
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

		#if 1
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)dta_tainted_mem_write, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                                     IARG_END);
        }
		// Disabling this for now as there is no need to check on whether tagged memory is written.
		if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)dta_tainted_mem_read, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                                     IARG_END);
        }
		#endif 
		 // UNUSED
    }
}
#endif
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
	
	trace = fopen("dft.out", "w");
	if (trace != NULL)
	{
		//printf("Success\n");
	}
	IMG_AddInstrumentFunction(getMetadata, 0);
	INS_AddInstrumentFunction(Instruction, 0);
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
	
	#if 0
	/* open(2), creat(2) */
	if (fs.Value() != 0) {
		(void)syscall_set_post(&syscall_desc[__NR_open],
				post_open_hook);
		(void)syscall_set_post(&syscall_desc[__NR_creat],
				post_open_hook);
	}
	#endif
	/* add stdin to the interesting descriptors set */
	if (stdin_.Value() != 0)
		fdset.insert(STDIN_FILENO);

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