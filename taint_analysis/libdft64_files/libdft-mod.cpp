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
#if 0
static tag_traits<tag_t>::type dta_tag = 1;
/* socket related syscalls */
static int sock_syscalls[] = {
	__NR_socket,
	__NR_accept,
	__NR_accept4,
	__NR_getsockname,
	__NR_getpeername,
	__NR_socketpair,
	__NR_recvfrom,
	__NR_getsockopt,
	__NR_recvmsg,
	__NR_recvmmsg,
};
#endif

static std::map<int, uint8_t> fd2tag;
#define	MAX_TAG 	  0x10U
uint8_t NEXT_TAG 	= 0x01;
/* the tag value used for tainting */

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
		cerr << hex << ins_addr << " [*] " << RTN_Name(callRtn) << endl;
		#endif
		RTN_Close(callRtn);
	}
	taintSrc = false;
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
			#if DBG_FLAG
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
	uint8_t TAG;
	
	/* read() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
			return;

	cerr << "FD: " << ctx->arg[SYSCALL_ARG0] << endl;
	/* taint-source */
	if (fdset.find(ctx->arg[SYSCALL_ARG0]) != fdset.end()){
		if(!fd2tag[ctx->arg[SYSCALL_ARG0]]) {
			TAG = NEXT_TAG;
			fd2tag[ctx->arg[SYSCALL_ARG0]] = TAG;
			if(NEXT_TAG < MAX_TAG) NEXT_TAG <<= 1;
		} else {
			/* reuse color of file with same fd which was opened previously */
			TAG = fd2tag[ctx->arg[SYSCALL_ARG0]];
		}
		/* set the tag markings */ // << unwindStack.top() << " " << std::hex << ctx->arg[SYSCALL_ARG1]
		//hex << ctx->arg[SYSCALL_ARG1] << "fd: " << ctx->arg[SYSCALL_ARG0] << " " << std::hex 
		cerr << "\t► read(2) taint set | " << unwindStack.top() << endl;
		taintSrc = true;
		// \nCurr Fun: %s\n\t  unwindStack.top()
		fprintf(trace, "Taint source: %s 0x%lx %d\n", routineStack.top(), addressStack.top(), TAG);
		cerr << "\t - Routine: " << routineStack.top() << endl;
		tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret, TAG);
		unwindStack.pop();
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
	uint8_t TAG;
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
	if(!fd2tag[ctx->arg[SYSCALL_ARG0]]) {
		TAG = NEXT_TAG;
		fd2tag[ctx->arg[SYSCALL_ARG0]] = TAG;
		if(NEXT_TAG < MAX_TAG) NEXT_TAG <<= 1;
	} else {
		/* reuse color of file with same fd which was opened previously */
		TAG = fd2tag[ctx->arg[SYSCALL_ARG0]];
	}
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
			cerr << "\t► readv(2) taint set | " << unwindStack.top() << endl;
			tagmap_setn((size_t)iov->iov_base, iov_tot, TAG);
			unwindStack.pop();
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

/*
 * socket(2) syscall post hook(auxiliary)
 *
 * when socket(2) open INET fd, add the fd to the fdset
 */
static void 
post_socket_hook(THREADID tid, syscall_ctx_t *ctx) 
{

	cerr << "Socket FD: " << (int)ctx->ret << endl;
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



#if 0
/*
 *
 */
static void 
post_sockpeer_hook(THREADID tid, syscall_ctx_t *ctx)
{
  if (unlikely((long)ctx->ret < 0))
				return;
	/* addr argument is provided */
	if ((void *)ctx->arg[SYSCALL_ARG1] != NULL) {
		cerr << "\t► sock/peer(2) taint clear " << endl;
		/* clear the tag bits */
		tagmap_clrn(ctx->arg[SYSCALL_ARG1],
			*((int *)ctx->arg[SYSCALL_ARG2]));
		
		/* clear the tag bits */
		tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(int));
	}
}

/*
 *
 */
static void 
post_socketpair_hook(THREADID tid, syscall_ctx_t *ctx)
{
  	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;

	cerr << "\t► socketpair(2) taint clear " << endl;
	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG3], (sizeof(int) * 2));
}

/*
 * recvfrom() syscall post hook(source)
 *
 * tag the buffer
 */
static void 
post_getsockopt_hook(THREADID tid, syscall_ctx_t *ctx)
{
	if (unlikely((long)ctx->ret < 0))
		return;
		
	cerr << "\t► getsockopt(2) taint clear " << endl;
	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG3],
			*((int *)ctx->arg[SYSCALL_ARG4]));
	
	/* clear the tag bits */
	tagmap_clrn(ctx->arg[SYSCALL_ARG4], sizeof(int));
}
#endif
/*
 * recvfrom() syscall post hook(source)
 *
 * tag the buffer
 */
#if 0
static void 
post_recvfrom_hook(THREADID tid, syscall_ctx_t *ctx)
{
	uint8_t TAG;
  	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;
	
	/* taint-source */	
	if (fdset.find((int)ctx->arg[SYSCALL_ARG0]) != fdset.end())
	{
		if(!fd2tag[ctx->arg[SYSCALL_ARG0]]) {
			TAG = NEXT_TAG;
			fd2tag[ctx->arg[SYSCALL_ARG0]] = TAG;
			if(NEXT_TAG < MAX_TAG) NEXT_TAG <<= 1;
		} else {
			/* reuse color of file with same fd which was opened previously */
			TAG = fd2tag[ctx->arg[SYSCALL_ARG0]];
		}
		/* set the tag markings */
		cerr << "\t► recvfrom(2) taint set | " << unwindStack.top() << endl;
		tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret, TAG);
		unwindStack.pop();
		//printf("tag the buffer\n");
	}
	else {
		/* clear the tag markings */
		cerr << "\t► recvfrom(2) taint clear " << endl;
		tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
	}

	/* sockaddr argument is specified */
	if ((void *)ctx->arg[SYSCALL_ARG4] != NULL)
	{
		cerr << "\t► recvfrom(2) taint clear " << endl;
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
	uint8_t TAG;
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

	if(!fd2tag[ctx->arg[SYSCALL_ARG0]]) {
		TAG = NEXT_TAG;
		fd2tag[ctx->arg[SYSCALL_ARG0]] = TAG;
		if(NEXT_TAG < MAX_TAG) NEXT_TAG <<= 1;
	} else {
		/* reuse color of file with same fd which was opened previously */
		TAG = fd2tag[ctx->arg[SYSCALL_ARG0]];
	}
	/* ancillary data specified */
	if (msg->msg_control != NULL) {
		/* taint-source */
		if (it != fdset.end()){
			/* set the tag markings */
			//cerr << "\t► recvmsg(2) taint set | " << unwindStack.top() << endl;
			tagmap_setn((size_t)msg->msg_control,
				msg->msg_controllen, TAG);
			//unwindStack.pop();
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
			//cerr << "\t► recvmsg(2) taint set | " << unwindStack.top() << endl;
			tagmap_setn((size_t)iov->iov_base,
						iov_tot, TAG);
			//unwindStack.pop();
		}
		else
			/* clear the tag markings */
			tagmap_clrn((size_t)iov->iov_base,
						iov_tot);

		/* housekeeping */
		tot -= iov_tot;
	}
	//printf("tag the buffer\n");
}
#endif

/* 
 * Alert Function
 *
 * @buff:	address of sensitive information buffer
 * @buffsize: buffer size
 * @tag: tag of the buffer
 */
#if 0

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
static void 
alert(ADDRINT buff, size_t buffsize , tag_t tag)
{
	printf("Info Leakage Detected!\n");

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
#endif
#if 0
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
#endif
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
		auto tag_val = tagmap_getn(paddr, 8) | tagmap_getn(eaddr, 8);
		#if DBG_FLAG
		printf("Tagged Mem Write (TMW)\n");
		#endif
		if (taintSrc == false){
			cerr << "\t▷ dta_mem_write() " << endl;
			fprintf(trace, "\tTaint sink: %s 0x%lx %d\n", routineStack.top(), addressStack.top(), tag_val);
		}
		//fprintf(trace, "\tTMW: %s | %p", rtn_name.c_str(), (void *)ip);
	}
}
#if 1
static void
dta_tainted_mem_read(ADDRINT paddr, ADDRINT eaddr)
{
	// print when addr is tagged.
	if (tagmap_getn(paddr, 8) | tagmap_getn(eaddr, 8))
	{
		auto tag_val = tagmap_getn(paddr, 8) | tagmap_getn(eaddr, 8);
		#if DBG_FLAG
		printf("Tagged Mem Read (TMR)\n");
		#endif
		if (taintSrc == false){
			cerr << "\t▷ dta_mem_read()" << std::hex << " " << endl;
			fprintf(trace, "\tTaint sink: %s 0x%lx %d\n", routineStack.top(), addressStack.top(), tag_val);
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
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)dta_tainted_mem_write, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                                     IARG_END);
        }
		#if 1
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
#if 0
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

#if 0
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
	{
		// cerr << "Open fd: " << (int)ctx->ret << endl;
		fdset.insert((int)ctx->ret);
	}
}
#endif
VOID Fini(INT32 code, VOID *v)
{
	fclose(trace);	
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

	trace = fopen("dft.out", "w");
	if (trace != NULL)
	{
		printf("Success\n");
	}
	IMG_AddInstrumentFunction(getMetadata, 0);
	INS_AddInstrumentFunction(Instruction, 0);

	// ---------- Taint sources ---------- // 
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
	//(void)syscall_set_post(&syscall_desc[__NR_recvfrom] , post_recvfrom_hook);
	//(void)syscall_set_post(&syscall_desc[__NR_recvmsg] , post_recvmsg_hook);
	#endif

	/* add stdin to the interesting descriptors set */
	if (stdin_.Value() != 0)
		fdset.insert(STDIN_FILENO);

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