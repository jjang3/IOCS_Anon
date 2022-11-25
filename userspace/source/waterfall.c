/************
 * shroud.c
*************/
#include "../include/waterfall.h"
#include <libunwind.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#if __x86_64__
#  define ElfW(type) Elf64_##type
#else
#  define ElfW(type) Elf32_##type
#endif

int mte_enabled () {
    /*
    * Enable the tagged address ABI, synchronous or asynchronous MTE
    * tag check faults (based on per-CPU preference) and allow all
    * non-zero tags in the randomly generated set.
    */
    //|  PR_MTE_TCF_ASYNC
    if (prctl(PR_SET_TAGGED_ADDR_CTRL,
              PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC |
              (0xfffe << PR_MTE_TAG_SHIFT),
              0, 0, 0)) {
            perror("prctl() failed");
            return EXIT_FAILURE;
    }
    return 1;
}


char *mte_init(char *address) {
    #if 1
    printf(" _______________________\n");
    printf("|                       |\n");
    printf("|       MTE Init        |\n");
    printf("|_______________________|\n");

    printf("MTE-C Initialization\n");
    #endif
    
    unsigned long page_sz = sysconf(_SC_PAGESIZE);

    if (mte_enabled()) {
        //printf("MTE enabled\n");  
    } 
    else { 
        printf("MTE not enabled\n");  
        exit(1); 
    }

    if (mprotect((char *) ((uintptr_t) address & ~(uintptr_t) 0xfffUL), page_sz, PROT_READ | PROT_WRITE | PROT_MTE)) {
        perror("mprotect() failed");
        exit(1); 
    }
    
    address = __arm_mte_create_random_tag((char *)address, 0x0); 
    // __arm_mte_set_tag(address);
    printf("Compartmentalized: %p\n", address);
    return address;
}


// Call this function to get a backtrace.
void backtrace() {
  unw_cursor_t cursor;
  unw_context_t context;

  // Initialize cursor to current frame for local unwinding.
  unw_getcontext(&context);
  unw_init_local(&cursor, &context);

  // Unwind frames one by one, going up the frame stack.
  while (unw_step(&cursor) > 0) {
    unw_word_t offset, pc;
    unw_get_reg(&cursor, UNW_REG_IP, &pc);
    if (pc == 0) {
      break;
    }
    printf("0x%lx:", pc);

    char sym[256];
    if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0) {
      printf(" (%s+0x%lx)\n", sym, offset);
    } else {
      printf(" -- error: unable to obtain symbol name for this frame\n");
    }
  }
}