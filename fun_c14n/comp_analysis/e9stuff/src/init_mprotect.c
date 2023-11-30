/*
 * ARGS instrumentation.
 */

#include "../include/stdlib.c"
// #include "../../pku/include/pkey.h"
// #include "../../pku/include/pkuapi.h"
#include "../e9pku/e9_pkuapi.c"
// #include "sub.c"

#define RED     "\33[31m"
#define GREEN   "\33[32m"
#define YELLOW  "\33[33m"
#define WHITE   "\33[0m"
#define PAGESIZE    4096

#define DBG_FLAG 1

int check;
/*
 * Entry point.
 *
 * call entry(...)
 */
void entry(intptr_t static_addr, intptr_t fun_str, const char *entry_exit_flag, void *section_addr, void *static_section_addr)
{
    if (strcmp(entry_exit_flag, "protect") == 0) {
        #if DBG_FLAG
        fprintf(stderr, YELLOW "%.16lx %p" GREEN " mprotect\n" WHITE, static_addr, static_section_addr);
        // global_var = 1;
        // sub_fun();
        #endif
        if(pkey_mprotect(section_addr, PAGESIZE, PROT_READ | PROT_EXEC, pkey) == -1) {
            //perror("pkey_mprotect()");
            fprintf(stderr, RED "pkey_mprotect()\n" WHITE);
            //exit(0);
            //fprintf(stderr, "0x%hhx\n", *(int*)section_addr);//This is to verify whether mprotect is working properly.
            return;
        }
        
    }
    else if (strcmp(entry_exit_flag, "entry") == 0) {
        pkey_disable_access(); // <- segmentation fault here.
        #if DBG_FLAG
        fprintf(stderr, YELLOW "%.16lx (%s):" RED " disable access\n" WHITE, static_addr, fun_str, entry_exit_flag);
        #endif
        // uncomment this to enable restriction access
    }
    else {
        pkey_all_access();
        #if DBG_FLAG
        fprintf(stderr, YELLOW "%.16lx (%s):" GREEN " returning, enable access\n"  WHITE, static_addr, fun_str, entry_exit_flag);
        #endif
    }
    // printf("This is where pkey will be set/disabled\n");
}


/*
 * Initialization.
 */
void init(int argc, char **argv, char **envp)
{
    /*
        MPK-related stuff.
    */
    // Allocate protection key (how this is used is in pkuapi.c)
    // pkey = 1;
    pkey = pkey_alloc();
    if (pkey == -1) {
        //perror("pkey_alloc()");
        return;
	}
    // Assign "All Access" permission to pkey (not designated to any memory locations yet)
    // PKEY_ALL_ACCESS
    if (pkey_set(pkey, PKEY_ALL_ACCESS, 0) == -1) {
        //perror("pkey_set()");
        return;
    }
    // global_var = 1;
    // sub_fun();
    fprintf(stderr, YELLOW "Initializing pkey: %d\n" WHITE, pkey);
}