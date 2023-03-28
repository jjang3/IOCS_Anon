/*
 * ARGS instrumentation.
 */

#include "../include/stdlib.c"
#include "../../pku/include/pkuapi.h"

#define RED     "\33[31m"
#define GREEN   "\33[32m"
#define YELLOW  "\33[33m"
#define WHITE   "\33[0m"
#define PAGESIZE    4096

int pkey;
int check;
/*
 * Entry point.
 *
 * call entry(...)
 */
void entry(intptr_t static_addr, intptr_t asm_str, const char *entry_exit_flag, void *section_addr, void *static_section_addr)
{
    check++;
    if (strcmp(entry_exit_flag, "protect") == 0) {
        fprintf(stderr, YELLOW "%.16lx: pkey: %d %p" GREEN " mprotect\n" WHITE, static_addr, pkey, static_section_addr);
        if (check == 1) {
            if(pkey_mprotect(section_addr, PAGESIZE, PROT_READ | PROT_EXEC, pkey) == -1) {
                //perror("pkey_mprotect()");
                fprintf(stderr, RED "pkey_mprotect()\n" WHITE);
                exit(0);
                return;
            }
            // fprintf(stderr, "0x%hhx\n", *(int*)section_addr); This is to verify whether mprotect is working properly.
        }
    }
    else if (strcmp(entry_exit_flag, "entry") == 0) {
        fprintf(stderr, YELLOW "%.16lx: pkey: %d" RED " disable access\n" WHITE, static_addr, pkey, entry_exit_flag);
        pkey_disable_access(); // <- segmentation fault here.
        // uncomment this to enable restriction access
    }
    else {
        fprintf(stderr, YELLOW "%.16lx: pkey: %d" GREEN " returning, enable access\n"  WHITE, static_addr, pkey, entry_exit_flag);
        pkey_all_access();
    }
    //printf("This is where pkey will be set/disabled\n");
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
    pkey = pkey_alloc();
    if (pkey == -1) {
        //perror("pkey_alloc()");
        return;
	}
    // Assign "All Access" permission to pkey (not designated to any memory locations yet)
    if (pkey_set(pkey, PKEY_DISABLE_ACCESS, 0) == -1) {
        //perror("pkey_set()");
        return;
    }
    fprintf(stderr, YELLOW "Initialization (incrementing pkey): %d\n" WHITE, pkey);
}