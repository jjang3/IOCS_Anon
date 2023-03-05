/*
 * ARGS instrumentation.
 */

#include "../include/stdlib.c"
#include "../../pku/include/pkuapi.h"

#define RED     "\33[31m"
#define GREEN   "\33[32m"
#define YELLOW  "\33[33m"
#define WHITE   "\33[0m"

extern int pkey;
/*
 * Entry point.
 *
 * call entry(...)
 */
void entry(intptr_t static_addr, intptr_t asm_str, const char *entry_exit_flag, intptr_t arg4)
{
    if (strcmp(entry_exit_flag, "entry") == 0) {
        pkey++;
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

