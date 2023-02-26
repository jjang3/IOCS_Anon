/*
 * ARGS instrumentation.
 */

#include "../include/stdlib.c"

#define YELLOW  "\33[33m"
#define WHITE   "\33[0m"

/*
 * Entry point.
 *
 * call entry(...)
 */
void entry(intptr_t static_addr, intptr_t asm_str, intptr_t arg3, intptr_t arg4)
{
    fprintf(stderr, YELLOW "%.16lx" WHITE " %s\n",
           static_addr, asm_str);
    printf("This is where pkey will be set/disabled\n");
}

