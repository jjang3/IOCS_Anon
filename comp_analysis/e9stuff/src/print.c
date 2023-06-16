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

/*
 * Entry point.
 *
 * call entry(...)
 */

extern const void *__text_start;
extern const void *__text_end;

void entry(intptr_t static_addr, intptr_t asm_str, const void *entry_addr, const void *end_addr)
{
	fprintf(stderr, YELLOW "%p - %s: Text section ranging from %p - %p\n" WHITE, static_addr, asm_str, entry_addr, end_addr);
}


/*
 * Initialization.
 */
void init(int argc, char **argv, char **envp)
{
    #if 0 // Total if/endif
    // Sanity check.
    /*
        This is used to figure out the pagesize length of section
        as there could be multiple functions in a section. 
    */

	fprintf(stderr, YELLOW "Text section ranging from %p - %p\n" WHITE, &__text_start, &__text_end);
    size_t protect_len = ((uintptr_t)&__text_end)-((uintptr_t)&__text_start);
    //size_t untrusted_len = ((uintptr_t)&_end_untrusted_sec)-((uintptr_t)&_start_untrusted_sec);
    int pagelen;
    if (protect_len < PAGESIZE)
    {
        pagelen = 1;
    }
    else if (protect_len / PAGESIZE > 0)
    {
        int base = protect_len / PAGESIZE;
        if (protect_len % PAGESIZE != 0)
        {
            base += 1;
        }
        pagelen = base;
    }

    /*
        MPK-related stuff.
    */
    #if 1
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
    #endif

    #if 1
    /*
    PROT_NONE
        The memory cannot be accessed at all.
    PROT_READ
        The memory can be read.
    PROT_WRITE
        The memory can be modified.
    PROT_EXEC
        The memory can be executed.
    */
    // This will make the .isolate_sec execute-only page. 
    if(pkey_mprotect(&__text_start, pagelen * PAGESIZE, PROT_READ | PROT_EXEC, pkey) == -1) {
        //perror("pkey_mprotect()");
        fprintf(stderr, RED "pkey_mprotect()\n" WHITE);
        return;
    }
    #endif
    #endif
}