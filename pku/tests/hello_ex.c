#include "../include/pkuapi.h"

#define PAGESIZE 	4096


void foo() __attribute__((aligned(PAGESIZE)))  __attribute__ ((section ("isolate_target")));

struct fun_info {
    char *name;
};

/* The linker automatically creates these symbols for "my_custom_section". */
extern struct fun_info *__start_isolate_target;
extern struct fun_info *__stop_isolate_target;

int pkey;

int main()
{

    printf("Hello World\n");
    printf("Isolated functions are sitting from %p to %p\n",
	   (void *)&__start_isolate_target,
	   (void *)&__stop_isolate_target);

    size_t isolate_target_len = ((uintptr_t)&__stop_isolate_target)-((uintptr_t)&__start_isolate_target);
    int pagelen;
    if (isolate_target_len < PAGESIZE)
    {
        pagelen = 1;
    }
    else if (isolate_target_len / PAGESIZE > 0)
    {
        int base = isolate_target_len / PAGESIZE;
        if (isolate_target_len % PAGESIZE != 0)
        {
            base += 1;
        }
        pagelen = base;
    }
    #if 1
    // Allocate protection key
    pkey = pkey_alloc();
    if (pkey == -1) {
        perror("pkey_alloc()");
        return 1;
	}
    // Assign "No access" permission to permission key (not designated)
    if (pkey_set(pkey, PKEY_DISABLE_ACCESS, 0) == -1) {
        perror("pkey_set()");
        return 1;
    }

    if(pkey_mprotect(&__start_isolate_target, getpagesize(), PROT_READ | PROT_WRITE, pkey) == -1) {
        perror("pkey_mprotect()");
        return 1;
    }
    #endif
    
    return 0;
}

void foo()
{
    printf("Foo\n");
}