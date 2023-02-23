#include <stdio.h>
#include "../include/pkuapi.h"

#define PAGESIZE 	4096

void foo() __attribute__ ((section (".isolate_target")));

#if 0
struct fun_info {
    char *name;
};
/* The linker automatically creates these symbols for "my_custom_section". */
extern struct fun_info *__start_isolate_target;
extern struct fun_info *__stop_isolate_target;
#endif
const void * _smysection;
const void * _emysection;
int main()
{
    #if 0
    printf("Isolated functions are sitting from %p to %p\n",
	   (void *)&__start_isolate_target,
	   (void *)&__stop_isolate_target);
    #endif
    #if 1
    printf("Isolated functions are sitting from %p to %p\n",
	   (uintptr_t)&_smysection,
	   (uintptr_t)&_emysection);
    #endif
    if(mprotect(&foo, 4096, PROT_READ | PROT_WRITE) == -1) {
        perror("pkey_mprotect()");
        return 1;
    }
    printf("Hello World\n");
}

void foo()
{
    printf("Foo\n");
}

//0x56316eff1932