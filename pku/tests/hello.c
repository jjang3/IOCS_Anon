#include "../include/pkuapi.h"

#define PAGESIZE 	4096

void __attribute__((constructor)) init();
// This line creates a custom section called "isolate_target", and then align this section with the pagesize
// More information here: https://stackoverflow.com/questions/16552710/how-do-you-get-the-start-and-end-addresses-of-a-custom-elf-section
void foo() __attribute__ ((section (".isolate_target")));
//void foo();
//void bar() __attribute__ ((section (".isolate_target")));
void bar();
// objdump -d hello_ex.out &> hello.objdump will dump isolated section

/* The linker automatically creates these symbols for "my_custom_section". */
const void * _start_isolate_sec;
const void * _end_isolate_sec;

// We are making pkey global because we want to use pkey_set to flexibly enable/disable access
void init()
{
    // Sanity check.
    printf("Isolated functions are sitting from %p to %p\n",
	   (void *)&_start_isolate_sec,
	   (void *)&_end_isolate_sec);
    /*
        This is used to figure out the pagesize length of section
        as there could be multiple functions in a section. 
    */
    size_t isolate_target_len = ((uintptr_t)&_end_isolate_sec)-((uintptr_t)&_start_isolate_sec);
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

    /*
        MPK-related stuff.
    */
    #if 1
    // Allocate protection key (how this is used is in pkuapi.c)
    pkey = pkey_alloc();
    if (pkey == -1) {
        perror("pkey_alloc()");
        return;
	}
    // Assign "All Access" permission to pkey (not designated to any memory locations yet)
    if (pkey_set(pkey, PKEY_DISABLE_ACCESS, 0) == -1) {
        perror("pkey_set()");
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
    // Question, why do I get segmentation fault here when I'm not even trying to access function foo?
    // Furthermore, I am using PKEY_ALL_ACCESS which means there is no pkey set to the memory region.
    // We are designating pkey (which has disable access flag) to the isolated_target ELF section

    // Potential reason of why segmentation fault is happening: because inside of this "isolate_target" section
    // there is still a code which is inside of this region that is being touched.
    /*
    if(pkey_mprotect(&__start_isolate_target, pagelen * getpagesize(), PROT_READ | PROT_WRITE, pkey) == -1) {
        perror("pkey_mprotect()");
        return 1;
    }
    */
    // As discussed, we only want read / execute permission to the function
    if(pkey_mprotect(&_start_isolate_sec, pagelen * getpagesize(), PROT_READ | PROT_EXEC, pkey) == -1) {
        perror("pkey_mprotect()");
        return;
    }
    #endif
}

int main()
{
    printf("Hello World\n");
    foo();
    return 0;
}

void foo()
{
    printf("Foo\n");
    bar();
    printf("After\n");
}

void bar()
{
    //foo();
    printf("Bar\n");
}