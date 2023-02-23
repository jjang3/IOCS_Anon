#include "../include/pkuapi.h"

#define PAGESIZE 	4096

// This line creates a custom section called "isolate_target", and then align this section with the pagesize
// More information here: https://stackoverflow.com/questions/16552710/how-do-you-get-the-start-and-end-addresses-of-a-custom-elf-section
void foo() __attribute__((aligned(PAGESIZE)))  __attribute__ ((section ("isolate_target")));
// objdump -d hello_ex.out &> hello.objdump will dump isolated section

/* The linker automatically creates these symbols for "my_custom_section". */
extern struct fun_info *__start_isolate_target;
extern struct fun_info *__stop_isolate_target;

// We are making pkey global because we want to use pkey_set to flexibly enable/disable access
int pkey;

int main()
{
    // Sanity check.
    printf("Isolated functions are sitting from %p to %p\n",
	   (void *)&__start_isolate_target,
	   (void *)&__stop_isolate_target);
    /*
        This is used to figure out the pagesize length of section
        as there could be multiple functions in a section. 
    */
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

    /*
        MPK-related stuff.
    */
    #if 1
    // Allocate protection key (how this is used is in pkuapi.c)
    pkey = pkey_alloc();
    if (pkey == -1) {
        perror("pkey_alloc()");
        return 1;
	}
    // Assign "All Access" permission to pkey (not designated to any memory locations yet)
    if (pkey_set(pkey, PKEY_ALL_ACCESS, 0) == -1) {
        perror("pkey_set()");
        return 1;
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
    /*
    if(pkey_mprotect(&__start_isolate_target, pagelen * getpagesize(), PROT_READ | PROT_WRITE, pkey) == -1) {
        perror("pkey_mprotect()");
        return 1;
    }
    */
    if(mprotect(&__start_isolate_target, pagelen * getpagesize(), PROT_READ | PROT_WRITE) == -1) {
        perror("pkey_mprotect()");
        return 1;
    }
    #endif

    #if 0
    // However, if mprotect is assigned with PROT_EXEC flag, then there is no segmentation fault.
    // Some potential information regarding PROT_EXEC: 
    // https://people.cs.kuleuven.be/~stijn.volckaert/papers/2022_EuroSys_Cerberus.pdf
    // https://man7.org/linux/man-pages/man2/pkey_mprotect.2.html - There is a note regarding PROT_EXEC
    if(pkey_mprotect(&__start_isolate_target, pagelen * getpagesize(), PROT_EXEC, pkey) == -1) {
        perror("pkey_mprotect()");
        return 1;
    }
    #endif

    printf("Hello World\n");
    return 0;
}

void foo()
{
    printf("Foo\n");
    #if 0 
    // Disabled for now.
    if (pkey_set(pkey, PKEY_DISABLE_ACCESS, 0) == -1) {
        perror("pkey_set()");
        return 1;
    }
    #endif
}