#include "../include/pkuapi.h"
//#include "/home/jaewon/Waterfall/e9stuff/include/stdlib.c"


//__attribute__((no_instrument_function))
//void __cyg_profile_func_enter (void *this_fn, void *call_site){}

int
wrpkru(unsigned int pkru)
{
    unsigned int eax = pkru;
    unsigned int ecx = 0;
    unsigned int edx = 0;

    asm volatile(".byte 0x0f,0x01,0xef\n\t"
                 : : "a" (eax), "c" (ecx), "d" (edx));
    return 0;
}

int
pkey_set(int pkey, unsigned long rights, unsigned long flags)
{
    unsigned int pkru = (rights << (2 * pkey));
    return wrpkru(pkru);
}

int
pkey_mprotect(void *ptr, size_t size, unsigned long orig_prot,
                unsigned long pkey)
{
    return syscall(SYS_pkey_mprotect, ptr, size, orig_prot, pkey);
}

int
pkey_alloc(void)
{
    return syscall(SYS_pkey_alloc, 0, 0);
}

int
pkey_free(unsigned long pkey)
{
    return syscall(SYS_pkey_free, pkey);
}

void pkey_disable_access()
{
    //printf("Pkey disable\n");
    pkey_set(pkey, PKEY_DISABLE_ACCESS, 0);
}
void pkey_all_access()
{
    //printf("Pkey enable\n");
    pkey_set(pkey, PKEY_ALL_ACCESS, 0);
}