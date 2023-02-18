#define _GNU_SOURCE

#include <errno.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <setjmp.h>
#define PKEY_ALL_ACCESS 0x0
#define PKEY_DISABLE_ACCESS	0x1
#define PKEY_DISABLE_WRITE	0x2

static inline void
wrpkru(unsigned int pkru)
{
    unsigned int eax = pkru;
    unsigned int ecx = 0;
    unsigned int edx = 0;

    asm volatile(".byte 0x0f,0x01,0xef\n\t"
                : : "a" (eax), "c" (ecx), "d" (edx));
}

int
pkey_set(int pkey, unsigned long rights, unsigned long flags)
{
    unsigned int pkru = (rights << (2 * pkey));

    unsigned int eax = pkru;
    unsigned int ecx = 0;
    unsigned int edx = 0;

    asm volatile(".byte 0x0f,0x01,0xef\n\t"
                : : "a" (eax), "c" (ecx), "d" (edx));
    //return wrpkru(pkru);
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

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                            } while (0)

int
main(void)
{
    int status;
    int pkey;
    int *buffer;

    /*
    * Allocate one page of memory.
    */
    buffer = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (buffer == MAP_FAILED)
        errExit("mmap");

    /*
    * Put some random data into the page (still OK to touch).
    */
    *buffer = __LINE__;
    printf("buffer contains: %d\n", *buffer);

    /*
    * Allocate a protection key:
    */
    pkey = pkey_alloc();
    if (pkey == -1)
        errExit("pkey_alloc");

    /*
    * Disable access to any memory with "pkey" set,
    * even though there is none right now.
    */
    status = pkey_set(pkey, PKEY_DISABLE_ACCESS, 0);
    if (status == -1)
        errExit("pkey_set");
    /*
    * Set the protection key on "buffer".
    * Note that it is still read/write as far as mprotect() is
    * concerned and the previous pkey_set() overrides it.
    */
    status = pkey_mprotect(buffer, getpagesize(),
                            PROT_READ | PROT_WRITE, pkey);
    if (status == -1)
        errExit("pkey_mprotect");

    printf("about to read buffer again...\n");

    /*
    * This will crash, because we have disallowed access.
    */
    printf("buffer contains: %d\n", *buffer);

    status = pkey_free(pkey);
    if (status == -1)
        errExit("pkey_free");

    exit(EXIT_SUCCESS);
}