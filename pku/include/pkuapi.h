
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

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                            } while (0)

static inline int
wrpkru(unsigned int pkru);

int
pkey_set(int pkey, unsigned long rights, unsigned long flags);

int
pkey_mprotect(void *ptr, size_t size, unsigned long orig_prot,
                unsigned long pkey);

int
pkey_alloc(void);


int
pkey_free(unsigned long pkey);