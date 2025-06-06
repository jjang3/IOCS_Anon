/*
 * PRINT instrumentation.
 */


#include "../include/stdlib.c"
#include "sub.c"

#define RED     "\33[31m"
#define GREEN   "\33[32m"
#define YELLOW  "\33[33m"
#define WHITE   "\33[0m"

/*
 * Entry point.
 *
 * call entry(addr,instr,size,asm)@print
 */
void entry(const void *addr, const uint8_t *instr, size_t size,
    const char *_asm)
{
    global_var = 1;
    sub_fun();
    static mutex_t mutex = MUTEX_INITIALIZER;
    if (mutex_lock(&mutex) < 0)
        return;

    clearerr_unlocked(stderr);
    fprintf_unlocked(stderr, RED "Testing: %.16lx" WHITE ": " YELLOW, addr);
    int i;
    for (i = 0; i < size; i++)
    {
        fprintf_unlocked(stderr, "Testing: %.2x ", instr[i]);
        if (i == 7 && size > 8)
            fprintf_unlocked(stderr, GREEN "%s test" WHITE "\n                  "
                YELLOW, _asm);
    }
    if (i <= 8)
    {
        for (; i < 8; i++)
            fputs_unlocked("   ", stderr);
        fprintf_unlocked(stderr, GREEN "%s", _asm);
    }
    fputs_unlocked(WHITE "\n", stderr);
    fflush_unlocked(stderr);

    mutex_unlock(&mutex);
}

void init(void)
{
    // printf("What\n");
    setvbuf(stderr, NULL, _IOFBF, 0);
}

