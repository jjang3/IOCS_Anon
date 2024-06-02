
#include <sys/auxv.h>
#include <elf.h>
#include <immintrin.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
/* Will be eventually in asm/hwcap.h */
#ifndef HWCAP2_FSGSBASE
#define HWCAP2_FSGSBASE        (1 << 1)
#endif
#define _GNU_SOURCE
#define PAGE_SIZE 4096

// How many variables are going to be stored in the table
#define VAR_COUNT 10

void **table;
void __attribute__((constructor)) create_table()
{    
    table = malloc(sizeof(void*)*26);

    if (!table) {
        perror("Failed to allocate memory for page table");
        exit(EXIT_FAILURE);
    }
    /*Pointer to shared memory region*/    

    // Map each page
    for (int i = 0; i < VAR_COUNT; ++i) {
        table[i] = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_32BIT | MAP_PRIVATE, -1, 0);
        if (table[i] == MAP_FAILED) {
            perror("Memory mapping failed");
            // Clean up previously mapped pages
            for (int j = 0; j < i; ++j) {
                munmap(table[j], PAGE_SIZE);
            }
            free(table);
            exit(EXIT_FAILURE);
        }
    }
	_writegsbase_u64((long long unsigned int)table);
}
void __attribute__((destructor)) cleanup_table() {
    // Unmap each page and free the table
    for (int i = 0; i < VAR_COUNT; ++i) {
        if (table[i]) {
            munmap(table[i], PAGE_SIZE);
        }
    }
    free(table);
}
