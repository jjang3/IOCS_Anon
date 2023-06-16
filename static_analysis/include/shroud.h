/*
 * To be compiled with -march=armv8.5-a+memtag
 */
#include <asm/hwcap.h>
#include <asm/mman.h>
#include <stdbool.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include "arm_acle.h"
#include "uthash.h"

/*
 * From arch/arm64/include/uapi/asm/hwcap.h
 */
#define HWCAP2_MTE              (1 << 18)

/*
 * From arch/arm64/include/uapi/asm/mman.h
 */
#define PROT_MTE                 0x20

/*
 * From include/uapi/linux/prctl.h
 */
#define PR_SET_TAGGED_ADDR_CTRL 55
#define PR_GET_TAGGED_ADDR_CTRL 56
# define PR_TAGGED_ADDR_ENABLE  (1UL << 0)
# define PR_MTE_TCF_SHIFT       1
# define PR_MTE_TCF_NONE        (0UL << PR_MTE_TCF_SHIFT)
# define PR_MTE_TCF_SYNC        (1UL << PR_MTE_TCF_SHIFT)
# define PR_MTE_TCF_ASYNC       (2UL << PR_MTE_TCF_SHIFT)
# define PR_MTE_TCF_MASK        (3UL << PR_MTE_TCF_SHIFT)
# define PR_MTE_TAG_SHIFT       3
# define PR_MTE_TAG_MASK        (0xffffUL << PR_MTE_TAG_SHIFT)
# define MTE_GRANULE_SIZE       16

typedef struct {
  char *key;      /* key; mte address*/
  uint64_t val;   /* value; rand_key */
  UT_hash_handle hh;  /* hash table structure */
} ut_table;

ut_table *shroud_hash = NULL; 

uint64_t gen_rand_key();
uint64_t enc_dec_ptr(uint64_t ptr, uint64_t key);

int mte_enabled();

char *mte_init(char *address);
char *enc_init(char *address);
char *mte_enc_dec(char *address);
char *mte_retag(char *address);
char *mte_retag_scanf(char *address);
void tag_granule (char *address, int len);
int get_granule(char *input_string);
void *untag_granule (char *address);
void *only_untag_granule (char *address);

char *debug_mte_init(char *address);
void *debug_untag_granule (char *address);
char *debug_mte_retag(char *address);
char *debug_mte_enc_dec(char *address, char *str);
char *debug_fun(char *str);

bool enc_dec_check(char *address);
void *inter_address(char *address);
void* untag_inter_granule (char *address);
char *inter_mte_retag(char *address);
char *inter_mte_retag_scanf(char *address);


void shroud_bench(char *address);