/************
 * shroud.c
*************/

#include "../include/shroud.h"

uint64_t rand_key;

uint64_t gen_rand_key() {
  uint64_t result;
  asm("eor x6, x6, x6\n\t"
      "mrs x6, rndr\n\t"
      "mov %0, x6\n"
      : "=r" (result)
      : 
      : "x6");
  return result;
}


uint64_t enc_dec_ptr(uint64_t ptr, uint64_t key) {
  uint64_t result;
  asm("eor %0, %1, %2\n"
      : "=r" (result)
      : "r" (ptr), "r"(key)
      : "x6");
  return result;
  
}

int mte_enabled () {
    /*
    * Enable the tagged address ABI, synchronous or asynchronous MTE
    * tag check faults (based on per-CPU preference) and allow all
    * non-zero tags in the randomly generated set.
    */
    //|  PR_MTE_TCF_ASYNC
    if (prctl(PR_SET_TAGGED_ADDR_CTRL,
              PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC |
              (0xfffe << PR_MTE_TAG_SHIFT),
              0, 0, 0)) {
            perror("prctl() failed");
            return EXIT_FAILURE;
    }
    return 1;
}


char *mte_init(char *address) {
    #if 0
    printf(" _______________________\n");
    printf("|                       |\n");
    printf("|       MTE Init        |\n");
    printf("|_______________________|\n");

    printf("MTE-C Initialization\n");
    #endif
    
    int granule_size = get_granule(address);
    //Initial addr: %p\tsize: %lu\n", address, sizeof(address));

    unsigned long page_sz = sysconf(_SC_PAGESIZE);

    if (mte_enabled()) {
        //printf("MTE enabled\n");  
    } 
    else { 
        printf("MTE not enabled\n");  
        exit(1); 
    }

    if (mprotect((char *) ((uintptr_t) address & ~(uintptr_t) 0xfffUL), page_sz, PROT_READ | PROT_WRITE | PROT_MTE)) {
        perror("mprotect() failed");
        exit(1); 
    }
    
    address = __arm_mte_create_random_tag((char *)address, 0x0); 
    
    if (granule_size == 0) {
      __arm_mte_set_tag(address);
    } 
    else {
      //granule_size = 1;
      tag_granule(address, granule_size);
    }
    address = enc_init(address);
    //printf("Shroud initialized: %p\n", address);
    return address;
}


char *enc_init(char *address) {
  ut_table *enc_init_entry =  (ut_table *)malloc(sizeof(*enc_init_entry));
  uint64_t seed = gen_rand_key();
  enc_init_entry->key = address;
  enc_init_entry->val = seed;
  HASH_ADD_PTR(shroud_hash, key, enc_init_entry);
  address = (char *)enc_dec_ptr((uint64_t)address, seed); 
  ut_table *enc_entry =  (ut_table *)malloc(sizeof(*enc_entry));
  enc_entry->key = address;
  enc_entry->val = seed;
  HASH_ADD_PTR(shroud_hash, key, enc_entry);
  //printf("Encryption initialized: %p\n", address);
  return address;
}

char *mte_enc_dec(char *address) {
  #if 0
  printf(" _______________________\n");
  printf("|                       |\n");
  printf("|    MTE Enc / Dec      |\n");
  printf("|_______________________|\n");
  #endif
  //printf("Input: %p\n", address);
 
  ut_table *enc_dec_table; 
  enc_dec_check(address);
  HASH_FIND_PTR(shroud_hash, &address, enc_dec_table);
  if (enc_dec_table) {
    //printf("Found; key: %lu\n", enc_dec_table->val);
    address = (char *)enc_dec_ptr((uint64_t)address, (uint64_t)enc_dec_table->val);
  } 
  //printf("Enc/Dec: %p\n", address);
  return address;
}

char *mte_retag(char *address) {
  #if 0
  printf(" _________________\n");
  printf("|                 |\n");
  printf("|    MTE Retag    |\n");
  printf("|_________________|\n");
  #endif
  //printf("Current string: %s\n", address);
  address = __arm_mte_create_random_tag((char *)address, 0x0); // does this intrinsically include 'set tag' feature as well?
  __arm_mte_set_tag(address);
  address = enc_init(address);
  printf("MTE-C re-initialized: %p\n", address);
  return address;
}

char *mte_retag_scanf (char *address)
{
  #if 0
  printf(" _______________________\n");
  printf("|                       |\n");
  printf("|    MTE Retag Scanf    |\n");
  printf("|_______________________|\n");
  printf("Retagging pointer\n");
  #endif
  int granule_size = get_granule(address);
  printf("Input string: %s | Granule size: %d\n", address, granule_size);
  
  
  printf("Tag granule: %d\n", granule_size);
  address = (char*)__arm_mte_create_random_tag((char *)address, 0x0);
  //printf("%p\n", address);
  //__arm_mte_set_tag(address);
  tag_granule(address, granule_size);
 
  address = enc_init(address);
  printf("MTE-C scanf re-initialized: %p\n", address);
  return address;
}

void tag_granule (char *address, int len) {
  #if 0
  printf(" _______________________\n");
  printf("|                       |\n");
  printf("|      Tag Granule      |\n");
  printf("|_______________________|\n");
  #endif
  char *end_addr = address + (len * 16);
  //printf("Start: %p\tEnd: %p\n", address, end_addr);
  for (; address < end_addr; address += MTE_GRANULE_SIZE){
    //printf("Tagging\n");
    __arm_mte_set_tag (address);
  }
}

int get_granule(char *input_string) {
  int str_len = strlen(input_string);
  int str_len_remain = str_len % 16;
  int tag_granule = 1;
  if (str_len == 0) {
    tag_granule = 1;
  } 
  else if (str_len_remain == 0) {
    tag_granule = (str_len / 16);
  }
  else {
    tag_granule += (str_len / 16);
  }
  //printf("Granule: %d\n", tag_granule);
  return tag_granule;
}


void* untag_granule (char *address) {
  
  #if 0
  printf(" _______________________\n");
  printf("|                       |\n");
  printf("|    Untag Granule      |\n");
  printf("|_______________________|\n");
  #endif
  // untagging the pointer
  //int granule_size = 1;
  if (enc_dec_check(address)) {
    //printf("Encrypted\n");
    address = mte_enc_dec(address);
  }
  else {
    //printf("Not encrypted\n");
  }
  //address = mte_enc_dec(address);
  //printf("%p\n", address);
  int len = get_granule(address);
  //int len=1;
  //}

  //printf("length: %d %d\n", len, granule_size);
  address = (char *) ((uintptr_t) address & (~0ULL >> 8));
  char *end_addr = address + (len * 16);
  //printf("Start: %p\tEnd: %p\n", address, end_addr);
  for (; address < end_addr; address += MTE_GRANULE_SIZE){
    //printf("Untagging\n");
    __arm_mte_set_tag (address);
  }
  address -= (len * 16);
  //printf("Untagged: %p\n", address);
  return address;
}


void* only_untag_granule (char *address) {
  
  #if 1
  printf(" _______________________\n");
  printf("|                       |\n");
  printf("|  Only Untag Granule   |\n");
  printf("|_______________________|\n");
  #endif
  // untagging the pointer
  //int granule_size = 2;
  int len = get_granule(address);
  //int len=2;
  //}

  //printf("length: %d %d\n", len, granule_size);
  address = (char *) ((uintptr_t) address & (~0ULL >> 8));
  char *end_addr = address + (len * 16);
  printf("Start: %p\tEnd: %p\n", address, end_addr);
  for (; address < end_addr; address += MTE_GRANULE_SIZE){
    printf("Untagging\n");
    __arm_mte_set_tag (address);
  }
  address -= (len * 16);
  printf("Untagged: %p\n", address);
  return address;
}

char *debug_mte_init(char *address) {
  address = malloc(sizeof(char*));
  int granule_size = 0;
  unsigned long page_sz = sysconf(_SC_PAGESIZE);
  if (mte_enabled()) {
      //printf("MTE enabled\n");  
  } 
  else { 
      printf("MTE not enabled\n");  
      exit(1); 
  }
  
  if (mprotect((char *) ((uintptr_t) address & ~(uintptr_t) 0xfffUL), page_sz,PROT_READ | PROT_WRITE |  PROT_MTE)) { //
      perror("mprotect() failed");
      exit(1); 
  }
  address = __arm_mte_create_random_tag((char *)address, 0x0); 
  //address = debug_untag_granule(address);
  #if 1
  if (granule_size == 0) {
    __arm_mte_set_tag(address);
  } 
  else {
    //granule_size = 1;
    tag_granule(address, granule_size);
  }
  #endif
  address = enc_init(address);
  printf("Shroud initialized: %p\n", address);
  return address;
}


void* debug_untag_granule (char *address) {
  
  #if 0
  printf(" _______________________\n");
  printf("|                       |\n");
  printf("|    Untag Granule      |\n");
  printf("|_______________________|\n");
  #endif
  int len = 1;
  //}
  if (enc_dec_check(address)) {
    address = mte_enc_dec(address);
  }
  else {
    //printf("Not encrypted\n");
  }
  //printf("length: %d %d\n", len, granule_size);
  address = (char *) ((uintptr_t) address & (~0ULL >> 8));
  char *end_addr = address + (len * 16);
  printf("Start: %p\tEnd: %p\n", address, end_addr);
  for (; address < end_addr; address += MTE_GRANULE_SIZE){
    printf("Untagging\n");
    __arm_mte_set_tag (address);
  }
  address -= (len * 16);
  printf("Untagged: %p\n", address);
  return address;
}


char *debug_mte_retag(char *address) {
  #if 0
  printf(" _________________\n");
  printf("|                 |\n");
  printf("|    MTE Retag    |\n");
  printf("|_________________|\n");
  #endif
  //printf("Current string: %s\n", address);
  address = __arm_mte_create_random_tag((char *)address, 0x0); // does this intrinsically include 'set tag' feature as well?
  __arm_mte_set_tag(address);
  #if 0
  #endif
  address = enc_init(address);
  printf("MTE-C re-initialized: %p\n", address);
  return address;
}

char *debug_mte_enc_dec(char *address, char *str) {
  #if 0
  printf(" _______________________\n");
  printf("|                       |\n");
  printf("|    MTE Enc / Dec      |\n");
  printf("|_______________________|\n");
  #endif
  //printf("At instruction: %s\n", str);
  //printf("Input: %p\n", address);
  enc_dec_check(address);
  ut_table *enc_dec_table; 
  
  HASH_FIND_PTR(shroud_hash, &address, enc_dec_table);
  if (enc_dec_table) {
    //printf("Found; key: %lu\n", enc_dec_table->val);
    address = (char *)enc_dec_ptr((uint64_t)address, (uint64_t)enc_dec_table->val);
  } 
  
  //printf("Enc/Dec: %p\n", address);
  return address;
}

char *debug_fun(char *str) {
  #if 0
  printf(" _______________________\n");
  printf("|                       |\n");
  printf("|    Debug Function     |\n");
  printf("|_______________________|\n");
  #endif
  //printf("After instruction: %s\n", str);
  return 0;
}

void *inter_address(char *address) {
  char *tag_addr = (char*)((uintptr_t)address & (~0ULL << 56));
  address = (char *) ((uintptr_t) address & (~0ULL >> 8));
  ut_table *inter_entry =  (ut_table *)malloc(sizeof(*inter_entry));
  inter_entry->key = address;
  inter_entry->val = (uint64_t)tag_addr;
  HASH_ADD_PTR(shroud_hash, key, inter_entry);
  return address;
}


bool enc_dec_check(char *address) {
  //printf("%p\n", address);

  char *enc_addr = (char*)((uintptr_t)address & (~0ULL << 60));
  unsigned long long mask = (~0ULL << 60);
  unsigned long long mask_2 = (~0ULL << 56);
  unsigned long long mask_3 = (~0ULL << 52);
  unsigned long long mask_4 = mask_3 - mask_2;
  uintptr_t result = (uintptr_t)address & ((uintptr_t)mask_4);
  result += (uintptr_t)enc_addr;
  //printf("%p\n%p\n%p\n%p\n%p\n", mask, mask_2, mask_3, mask_4, result);
  //enc_addr = (char *) ((uintptr_t) enc_addr & (~0ULL << 8));
  //printf("checking bit: %p\n", result);
  if (result != (uintptr_t)NULL) {
    //printf("Encrypted\n");
    return true;
  }
  else {
    //printf("Not Encrypted\n");
    return false;
  }
}

void* untag_inter_granule (char *address) {
  #if 0
  printf(" _______________________\n");
  printf("|                       |\n");
  printf("|  Untag Inter Granule  |\n");
  printf("|_______________________|\n");
  #endif
  address = mte_enc_dec(address);
  int len = get_granule(address);
  //char *tag_addr = (char*)((uintptr_t)address & (~0ULL << 56));
  
  //address = (char *) ((uintptr_t) address & (~0ULL >> 8));
  address = inter_address(address);
  char *end_addr = address + (len * 16);
  printf("Start: %p\tEnd: %p\n", address, end_addr);
  for (; address < end_addr; address += MTE_GRANULE_SIZE){
    printf("Untagging\n");
    __arm_mte_set_tag (address);
  }
  address -= (len * 16);
  printf("Untagged: %p\n", address);

  return address;
}

char* inter_mte_retag (char *address) {
  #if 0
  printf(" _______________________\n");
  printf("|                       |\n");
  printf("|   Inter MTE Retag     |\n");
  printf("|_______________________|\n");
  #endif
  ut_table *inter_table;
  HASH_FIND_PTR(shroud_hash, &address, inter_table);
  char *tag_addr = NULL;
  if (inter_table) {
    
    tag_addr = (char *)inter_table->val;
    printf("Found: %p\n", tag_addr);
  } 
  address = (char*)((uintptr_t)address | (uintptr_t)tag_addr);
  printf("%p\n", address);
  return address;
}


char* inter_mte_retag_scanf (char *address)
{
  #if 0
  printf(" _______________________\n");
  printf("|                       |\n");
  printf("|    MTE Retag Scanf    |\n");
  printf("|_______________________|\n");
  printf("Retagging pointer\n");
  #endif
  int granule_size = get_granule(address);
  printf("Input string: %s | Granule size: %d\n", address, granule_size);
  
  
  printf("Tag granule: %d\n", granule_size);
  ut_table *inter_table;
  HASH_FIND_PTR(shroud_hash, &address, inter_table);
  char *tag_addr = NULL;
  if (inter_table) {
    
    tag_addr = (char *)inter_table->val;
    printf("Found: %p\n", tag_addr);
  } 
  address = (char*)((uintptr_t)address | (uintptr_t)tag_addr);
  tag_granule(address, granule_size);

  address = enc_init(address);
  printf("MTE-C scanf re-initialized: %p\n", address);

  return address;
}

void shroud_bench(char *address) {
  #if 0
  printf(" _______________________\n");
  printf("|                       |\n");
  printf("|    Shroud Bench       |\n");
  printf("|_______________________|\n");
  #endif
  ut_table *enc_dec_table;
  //printf("Input: %p\n", address);
  HASH_FIND_PTR(shroud_hash, &address, enc_dec_table);
  if (enc_dec_table) {
    //printf("Found; key: %lu\n", enc_dec_table->val);
    rand_key = enc_dec_table->val;
  } else {
    //printf("Not found\n");
  }
  int bench_count = 0001;
  printf("Benchmark: %d\n", bench_count);
  int bench_it = 0;
  while (bench_it < bench_count) {
    //printf("bench_it %d\n", bench_it);
    //printf("Enc/Dec\n");
    address = (char *)enc_dec_ptr((uint64_t)address, (uint64_t)rand_key);
    bench_it += 1;
  }
}