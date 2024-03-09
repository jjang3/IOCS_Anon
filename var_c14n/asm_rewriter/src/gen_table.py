import sys, getopt
import logging

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('main')

from pprint import pprint

fun_table_offsets       = dict()

def generate_table(dwarf_var_count, dwarf_fun_var_info, target_dir):
    # Offset to table offset set of the current working function
    offset_expr_to_table    = set()
    table_offset = 0
    
    # Variable that is going to be patched
    off_var_count = 0
    # Variable count to patch
    var_patch = 9999
    # Function count to patch
    fun_patch = 0
    # print("Total variables to patch: ", count)
    # exit()
    for fun_idx,fun in enumerate(dwarf_fun_var_info):
        if True: 
        # if fun_idx == 0: # This is used to debug specific function
            vars = dwarf_fun_var_info[fun]
            # print(fun)
            for var_idx, var in enumerate(vars):
                if True:
                # if var_idx == 4: #Not work: 1,4,5
                    #     print(var)
                    #     exit()
                    if var_idx < var_patch: #and var_idx != 5: # and var_idx == 6: # (and var_idx is used to debug)
                        if var.base_type == "DW_TAG_base_type":
                            if var.offset_expr != None:
                                offset_expr_to_table.add((var.offset_expr, table_offset))
                                table_offset += 8
                                off_var_count += 1
                        elif var.base_type == "DW_TAG_structure_type":
                            # Because structure is a variable type like how int is used
                            var_struct = var.struct
                            # result = any("DW_TAG_structure_type" in member.base_type for member in var_struct.member_list)
                            result = False
                            for member in var_struct.member_list:
                                if member.base_type != None:
                                    if member.base_type == "DW_TAG_structure_type":
                                        result = True
                                    # elif member.base_type == "DW_TAG_pointer_type":    
                                        # result = True
                            # If none of the struct members are structure, then it's fine
                            if not result:
                                for mem_idx, member in enumerate(var_struct.member_list):
                                    # Avoid double struct
                                    if True:
                                    # if (member.base_type != "DW_TAG_structure_type" and 
                                    #     member.base_type != "DW_TAG_array_type"): 
                                    #     None
                                        if True:
                                            # if mem_idx == 0:
                                            if (member.base_type != "DW_TAG_structure_type" and 
                                                member.base_type != "DW_TAG_array_type"): #  and member.base_type != "DW_TAG_pointer_type"
                                                if member.offset_expr != None:
                                                    offset_expr_to_table.add((member.offset_expr, table_offset))
                                                    table_offset += 8
                                                    off_var_count += 1
                        elif (var.base_type == "DW_TAG_typedef" and
                              var.struct == None):
                            if var.offset_expr != None:
                                offset_expr_to_table.add((var.offset_expr, table_offset))
                                table_offset += 8
                                off_var_count += 1
                        elif (var.base_type == "DW_TAG_array_type"):
                            if var.offset_expr != None:
                                offset_expr_to_table.add((var.offset_expr, table_offset))
                                table_offset += 8
                                off_var_count += 1
                        else:
                            # Currently skipping arrays and pointers
                            logger.error("Skipping: %s", var)
            fun_table_offsets[fun] = offset_expr_to_table.copy()
            offset_expr_to_table.clear()
        
    
    # print("Total function: ", len(dwarf_fun_var_info))
    # print("Total variables getting patched: ", off_var_count)
    # varlist = list()
    logger.info("Generating the table with variable count: %d", off_var_count)
    if off_var_count % 2 != 0 and off_var_count != 1:
        # This is to avoid malloc(): corrupted top size error, malloc needs to happen in mod 2
        off_var_count += 1
    # ptr = "%p\n".strip()    printf("%s", addr_%d);
    include_lib_flags="""
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
"""
    begin_table="""
void **table;
void __attribute__((constructor)) create_table()
{    
    table = malloc(sizeof(void*)*%d);\n
    if (!table) {
        perror("Failed to allocate memory for page table");
        exit(EXIT_FAILURE);
    }
    /*Pointer to shared memory region*/    
""" % (off_var_count) #(dwarf_var_count) #

    loop_table="""
    // Map each page
    for (int i = 0; i < %d; ++i) {
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
""" % (off_var_count) # (dwarf_var_count) 
#     count = 0
#     while count <= dwarf_var_count: # May need to make this <= in order to avoid mod 2 bug
#         varentry = "\tvoid *addr_%d;" % count
#         mmapentry = """
#     addr_%d = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_32BIT, -1, 0);     
#     if (addr_%d == MAP_FAILED) {     
#         fprintf(stderr, "mmap() failed\\n");     
#         exit(EXIT_FAILURE);
#     }
#     table[%d] = addr_%d;\n
# """ % (count, count, count, count) #  | MAP_32BIT
#         varlist.append((varentry, mmapentry))
#         count += 1

    end_table="""\t_writegsbase_u64((long long unsigned int)table);
}
void __attribute__((destructor)) cleanup_table() {
    // Unmap each page and free the table
    for (int i = 0; i < %d; ++i) {
        if (table[i]) {
            munmap(table[i], PAGE_SIZE);
        }
    }
    free(table);
}
""" % (off_var_count)# (dwarf_var_count) 
    table_file = open("%s/table.c" % target_dir, "w")
    table_file.write(include_lib_flags)
    table_file.write(begin_table)
    table_file.write(loop_table)
    # for item in varlist:
    #     table_file.write(item[0])
    #     table_file.write(item[1])
    table_file.write(end_table)
    table_file.close()
    logger.info("Based on offsets, generate offsets per respective variables")
    return fun_table_offsets
    # pprint(dwarf_fun_var_info, width=1)