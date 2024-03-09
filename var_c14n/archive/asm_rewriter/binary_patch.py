from __future__ import print_function
from inspect import stack
from math import sin
from pickle import FALSE
from tkinter import N
from termcolor import colored
from configparser import NoSectionError
from posixpath import basename
from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture, ArchitectureHook
from typing import NamedTuple
from typing import Optional
from enum import Enum
if (sys.version[0] == '2'):
    import Queue 
else:
    import queue as Queue
from collections import deque
import sys, getopt
import time
from pprint import pprint
import fileinput
from dataclasses import dataclass, field

from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser, DWARFExprOp
from elftools.dwarf.descriptions import (
    describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)
from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.callframe import (
    CallFrameInfo, CIE, FDE, instruction_name, CallFrameInstruction,
    RegisterRule, DecodedCallFrameTable, CFARule)
from elftools.dwarf.structs import DWARFStructs
from elftools.dwarf.descriptions import (describe_CFI_instructions,
    set_global_machine_arch)
from elftools.dwarf.enums import DW_EH_encoding_flags
import logging
import re
import shutil
from pathlib import Path

import taint_analysis

@dataclass(unsafe_hash = True)
class FileData:
    name: str = None
    asm_path: str = None
    obj_path: str = None
    fun_list: Optional[list] = None

# @dataclass
@dataclass(unsafe_hash = True)
class VarData:
    name: Optional[str] = None
    offset: str = None
    var_type: str = None    
    base_type: Optional[str] = None
    fun_name: str = None
    offset_expr: str = None

@dataclass(unsafe_hash = True)
class StructData:
    name: Optional[str] = None
    offset: str = None
    size: int = None
    line: int = None
    member_list: Optional[list] = None
    fun_name: str = None
    offset_expr: str = None

@dataclass(unsafe_hash = True)
class StructMember:
    name: str = None
    offset: str = None
    var_type: str = None
    base_type: Optional[str] = None
    begin: Optional[str] = None
    end: Optional[str] = None

@dataclass(unsafe_hash=True)
class FunData:
    name: str = None
    var_list: list[VarData] = None
    struct_list: list[StructData] = None

@dataclass(unsafe_hash=True)
class TargetData:
    type: Optional[set[str]] = None
    var_name: str = None
    member_name: Optional[str] = None


class PatchingInst:
    def __init__(self, inst_type, suffix, src, dest, ptr_op):#, struct_bool):
        self.inst_type = inst_type
        self.suffix = suffix
        self.src = src
        self.dest = dest
        self.ptr_op = ptr_op # This indicates whether ptr access is either src/dest 
        #self.struct = struct_bool # This indicates whether offset that is being accessed here is struct or not
    
    def inst_print(self):
        # print("Inst type: %s | Suffix: %s | Source: %s | Dest: %s" % (self.inst_type, self.suffix, self.src, self.dest))
        info = "Inst type: %s | Suffix: %s | Source: %s | Dest: %s | Ptr: %s" % (self.inst_type, self.suffix, self.src, self.dest, self.ptr_op)
        return info
    def inst_check(self, tgt_inst):
        # print(self.inst_print())
        # print(tgt_inst.inst_print())
        if (self.inst_type == tgt_inst.inst_type):
            if (self.suffix == tgt_inst.suffix):
                if (self.src == tgt_inst.src):
                    if (self.dest == tgt_inst.dest):
                        return True
                # else:
                #     print(self.src, tgt_inst.src)
                #     print(self.src == tgt_inst.src)
        else:
            # log.debug("%s %s %s %s", 
            #           self.inst_type == tgt_inst.inst_type,
            #           self.suffix == tgt_inst.suffix,
            #           self.src == tgt_inst.src,
            #           self.dest == tgt_inst.dest)
            return False
        

class BnNode:
    def __repr__(self):
        return self.__class__.__name__ 

class RegNode(BnNode):
    def __init__(self, value):
        self.value = value

class BnSSAOp(BnNode):
    def __init__(self, left, op, right):
        self.left = left
        self.op = op
        self.right = right

@dataclass(unsafe_hash=True)
class BnVarData:
    name: str = None
    dis_inst: str = None
    patch_inst: PatchingInst = None
    offset_expr: str = None
    asm_syntax_tree: BnSSAOp = None
    llil_inst: LowLevelILInstruction = None
    arg: bool = None # Whether this bn_var is used for argument or not

@dataclass(unsafe_hash=True)
class BnFunData:
    name: str = None
    begin: int = None
    end: int = None
    vars: list[BnVarData] = None
    

class CustomFormatter(logging.Formatter):

    # FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s | %(levelname)s"
    # logging.basicConfig(level=os.environ.get("LOGLEVEL", "DEBUG"), format=FORMAT)
    blue = "\x1b[33;34m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_green = "\x1b[42;1m"
    purp = "\x1b[38;5;13m"
    reset = "\x1b[0m"
    # format = "%(funcName)5s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    format = "[Line:%(lineno)4s -%(funcName)18s()] %(levelname)7s    %(message)s "

    FORMATS = {
        logging.DEBUG: yellow + format + reset,
        logging.INFO: blue + format + reset,
        logging.WARNING: purp + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_green + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
    
# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']
sys.path.insert(0, '/home/jaewon/binaryninja')
sys.path.insert(0, '/home/jaewon/ARCS_Final/useful_scripts')
import dwarf_analysis

fun_patch_tgts          = dict()
fun_table_offsets       = dict()

# This dict is for static function (numcompare (0 var): 0x658b vs numcompare (5 vars): 0x163ea)
fun_entry_to_args   = dict()


@dataclass(unsafe_hash=True)
class c14nVarData:
    name:           str = None
    offset_expr:    Optional[str] = None
    dis_insts:      Optional[list[str]] = field(default_factory=set, compare=False, hash=False)
    # List of disassembly instructions that use this
    exposure:       Optional[int] = None 
    # Number of times this variable is used in an instruction
    origin:         Optional[str] = "Local"
    # Is there an origin for this variable? (e.g., caller argument, local definition, etc)
    # Assume at first it's going to be local
    var_type:       Optional[str] = None
    arg_use:        Optional[bool] = False 
    # How is a variable used throughout the function, should I expand on this somehow?
    sec_sensitive:  Optional[bool] = False
    score:          Optional[int] = 0
    llil_insts:     Optional[list[LowLevelILInstruction]] = field(default_factory=set, compare=False, hash=False)
    
    def calc_c14n(self):
        # Initial score is 0
        aggregate_score = 0

        # Example: Add 10 points if the variable is security-sensitive
        if self.sec_sensitive:
            aggregate_score += 10

        # Use of the variable in arguments might increase its importance
        if self.arg_use:
            aggregate_score += 5

        # Add exposure points directly if available
        if self.exposure is not None:
            aggregate_score += self.exposure

        # Additional logic can be applied based on origin, var_type, etc.
        # For example, add points if the origin is not local
        if self.origin != "Local":
            aggregate_score += 3

        # Set the score
        self.score = aggregate_score
    
fun_var_dict    = dict()

        
def display_var(var: c14nVarData):
    log.info("Variable name: %s", var.name)
    log.debug("\tOffset: %s", var.offset_expr)
    log.debug("\tExposure num: %d", var.exposure)
    log.debug("\tUsed as an arg: %s", var.arg_use)
    log.debug("\tOrigin: %s", var.origin)
    log.debug("\tSecurity sensitive: %s", var.sec_sensitive)
    # pprint.pprint(var.dis_insts)
    print()

def update_var(**kwargs):
    log.info("Updating variable")
    for var in kwargs["set"]:
        if isinstance(var, c14nVarData):
            if var.name == kwargs["var_name"]:
                # log.debug("Found the variable")
                
                if kwargs.get("offset") is not None and var.offset_expr == None:
                    var.offset_expr = kwargs["offset"]
                
                if kwargs.get("var_type") is not None and var.var_type == None:
                    var.var_type = kwargs["var_type"]
                
                if kwargs.get("dis_inst") is not None:
                    var.exposure += 1
                    var.dis_insts.append(kwargs["dis_inst"])    
                    
                if kwargs.get("arg_use") is not None:
                    var.arg_use = kwargs["arg_use"]
                    
                if kwargs.get("origin") is not None:
                    var.origin = kwargs["origin"]
                    
                if kwargs.get("llil_inst") is not None:
                    var.llil_insts.append(kwargs["llil_inst"])

def find_call(inst):
    try:
        if inst.operation == LowLevelILOperation.LLIL_CALL:
            return inst
        if inst.operation == HighLevelILOperation.HLIL_CALL:
            return inst
        if inst.operation == LowLevelILOperation.LLIL_IF:
            inst = find_call(inst.hlil)
            if inst != None:
                return inst
        if inst.operation == HighLevelILOperation.HLIL_IF:
            inst = find_call(inst.operands[0].left)
            if inst != None:
                return inst
        inst = None
    except:
        return None
    

def c14n_analysis(bv: binaryninja.BinaryView, bn_fun: binaryninja.Function):
    log.info("Calc. c14n metric for the function: %s", bn_fun.name)
    gen_regs = {"%rax", "%rbx", "%rcx", "%rdx", "%rdi", "%rsi",
            "%eax", "%ebx", "%ecx", "%edx", "%edi", "%esi",
            "%ax",  "%bx",  "%cx",  "%dx"}
    arg_regs = {"%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9",
                "%ecx", "%edx", "%edi", "%esi"}
    sec_sen_funs = {'atoi', 'calloc', 'execve', 'fclose', 'fgetc', 'fopen',
                    'fread', 'free', 'freopen', 'fscanf', 'fwrite', 'getchar',
                    'gets', 'malloc', 'memcmp', 'memcpy', 'memset', 'popen',
                    'printf', 'realloc', 'scanf', 'snprintf', 'sprintf', 'sscanf',
                    'strcat', 'strcpy', 'strncat', 'strncpy', 'system',
                    '__isoc99_scanf', '__isoc99_printf', '__isoc99_sprintf'}
    
    var_set: set[c14nVarData] = set()
    
    bn = BinAnalysis(bv)
    fun_name = bn_fun.name
    call_insts = list()
    for var in bn_fun.vars:
        if (var.source_type == VariableSourceType.StackVariableSourceType and 
            "var" in var.name):
            # There are duplicate variable names (e.g., var_14 vs var_14_1), so we first create BnVarData for all names, then if they are empty
            # at the end, we will clean them up.
            new_var = c14nVarData(name=var.name, dis_insts=list(), exposure=0, var_type=var.type, llil_insts=list())
            # <TypeClass.IntegerTypeClass: 2>
            
            # This is used to find whether variable in this function is used or value is from security-sensitive functions
            
            for ref in bn_fun.get_hlil_var_refs(var):
                # Need to recursively check ref_inst to find call instruction
                ref_inst = bn_fun.get_low_level_il_at(ref.address)
                # for item in bv.get_code_refs_from(ref.address):
                #     print(hex(item))
                #     print(bv.get_disassembly(item))
                
                # print(bv.get_code_refs(ref.address).hlil)
                call_inst = find_call(ref_inst)
                try:
                    if (bn_fun.is_call_instruction(ref_inst.address)):
                        call_ref = bn_fun.get_llil_at(ref.address)
                        print(call_ref)
                        try:
                            call_fun_name = bv.get_function_at(call_ref.dest.constant).name
                            # log.debug(call_fun_name)
                            if call_fun_name in sec_sen_funs:
                                log.error("%s Security-sensitive fun detected", var)
                                new_var.sec_sensitive = True
                        except:
                            None
                    elif (call_inst.operation == HighLevelILOperation.HLIL_CALL and 
                        bn_fun.is_call_instruction(call_inst.address)):
                        call_ref = bn_fun.get_llil_at(call_inst.address)
                        print(call_ref)
                        try:
                            call_fun_name = bv.get_function_at(call_ref.dest.constant).name
                            # log.debug(call_fun_name)
                            if call_fun_name in sec_sen_funs:
                                log.error("%s Security-sensitive fun detected", var)
                                new_var.sec_sensitive = True
                        except:
                            None
                except:
                    log.error("NoneType")

            var_set.add(new_var)
    
    for callee_address in bn_fun.callee_addresses:
        callee_fun = bv.get_function_at(callee_address)
        print(callee_fun.name)
        
    # if False:
    if True:
        for llil_bb in bn_fun.low_level_il:
            # if bn_fun.name == "client_error": # debug
            if True:
            # This part analyzes the exposure count and calculates the offset for each bninja variable
                for llil_inst in llil_bb:
                    # This is going to be used to find definitions
                    dis_inst = bv.get_disassembly(llil_inst.address)
                    mapped_il = llil_inst.mapped_medium_level_il
                    if llil_inst.operation == LowLevelILOperation.LLIL_SET_REG:
                        if len(mapped_il.vars_read) > 0:
                            var_idx = None
                            result = any("var" in var.name for var in mapped_il.vars_read)
                            if result:
                                for idx, var in enumerate(mapped_il.vars_read):
                                    # This is needed as there are possibilities of diff var_idx for var_name
                                    if "var" in var.name:
                                        var_idx = idx
                            if result and var_idx != None:
                                dest_reg    = llil_inst.ssa_form.dest
                                dest_reg_name = None
                                try:
                                    if type(dest_reg) == binaryninja.lowlevelil.ILRegister:
                                        dest_reg_name = dest_reg.name
                                    elif type(dest_reg) == binaryninja.lowlevelil.SSARegister:
                                        dest_reg_name = dest_reg.reg.name
                                        
                                except Exception as err:
                                    log.error(err)
                                    log.warning("Not the target")
                                
                                temp_var = mapped_il.vars_read[var_idx]
                                var_name = temp_var.name
                                # log.debug(llil_inst.operation)
                                if dest_reg_name in gen_regs:
                                    offset_expr = None
                                    try:
                                        offset_expr = bn.calc_ssa_off_expr(llil_inst.ssa_form)
                                        update_var(set=var_set, var_name=var_name, 
                                                offset=offset_expr, dis_inst=dis_inst, llil_inst=llil_inst)
                                    except:
                                        log.error("Can't calculate offset")
                                        update_var(set=var_set, var_name=var_name, 
                                                offset=None, dis_inst=dis_inst, llil_inst=llil_inst)
                                if dest_reg_name in arg_regs:
                                    update_var(set=var_set, var_name=var_name, 
                                            arg_use=True)
                                    
                    elif llil_inst.operation == LowLevelILOperation.LLIL_STORE:
                        if len(mapped_il.vars_written) > 0:
                            result = any("var" in var.name for var in mapped_il.vars_written)
                            temp_var = mapped_il.vars_written[0]
                            var_name = temp_var.name
                            if result:
                                src_reg = llil_inst.ssa_form.src
                                src_reg_name = None
                                try:
                                    if type(src_reg) == binaryninja.lowlevelil.ILRegister:
                                        src_reg_name = src_reg.name
                                    elif type(src_reg) == binaryninja.lowlevelil.SSARegister:
                                        src_reg_name = src_reg.reg.name
                                    elif type(src_reg) == binaryninja.lowlevelil.LowLevelILRegSsaPartial:
                                        src_reg_name = src_reg.full_reg.reg.name
                                        
                                except Exception as err:
                                    log.error(err)
                                    log.warning("Not the target")
                                # log.debug(llil_inst.operation)
                                offset_expr = bn.calc_ssa_off_expr(llil_inst.ssa_form)
                                update_var(set=var_set, var_name=var_name, 
                                        offset=offset_expr, dis_inst=dis_inst, llil_inst=llil_inst)
                                if src_reg_name in arg_regs:
                                    update_var(set=var_set, var_name=var_name, 
                                            origin="Argument")
                    elif llil_inst.operation == LowLevelILOperation.LLIL_CALL:
                        call_fun = bv.get_function_at(llil_inst.dest.constant)
                        if call_fun.symbol.type is not SymbolType.ImportedFunctionSymbol:
                            # print(call_fun.symbol)
                            call_insts.append(llil_inst)
                        
                    else:
                        log.error("%s, %s", llil_inst, llil_inst.operation)
                        None
    # Compute the score
    to_remove = set()
    for var in var_set:
        if var.offset_expr == None:
            log.error("Removing: %s", var)
            to_remove.add(var)
        elif var.offset_expr != None:
            var.calc_c14n()
    # calc_c14n(var_set)
    # bin_analysis.custom_pprint(var_set)
    var_set.difference_update(to_remove)
    bn.fun_call_insts[fun_name] = call_insts.copy()
    call_insts.clear()
    
    return var_set

class SizeType(Enum):
    CHAR = 1
    INT = 4
    CHARPTR = 8
    
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
                        # elif (var.base_type == "DW_TAG_array_type"):
                        #     if var.offset_expr != None:
                        #         offset_expr_to_table.add((var.offset_expr, table_offset))
                        #         table_offset += 8
                        #         off_var_count += 1
                        else:
                            # Currently skipping arrays and pointers
                            log.error("Skipping: %s", var)
            fun_table_offsets[fun] = offset_expr_to_table.copy()
            offset_expr_to_table.clear()
        
    
    print("Total function: ", len(dwarf_fun_var_info))
    print("Total variables getting patched: ", off_var_count)
    # varlist = list()
    log.info("Generating the table %d", off_var_count)
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
    log.info("Based on offsets, generate offsets per respective variables")
    pprint(dwarf_fun_var_info, width=1)
    
    # if fun_idx == fun_patch:
    # pprint(fun_table_offsets["sequential_sort"], width=1)
        # break
    
def conv_expr(expr):
    print("Converting expression", expr)
    expr_pattern = r"(\b[a-z]+\b)([-|+])(.*)"
    fs_pattern = r"(\b[a-z]+\b):(.*)"
    expr_regex = re.search(expr_pattern, expr)
    fs_regex = re.search(fs_pattern, expr)
    new_expr = str()
    if expr_regex:
        new_expr = expr_regex.group(1) + expr_regex.group(2) + str(int(expr_regex.group(3), 16))
    elif fs_regex:
        new_expr = fs_regex.group(1) + ":" + str(int(fs_regex.group(2), 16))
    print("New expression: ", new_expr)
    return new_expr

# def conv_instr(instr, suffix=None):
#     match instr:
#         case "movzx":
#             if suffix == "byte ptr":
#                 return "movzb"
#             else:
#                 return instr
#     return instr
#, inst_type = None, dest_reg = None
def conv_suffix(suffix):
    print("Converting suffix %s", suffix)
    # reg_regex = r"(%e.x)"
    # if inst_type != None:
    #     if re.search(reg_regex, dest_reg):
    #         return "l"
    match suffix:
        case "byte ptr":
            return "b" # 8-bit
        case "word ptr":
            return "w" #16-bit
        case "dword ptr":
            return "l" # 32-bit
        case "qword ptr":
            return "q" # 64-bit
    
        
def conv_imm(imm):
    log.debug("Converting: %s", imm)
    arr_pattern = r"(-\d+)\((%\w+)(?:,(%\w+))?\)"
    arr_regex = re.search(arr_pattern, str(imm))
    imm_pattern = r"(\$)(0x.*)"
    imm_regex = re.search(imm_pattern, imm)
    new_imm = str()
    if imm_regex:
        offset = int(imm_regex.group(2), 16)
        if offset == 4294967295:
            offset = -1
        elif offset == 18446744073709551615:
            offset = -1
        elif offset == 4294967196:
            offset = -100
        elif offset == 4294967165:
            offset = -130
        elif offset == 4294967166:
            offset = -131
        # print(imm_regex.group(1))
        new_imm = imm_regex.group(1) + str(offset)
        return new_imm
    # elif arr_regex != None and arr_regex.group(3) != None:
    #     offset = arr_regex.group(1)
    #     new_imm = str(offset) + "(" + arr_regex.group(2) + "+" + arr_regex.group(3) + ")"
    #     return new_imm
    else:
        return imm
        
    
def process_argument(argv):
    inputfile = ''
    taintfile = ''
    dirloc = None
    funfile = None
    try:
        opts, args = getopt.getopt(argv,"hfic:",["binary=","taint=","dir=","fun="])
    except getopt.GetoptError:
        print ('binary_patch.py --binary <binary> --taint <dft.out> --dir <dir name> --fun <fun.list>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('binary_patch.py --binary <binary> --taint <dft.out> --dir <dir name> --fun <fun.list>')
            sys.exit()
        elif opt in ("-b", "--binary"):
            inputfile = arg
        elif opt in ("-f", "--fun"):
            funfile = arg
        elif opt in ("-t", "--taint"):
            taintfile = arg
        elif opt in ("-d", "--dir"):
            dirloc = arg
    process_binary(inputfile, taintfile, dirloc, funfile)

dwarf_fun_var_info  = dict()
bn_fun_var_info     = dict()

# Total number of variables from the DWARF analysis
dwarf_var_count = 0

# This list will contain all target variables
target_list = list()

# This list will contain all target files based on searching through all directories
target_files = list()

# This dict will have function -> fun_list relationship
file_fun = dict()
fun_list = list() # This list contains all functions analyzed per asm file

file_list = list()

patch_count = 0

def find_funs(file_list):
    fun_regex = re.compile(r'\t\.type\s+.*,\s*@function\n\b(^.[a-zA-Z_.\d]+)\s*:', re.MULTILINE)
    for file_item in file_list:
        if file_item.asm_path != None:
            # pprint(file_item)
            with open(file_item.asm_path, 'r') as asm_file:
                asm_string = asm_file.read()
                fun_names = fun_regex.findall(asm_string)
            for name in fun_names:
                fun_list.append(name)
            if file_item.fun_list == None:
                file_item.fun_list = fun_list.copy()
            fun_list.clear()

def visit_dir(dir_list):
    for root, dirs, files in os.walk(dir_list):
        # print(f"Current directory: {root}")
        
        # Print subdirectories
        # for dir_name in dirs:
        #     print(os.path.join(root, dir_name))

        # Print files
        for file_name in files:
            temp_file = None
            tgt_index = None
            base_name = os.path.splitext(os.path.basename(file_name))[0]
            for index, file_item in enumerate(file_list):
                if isinstance(file_item, FileData) and file_item.name == base_name:
                    tgt_index = index
            if tgt_index != None:
                temp_file = file_list[tgt_index]
            else:
                temp_file = FileData(base_name)

            if file_name.endswith(".s"):
                file_path = os.path.join(root, file_name)
                temp_file.asm_path = file_path
            elif file_name.endswith(".o"):
                file_path = os.path.join(root, file_name)
                temp_file.obj_path = file_path
                
            if temp_file != None and tgt_index == None:
                file_list.append(temp_file)
            # pprint(temp_file)

def gen_obj_file(filename):
    print(filename.asm_path, filename.obj_path)
    try:
        # Call GNU assembler with the source and destination file paths
        subprocess.run(['as', filename.asm_path, '-o', filename.obj_path], check=True)
        print(f"Assembly of {filename.asm_path} completed. Output in {filename.obj_path}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
    except FileNotFoundError:
        print("GNU assembler (as) not found. Please ensure it is installed and in your PATH.")

def process_binary(filename, taintfile, dirloc, funfile):
    global dwarf_var_count
    target_dir = None        
    target_file = None
    if dirloc != None:
        target_dir = Path(os.path.abspath(dirloc))
        visit_dir(target_dir)
    else:
        target_dir = Path(os.path.abspath(filename))
        target_dir = target_dir.parent.parent.joinpath("result", os.path.splitext((os.path.basename(filename)))[0])
        taint_file = target_dir.joinpath("dft.out")
        filename = target_dir.joinpath(os.path.splitext((os.path.basename(filename)))[0] + ".out")
        target_file = target_dir.joinpath(os.path.splitext((os.path.basename(filename)))[0] + ".s")
        
    funfile_list = None
    funfile_path = None
    if funfile != None:
        funfile_path = target_dir.joinpath(os.path.splitext((os.path.basename(funfile)))[0] + ".list")
        with open(funfile_path) as ff:
            for line in ff:
                # print(line)
                funfile_list = line.split(',')
    
    # print("File list:")
    find_funs(file_list)
    # pprint(file_list)
    
    
    # print("Function list:")
    # pprint(funfile_list, width=1)

    for file_item in file_list:
        if file_item.fun_list != None:
            file_fun_list = file_item.fun_list
            found = [element for element in funfile_list if element in file_fun_list]
            if found:
                # pprint(file_item)
                # for element in found:
                #     print(f"The item {element} is found in both lists.")
                target_files.append(file_item)
    
    # pprint(target_files)
    # exit()
    
    
    print("Analyzing: ", target_files)
    print(funfile_list)
    pprint(target_files)
    print(target_dir)
    patch_inst_file = target_dir.joinpath("insts.out")
    # exit()
    # time.sleep(1.5)
    funlist = list()
    if dirloc != None:
        for file_item in target_files:
            print(file_item)
            dwarf_output = dwarf_analysis.dwarf_analysis(file_item.obj_path)
            # pprint(dwarf_output)
            for fun in dwarf_output:
                if fun.name in funfile_list:
                    pprint(fun)
                    funlist.append(fun.name)
                    temp_var_count = fun.var_count
                    # pprint(fun)
                    # Make copy of var_list to make modification and copy it to dwarf_fun_var_info
                    temp_var_list = fun.var_list.copy()
                    dwarf_fun_var_info[fun.name] = temp_var_list.copy()
                    fun_entry_to_args[fun.begin] = temp_var_count
                    dwarf_var_count += temp_var_count
        print(dwarf_var_count)
        generate_table(dwarf_var_count, dwarf_fun_var_info, target_dir)
        for file_item in target_files:
            print("Binary ninja input:", file_item.obj_path)
            with load(file_item.obj_path.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
                arch = Architecture['x86_64']
                bn = BinAnalysis(bv)
                bn.analyze_binary(funlist)
            process_file(funlist, None, file_item)
            gen_obj_file(file_item)
        pprint(patch_inst_list)
        with open(patch_inst_file, 'w') as file:
            for patch_inst in patch_inst_list:
                file.write(patch_inst + '\n')
        log.critical("Patch count %d", patch_count)
                # print(fun)
        # for dir_file in dir_list:
        #     if (dir_file.endswith('.s')):
        #         process_file(funlist, target_dir, dir_file)
    else:
        # print(filename, funfile, target_dir)
        # --- DWARF analysis --- #
        dwarf_output = dwarf_analysis.dwarf_analysis(filename)
        # pprint(dwarf_output, width=1)
        for fun in dwarf_output:
            if funfile_list == None:
                # In this case, we will try to c14n all functions
                funlist.append(fun.name)
                temp_var_count = fun.var_count
                # Make copy of var_list to make modification and copy it to dwarf_fun_var_info
                temp_var_list = fun.var_list.copy()
                # Temporary disabled taint analysis information
                # for var in temp_var_list:
                    # target_vars = [(target.var_name, idx) for (idx,target) in enumerate(target_list)]
                    # # print(target_vars[0])
                    # for target_var in target_vars:
                    #     if target_var[0] == var.name:
                    #         # target_var[1] is an index
                    #         if var.struct is not None:
                    #             if var.struct.member_list is not None:
                    #                 for member in var.struct.member_list:
                    #                     if target_list[target_var[1]].member_name is member.name:
                    #                         None
                    #                     else:
                    #                         var.struct.member_list.remove(member)
                    #                         temp_var_count -= 1
                # pprint(temp_var_list, width=1)
                dwarf_fun_var_info[fun.name] = temp_var_list.copy()
                fun_entry_to_args[fun.begin] = temp_var_count
                dwarf_var_count += temp_var_count
            else:
                if fun.name in funfile_list:
                    funlist.append(fun.name)
                    temp_var_count = fun.var_count
                    # pprint(fun)
                    # Make copy of var_list to make modification and copy it to dwarf_fun_var_info
                    temp_var_list = fun.var_list.copy()
                    dwarf_fun_var_info[fun.name] = temp_var_list.copy()
                    fun_entry_to_args[fun.begin] = temp_var_count
                    dwarf_var_count += temp_var_count

        # pprint(dwarf_fun_var_info, width=1)
        # print(dwarf_var_count)

        # Based on variable counts and targets found by dwarf analysis, generate table.
        generate_table(dwarf_var_count, dwarf_fun_var_info, target_dir)

        pprint(dwarf_fun_var_info, width=1)
        # --- Binary Ninja Analysis --- #
        print("Binary ninja input:", filename)
        with load(filename.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
            # print("Here")                  
            arch = Architecture['x86_64']
            bn = BinAnalysis(bv)
            bn.analyze_binary(funlist)
        # process_file(funlist, target_dir, str(target_file))
        # pprint(patch_inst_list)
        # with open(patch_inst_file, 'w') as file:
        #     for patch_inst in patch_inst_list:
        #         file.write(patch_inst + '\n')
        # log.critical("Patch count %d", patch_count)

asm_macros = """# var_c14n macros
# Load effective address macro
.macro lea_gs dest, offset
\trdgsbase %r11
\tmov   \offset(%r11), %r11
\tlea   (%r11), \dest
.endm

.macro lea_store_gs src, offset
\tleaq  \src, %r11
\tmovq  (%r11), %r12
\trdgsbase %r11
\tmovq  \offset(%r11), %r11
\tmovq  %r12, (%r11)
.endm

# Data movement macros
.macro mov_store_gs src, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovb \src, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tmovw \src, (%r11)  # 16-bit
\t.elseif \\value == 32
\t\tmovl \src, (%r11)  # 32-bit
\t.elseif \\value == 64
\t\tmovq \src, (%r11)  # 64-bit
\t.endif
.endm

.macro mov_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovb (%r11), \dest  # 8-bit 
\t.elseif \\value == 16
\t\tmovw (%r11), \dest  # 16-bit
\t.elseif \\value == 32
\t\tmovl (%r11), \dest  # 32-bit
\t.elseif \\value == 64
\t\tmovq (%r11), \dest  # 64-bit
\t.endif
.endm

.macro mov_arr_store_gs src, offset, disp, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tadd \disp, %r11
\t.if \\value == 8
\t\tmovb \src, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tmovw \src, (%r11)  # 16-bit 
\t.elseif \\value == 32
\t\tmovl \src, (%r11)  # 32-bit 
\t.elseif \\value == 64
\t\tmovq \src, (%r11)  # 64-bit 
\t.endif
.endm

.macro mov_arr_load_gs src, offset, disp, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tadd \disp, %r11
\t.if \\value == 8
\t\tmovb (%r11), \dest  # 8-bit
\t.elseif \\value == 16
\t\tmovw (%r11), \dest  # 16-bit
\t.elseif \\value == 32
\t\tmovl (%r11), \dest  # 32-bit
\t.elseif \\value == 64
\t\tmovq (%r11), \dest  # 64-bit
\t.endif
.endm

.macro movss_store_gs src, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t\tmovss \src, (%r11)  # 64-bit
.endm

.macro movss_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tmovss (%r11), \dest  # 64-bit
.endm

.macro movzx_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovzbl (%r11), \dest  # 8-bit 
\t.elseif \\value == 16
\t\tmovzx (%r11), \dest  # 16-bit
\t.endif
.endm

# Comparison / Shift macros
# ---- Comparison ---- #
.macro cmp_store_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tcmpb \operand, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tcmpw \operand, (%r11)  # 16-bit
\t.elseif \\value == 32
\t\tcmpl \operand, (%r11)  # 32-bit
\t.elseif \\value == 64
\t\tcmpq \operand, (%r11)  # 64-bit
\t.endif
.endm

.macro cmp_load_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tcmpb (%r11), \operand  # 8-bit 
\t.elseif \\value == 16
\t\tcmpw (%r11), \operand  # 16-bit
\t.elseif \\value == 32
\t\tcmpl (%r11), \operand  # 32-bit
\t.elseif \\value == 64
\t\tcmpq (%r11), \operand  # 64-bit
\t.endif
.endm

.macro and_store_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tandb \operand, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tandw \operand, (%r11)  # 16-bit
\t.elseif \\value == 32
\t\tandl \operand, (%r11)  # 32-bit
\t.elseif \\value == 64
\t\tandq \operand, (%r11)  # 64-bit
\t.endif
.endm

.macro and_load_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tandb (%r11), \operand  # 8-bit 
\t.elseif \\value == 16
\t\tandw (%r11), \operand  # 16-bit
\t.elseif \\value == 32
\t\tandl (%r11), \operand  # 32-bit
\t.elseif \\value == 64
\t\tandq (%r11), \operand  # 64-bit
\t.endif
.endm

# Arithmetic macros
# ---- Addition ---- #
.macro add_store_gs operand, offset, value
\trdgsbase %r12
\tmov	\offset(%r12), %r12 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\tadd \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r12)
\t.elseif \\value == 16
\tadd \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r12)
\t.elseif \\value == 32
\tadd \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r12)
\t.elseif \\value == 64
\tadd \\operand, %r11   # 64-bit 
\tmov %r11, (%r12)
\t.endif
.endm

.macro add_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r11b
\tadd %r11b, \dest  # 8-bit 
\t.elseif \\value == 16
\tmov (%r11), %r11w
\tadd %r11w, \dest  # 16-bit 
\t.elseif \\value == 32
\tmov (%r11), %r11d
\tadd %r11d, \dest  # 32-bit 
\t.elseif \\value == 64
\tmov (%r11), %r11
\tadd %r11, \dest   # 64-bit 
\t.endif
.endm

# ---- Subtraction ---- #
.macro sub_store_gs operand, offset, value
\trdgsbase %r12
\tmov	\offset(%r12), %r12 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\tsub \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r12)
\t.elseif \\value == 16
\tsub \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r12)
\t.elseif \\value == 32
\tsub \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r12)
\t.elseif \\value == 64
\tsub \\operand, %r11   # 64-bit 
\tmov %r11, (%r12)
\t.endif
.endm

.macro sub_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r11b
\tsub %r11b, \dest  # 8-bit 
\t.elseif \\value == 16
\tmov (%r11), %r11w
\tsub %r11w, \dest  # 16-bit 
\t.elseif \\value == 32
\tmov (%r11), %r11d
\tsub %r11d, \dest  # 32-bit 
\t.elseif \\value == 64
\tmov (%r11), %r11
\tsub %r11, \dest   # 64-bit 
\t.endif
.endm

# ---- Multiplication ---- #
.macro imul_store_gs operand, offset, value
\trdgsbase %r12
\tmov	\offset(%r12), %r12 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\timul \\operand, %r13b  # 8-bit 
\tmov %r13b, (%r12)
\t.elseif \\value == 16
\timul \\operand, %r13w  # 16-bit 
\tmov %r13w, (%r12)
\t.elseif \\value == 32
\timul \\operand, %r13d  # 32-bit 
\tmov %r13d, (%r12)
\t.elseif \\value == 64
\timul \\operand, %r13   # 64-bit 
\tmov %r13, (%r12)
\t.endif
.endm

.macro imul_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r12b
\timul %r12b, \dest  # 8-bit 
\t.elseif \\value == 16
\tmov (%r11), %r12w
\timul %r12w, \dest  # 16-bit 
\t.elseif \\value == 32
\tmov (%r11), %r12d
\timul %r12d, \dest  # 32-bit 
\t.elseif \\value == 64
\tmov (%r11), %r12
\timul %r12, \dest   # 64-bit 
\t.endif
.endm

.macro shl_store_gs operand, offset, value
\trdgsbase %r12
\tmov	\offset(%r12), %r12 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\tshl \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r12)
\t.elseif \\value == 16
\tshl \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r12)
\t.elseif \\value == 32
\tshl \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r12)
\t.elseif \\value == 64
\tshl \\operand, %r11   # 64-bit 
\tmov %r11, (%r12)
\t.endif
.endm
"""

def traverse_ast(tgt_ast, bn_var_info, depth):
    # log.debug("Traversing the AST to patch")
    # parse_ast(tgt_ast)
    # print("Depth = ", depth)
    
    if repr(tgt_ast.right) == 'BnSSAOp':
        return traverse_ast(tgt_ast.right, bn_var_info, depth+1)
                        
    if repr(tgt_ast.left) == 'RegNode' and depth != 0:
        for var in bn_var_info:
            var_ast = var.asm_syntax_tree
            try:
                if var_ast.left.value == tgt_ast.left.value:
                    # print("Found", tgt_ast.left.value)
                    return var
            except Exception as err:
                None
    else:
        return None
    
# This list will contain lea_store_gs insts that will be used to update the value after reference returns
lea_list = list()
patch_inst_list = list()

def patch_inst(dis_inst, temp_inst: PatchingInst, bn_var, bn_var_info: list, tgt_offset, dwarf_var_info, offset_targets: set):
    log.critical("Patch the instruction %s | Offset: %d", dis_inst, tgt_offset)
    # parse_ast(bn_var.asm_syntax_tree)
    off_regex       = r"(-|\$|)(-?[0-9].*\(%r..*\))"
    array_regex = r"(-\d+)\((%\w+)(?:\+(%\w+))?\)"
    #offset_expr_regex = r'(\-[0-9].*)\((.*)\)'
    offset_expr_regex = r'(-[0-9]+)\((%rbp)(,%r[a-d]x)?\)'
    store_or_load   = str()
    if re.search(off_regex, bn_var.patch_inst.src):
        store_or_load = "load"
    elif re.search(off_regex, bn_var.patch_inst.dest):
        store_or_load = "store"

    arr_regex = None
    # print(bn_var.patch_inst.dest)
    if store_or_load == "load":
        arr_regex = re.search(array_regex, bn_var.patch_inst.src)
    elif store_or_load == "store":
        arr_regex = re.search(array_regex, bn_var.patch_inst.dest)
        
    tgt_ast = bn_var.asm_syntax_tree
    # print(bn_var, store_or_load)
    line = None
    patch_inst_line = None
    # print(bn_var.patch_inst.inst_print())
    
    ssa_var = traverse_ast(tgt_ast, bn_var_info, 0)
    if ssa_var != None:
        # Found SSA register    
        if ssa_var.patch_inst.inst_type == "lea":
            new_inst_type = "lea_gs"
            log.info("Patching with lea_gs w/ base obj")
            line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d" % 
                        (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, temp_inst.dest, tgt_offset)
            # log.debug(temp_inst.inst_print())
            # log.debug(bn_var)
    else:
        if bn_var.patch_inst.inst_type == "lea":
            new_inst_type = "lea_gs"
            log.info("Patching with lea_gs w/o base obj")
            # If there is no stack offset being set as a value, we cannot use the LEA_GS for such case
            for var_item in bn_var_info:
                # print(bn_var)
                if var_item.offset_expr == temp_inst.dest:
                    if repr(var_item.asm_syntax_tree.left) == 'BnSSAOp':
                        # If left is a stack offset, extract the offset value and check whether it is being set
                        offset_num = var_item.asm_syntax_tree.left.right.value
                        offset_reg = re.search(offset_expr_regex, var_item.offset_expr)
                        base_offset = offset_reg.group(1)
                        array_indx  = offset_reg.group(3)
                        if array_indx != None:
                            log.critical("Array found")
                        if offset_num == base_offset:
                            # If stack offset is set before, then it is safe to use the new macro
                            line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d" % 
                            (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
                            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, temp_inst.dest, tgt_offset)
                else:
                    # Else, we need to use the original stack offset.
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t#%s\t%s, %d" % 
                            (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, temp_inst.dest, tgt_offset)
                    
            # line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d" % 
            #             (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
    # log.debug(bn_var)
    if bn_var.arg == True and bn_var.patch_inst.inst_type != "lea":
        return dis_inst
    elif bn_var.arg == True and bn_var.patch_inst.inst_type == "lea":
        log.debug("Here")
        new_inst_type = "lea_store_gs" 
        line = ""
        for var in dwarf_var_info:
            if var.offset_expr == bn_var.offset_expr:
                # Found that base struct object is being passed as an argument, need to lea_store_gs all the members as well
                log.error("Found struct object")
                if var.struct != None:
                    for member in var.struct.member_list:
                        # log.debug(offset_targets)
                        offset_value = 0
                        for offset in offset_targets:
                            if offset[0] == member.offset_expr:
                                offset_value = offset[1]
                        if offset_value != None and member.offset_expr != None:
                            line = "\t%s\t%s, %d\n" % (new_inst_type, member.offset_expr, offset_value)
                            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, member.offset_expr, offset_value)
                        
                        if line != "" and line not in lea_list:
                            lea_list.append(line)
                            patch_inst_list.append(patch_inst_line)
        if line == "" and bn_var.offset_expr != None:
            line = "\t%s\t%s, %d\n" % (new_inst_type, bn_var.offset_expr, tgt_offset)
            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, bn_var.offset_expr, tgt_offset)
            if line != "" and line not in lea_list:
                lea_list.append(line)
                patch_inst_list.append(patch_inst_line)
        log.debug(bn_var)
        log.debug(lea_list)
        return dis_inst

    if line == None:
        # If line is None by now, it means patching without any context register
        value = 0
        if bn_var.patch_inst.suffix == "b":
            value = 8
        elif bn_var.patch_inst.suffix == "w":
            value = 16
        elif bn_var.patch_inst.suffix == "l":
            value = 32
        elif bn_var.patch_inst.suffix == "q":
            value = 64
        # Only store should comment out macro to update value, loading value should be from the page
        if bn_var.patch_inst.inst_type == "mov":
            log.debug(store_or_load)
            # if arr_regex != None and arr_regex.group(3) == None: # Disabling array support due to challenge of not being able to update specific array value
            log.info("Patching with mov_gs")
            if arr_regex != None and arr_regex.group(3) != None:
                log.info("Patching with mov_arr_gs")
                if store_or_load == "store":
                    new_inst_type = "mov_arr_store_gs"
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %s, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, arr_regex.group(3), value), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d, %s, %d" % (new_inst_type, temp_inst.src, tgt_offset, arr_regex.group(3), value)
                elif store_or_load == "load":
                    new_inst_type = "mov_arr_load_gs"
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %s, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, arr_regex.group(3), value), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d, %s, %d" % (new_inst_type, temp_inst.dest, tgt_offset, arr_regex.group(3), value)
            else:
                if store_or_load == "store":
                    new_inst_type = "mov_store_gs"
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
                elif store_or_load == "load":
                    new_inst_type = "mov_load_gs"
                    log.debug(bn_var)
                    for var in dwarf_var_info:
                        if var.offset_expr == bn_var.offset_expr:
                            # Found that base struct object is being copied into a value, then, just load stack offset
                            if var.struct != None:
                                log.error("Found struct object")
                                line = re.sub(r"(\b[a-z]+\b).*", "%s\t#%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
                            else:
                                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
                    if line == None:
                        line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                        patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "movss":
            if store_or_load == "store":
                new_inst_type = "movss_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "movss_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "movzx":
            log.info("Patching with movzx_gs")
            if store_or_load == "store":
                new_inst_type = "movzx_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "movzx_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "add":
            log.info("Patching with add_gs")
            if store_or_load == "store":
                new_inst_type = "add_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "add_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "sub":
            log.info("Patching with sub_gs")
            if store_or_load == "store":
                new_inst_type = "sub_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "sub_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "imul": # Signed multiply (two's comp arith)
            log.info("Patching with imul_gs")
            if store_or_load == "store":
                new_inst_type = "imul_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "imul_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "shl": # shift left
            log.info("Patching with shl_gs")
            if store_or_load == "store":
                new_inst_type = "shl_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "shl_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "cmp":
            log.info("Patching with cmp_gs")
            if store_or_load == "store":
                new_inst_type = "cmp_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "cmp_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "and":
            log.info("Patching with and_gs")
            if store_or_load == "store":
                new_inst_type = "and_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "and_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
            
    if line != None:
        patch_inst_list.append(patch_inst_line)
        return line

def remove_duplicate_lines(lines):
    """
    Remove duplicate lines from a list while preserving the order.
    
    :param lines: List of lines (strings)
    :return: List of lines with duplicates removed
    """
    seen = set()
    result = []
    for line in lines:
        if line not in seen:
            result.append(line)
            seen.add(line)
    return result
  
def process_file(funlist, target_dir, target_file):
    global patch_count
    file_path = None
    if target_dir != None:
        # This is for a single binary c14n. 
        file_path = os.path.join(target_dir, target_file)
        print(file_path)
        debug_file = target_file + ".bak"
        if os.path.isfile(os.path.join(target_dir, debug_file)):
            print("Copying debug file")
            shutil.copyfile(os.path.join(target_dir, debug_file), os.path.join(target_dir, target_file))
        else:
            print("No debug file exists")
    elif target_dir == None:
        # This is for a binary with multiple object files and they are in their own separate location
        file_path = target_file.asm_path
        file_path_dir = os.path.dirname(file_path)
        debug_file = file_path + ".bak"
        if os.path.isfile(debug_file):
            print("Copying debug file")
            shutil.copyfile(debug_file, file_path)
            time.sleep(2)
        else:
            print("No debug file exists")
        # print(file_path, file_path_dir, debug_file)
        # exit()
        
    
    debug = False
    with fileinput.input(file_path, 
                            inplace=(not debug), encoding="utf-8", backup='.bak') as f:
        file_pattern = re.compile(r'\.file\s+"([^"]+)"')
        fun_begin_regex = r'(?<=.type\t)(.*)(?=,\s@function)'
        fun_end_regex   = r'(\t.cfi_endproc)'
        
        dis_line_regex = r'(mov|movz|lea|sub|add|cmp|sal|and|imul|call|movss)([l|b|w|q|bl|xw|wl]*)\s+(\S+)(?:,\s*(\S+))?(?:,\s*(\S+))?\n'
        # sing_line_regex = r'\t(div)([a-z]*)\t(.*)'
        check = False
        currFun = str()
        patch_targets = list()
        offset_targets = list()
        struct_targets = set()
        
        for line in f:
            if file_pattern.findall(line): #.startswith('\t.file\t"%s.c"' % target_file.rsplit('.', maxsplit=1)[0]):
                print(asm_macros, end='')
            fun_begin = re.search(fun_begin_regex, line)
            if fun_begin is not None:
                if fun_begin.group(1) in funlist:
                    currFun = fun_begin.group(1)
                    log.warning(currFun)
                    try:
                        dwarf_var_info   = dwarf_fun_var_info[currFun]
                        bninja_info     = bn_fun_var_info[currFun]
                        offset_targets  = fun_table_offsets[currFun]
                        check = True
                    except Exception as err:
                        log.error("Skipping", type(err))
                        check = False
                    if debug:
                        # if currFun != "sort": # Debug
                        #     check = False
                        # else:
                        #     check = True
                        None
                        pprint(dwarf_var_info, width = 1)
                        pprint(bninja_info, width = 1)
                        pprint(offset_targets, width = 1)
                    else:
                        if offset_targets != None:
                            for tgt in offset_targets:
                                log.warning(tgt)
            fun_end = re.search(fun_end_regex, line)
            if fun_end is not None:
                lea_list.clear() # Clear the lea_list per function and also after rewriting the call instruction
                check = False
                dwarf_var_info = None
                bninja_info = None
                offset_targets = None
        
            if check == True:
                # dis_line = line.rstrip('\n')
                dis_line = line
                # mnemonic source, destination AT&T
                log.debug(dis_line)
                dis_regex   = re.search(dis_line_regex, dis_line)
                if dis_regex is not None:
                    inst_type   = dis_regex.group(1)
                    suffix      = dis_regex.group(2)
                    src         = dis_regex.group(3)
                    dest        = dis_regex.group(4)
                    # temp_inst = PatchingInst(conv_instr(inst_type), src, dest, expr, suffix)
                    log.debug("%s %s %s %s", inst_type, suffix, src, dest)
                    # Need to convert movzbl and movzxw to movzx + suffix (b or w)
                    if inst_type == "movz":
                        inst_type = "movzx"
                    elif inst_type == "call" and len(lea_list) > 0:
                        uniq_lea_list = remove_duplicate_lines(lea_list)
                        log.critical("Patch the instruction %s", dis_line)
                        lea_set_line = ""
                        for lea_inst in uniq_lea_list:
                            lea_set_line += lea_inst
                            patch_count += 1
                        # print(lea_set_line)
                        new_inst = re.sub(r"(\b[a-z]+\b).*", "%s%s" % (dis_line, lea_set_line), dis_line)
                        # Clear the list once your done patching
                        if new_inst != None:
                            print(new_inst, end='')
                        else:
                            print(line, end='')
                        lea_list.clear()
                        uniq_lea_list.clear()
                        continue
                        
                    if suffix == "bl":
                        suffix = "b"
                    elif suffix == "xw" or suffix == "wl":
                        suffix = "w"
                    
                    if dest != None:
                        temp_inst = PatchingInst(inst_type=inst_type, suffix=suffix,
                                                    dest=conv_imm(dest), src=conv_imm(src), ptr_op="")
                    else:
                        # For a single operand assembly instruction (e.g., salq)
                        if inst_type == "sal":
                            temp_inst = PatchingInst(inst_type="shl", suffix=suffix,
                                                    dest=conv_imm(src), src="$1", ptr_op="")
                        
                    if debug:
                        log.warning(temp_inst.inst_print())
                        if src != None:
                            for offset in offset_targets:
                                if conv_imm(src) == offset[0]:
                                    # log.warning(temp_inst.inst_print())
                                    log.warning("Debug found")
                        if dest != None:
                            for offset in offset_targets:
                                if conv_imm(dest) == offset[0]:
                                    # log.warning(temp_inst.inst_print())
                                    log.warning("Debug found")
                    new_inst = None
                    for idx, bn_var in enumerate(bninja_info):
                        # log.warning(bn_var.patch_inst.inst_print())
                        if debug:
                            log.warning(temp_inst.inst_print())
                            log.warning(bn_var.offset_expr)
                            log.warning(bn_var.patch_inst.inst_print())
                            None
                        if temp_inst.inst_check(bn_var.patch_inst):
                            # print("Found\n", temp_inst.inst_print(), "\n", bn_var.patch_inst.inst_print())
                            offset_expr = bn_var.offset_expr
                            offset_regex = r"(-\d+)\((%\w+)(?:,(%\w+))?\)"
                            offset_search = re.search(offset_regex, str(offset_expr))
                            if offset_search and offset_search.group(3) != None:
                                log.error("Fix offset")
                                offset = offset_search.group(1)
                                new_offset = str(offset) + "(" + offset_search.group(2) + ")"
                                offset_expr = new_offset
                            for offset in offset_targets:
                                if offset_expr == offset[0]:
                                    # Found the offset target; need to patch this instruction
                                    log.warning("Offset found")
                                    log.warning(bn_var)
                                    new_inst = patch_inst(dis_line, temp_inst, bn_var, bninja_info, offset[1], dwarf_var_info, offset_targets)
                                    # bninja_info.pop(idx) # problem: for all patch, i'm popping rdx
                                    if new_inst != None:
                                        # log.debug("\n%s",new_inst)
                                        break
                                    else:
                                        # Exit out of entire script if we find a missing instruction
                                        import signal
                                        log.error(temp_inst.inst_print())
                                        os.kill(os.getppid(),signal.SIGTERM)
                                        sys.exit(2)
                            else:
                                continue
                            break
                        # print("Here")
                            # if offset_expr in 
                            # parse_ast(bn_var.asm_syntax_tree)
                    if new_inst != None:
                        patch_count += 1
                        log.debug("\n%s",new_inst)
                        print(new_inst, end='')
                    else:
                        if debug != True:
                            print(line, end='')
                        None
                else:
                    if debug != True:
                        print(line, end='')
                    None
            else:
                if debug != True:
                    print(line, end='')
                None
                
        # if target_dir != None:
        #     log.critical("Patch count %d", patch_count)
                                
# Debug options here
debug_level = logging.DEBUG
ch = logging.StreamHandler()
ch.setLevel(debug_level) 
ch.setFormatter(CustomFormatter())

log = logging.getLogger(__name__)
log.setLevel(debug_level)

# create console handler with a higher log level
log_disable = False
log.addHandler(ch)
log.disabled = log_disable

spec_log = logging.getLogger('speclogger')
spec_log.addHandler(ch)
spec_log.setLevel(logging.DEBUG)
spec_log.disabled = (not log_disable)


def parse_ast(ast, depth=0):
    if repr(ast) == 'BnSSAOp':
        parse_ast(ast.left)
        print(ast.op)
        parse_ast(ast.right)
    elif repr(ast) == 'RegNode':
        print(ast.value)
    
        
class BinAnalysis:
    # Binary ninja variable list; list is used to make it stack and remove instructions in orderily fashion
    bn_var_list      = list()
    fun_call_insts      = dict()
    
    def find_ssa_reg(self, ssa_form, llil_insts, mlil_fun):
        log.info("Finding the SSA register among LLIL insts for %s", ssa_form)
        for addr in llil_insts:
            llil_inst = llil_insts[addr]
            # try:
            #     print(llil_inst, mlil_fun.get_ssa_var_uses(llil_inst.mapped_medium_level_il.ssa_form.src))
            # except:
            #     None
            # log.debug(llil_inst.ssa_form)
    
    def get_ssa_reg(self, inst_ssa):
        arrow = 'U+21B3'
        log.info("Getting the SSA register of %s %s", inst_ssa, type(inst_ssa)) 
        if type(inst_ssa) == binaryninja.lowlevelil.SSARegister:
            return inst_ssa
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsa:
            return self.get_ssa_reg(inst_ssa.src)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsaPartial:
            return self.get_ssa_reg(inst_ssa.full_reg)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            log.debug("%s LoadReg", chr(int(arrow[2:], 16)))
            return inst_ssa
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILZx:
            return self.get_ssa_reg(inst_ssa.src.full_reg)
        elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
            # this is where we should handle %rax#3 + 4 case;
            return self.get_ssa_reg(inst_ssa.left.src)
            # return inst_ssa
        else:
            print(inst_ssa.__class__.__bases__)
    
    def calc_ssa_off_expr(self, inst_ssa):
        # This is for binary ninja diassembly
        arrow = 'U+21B3'
        log.info("Calculating the offset of %s %s", inst_ssa, type(inst_ssa)) 
        offset_expr_regex = r'(\-[0-9].*)\((.*)\)'
        # try:
        if type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            log.debug("%s LoadReg", chr(int(arrow[2:], 16)))
            mapped_MLLIL = inst_ssa.mapped_medium_level_il # This is done to get the var (or find if not)
            if mapped_MLLIL != None:
                result = self.calc_ssa_off_expr(inst_ssa.src)
                if result != None:
                    return result
            else:
                log.error("No variable assigned, skip")
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILStoreSsa:
            log.debug("%s StoreSSA",  chr(int(arrow[2:], 16)))
            result = self.calc_ssa_off_expr(inst_ssa.dest)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsa:
            log.debug("%s SetRegSSA",  chr(int(arrow[2:], 16)))
            result = self.calc_ssa_off_expr(inst_ssa.src)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsaPartial:
            log.debug("%s SetRegSSAPartial",  chr(int(arrow[2:], 16)))
            # reg_def = llil_fun.get_ssa_reg_definition(llil_inst.full_reg)
            result = self.calc_ssa_off_expr(inst_ssa.src)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILZx:
            log.debug("%s ZeroExtendSSA",  chr(int(arrow[2:], 16)))
            result = self.calc_ssa_off_expr(inst_ssa.src)
            if result != None:
                return result
        elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
            log.debug("%s Arithmetic",  chr(int(arrow[2:], 16)))
            try:
                # Expression
                reg = inst_ssa.left.src
            except:
                # Single register
                reg = inst_ssa.left
            
            base_offset = 0
            base_reg = None
            for bn_var in self.bn_var_list:
                ast = bn_var.asm_syntax_tree
                # print(ast, bn_var.patch_inst.inst_print())
                if ast != None:
                    # If AST is none, his means that SSA register is not yet available
                    if repr(ast.left) == 'RegNode':
                        # If this is just a register node (e.g., rcx#3)
                        if reg == ast.left.value:
                            # base_offset = int(bn_var.offset)
                            offset_reg = re.search(offset_expr_regex, bn_var.offset_expr)
                            if offset_reg:
                                base_offset = offset_reg.group(1)
                                base_reg = offset_reg.group(2)
            # print(type(inst_ssa.right) )
            if base_reg is not None and type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILLoadSsa:
                offset = self.calc_ssa_off_expr(inst_ssa.right)
                expr = offset
            elif base_reg is not None:
                # print("Here 2")
                try:
                    offset = str(int(inst_ssa.right.__str__(), base=16) + int(base_offset))
                    expr = offset + "(" + base_reg + ")"
                except:
                    # %rdx#9 + %rax#12
                    expr = "(" + inst_ssa.left.__str__() + "," + inst_ssa.right.__str__() + ")"
            # need to hanlde %rax#33.%eax - [%rbp#1 - 4 {var_c_1}].d case
            elif type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILLoadSsa:
                # print("Here 3")
                offset = self.calc_ssa_off_expr(inst_ssa.right)
                expr = offset
            elif (binaryninja.commonil.Arithmetic in inst_ssa.left.__class__.__bases__ and 
                  type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILConst):
                print("Array access found")
                base_reg    = inst_ssa.left.left.src.reg.__str__()
                array_reg   = inst_ssa.left.right.src.reg.__str__()
                offset      = inst_ssa.right.constant
                expr = str(offset) + "(" + base_reg + "," + array_reg + ")"
            else:
                # print(inst_ssa.right, type(inst_ssa.right))
                offset = str(int(inst_ssa.right.__str__(), base=16))
                expr = offset + "(" + reg.reg.__str__() + ")"
            
            log.debug(expr)
            return expr
    
    def gen_ast(self, llil_fun, llil_inst, asm_inst = None):
        # log.info("Generating AST")
        # try:
        #     if hex(llil_inst.address) == "0x11b7":
        #         print(llil_inst, llil_inst.operation)
        # except:
        #     None
        if asm_inst == None:
            if type(llil_inst) == binaryninja.lowlevelil.SSARegister:
                # Register
                reg_def = llil_fun.get_ssa_reg_definition(llil_inst)
                if reg_def != None:
                    try:
                        # Try to find whether we are dealing with global variable
                        if type(reg_def.src) == binaryninja.lowlevelil.LowLevelILConstPtr:
                            log.error("Global")
                            return None
                        else:
                            node = RegNode(llil_inst)
                            return node
                    except:
                        # If not successful, just create a node based on the instruction
                        node = RegNode(llil_inst)
                        return node    
                else:
                    node = RegNode(llil_inst)
                    return node
            elif type(llil_inst) == binaryninja.lowlevelil.ILRegister:
                node = RegNode(llil_inst)
                return node
            elif type(llil_inst) == binaryninja.lowlevelil.LowLevelILConst:
                # Const value
                node = RegNode(llil_inst.constant)
                return node
            elif type(llil_inst) == binaryninja.lowlevelil.LowLevelILRegSsa:
                # Register SSA expr
                node = self.gen_ast(llil_fun, llil_inst.src)
                return node
            elif type(llil_inst) == binaryninja.lowlevelil.LowLevelILRegSsaPartial:
                log.debug("RegisterSSAPartial")
                reg_def = llil_fun.get_ssa_reg_definition(llil_inst.full_reg)
                if reg_def != None:
                    try:
                        # Try to find whether we are dealing with global variable
                        # log.debug("Reg ref %s", reg_def)
                        if type(reg_def.src) == binaryninja.lowlevelil.LowLevelILConstPtr:
                            log.error("Global")
                            return None
                        else:
                            # for the case of %rcx#1.%ecx, we just return rcx#1 
                            node = RegNode(llil_inst.full_reg)
                            return node   
                    except:
                        # If not successful, just create a node based on the instruction
                        node = RegNode(llil_inst)
                        return node    
            elif type(llil_inst) == binaryninja.lowlevelil.LowLevelILLoadSsa:
                # [%rbp#1 - 0x210 {var_218}].q @ mem#5
                right = self.gen_ast(llil_fun, llil_inst.src)
                sub_node = BnSSAOp(None, llil_inst.operation, right)
                return sub_node
            elif type(llil_inst) == binaryninja.lowlevelil.LowLevelILZx:
                # zx.q([%rbp#1 - 8 {var_10}].d @ mem#5)
                right = self.gen_ast(llil_fun, llil_inst.src)
                sub_node = BnSSAOp(None, llil_inst.operation, right)
                return sub_node
            elif type(llil_inst) == binaryninja.lowlevelil.LowLevelILLowPart:
                right = self.gen_ast(llil_fun, llil_inst.src)
                sub_node = BnSSAOp(None, llil_inst.operation, right)
                return sub_node
            elif binaryninja.commonil.Arithmetic in llil_inst.__class__.__bases__:
                # Arithmetic operation
                log.debug("%s Arithmetic",  llil_inst)
                # .src is used to get SSARegister
                left = self.gen_ast(llil_fun, llil_inst.left) 
                right = self.gen_ast(llil_fun, llil_inst.right)
                sub_node = BnSSAOp(left, llil_inst.operation, right)
                return sub_node
            inst_ssa = llil_inst.ssa_form
            log.debug(inst_ssa)
            if inst_ssa.operation == LowLevelILOperation.LLIL_SET_REG_SSA:
                # SET_REG_SSA means setting up the reg value, create a first tree based on this info
                left = self.gen_ast(llil_fun, inst_ssa.dest) 
                right = self.gen_ast(llil_fun, inst_ssa.src)
                root_node = BnSSAOp(left, "=", right)
                # self.parse_ast(root_node)
                # log.debug("%s %s %s", self.parse_nodes(root_node.left), root_node.op, root_node.right)
                return root_node
            if inst_ssa.operation == LowLevelILOperation.LLIL_SET_REG_SSA_PARTIAL:
                # <llil: %rax#9.%ax = %rax#8.%ax - [%rbp#1 - 0xc {var_14}].w @ mem#9>
                left = self.gen_ast(llil_fun, inst_ssa.dest) 
                right = self.gen_ast(llil_fun, inst_ssa.src)
                root_node = BnSSAOp(left, "=", right)
                print(root_node)
                parse_ast(root_node)
                # exit()
                # log.debug("%s %s %s", self.parse_nodes(root_node.left), root_node.op, root_node.right)
                return root_node
            if inst_ssa.operation == LowLevelILOperation.LLIL_STORE_SSA:
                left = self.gen_ast(llil_fun, inst_ssa.dest) 
                right = self.gen_ast(llil_fun, inst_ssa.src)
                root_node = BnSSAOp(left, "=", right)
                return root_node
        else:
            # cmp     $0x2, dword ptr [%rbp-0x144] 
            log.debug(asm_inst.inst_print())
            left = RegNode(asm_inst.dest)
            right = RegNode(asm_inst.src)
            root_node = BnSSAOp(left, asm_inst.inst_type, right)
            return root_node

                
    def asm_lex_analysis(self, var_name, llil_fun, llil_inst, dis_inst = None, fun = None):
        print("")
        arrow = 'U+21B3'
        if llil_inst is not None and llil_fun is not None:
            dis_inst = self.bv.get_disassembly(llil_inst.address)
            fun_name = llil_fun.medium_level_il.source_function.name
            log.warning("ASM Lexical Analysis: %s | Fun: %s", llil_inst, fun_name)
            log.warning("\t%s %s", chr(int(arrow[2:], 16)), dis_inst)
        else:
            log.warning("ASM Lexical Analysis: %s | Fun: %s", dis_inst, fun.name)
        # Example: mov     qword [rbp-0x8], rax 
        dis_inst_pattern    = re.search(r"(\b[a-z]+\b)\s*(.*),\s(.*)", dis_inst)
        # Example: qword ptr [%rbp-0x410]
        reg_offset_pattern = r'(\b[qword ptr|dword ptr|byte ptr|word ptr]+\b)\s\[(%.*)([*+\/-]0x[a-z,0-9].*)\]'
        # Example: qword ptr [%rdx+%rax]
        reg_reg_pattern = r'(\b[qword ptr|dword ptr|byte ptr|word ptr]+\b)\s\[(%.*)\+(%.*)\]'
        reg_64_pattern = r'%r[a-z]x'
        reg_32_pattern = r'%e[a-z]x'
        inst_type           = str()
        src                 = str()
        dest                = str()
        if dis_inst_pattern != None:
            inst_type   = dis_inst_pattern.group(1)
            src         = dis_inst_pattern.group(2)
            dest        = dis_inst_pattern.group(3)
        else:
            log.error("Regex failed %s", dis_inst)
    
        # if inst_type == "movzx":
        #     print("Here")    # to debug in detail
    
        offset_src_dest = None
        patch_inst = None
        if re.search(r'(qword ptr|dword ptr|byte ptr|word ptr)', src):
            log.debug("ptr Source")
            offset_src_dest = "src" # Used for dis_inst
            suffix_regex = re.search(r'(qword ptr|dword ptr|byte ptr|word ptr)', src)
            if suffix_regex != None:
                suffix = suffix_regex.group(1)
                # conv_inst_type = conv_instr(inst_type, suffix)
                # log.debug("%s %s %s %s", inst_type, src, dest, suffix)
                offset_regex = re.search(reg_offset_pattern, src)
                reg_regex = re.search(reg_reg_pattern, src)
                if offset_regex:
                    expr = str(int(offset_regex.group(3),base=16)) + "(" + offset_regex.group(2) + ")"
                    # if inst_type != "movzx":
                    #     patch_inst = PatchingInst(inst_type, conv_suffix(suffix), conv_imm(expr), conv_imm(dest), offset_src_dest)
                    # else:
                    patch_inst = PatchingInst(inst_type, conv_suffix(suffix), conv_imm(expr), conv_imm(dest), offset_src_dest)
                    # print("Here") # conv_suffix(None, inst_type, dest)
                elif reg_regex:
                    expr = str("("+reg_regex.group(2)+","+reg_regex.group(3)+")")
                    # if inst_type != "movzx":
                    #     patch_inst = PatchingInst(inst_type, conv_suffix(suffix), conv_imm(expr), conv_imm(dest), offset_src_dest)
                    # else:
                    patch_inst = PatchingInst(inst_type, conv_suffix(suffix), conv_imm(expr), conv_imm(dest), offset_src_dest)
        elif re.search(r'(qword ptr|dword ptr|byte ptr|word ptr)', dest):
            log.debug("ptr Dest")
            offset_src_dest = "dest" # Used for dis_inst
            suffix_regex = re.search(r'(qword ptr|dword ptr|byte ptr|word ptr)', dest)
            if suffix_regex != None:
                suffix = suffix_regex.group(1)
                # conv_inst_type = conv_instr(inst_type, suffix)
                log.debug("%s %s %s %s", inst_type, src, dest, suffix)
                offset_regex = re.search(reg_offset_pattern, dest)
                reg_regex = re.search(reg_reg_pattern, src)
                if offset_regex:
                    expr = str(int(offset_regex.group(3),base=16)) + "(" + offset_regex.group(2) + ")"
                    # if inst_type != "movzx":
                    patch_inst = PatchingInst(inst_type, suffix=conv_suffix(suffix), src=conv_imm(src), dest=conv_imm(expr), ptr_op=offset_src_dest)
                    # else:
                    #     patch_inst = PatchingInst(inst_type, suffix=conv_suffix(None, inst_type, src), src=conv_imm(src), dest=conv_imm(expr), ptr_op=offset_src_dest)
                elif reg_regex:
                    expr = str("("+reg_regex.group(2)+","+reg_regex.group(3)+")")
                    # if inst_type != "movzx":
                    patch_inst = PatchingInst(inst_type, suffix=conv_suffix(suffix), src=conv_imm(src), dest=conv_imm(expr), ptr_op=offset_src_dest)
                    # else:
                    #     patch_inst = PatchingInst(inst_type, suffix=conv_suffix(None, inst_type, src), src=conv_imm(src), dest=conv_imm(expr), ptr_op=offset_src_dest)
        else:
            # log.debug("Neither")
            suffix = None
            if re.search(reg_64_pattern, src) or re.search(reg_64_pattern, dest):
                # 64-bit register
                suffix = "q"
            elif re.search(reg_32_pattern, src) or re.search(reg_32_pattern, dest):
                # 32-bit register
                suffix = "l"
            else: 
                # Byte
                suffix = "b"
            
            patch_inst = PatchingInst(inst_type=inst_type, suffix=suffix,
                                          dest=conv_imm(dest), src=conv_imm(src), ptr_op="")
            
                
        # log.debug(patch_inst)
        if patch_inst != None:
            log.debug(patch_inst.inst_print())
        
        log.debug("%s", dis_inst)
        # if (hex(llil_inst.address) == "0x11b7"):
        #         print("Here")
        # If LLIL is provided
        if llil_inst != None:
            log.debug("\t%s %s", chr(int(arrow[2:], 16)), llil_inst)
            asm_syntax_tree = self.gen_ast(llil_fun, llil_inst)
            # print("Here", asm_syntax_tree)
            parse_ast(asm_syntax_tree)
            
            print(llil_inst, type(llil_inst))
            
            #     exit()
            # try:
            offset_expr = self.calc_ssa_off_expr(llil_inst.ssa_form)
            # except:
            #     print(llil_inst)
            
            # src_offset_expr [0] | dest_offset_expr [1]
            bn_var = BnVarData(var_name, dis_inst, patch_inst, 
                            offset_expr, asm_syntax_tree, llil_inst, False)
            if bn_var.patch_inst.inst_type == "movss":
                bn_var.patch_inst.suffix = ""
            print(colored("bn_var %s\nbn_var: %s" % (bn_var, bn_var.patch_inst.inst_print()), 'blue', attrs=['reverse']))
            # print(bn_var)
            # print(bn_var.patch_inst.inst_print())
            return bn_var
        # If ASM is directly provided
        else:
            asm_syntax_tree = self.gen_ast(None, None, patch_inst)
            offset_expr = None
            if offset_src_dest == "dest":
                offset_expr = patch_inst.dest
            elif offset_src_dest == "src":
                offset_expr = patch_inst.src
            bn_var = BnVarData(var_name, dis_inst, patch_inst, 
                            offset_expr, asm_syntax_tree, llil_inst, False)
            if bn_var.patch_inst.inst_type == "movss":
                bn_var.patch_inst.suffix = ""
            # parse_ast(asm_syntax_tree)
            # print(bn_var)
            return bn_var
    
    # Need debug info to handle static functions
    def analyze_binary(self, funlist):
        # print("Step: Binary Ninja")
        debug_fun = "sort"
        gen_regs = {"%rax", "%rbx", "%rcx", "%rdx", "%rdi", "%rsi",
            "%eax", "%ebx", "%ecx", "%edx", "%edi", "%esi",
            "%ax",  "%bx",  "%cx",  "%dx",
            "%xmm0", "%xmm1", "%xmm2", "%xmm3",
            "%xmm4", "%xmm5", "%xmm6", "%xmm7",
            "%xmm8", "%xmm9", "%xmm10", "%xmm11",
            "%xmm12", "%xmm13", "%xmm14", "%xmm15"}
        arg_regs = {"%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9",
                    "%ecx", "%edx"}
        addr_to_llil = dict()
        for func in self.bv.functions:
            self.fun = func.name
            if self.fun in funlist:
                var_set: set[c14nVarData] = []
                var_set = c14n_analysis(self.bv, func)
                
                pprint(var_set)
                # exit()
                addr_range = func.address_ranges[0]
                begin   = addr_range.start
                end     = addr_range.end
                log.info("Function: %s | begin: %s | end: %s", func.name, hex(begin), hex(end))
                llil_fun = func.low_level_il
                # Clear dict per function
                addr_to_llil.clear()
                for llil_bb in llil_fun:
                    if True: 
                    # if self.fun == debug_fun: # Specific function
                        # Making these variable per basic block level
                        arg_idx = 0
                        call_args = 1
                        for llil_inst in llil_bb:
                            addr_to_llil[llil_inst.address] = llil_inst
                            # print(llil_inst, llil_inst.operation)
                            mapped_il = llil_inst.mapped_medium_level_il
                            # log.debug("%s | %s", llil_inst, mapped_il)
                            # if hex(llil_inst.address) == "0xbe27":
                            #     print(llil_inst, llil_inst.operation)
                            #     log.error("%s | %s", llil_inst, mapped_il)
                                # exit()
                            if llil_inst.operation == LowLevelILOperation.LLIL_SET_REG:
                                # try:
                                #     # Try to catch argument register
                                #     # if llil_inst.dest.name.__str__() in arg_regs and arg_idx < call_args:
                                #     #     # 64-bit arg register
                                #     #     # print("ARG", llil_inst, mapped_il, llil_inst.operation)
                                #     #     log.debug(llil_inst.ssa_form)
                                #     #     # Determine how many arguments is for a call; Upon reaching call instruction
                                #     #     # this both arg_idx and call_args should reset
                                #     #     call_fun = llil_fun.get_ssa_reg_uses(llil_inst.ssa_form.dest)
                                #     #     call_args = len(llil_fun.high_level_il.params)
                                #     #     # print(call_fun)
                                #     #     arg_idx += 1
                                #     None
                                # except: 
                                    # Else here
                                if len(mapped_il.vars_read) > 0:
                                    print("NON ARG", llil_inst, mapped_il, llil_inst.operation)
                                    var_idx = None
                                    result = any("var" in var.name for var in mapped_il.vars_read)
                                    if result:
                                        for idx, var in enumerate(mapped_il.vars_read):
                                            if "var" in var.name:
                                                var_idx = idx
                                    if var_idx != None:
                                        # temp_var = mapped_il.vars_read[0]
                                        temp_var = mapped_il.vars_read[var_idx]
                                        var_name = temp_var.name
                                        dest_reg = llil_inst.ssa_form.dest
                                        # Avoid RSP registers
                                        try:
                                            if type(dest_reg) == binaryninja.lowlevelil.ILRegister:
                                                reg_name = dest_reg.name
                                            elif type(dest_reg) == binaryninja.lowlevelil.SSARegister:
                                                reg_name = dest_reg.reg.name
                                                
                                            if (temp_var.core_variable.source_type == VariableSourceType.StackVariableSourceType and "var" in var_name 
                                                and reg_name in gen_regs):
                                                bn_var = self.asm_lex_analysis(var_name, llil_fun, llil_inst)
                                                # print(bn_var)
                                                self.bn_var_list.append(bn_var)
                                            # elif (temp_var.core_variable.source_type == VariableSourceType.StackVariableSourceType and "var" in var_name 
                                            #     and reg_name in gen_regs):
                                            #     # For the case of 16-bit reg like %al
                                            #     bn_var = self.asm_lex_analysis(var_name, llil_fun, llil_inst)
                                            #     self.bn_var_list.append(bn_var)
                                        except Exception as err:
                                            # print(type(dest_reg))
                                            # print(err)
                                            log.error(err)
                                            log.warning("Not the target")
                            # If store -> vars written
                            elif llil_inst.operation == LowLevelILOperation.LLIL_STORE:
                                # if hex(llil_inst.address) == "0xbe27": For debugging
                                #     print(llil_inst, llil_inst.operation)
                                #     log.error("%s | %s", llil_inst, mapped_il)
                                if len(mapped_il.vars_written) > 0:
                                    # print(llil_inst)
                                    result = any("var" in var.name for var in mapped_il.vars_written)
                                    temp_var = mapped_il.vars_written[0]
                                    var_name = temp_var.name
                                    # Avoid RSP registers
                                    if (temp_var.core_variable.source_type == VariableSourceType.StackVariableSourceType and "var" in var_name):
                                        bn_var = self.asm_lex_analysis(var_name, llil_fun, llil_inst)
                                        self.bn_var_list.append(bn_var)
                                elif (mapped_il.dest.operation == MediumLevelILOperation.MLIL_ADD):
                                    # <mlil: [&var_78 + %rax].b = 0x41>, array operation where %rax is used as an index; need to handle such case
                                    var_name = None # No variable name for this kind of case
                                    bn_var = self.asm_lex_analysis(var_name, llil_fun, llil_inst)
                                    self.bn_var_list.append(bn_var)
                                    # print(bn_var)
                                    # exit()
                                else:
                                    None
                                    # print(llil_inst, llil_inst.operation)
                            elif llil_inst.operation == LowLevelILOperation.LLIL_CALL:
                                # print(llil_inst)
                                call_ops = llil_inst.medium_level_il.operands[2]
                                # Try to implement using llil_inst.medium_level_il.low_level_il.operands[3].operands[0]
                                # <binaryninja.lowlevelil.LowLevelILCallParam object at 0x7fae2098e710>
                                if (llil_inst.address == int(0x56e)):

                                    log.error("Here")
                                log.warning("Handling call instruction %s", llil_inst.medium_level_il)
                                print(call_ops)
                                for op in call_ops:
                                    print(hex(op.address), type(op), op.ssa_form)
                                    if (type(op) == binaryninja.mediumlevelil.MediumLevelILConst or
                                        type(op) == binaryninja.mediumlevelil.MediumLevelILConstPtr):
                                        # %rsi = -1
                                        continue
                                    elif type(op) != binaryninja.mediumlevelil.MediumLevelILVar:
                                        arg_llil_inst = addr_to_llil[op.address]
                                        print(arg_llil_inst)
                                        ssa_reg = self.get_ssa_reg(arg_llil_inst.src.ssa_form)
                                        log.debug(ssa_reg)
                                        if type(ssa_reg) != binaryninja.lowlevelil.LowLevelILLoadSsa:
                                            def_llil_inst = llil_fun.get_ssa_reg_definition(ssa_reg).ssa_form
                                            for var in self.bn_var_list:
                                                # print(var.llil_inst.ssa_form)
                                                if def_llil_inst == var.llil_inst.ssa_form:
                                                    var.arg = True
                                        else:
                                            def_llil_inst = arg_llil_inst.ssa_form
                                            for var in self.bn_var_list:
                                                # print(var.llil_inst.ssa_form)
                                                if def_llil_inst == var.llil_inst.ssa_form:
                                                    var.arg = True
                                    elif (type(op) == binaryninja.mediumlevelil.MediumLevelILVar and
                                          len(op.llils) < 1):
                                        # arg4 - ngx_hash_init
                                        ssa_reg = self.find_ssa_reg(op, addr_to_llil, llil_fun.mlil)
                                        # inst_var = llil_fun.mlil.get_ssa_var_uses(op.ssa_form.src)
                                        # log.debug(inst_var)
                                        # exit()
                                    else:
                                        arg_llil_inst = op.llils[len(op.llils)-1].ssa_form
                                        # , addr_to_llil
                                        try:
                                            print(arg_llil_inst)
                                            ssa_reg = self.get_ssa_reg(arg_llil_inst.src.ssa_form)
                                            log.debug(ssa_reg)
                                        # if (type(ssa_reg) != binaryninja.lowlevelil.LowLevelILLoadSsa):
                                            def_llil_inst = llil_fun.get_ssa_reg_definition(ssa_reg).ssa_form
                                            for var in self.bn_var_list:
                                                if arg_llil_inst == var.llil_inst.ssa_form:
                                                    # %rdx#1 = %rax#3 + 4 {var_c}
                                                    log.critical(var.llil_inst.ssa_form)
                                                    var.arg = True
                                                    print(var)
                                                if def_llil_inst == var.llil_inst.ssa_form:
                                                    #  %rax#3 = %rbp#1 - 8 {var_10}
                                                    log.critical(var.llil_inst.ssa_form)
                                                    var.arg = True
                                                    print(var)
                                        # else:
                                        except:
                                            def_llil_inst = arg_llil_inst.ssa_form
                                            for var in self.bn_var_list:
                                                if def_llil_inst == var.llil_inst.ssa_form:
                                                    log.critical(var.llil_inst.ssa_form)
                                                    var.arg = True
                                # exit()
                            else:
                                log.error("%s, %s", llil_inst, llil_inst.operation)
                                None


                # Control transfer instructions (e.g., cmp) cannot be referenced using the SSA form 
                # due to theta function; hence we use dis_inst for these.
                for bb in func:
                    if True:
                    # if self.fun == debug_fun:
                        dis_bb = bb.get_disassembly_text()
                        for dis_inst in dis_bb:
                            # Check tokens for cmp instruction
                            if dis_inst.tokens[0].text == "cmp":
                                # print("cmp", dis_inst)
                                target = "var"
                                indices = [index for index, token in enumerate(dis_inst.tokens) if target in token.text]
                                if indices:
                                    var_name = dis_inst.tokens[indices[0]]
                                    bn_var = self.asm_lex_analysis(var_name, None, None, self.bv.get_disassembly(dis_inst.address), func)
                                    self.bn_var_list.append(bn_var)
                    
            # pprint(self.bn_var_list)
            bn_fun_var_info[self.fun] = self.bn_var_list.copy()
            self.bn_var_list.clear()
            # pprint(bn_fun_var_info[self.fun], width=1)
            # print(len(bn_fun_var_info[self.fun]))
        # for bn_var in bn_fun_var_info[debug_fun]:
        #     print(bn_var)
        #     print(bn_var.patch_inst.inst_print())
        #     print("")
        # exit()
        # DEBUG       movq    -8(%rbp), %rsi 
    def __init__(self, bv):
        self.bv = bv
        self.fun = None
        
if __name__ == '__main__':
    process_argument(sys.argv[1:])
    