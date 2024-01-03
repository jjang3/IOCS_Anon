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


# @dataclass
# class PatchingInst:
#     inst_type: Optional[str] = None
#     src: Optional[str] = None
#     dest: Optional[str] = None
#     offset: Optional[str] = None
#     suffix: Optional[str] = None
#     # fun: Optional[str] = None


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
    def __init__(self, inst_type, suffix, src, dest):
        self.inst_type = inst_type
        self.suffix = suffix
        self.src = src
        self.dest = dest
    def inst_print(self):
        # print("Inst type: %s | Suffix: %s | Source: %s | Dest: %s" % (self.inst_type, self.suffix, self.src, self.dest))
        info = "Inst type: %s | Suffix: %s | Source: %s | Dest: %s" % (self.inst_type, self.suffix, self.src, self.dest)
        return info
    def inst_check(self, tgt_inst):
        if (self.inst_type == tgt_inst.inst_type and
            self.suffix == tgt_inst.suffix and
            self.src == tgt_inst.src and
            self.dest == tgt_inst.dest):
            return True
        else:
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

class SizeType(Enum):
    CHAR = 1
    INT = 4
    CHARPTR = 8
    
def generate_table(dwarf_var_count, dwarf_fun_var_info, target_dir):
    varlist = list()
    log.info("Generating the table")
    if dwarf_var_count % 2 != 0 and dwarf_var_count != 1:
        # This is to avoid malloc(): corrupted top size error, malloc needs to happen in mod 2
        dwarf_var_count += 1
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
"""
    begin_table="""
void __attribute__((constructor)) table()
{    
    void **table = malloc(sizeof(void*)*%d);\n
    /*Pointer to shared memory region*/    
""" % (dwarf_var_count)

    count = 0
    while count < dwarf_var_count: # May need to make this <= in order to avoid mod 2 bug
        varentry = "\tvoid *addr_%d;" % count
        mmapentry = """
    addr_%d = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_32BIT, -1, 0);     
    if (addr_%d == MAP_FAILED) {     
        fprintf(stderr, "mmap() failed\\n");     
        exit(EXIT_FAILURE);
    }
    table[%d] = addr_%d;\n
""" % (count, count, count, count) #  | MAP_32BIT
        varlist.append((varentry, mmapentry))
        count += 1

    end_table="""\t_writegsbase_u64((long long unsigned int)table);
}
"""
    table_file = open("%s/table.c" % target_dir, "w")
    table_file.write(include_lib_flags)
    table_file.write(begin_table)
    for item in varlist:
        table_file.write(item[0])
        table_file.write(item[1])
    table_file.write(end_table)
    table_file.close()
    log.info("Based on offsets, generate offsets per respective variables")
    pprint(dwarf_fun_var_info, width=1)
    
    # Offset to table offset set of the current working function
    offset_expr_to_table    = set()
    table_offset = 0
    
    for fun in dwarf_fun_var_info:
        vars = dwarf_fun_var_info[fun]
        for var in vars:
            if var.var_type == "DW_TAG_structure_type":
                var_struct = var.struct
                for member in var_struct.member_list:
                    offset_expr_to_table.add((member.offset_expr, table_offset))
                    table_offset += 8
        fun_table_offsets[fun] = offset_expr_to_table.copy()
    
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

def conv_instr(instr):
    match instr:
        case "sal":
            return "shl"
        case "movsbl":
            return "movsx"
        case "movzbl":
            return "movzx"
    return instr

def conv_suffix(suffix):
    log.info("Converting suffix %s", suffix)
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
    # print("Converting: ", imm)
    imm_pattern = r"(\$)(0x.*)"
    imm_regex = re.search(imm_pattern, imm)
    new_imm = str()
    if imm_regex:
        offset = int(imm_regex.group(2), 16)
        if offset == 4294967295:
            offset = -1
        elif offset == 18446744073709551615:
            offset = -1
        elif offset == 4294967165:
            offset = -130
        elif offset == 4294967166:
            offset = -131
        # print(imm_regex.group(1))
        new_imm = imm_regex.group(1) + str(offset)
        return new_imm
    else:
        return imm
        
    
def process_argument(argv):
    inputfile = ''
    taintfile = ''
    dirloc = None
    try:
        opts, args = getopt.getopt(argv,"hfic:",["binary=","taint=","dir="])
    except getopt.GetoptError:
        print ('binary_patch.py --binary <binary> --taint <dft.out> --dir <dir name>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('binary_patch.py --binary <binary> --taint <dft.out> --dir <dir name>')
            sys.exit()
        elif opt in ("-b", "--binary"):
            inputfile = arg
        elif opt in ("-t", "--taint"):
            taintfile = arg
        elif opt in ("-d", "--dir"):
            dirloc = arg
    process_binary(inputfile, taintfile, dirloc)

dwarf_fun_var_info  = dict()
bn_fun_var_info     = dict()

# Total number of variables from the DWARF analysis
dwarf_var_count = 0

target_list = list()

def process_binary(filename, taintfile, dirloc):
    global dwarf_var_count
    target_dir = None        
    # print("Dirloc", dirloc)
    if dirloc != None:
        # print("Here")
        target_dir = os.path.join(os.path.dirname(os.path.abspath(filename)), dirloc)
        # filename = os.path.join(target_dir, filename)
        # funfile = os.path.join(target_dir, funfile)
        # target_dir = Path(os.path.abspath(filename))
    else:
        target_dir = Path(os.path.abspath(filename))
        target_dir = target_dir.parent.parent.joinpath("result", os.path.splitext((os.path.basename(filename)))[0])
        taint_file = target_dir.joinpath("dft.out")
        filename = target_dir.joinpath(os.path.splitext((os.path.basename(filename)))[0] + ".out")
        # target_dir= (os.path.abspath(filename)) #os.path.abspath(os.path.abspath(os.path.dirname))

    # print("\tTarget dir:", target_dir)
    # print(funfile)

    target_file = target_dir.joinpath(os.path.splitext((os.path.basename(filename)))[0] + ".s")
    
    funlist = list()
    taint_src_regex = r"(?:T_SRC.*?:\s)(.*)"
    taint_sink_regex = r"(?:(W|R)\s0x[0-9,A-z]*:\s)(.*)\.(.*)"
    if taint_file != "":
        with open(taint_file) as c:
            for line in c:
                taint_src = re.search(taint_src_regex, line)
                if (taint_src):
                    print(taint_src.group(1))
                    funlist.append(taint_src.group(1))
                taint_sink = re.search(taint_sink_regex, line)
                if (taint_sink):
                    print(line)
                    op_type = taint_sink.group(1)
                    var_name = taint_sink.group(2)
                    mem_name = taint_sink.group(3)
                    target_var = None
                    if mem_name != None:
                        target_var = TargetData(set(), var_name, mem_name)
                    else:
                        target_var = TargetData(set(), var_name, None)
                    
                    if len(target_list) != 0:
                        for target in target_list:
                            if target.var_name == target_var.var_name:
                                if mem_name != None:
                                    if target.member_name == target_var.member_name:
                                        target.type.add(op_type)
                                else:
                                    target.type.add(op_type)
                            else:
                                target_list.append(target_var)
                    else:
                        target_var.type.add(op_type)
                        target_list.append(target_var)
                else:
                    print(line)
    
    print("Target list:")
    pprint(target_list, width=1)

    dir_list = os.listdir(target_dir)
    # print(filename, funfile, target_dir)
    # --- DWARF analysis --- #
    dwarf_output = dwarf_analysis.dwarf_analysis(filename)
    pprint(dwarf_output, width=1)
    for fun in dwarf_output:
        temp_var_count = fun.var_count
        # Make copy of var_list to make modification and copy it to dwarf_fun_var_info
        temp_var_list = fun.var_list.copy()
        for var in temp_var_list:
            target_vars = [(target.var_name, idx) for (idx,target) in enumerate(target_list)]
            # print(target_vars[0])
            for target_var in target_vars:
                if target_var[0] == var.name:
                    # target_var[1] is an index
                    if var.struct is not None:
                        if var.struct.member_list is not None:
                            for member in var.struct.member_list:
                                if target_list[target_var[1]].member_name is member.name:
                                    None
                                else:
                                    var.struct.member_list.remove(member)
                                    temp_var_count -= 1
        # pprint(temp_var_list, width=1)
        dwarf_fun_var_info[fun.name] = temp_var_list.copy()
        fun_entry_to_args[fun.begin] = temp_var_count
        dwarf_var_count += temp_var_count

    # Based on variable counts and targets found by dwarf analysis, generate table.
    generate_table(dwarf_var_count, dwarf_fun_var_info, target_dir)

    # pprint(dwarf_fun_var_info)
    #--- Binary Ninja Analysis --- #
    print("Binary ninja input:", filename)
    with load(filename.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
        # print("Here")                  
        arch = Architecture['x86_64']
        bn = BinAnalysis(bv)
        bn.analyze_binary(funlist)

    if dirloc != '':
        for dir_file in dir_list:
            if (dir_file.endswith('.s')):
                process_file(funlist, target_dir, dir_file)
    else:
        process_file(funlist, target_dir, target_file)



asm_macros = """# ASM Rewriting Macros:
    .macro movb_set_gs src offset
        rdgsbase %r11
        mov \offset(%r11),	%r11
        movb \src, (%r11)
    .endm
    .macro movl_set_gs src offset
        rdgsbase %r11
        mov \offset(%r11),	%r11
        movl \src, (%r11)
    .endm
    .macro movq_set_gs src offset
        rdgsbase %r11
        mov \offset(%r11),	%r11
        movq \src, (%r11)
    .endm
    .macro movb_load_gs dest, offset
        rdgsbase %r11
        mov \offset(%r11), %r11
        movb (%r11), \dest
    .endm
     .macro movl_load_gs dest, offset
        rdgsbase %r11
        mov \offset(%r11), %r11
        movl (%r11), \dest
    .endm
     .macro movq_load_gs dest, offset
        rdgsbase %r11
        mov \offset(%r11), %r11
        movq (%r11), \dest
    .endm
    .macro movzx_load_gs dest, offset
        rdgsbase %r11
        mov \offset(%r11), %r11
        movzx (%r11), \dest
    .endm
    .macro movsx_load_gs dest, offset
        rdgsbase %r11
        mov \offset(%r11), %r11
        movsx (%r11), \dest
    .endm
    .macro lea_gs dest, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
        lea (%r11), \dest
    .endm
    .macro addq_store_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
        mov (%r11), %r11
        add \\value, %r11
		rdgsbase %r12
        mov	\offset(%r12), %r12 
        mov %r11, (%r12)
    .endm
    .macro addl_store_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
        mov (%r11), %r11
        add \\value, %r11d
		rdgsbase %r12
        mov	\offset(%r12), %r12 
        mov %r11d, (%r12)
    .endm
    .macro subq_store_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
        mov (%r11), %r11
        sub \\value, %r11
		rdgsbase %r12
        mov	\offset(%r12), %r12 
        mov %r11, (%r12)
    .endm
    .macro subl_store_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
        mov (%r11), %r11
        sub \\value, %r11d
		rdgsbase %r12
        mov	\offset(%r12), %r12 
        mov %r11d, (%r12)
    .endm
	.macro add_load_gs dest, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
        mov (%r11), %r11
        add %r11, \dest
    .endm
    .macro subl_load_gs dest, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
        mov (%r11), %r11d
        subl %r11d, \dest
    .endm
    .macro subq_load_gs dest, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
        mov (%r11), %r11
        sub %r11, \dest
    .endm
    .macro imull_load_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
		mov (%r11), %r12d
        imull %r12d, \\value
    .endm
	.macro imulq_load_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
		mov (%r11), %r12
        imulq %r12, \\value
    .endm
    .macro cmpl_load_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
		mov (%r11), %r12d
        cmpl %r12d, \\value
    .endm
	.macro cmpq_load_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
		mov (%r11), %r12
        cmpq %r12, \\value
    .endm
	.macro cmpb_load_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
		mov (%r11), %r12b
        cmpb %r12b, \\value
    .endm
    .macro cmpl_store_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
		mov (%r11), %r12d
        cmpl \\value, %r12d
    .endm
	.macro cmpq_store_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
		mov (%r11), %r12
        cmpq \\value, %r12
    .endm
	.macro cmpb_store_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
		mov (%r11), %r12b
        cmpb \\value, %r12b
    .endm
    .macro shll_set_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
        mov (%r11), %r11
        shl \\value, %r11d
        rdgsbase %r12
        mov	\offset(%r12), %r12 
        mov %r11d, (%r12)
    .endm
    .macro shlq_set_gs value, offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
        mov (%r11), %r11
        shl \\value, %r11
        rdgsbase %r12
        mov	\offset(%r12), %r12 
        mov %r11, (%r12)
    .endm
    .macro divq_load_gs offset
        rdgsbase %r11
        mov	\offset(%r11), %r11
        mov (%r11), %r11
        divq %r11
    .endm
"""

def patch_inst(dis_inst, temp_inst: PatchingInst, bn_var, bn_var_info: list, tgt_offset):
    log.critical("Patch the instruction %s", dis_inst)
    # parse_ast(bn_var.asm_syntax_tree)
    # print("------")
    tgt_ast = bn_var.asm_syntax_tree
    for var in bn_var_info:
        var_ast = var.asm_syntax_tree
        # parse_ast(var_ast)
        if repr(tgt_ast.right) == 'BnSSAOp':
            if repr(var_ast.left) == 'RegNode':
            # print(var_ast.left.value, tgt_ast.right.left)
                if var_ast.left.value == tgt_ast.right.left.value:
                    # Check if this target may have offset value from different register and patch accordingly
                    # print(var.patch_inst.inst_print())
                    if var.patch_inst.inst_type == "lea":
                        new_inst_type = "lea_gs"
                        log.info("Patching with lea_gs")
                        line = re.sub(r"(\b[a-z]+\b).*", "#%s\n\t%s\t%s, %d\n" % 
                                      (dis_inst,new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
                        return line
                    # parse_ast(var_ast)
    
def process_file(funlist, target_dir, target_file):
        print(os.path.join(target_dir, target_file))
        debug_file = target_file + ".bak"
        if os.path.isfile(os.path.join(target_dir, debug_file)):
            print("Copying debug file")
            shutil.copyfile(os.path.join(target_dir, debug_file), os.path.join(target_dir, target_file))
        else:
            print("No debug file exists")
        
        debug = False
        patch_count = 0
        with fileinput.input(os.path.join(target_dir, target_file), 
                             inplace=(not debug), encoding="utf-8", backup='.bak') as f:
            fun_begin_regex = r'(?<=.type\t)(.*)(?=,\s@function)'
            fun_end_regex   = r'(\t.cfi_endproc)'
            dis_line_regex  = r'\t(mov|lea|sub|add|cmp|sal|imul)([a-z]*)\t(.*),\s(.*)'
            # 	salq	-40(%rbp) or shl $1, -40(%rbp), if no immediate -> $1
            sh_line_regex   = r'\t(sal)([a-z]*)\t(.*)'
            sing_line_regex = r'\t(div)([a-z]*)\t(.*)'
            check = False
            currFun = str()
            patch_targets = list()
            offset_targets = list()
            struct_targets = set()
            max_patch = 0
            # print(funlist)
            for line in f:
                # print('\t.file\t"%s.c"' % target_file.rsplit('.', maxsplit=1)[0])
                if line.startswith('\t.file\t"%s.c"' % target_file.rsplit('.', maxsplit=1)[0]):
                    print(asm_macros, end='')
                    # None
                fun_begin = re.search(fun_begin_regex, line)
                if fun_begin is not None:
                    if fun_begin.group(1) in funlist:
                        currFun = fun_begin.group(1)
                        try:
                            dwarf_var_info   = dwarf_fun_var_info[currFun]
                            bninja_info     = bn_fun_var_info[currFun]
                            offset_targets  = fun_table_offsets[currFun]
                            check = True
                        except Exception as err:
                            log.error("Skipping", type(err))
                            check = False
                        if debug:
                            pprint(dwarf_var_info, width = 1)
                            pprint(bninja_info, width = 1)
                            pprint(offset_targets, width = 1)
                fun_end = re.search(fun_end_regex, line)
                if fun_end is not None:
                    check = False
            
                if check == True: # and patch_count < max_patch:
                    dis_line = line.rstrip('\n')
                    # mnemonic source, destination AT&T
                    log.debug(dis_line)
                    dis_regex   = re.search(dis_line_regex, dis_line)
                    if dis_regex is not None:
                        inst_type   = dis_regex.group(1)
                        suffix      = dis_regex.group(2)
                        src         = dis_regex.group(3)
                        dest        = dis_regex.group(4)
                        # temp_inst = PatchingInst(conv_instr(inst_type), src, dest, expr, suffix)
                                    
                        temp_inst = PatchingInst(inst_type=inst_type, suffix=suffix,
                                                    dest=conv_imm(dest), src=conv_imm(src))
                        new_inst = None
                        for idx, bn_var in enumerate(bninja_info):
                            if temp_inst.inst_check(bn_var.patch_inst):
                                # print("Found\n", temp_inst.inst_print(), "\n", bn_var.patch_inst.inst_print())
                                offset_expr = bn_var.offset_expr
                                for offset in offset_targets:
                                    if offset_expr == offset[0]:
                                        # Found the offset target; need to patch this instruction
                                        new_inst = patch_inst(dis_line, temp_inst, bn_var, bninja_info, offset[1])
                                        bninja_info.pop(idx)
                                        if new_inst != None:
                                            # log.debug("\n%s",new_inst)
                                            break
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
                                # print(bn_var.patch_inst.inst_print())
                                
                                # break
                                # print(temp_inst.inst_print(), bn_var.patch_inst.inst_print())
            #         sh_regex    = re.search(sh_line_regex, dis_line)
            #         sing_regex  = re.search(sing_line_regex, dis_line)
            #         # log.error("%s %s %s", dis_regex,sh_regex,sing_regex)
            #         temp_inst = None
                   
            #             expr        = str()
            #             mov_regex   = r"mov"
            #             if re.search(mov_regex, inst_type):
            #                 if suffix == "zbl":
            #                     inst_type = "movzx"
            #                     suffix = "b"
            #                 elif suffix == "sbl":
            #                     inst_type = "movsx"
            #                     suffix = "b"
                    
            #             off_regex   = r"(-|)([a-z,0-9].*\(%r..\))"
            #             if re.search(off_regex, src):
            #                 expr = src
            #             elif re.search(off_regex, dest):
            #                 expr = dest
            #             else:
            #                 expr = None
                        
            #             # print("Inst Type: ", inst_type, "\t|\tSuffix: ", conv_suffix(suffix), "\t| src: ", src,"\t| dest: ", dest)
            #             temp_inst = PatchingInst(conv_instr(inst_type), src, dest, expr, suffix)
            #             log.warning("Temp: %s", temp_inst)
            #         elif sh_regex is not None:
            #             # print(sh_regex)
            #             log.debug(sh_regex)
            #             inst_type   = sh_regex.group(1)
            #             suffix      = sh_regex.group(2)
            #             src         = "$1"
            #             dest        = sh_regex.group(3)
            #             expr = str()
            #             off_regex   = r"(-|)([a-z,0-9].*\(%r..\))"
            #             if re.search(off_regex, dest):
            #                 expr = dest
            #             temp_inst = PatchingInst(conv_instr(inst_type), src, dest, expr, suffix)
            #             log.warning("Temp: %s", temp_inst)
            #         elif sing_regex is not None:
            #             inst_type   = sing_regex.group(1)
            #             suffix      = sing_regex.group(2)
            #             src         = sing_regex.group(3)
            #             expr = str()
            #             off_regex   = r"(-|)([a-z,0-9].*\(%r..\))"
            #             if re.search(off_regex, src):
            #                 expr = src
            #             temp_inst = PatchingInst(conv_instr(inst_type), src, '', expr, suffix)
            #             log.warning("Temp: %s", temp_inst)
                        
            #         if temp_inst != None:
            #             # pprint(patch_targets)
            #             if temp_inst in patch_targets:
            #                 log.critical("Found")
            #                 replace_inst = str()
            #                 try:
            #                     replace_inst = patch_inst(dis_line, temp_inst, offset_targets)
            #                 except:
            #                     log.error("No offset exists")
            #                     # break
                            # if replace_inst != None:
                            #     patch_count += 1
                            #     line = replace_inst
                            #     log.info(line)
                            #     print(line, end='')
            #             
            # log.critical("Patch count %d", patch_count)
                                
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
                # print(bn_var.patch_inst.inst_print())
                ast = bn_var.asm_syntax_tree
                if repr(ast.left) == 'RegNode':
                    # If this is just a register node (e.g., rcx#3)
                    if reg == ast.left.value:
                        # base_offset = int(bn_var.offset)
                        offset_reg = re.search(offset_expr_regex, bn_var.offset_expr)
                        if offset_reg:
                            base_offset = offset_reg.group(1)
                            base_reg = offset_reg.group(2)
            
            if base_reg is not None:
                offset = str(int(inst_ssa.right.__str__(), base=16) + int(base_offset))
                expr = offset + "(" + base_reg + ")"
            else:
                offset = str(int(inst_ssa.right.__str__(), base=16))
                expr = offset + "(" + reg.reg.__str__() + ")"
            
            log.debug(expr)
            return expr
    
    def gen_ast(self, llil_fun, llil_inst):
        # log.info("Generating AST")
        if type(llil_inst) == binaryninja.lowlevelil.SSARegister:
            # Register
            reg_def = llil_fun.get_ssa_reg_definition(llil_inst)
            if reg_def != None:
                if type(reg_def.src) == binaryninja.lowlevelil.LowLevelILConstPtr:
                    log.error("Global")
                    return None
                else:
                    node = RegNode(llil_inst)
                    return node    
            else:
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
                log.debug("Reg ref %s", reg_def)
                if type(reg_def.src) == binaryninja.lowlevelil.LowLevelILConstPtr:
                    log.error("Global")
                    return None
                else:
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
        if inst_ssa.operation == LowLevelILOperation.LLIL_STORE_SSA:
            left = self.gen_ast(llil_fun, inst_ssa.dest) 
            right = self.gen_ast(llil_fun, inst_ssa.src)
            root_node = BnSSAOp(left, "=", right)
            return root_node
        
    def asm_lex_analysis(self, var_name, llil_fun, llil_inst):
        print("")
        log.warning("ASM Lexical Analysis: %s", llil_inst)
        arrow = 'U+21B3'
        dis_inst = self.bv.get_disassembly(llil_inst.address)
        # Example: mov     qword [rbp-0x8], rax 
        dis_inst_pattern    = re.search(r"(\b[a-z]+\b)\s*(.*),\s(.*)", dis_inst)
        offset_pattern = r'(\b[qword ptr|dword ptr|byte ptr]+\b)\s\[(%.*)([*+\/-]0x[a-z,0-9].*)\]'
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
        patch_inst = None
        if re.search(r'(qword ptr|dword ptr|byte ptr)', src):
            log.debug("ptr Source")
            suffix_regex = re.search(r'(qword ptr|dword ptr|byte ptr)', src)
            if suffix_regex != None:
                suffix = suffix_regex.group(1)
                # log.debug("%s %s %s %s", inst_type, src, dest, suffix)
                offset_regex = re.search(offset_pattern, src)
                expr = str(int(offset_regex.group(3),base=16)) + "(" + offset_regex.group(2) + ")"
                patch_inst = PatchingInst(inst_type, conv_suffix(suffix),
                                          conv_imm(expr), conv_imm(dest))
        elif re.search(r'(qword ptr|dword ptr|byte ptr)', dest):
            log.debug("ptr Dest")
            suffix_regex = re.search(r'(qword ptr|dword ptr|byte ptr)', dest)
            if suffix_regex != None:
                suffix = suffix_regex.group(1)
                log.debug("%s %s %s %s", inst_type, src, dest, suffix)
                offset_regex = re.search(offset_pattern, dest)
                expr = str(int(offset_regex.group(3),base=16)) + "(" + offset_regex.group(2) + ")"
                patch_inst = PatchingInst(inst_type=inst_type, suffix=conv_suffix(suffix),
                                          src=conv_imm(src), dest=conv_imm(expr))
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
                                          dest=conv_imm(dest), src=conv_imm(src))
            
                
        # log.debug(patch_inst)
        if patch_inst != None:
            log.debug(patch_inst.inst_print())
        log.debug("%s", dis_inst)
        log.debug("\t%s %s", chr(int(arrow[2:], 16)), llil_inst)
        asm_syntax_tree = self.gen_ast(llil_fun, llil_inst)
        # print(asm_syntax_tree)
        parse_ast(asm_syntax_tree)
        offset_expr = self.calc_ssa_off_expr(llil_inst.ssa_form)
        # src_offset_expr [0] | dest_offset_expr [1]
        bn_var = BnVarData(var_name, dis_inst, patch_inst, 
                           offset_expr, asm_syntax_tree)
        print(bn_var)
        return bn_var
    
    # Need debug info to handle static functions
    def analyze_binary(self, funlist):
        print("Step: Binary Ninja")
        gen_regs = {"%rax","%rbx","%rcx","%rdx"}
        for func in self.bv.functions:
            self.fun = func.name
            if self.fun in funlist:
                addr_range = func.address_ranges[0]
                begin   = addr_range.start
                end     = addr_range.end
                log.info("Function: %s | begin: %s | end: %s", func.name, hex(begin), hex(end))
                llil_fun = func.low_level_il
                for llil_bb in llil_fun:
                    for llil_inst in llil_bb:
                        print(llil_inst, llil_inst.operation)
                        mapped_il = llil_inst.mapped_medium_level_il
                        # log.debug("%s | %s", llil_inst, mapped_il)
                        if llil_inst.operation == LowLevelILOperation.LLIL_SET_REG:
                            # print(llil_inst, llil_inst.operation)
                            if len(mapped_il.vars_read) > 0:
                                # print(inst)
                                temp_var = mapped_il.vars_read[0]
                                var_name = temp_var.name
                                dest_reg = llil_inst.ssa_form.dest
                                # Avoid RSP registers
                                if (temp_var.core_variable.source_type == VariableSourceType.StackVariableSourceType and "var" in var_name 
                                    and dest_reg.reg.name in gen_regs):
                                    bn_var = self.asm_lex_analysis(var_name, llil_fun, llil_inst)
                                    self.bn_var_list.append(bn_var)
                        # If store -> vars written
                        elif llil_inst.operation == LowLevelILOperation.LLIL_STORE:
                            # print(llil_inst, llil_inst.operation)
                            if len(mapped_il.vars_written) > 0:
                                # print(llil_inst)
                                temp_var = mapped_il.vars_written[0]
                                var_name = temp_var.name
                                # Avoid RSP registers
                                if (temp_var.core_variable.source_type == VariableSourceType.StackVariableSourceType and "var" in var_name):
                                    bn_var = self.asm_lex_analysis(var_name, llil_fun, llil_inst)
                                    self.bn_var_list.append(bn_var)
                        else:
                            # print(llil_inst, llil_inst.operation)
                            None

            bn_fun_var_info[self.fun] = self.bn_var_list.copy()
            self.bn_var_list.clear()
            # pprint(bn_fun_var_info[self.fun], width=1)
                
    def __init__(self, bv):
        self.bv = bv
        self.fun = None
        
if __name__ == '__main__':
    process_argument(sys.argv[1:])
    