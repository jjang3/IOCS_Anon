from __future__ import print_function
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

fun_patch_tgts      = dict()
fun_off_to_table    = dict()

# This dict is for static function (numcompare (0 var): 0x658b vs numcompare (5 vars): 0x163ea)
fun_entry_to_args   = dict()

class SizeType(Enum):
    CHAR = 1
    INT = 4
    CHARPTR = 8
    
def generate_table(varcount, target_dir):
    varlist = list()
    if varcount % 2 != 0:
        # This is to avoid malloc(): corrupted top size error, malloc needs to happen in mod 2
        varcount += 1
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
""" % (varcount)

    count = 0
    while count <= varcount: 
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
    imm_pattern = r"(\$)(.*)"
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
        new_imm = imm_regex.group(1) + str(offset)
        return new_imm
    else:
        return imm
        
    
def process_argument(argv):
    inputfile = ''
    funfile = ''
    dirloc = None
    try:
        opts, args = getopt.getopt(argv,"hfic:",["binary=","fun=","dir="])
    except getopt.GetoptError:
        print ('binary_patch.py --binary <binary> --fun <fun.list> --dir <dir name>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('binary_patch.py --binary <binary> --fun <fun.list> --dir <dir name>')
            sys.exit()
        elif opt in ("-b", "--binary"):
            inputfile = arg
        elif opt in ("-f", "--fun"):
            funfile = arg
        elif opt in ("-d", "--dir"):
            dirloc = arg
    process_binary(inputfile, funfile, dirloc)

offset_dict         = dict()
prog_offset_set     = dict()
struct_offset_set   = dict()
table_offset        = 0
def process_binary(filename, funfile, dirloc):
    global var_count
    global dwarf_var_count
    target_dir = None        
    print("Dirloc", dirloc)
    if dirloc != None:
        print("Here")
        target_dir = os.path.join(os.path.dirname(os.path.abspath(filename)), dirloc)
        # filename = os.path.join(target_dir, filename)
        # funfile = os.path.join(target_dir, funfile)
        # target_dir = Path(os.path.abspath(filename))
    else:
        target_dir = Path(os.path.abspath(filename))
        target_dir = target_dir.parent.parent.joinpath("result", os.path.splitext((os.path.basename(filename)))[0])
        funfile = target_dir.joinpath("taint.in")
        filename = target_dir.joinpath(os.path.splitext((os.path.basename(filename)))[0] + ".out")
        # target_dir= (os.path.abspath(filename)) #os.path.abspath(os.path.abspath(os.path.dirname))

    print("\tTarget dir:", target_dir)
    print(funfile)

    target_file = target_dir.joinpath(os.path.splitext((os.path.basename(filename)))[0] + ".s")
    print("\tTarget file: ", target_file, "\n\tTaint file: ", funfile)
    # print(target_file, funfile)
    if funfile != "":
        with open(funfile) as c:
            for line in c:
                funlist = line.split(",")
                
    dir_list = os.listdir(target_dir)
    print(filename, funfile, target_dir)
    # --- DWARF analysis --- #
    dwarf_analysis(funlist, filename)
    
    #--- Binary Ninja Analysis --- #
    print("Binary ninja input:", filename)
    with load(filename.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
        print("Here")                  
        arch = Architecture['x86_64']
        bn = BinAnalysis(bv)
        bn.analyze_binary(funlist)

    var_count += dwarf_var_count
    # Based on variable counts found by static analysis + dwarf analysis, generate table.
    generate_table(var_count, target_dir)

    if dirloc != '':
        for dir_file in dir_list:
            if (dir_file.endswith('.s')):
                process_file(funlist, target_dir, dir_file)
    else:
        process_file(funlist, target_dir, target_file)
            

fun_var_info = dict()
fun_ignore_info = dict()
struct_list = list()

@dataclass(unsafe_hash = True)
class StructData:
    name: Optional[str] = None
    size: int = None
    line: int = None
    member_list: Optional[list] = None
    
@dataclass(unsafe_hash = True)
class VarData:
    name: str = None
    struct_type: str = None
    offset: str = None

@dataclass
class PatchingInst:
    inst_type: Optional[str] = None
    src: Optional[str] = None
    dest: Optional[str] = None
    offset: Optional[str] = None
    suffix: Optional[str] = None
    # fun: Optional[str] = None

var_count = 0
dwarf_var_count = 0
def dwarf_analysis(funlist, filename):
    global dwarf_var_count
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()
        
        # The location lists are extracted by DWARFInfo from the .debug_loc
        # section, and returned here as a LocationLists object.
        location_lists = dwarfinfo.location_lists()

        # This is required for the descriptions module to correctly decode
        # register names contained in DWARF expressions.
        set_global_machine_arch(elffile.get_machine_arch())

        # Create a LocationParser object that parses the DIE attributes and
        # creates objects representing the actual location information.
        loc_parser = LocationParser(location_lists)
        target_fun = bool()
        reg_regex = r"(?<=\(DW_OP_fbreg:\s)(.*)(?=\))"
        rbp_regex = r"(?<=\(DW_OP_breg.\s\(rbp\):\s)(.*)(?=\))"
        off_regex = r"(?<=\(DW_OP_plus_uconst:\s)(.*)(?=\))"
        temp_struct = None
        funname = None
        lowpc = None # Start address
        var_list = list()
        var_blacklist = list()
        for CU in dwarfinfo.iter_CUs():
            # This is required for a program with only one function (main)
            DIE_count = sum(1 for _ in CU.iter_DIEs()) - 1
            DIE_index = 0
            # print(DIE_count)
            last_die_tag = []
            temp_struct = None
            temp_struct_members = list()
            for DIE in CU.iter_DIEs():
                # print(DIE_index, DIE.tag)
                DIE_index += 1
                # Check if this attribute contains location information
                #     print("----------------------------------------------------------------------------\n")
                if (DIE.tag == "DW_TAG_subprogram"):
                    if (len(var_list) != 0 and funname is not None):
                        # Store the variable for the function if finihsed
                        # print("Store var_list for", funname, len(var_list))
                        print(colored("Store var_list for %s | Var count: %d" % (funname, len(var_list)), 'blue', attrs=['reverse']))
                        pprint(var_list)
                        pprint(var_blacklist)
                        dwarf_var_count += len(var_list)
                        delete_set = set()
                        delete_list = list()
                        
                        # for item in var_list:
                        #     # For sequential sort function
                        #     if item.name == "nlo" and funname == "sequential_sort":
                        #         var_list.remove(item)
                        fun_var_info[funname] = var_list.copy()
                        fun_entry_to_args[hex(lowpc)] = len(var_list)
                        print(fun_entry_to_args[hex(lowpc)], hex(lowpc))
                        print(var_list)
                        
                        # -- This is used to debug specific variable --
                        # debug_var_count = 3
                        # debug_var_list = var_list[0:debug_var_count]
                        # delete_list = debug_var_list.copy()
                        # fun_entry_to_args[hex(lowpc)] = len(debug_var_list)
                        # pprint(debug_var_list)
                        # print(len(debug_var_list))
                        # # Keeping specific variable
                        # # for item in debug_var_list:
                        # #     if item.name != "i":
                        # #         print("Removing: ", item.name)
                        # #         delete_set.add(item)
                        # #     else:
                        # #         print("Keeping: ", item.name)
                        # # Removing specific variable
                        # for item in debug_var_list:
                        #     if item.name == "new_column_info_alloc":
                        #         delete_set.add(item)

                        # # pprint(delete_set)
                        # # pprint(delete_list)
                        # for del_item in delete_list:
                        #     if del_item in delete_set:
                        #         print(del_item, "removed")
                        #         debug_var_list.remove(del_item)

                        # pprint(debug_var_list)
                        # dwarf_var_count += len(debug_var_list)
                        # fun_var_info[funname] = debug_var_list.copy()
                        # debug_var_list.clear()
                        # -- End debug -- #
                        
                        fun_ignore_info[funname] = var_blacklist.copy()
                        var_list.clear()
                        var_blacklist.clear()
                    elif (len(var_blacklist) != 0 and funname is not None):
                        # In case if a function doesn't have local variable, but have blacklist
                        var_blacklist.clear()
                    target_fun = False
                    fun_frame_base = None
                    
                    for attr in DIE.attributes.values():
                        if loc_parser.attribute_has_location(attr, CU['version']):
                            lowpc = DIE.attributes['DW_AT_low_pc'].value
                            highpc_attr = DIE.attributes['DW_AT_high_pc']
                            highpc_attr_class = describe_form_class(highpc_attr.form)
                            if highpc_attr_class == 'address':
                                highpc = highpc_attr.value
                            elif highpc_attr_class == 'constant':
                                highpc = lowpc + highpc_attr.value
                            else:
                                print('Error: invalid DW_AT_high_pc class:',
                                    highpc_attr_class)
                                continue
                            funname = DIE.attributes["DW_AT_name"].value.decode()
                            if funname in funlist:
                                target_fun = True
                                print("Target fun: ", target_fun)
                                print("Function name:", funname, "\t| Begin: ", hex(lowpc), "\t| End:", hex(highpc))
                            # print('  Found a compile unit at offset %s, length %s' % (
                            #     CU.cu_offset, CU['unit_length']))
                            loc = loc_parser.parse_from_attribute(attr, CU['version'])
                            if isinstance(loc, list):
                                for loc_entity in loc:
                                    if isinstance(loc_entity, LocationEntry):
                                        offset = describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, CU.cu_offset)
                                        if "rbp" in offset:
                                            if rbp_offset := re.search(rbp_regex, offset):
                                                fun_frame_base = int(rbp_offset.group(1))
                                                # print(fun_frame_base)
                        # if (attr.name == "DW_AT_type"):
                        #     refaddr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
                        #     type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, DIE.cu)
                        #     print(type_die)
                    if target_fun == True:
                        print(colored("Target fun %s" % (funname), 'green', attrs=['reverse']))
                    
                if (DIE.tag == "DW_TAG_variable"):
                    var_name = None
                    reg_offset = None
                    struct_name = None
                    type_die = None
                    for attr in DIE.attributes.values():
                        offset = None
                        if (attr.name == "DW_AT_name" and target_fun == True):
                            print("\tVariable name:", DIE.attributes["DW_AT_name"].value.decode())
                            var_name = DIE.attributes["DW_AT_name"].value.decode()     
                        if (loc_parser.attribute_has_location(attr, CU['version']) and target_fun == True):
                            loc = loc_parser.parse_from_attribute(attr,
                                                                CU['version'])
                            if isinstance(loc, LocationExpr):
                                offset = describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset)
                                if offset_regex := re.search(reg_regex, offset):
                                    var_offset = int(offset_regex.group(1))
                                    var_offset += fun_frame_base
                                    reg_offset = str(var_offset) + "(%rbp)" 
                                    # print("\t\tStarting offset: ", reg_offset)
                        if (attr.name == "DW_AT_type" and target_fun == True):
                            try:
                                refaddr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
                                type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, DIE.cu)
                                if type_die.tag == "DW_TAG_structure_type":
                                    if 'DW_AT_name' in type_die.attributes:
                                        struct_name = type_die.attributes['DW_AT_name'].value.decode()
                                        print("\t\tStruct type found: ", struct_name)
                                        log.debug("\tStruct type found: %s", struct_name)
                                elif type_die.tag == "DW_TAG_typedef":
                                    if 'DW_AT_name' in type_die.attributes:
                                        typedef_name = type_die.attributes['DW_AT_name'].value.decode()
                                        typedef_ref = type_die.attributes['DW_AT_type'].value + type_die.cu.cu_offset
                                        typedef_ref_type_die = dwarfinfo.get_DIE_from_refaddr(typedef_ref, type_die.cu)
                                        # print(typedef_ref_type_die.tag, typedef_ref_type_die)
                                        if (typedef_ref_type_die.tag == "DW_TAG_structure_type"):
                                            log.debug("\tStruct type found: %s", typedef_name)
                                            byte_size   = typedef_ref_type_die.attributes['DW_AT_byte_size'].value
                                            line_num    = typedef_ref_type_die.attributes['DW_AT_decl_line'].value
                                            print(byte_size, line_num)
                                            for item in struct_list:
                                                if item.size == byte_size and item.line == line_num:
                                                    if typedef_name != None:
                                                        item.name = typedef_name
                                elif type_die.tag == "DW_TAG_pointer_type":
                                    # print(hex(type_die.attributes['DW_FORM_ref4'].value))
                                    ptr_ref = type_die.attributes['DW_AT_type'].value + type_die.cu.cu_offset
                                    ptr_type_die = dwarfinfo.get_DIE_from_refaddr(ptr_ref, type_die.cu)
                                    print("Pointer:", ptr_type_die.tag, ptr_type_die.attributes)
                                    if 'DW_AT_name' in ptr_type_die.attributes:
                                        obj_name = ptr_type_die.attributes['DW_AT_name'].value.decode()
                                        if (ptr_type_die.tag == "DW_TAG_structure_type"):
                                            print("\t\tStruct ptr type found: ", obj_name)
                                        elif (ptr_type_die.tag == "DW_TAG_base_type"):
                                            print("\t\tPointer type found: ", obj_name)
                                        elif (ptr_type_die.tag == "DW_TAG_typedef"):
                                            print("\t\tTypedef ptr type found: ", obj_name)
                                        elif (ptr_type_die.tag == "DW_TAG_const_type"):
                                            print("\t\tConst ptr type found: ", obj_name)
                                        # dwarf_var_count += 1
                                        struct_name = obj_name
                                        # for struct_item in struct_set:
                                        #     if struct_name == struct_item.name:
                                        #         # dwarf_var_count += len(struct_item.member_list)
                                        #         None
                                    elif (ptr_type_die.tag == "DW_TAG_pointer_type"):
                                        print("\t\tDouble Pointer type found")
                                        struct_name = "double"
                                # else:
                                    None
                                    # dwarf_var_count += 1
                            except Exception  as err:
                                print(err)
                    
                    temp_var = VarData(var_name, struct_name, reg_offset)
                    # Avoid struct variable and variable which offset cannot be determined in compile-time
                    if type_die != None:
                        # Question (think about whether we can / need to support these types:)
                        # or type_die.tag == "DW_TAG_array_type" or type_die.tag == "DW_TAG_enumeration_type"
                        # Comment: I could probably support array type, but is it necessary yet? probably not.
                        if (type_die.tag == "DW_TAG_base_type" or type_die.tag == "DW_TAG_typedef") and reg_offset != None:
                            print("Type:", type_die.tag)
                            print("Inserting into the list: ", temp_var, "\n")
                            var_list.append(temp_var)
                        elif (type_die.tag == "DW_TAG_pointer_type" or type_die.tag == "DW_TAG_structure_type" or temp_var.struct_type != None) and reg_offset != None:
                            print("Type:", type_die.tag)
                            print("Inserting into the blacklist: ", reg_offset, "\n")
                            var_blacklist.append(reg_offset)
                
                # This is used to catch struct name in a global fashion.
                if (DIE.tag == "DW_TAG_structure_type"):
                    # print(DIE.attributes)
                    byte_size = None
                    line_num = None
                    if 'DW_AT_byte_size' in DIE.attributes:
                        byte_size   = DIE.attributes['DW_AT_byte_size'].value
                    if 'DW_AT_decl_line' in DIE.attributes:
                        line_num    = DIE.attributes['DW_AT_decl_line'].value
                    if byte_size != None and line_num != None:
                        temp_struct = StructData(None, byte_size, line_num, None)
                    print(temp_struct)
                # This is used to catch member variables of a struct 
                if (DIE.tag == "DW_TAG_member"):
                    attr_name = None
                    offset = None
                    for attr in DIE.attributes.values():
                        if(attr.name == "DW_AT_name"):
                            attr_name = DIE.attributes["DW_AT_name"].value.decode()
                            # log.debug("\tStruct member found: %s", attr_name)
                        if loc_parser.attribute_has_location(attr, CU['version']):
                            loc = loc_parser.parse_from_attribute(attr,
                                                                CU['version'])
                            if(attr.name == "DW_AT_data_member_location"):
                                # print(attr)
                                if isinstance(loc, LocationExpr):
                                    offset = re.search(off_regex, describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset))
                                    # log.debug(offset.group(1))
                        if (attr.name == "DW_AT_type"):
                            refaddr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
                            type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, DIE.cu)
                            print(refaddr)
                    log.debug("Struct member name: %s\t| Offset: %s\n", attr_name, offset.group(1))
                    temp_struct_members.append((attr_name, offset.group(1)))
                # Struct stuff


                if (DIE.tag == None and len(var_list) != 0 and DIE_index == DIE_count):
                    #  This is used to store the variable list for a program with only one function
                    print(colored("Store var_list for %s | Var count: %d" % (funname, len(var_list)), 'blue', attrs=['reverse']))
                    pprint(var_list)
                    pprint(var_blacklist)
                    dwarf_var_count += len(var_list)
                    fun_var_info[funname] = var_list.copy()
                    fun_ignore_info[funname] = var_blacklist.copy()
                    var_list.clear()
                    var_blacklist.clear()
                elif (DIE.tag == None):
                    last_tag = last_die_tag.pop()
                    if (last_tag == "DW_TAG_member"):
                        # Put members into the struct object
                        if temp_struct != None: 
                            temp_struct.member_list = temp_struct_members.copy()
                            # log.debug("Inserting temp_struct")
                            # print(temp_struct)
                            struct_list.append(temp_struct)
                        temp_struct_members.clear()
                        temp_struct = None
                last_die_tag.append(DIE.tag)
                # elif (DIE.tag == None and funname != None and lowpc != None and target_fun is True and len(var_list) == 0):
                #     # print(colored("Store var_list for %s | Var count: %d" % (funname, len(var_list)), 'blue', attrs=['reverse']))
                #     fun_entry_to_args[lowpc] = len(var_list)
                #     print(fun_entry_to_args[lowpc])
            # if (target_fun == True):
            #     print("----------------------------------------------------------------------------\n")
            # ------- After DIE ------- #  
    
    # for item in struct_set:
    #     print(item)
    
    # for item in fun_var_info:
    #     print("Variables for:", item)
    #     for var in fun_var_info[item]:
    #         print(var)
    print("Variable count: ", dwarf_var_count)

def patch_inst(disassembly, temp: PatchingInst, offset_targets: dict):
    log.critical("Patch the instruction %s", disassembly)
    log.debug(temp)
    # This regex is used to find offset (e.g., -16(%rbp)) to determine or load
    off_regex       = r"(-|\$|)(-?[0-9].*\(%r..\))"
    tgt_offset      = int()
    for offset in offset_targets:
        if offset[0] == temp.offset:
            tgt_offset = offset[1]
    
    store_or_load   = str()
    if re.search(off_regex, temp.src):
        store_or_load = "load"
    elif re.search(off_regex, temp.dest):
        store_or_load = "store"
    else:
        store_or_load = None

    if temp.inst_type == "mov":
        if store_or_load == "store":
            if temp.suffix == "l":
                new_inst_type = "movl_set_gs"
            elif temp.suffix == "q":
                new_inst_type = "movq_set_gs"
            elif temp.suffix == "b":
                new_inst_type = "movb_set_gs"
            log.info("Patching with mov_set_gs")
            line = re.sub(r"(\b[a-z]+\b).*", "#%s\n\t%s\t%s, %d\n" % (disassembly, new_inst_type, temp.src, tgt_offset), disassembly)
        elif store_or_load == "load":
            if temp.suffix == "l":
                new_inst_type = "movl_load_gs"
            elif temp.suffix == "q":
                new_inst_type = "movq_load_gs"
            elif temp.suffix == "b":
                new_inst_type = "movb_load_gs"
            log.info("Patching with mov_load_gs")
            line = re.sub(r"(\b[a-z]+\b).*", "#%s\n\t%s\t%s, %d\n" % (disassembly,new_inst_type, temp.dest, tgt_offset), disassembly)
    elif temp.inst_type == "movsx":
        if store_or_load == "store":
            if temp.suffix == "b":
                new_inst_type = "movsxb_set_gs"
            line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %d\n" % (new_inst_type, temp.src, tgt_offset), disassembly)
        elif store_or_load == "load":
            log.info("Patching with movsx_load_gs")
            new_inst_type = "movzx_load_gs"
            line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %d\n" % (new_inst_type, temp.dest, tgt_offset), disassembly)
    elif temp.inst_type == "movzx":
        if store_or_load == "store":
            if temp.suffix == "b":
                new_inst_type = "movzxb_set_gs"
            line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %d\n" % (new_inst_type, temp.src, tgt_offset), disassembly)
        elif store_or_load == "load":
            new_inst_type = "movzx_load_gs"
            log.info("Patching with movzx_load_gs")
            line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %d\n" % (new_inst_type, temp.dest, tgt_offset), disassembly)
    elif temp.inst_type == "lea":
        new_inst_type = "lea_gs"
        log.info("Patching with lea_gs")
        #line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %d\n" % (new_inst_type, temp.dest, tgt_offset), disassembly)
        line = re.sub(r"(\b[a-z]+\b).*", "#%s\n\t%s\t%s, %d\n" % (disassembly,new_inst_type, temp.dest, tgt_offset), disassembly)
    elif temp.inst_type == "cmp":
        # print(temp, store_or_load)
        if store_or_load == "store":
            if temp.suffix == "l":
                new_inst_type = "cmpl_store_gs"
            elif temp.suffix == "q":
                new_inst_type = "cmpq_store_gs"
            elif temp.suffix == "b":
                new_inst_type = "cmpb_store_gs"
            line = re.sub(r"(\b[a-z]+\b).*", "#%s\n\t%s\t%s, %d\n" % (disassembly,new_inst_type, temp.src, tgt_offset), disassembly)
        elif store_or_load == "load":    
            if temp.suffix == "l":
                new_inst_type = "cmpl_load_gs"
            elif temp.suffix == "q":
                new_inst_type = "cmpq_load_gs"
            elif temp.suffix == "b":
                new_inst_type = "cmpb_load_gs"
            line = re.sub(r"(\b[a-z]+\b).*", "#%s\n\t%s\t%s, %d\n" % (disassembly,new_inst_type, temp.dest, tgt_offset), disassembly)
    elif temp.inst_type == "add":
        log.info("Patching with add_gs")
        if store_or_load == "store":
            # new_inst_type = "add_store_gs"
            if temp.suffix == "l":
                new_inst_type = "addl_store_gs"
            elif temp.suffix == "q":
                new_inst_type = "addq_store_gs"
            line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %d\n" % (new_inst_type, temp.src, tgt_offset), disassembly)
        elif store_or_load == "load":
            new_inst_type = "add_load_gs"
            line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %d\n" % (new_inst_type, temp.dest, tgt_offset), disassembly)
    elif temp.inst_type == "sub":
        log.info("Patching with sub_gs")
        if store_or_load == "store":
            if temp.suffix == "l":
                new_inst_type = "subl_store_gs"
            elif temp.suffix == "q":
                new_inst_type = "subq_store_gs"
            line = re.sub(r"(\b[a-z]+\b).*", "#%s\n\t%s\t%s, %d\n" % (disassembly,new_inst_type, temp.src, tgt_offset), disassembly)
        elif store_or_load == "load":
            if temp.suffix == "l":
                new_inst_type = "subl_load_gs"
            elif temp.suffix == "q":
                new_inst_type = "subq_load_gs"
            line = re.sub(r"(\b[a-z]+\b).*", "#%s\n\t%s\t%s, %d\n" % (disassembly,new_inst_type, temp.dest, tgt_offset), disassembly)
    elif temp.inst_type == "shl":
        log.info("Patching with shl_gs")
        if store_or_load == "store":
            if temp.suffix == "l":
                new_inst_type = "shll_set_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %d\n" % (new_inst_type, temp.src, tgt_offset), disassembly)
            elif temp.suffix == "q":
                new_inst_type = "shlq_set_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %d\n" % (new_inst_type, temp.src, tgt_offset), disassembly)
    elif temp.inst_type == "imul":
        log.info("Patching with imul_gs")
        if store_or_load == "store":
            if temp.suffix == "l":
                new_inst_type = "imull_store_gs"
            elif temp.suffix == "q":
                new_inst_type = "imulq_store_gs"
            line = re.sub(r"(\b[a-z]+\b).*", "#%s\n\t%s\t%s, %d\n" % (disassembly,new_inst_type, temp.src, tgt_offset), disassembly)
        elif store_or_load == "load":
            if temp.suffix == "l":
                new_inst_type = "imull_load_gs"
            elif temp.suffix == "q":
                new_inst_type = "imulq_load_gs"
            line = re.sub(r"(\b[a-z]+\b).*", "#%s\n\t%s\t%s, %d\n" % (disassembly,new_inst_type, temp.dest, tgt_offset), disassembly)
    elif temp.inst_type == "div":
        log.info("Patching with div_gs")
        if store_or_load == "load":
            if temp.suffix == "l":
                new_inst_type = "divl_load_gs"
            elif temp.suffix == "q":
                new_inst_type = "divq_load_gs"
            line = re.sub(r"(\b[a-z]+\b).*", "#%s\n\t%s\t%d\n" % (disassembly,new_inst_type, tgt_offset), disassembly)
    log.info(line)
    return line
    
def process_file(funlist, target_dir, target_file):
        # if (target_file.endswith('.asm')):
        # print(target_file)
        
        print(os.path.join(target_dir, target_file))
        debug_file = target_file + ".bak"
        if os.path.isfile(os.path.join(target_dir, debug_file)):
            print("Copying debug file")
            shutil.copyfile(os.path.join(target_dir, debug_file), os.path.join(target_dir, target_file))
        else:
            print("No debug file exists")
        # print(debug_file)
        # exit()
        debug = False
        patch_count = 0
        with fileinput.input(os.path.join(target_dir, target_file), inplace=(not debug), encoding="utf-8", backup='.bak') as f:
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
                    print("""# ASM Rewriting Macros:
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
""", end='')
                fun_begin = re.search(fun_begin_regex, line)
                if fun_begin is not None:
                    if fun_begin.group(1) in funlist:
                        currFun = fun_begin.group(1)
                        try:
                            patch_targets = fun_patch_tgts[currFun]
                            offset_targets = fun_off_to_table[currFun]   
                            check = True
                        except Exception as err:
                            log.error("Skipping", type(err))
                            check = False
                
                fun_end = re.search(fun_end_regex, line)
                if fun_end is not None:
                    check = False
            
                if check == True: # and patch_count < max_patch:
                    dis_line = line.rstrip('\n')
                    # log.debug(pprint(patch_targets))
                    # log.debug(pprint(offset_targets))
                    # mnemonic source, destination AT&T
                    log.debug(dis_line)
                    dis_regex   = re.search(dis_line_regex, dis_line)
                    sh_regex    = re.search(sh_line_regex, dis_line)
                    sing_regex  = re.search(sing_line_regex, dis_line)
                    # log.error("%s %s %s", dis_regex,sh_regex,sing_regex)
                    temp_inst = None
                    if dis_regex is not None:
                        inst_type   = dis_regex.group(1)
                        suffix      = dis_regex.group(2)
                        src         = dis_regex.group(3)
                        dest        = dis_regex.group(4)
                        expr        = str()
                        mov_regex   = r"mov"
                        if re.search(mov_regex, inst_type):
                            if suffix == "zbl":
                                inst_type = "movzx"
                                suffix = "b"
                            elif suffix == "sbl":
                                inst_type = "movsx"
                                suffix = "b"
                    
                        off_regex   = r"(-|)([a-z,0-9].*\(%r..\))"
                        if re.search(off_regex, src):
                            expr = src
                        elif re.search(off_regex, dest):
                            expr = dest
                        else:
                            expr = None
                        
                        # print("Inst Type: ", inst_type, "\t|\tSuffix: ", conv_suffix(suffix), "\t| src: ", src,"\t| dest: ", dest)
                        temp_inst = PatchingInst(conv_instr(inst_type), src, dest, expr, suffix)
                        log.warning("Temp: %s", temp_inst)
                    elif sh_regex is not None:
                        # print(sh_regex)
                        log.debug(sh_regex)
                        inst_type   = sh_regex.group(1)
                        suffix      = sh_regex.group(2)
                        src         = "$1"
                        dest        = sh_regex.group(3)
                        expr = str()
                        off_regex   = r"(-|)([a-z,0-9].*\(%r..\))"
                        if re.search(off_regex, dest):
                            expr = dest
                        temp_inst = PatchingInst(conv_instr(inst_type), src, dest, expr, suffix)
                        log.warning("Temp: %s", temp_inst)
                    elif sing_regex is not None:
                        inst_type   = sing_regex.group(1)
                        suffix      = sing_regex.group(2)
                        src         = sing_regex.group(3)
                        expr = str()
                        off_regex   = r"(-|)([a-z,0-9].*\(%r..\))"
                        if re.search(off_regex, src):
                            expr = src
                        temp_inst = PatchingInst(conv_instr(inst_type), src, '', expr, suffix)
                        log.warning("Temp: %s", temp_inst)
                        
                    if temp_inst != None:
                        # pprint(patch_targets)
                        if temp_inst in patch_targets:
                            log.critical("Found")
                            replace_inst = str()
                            try:
                                replace_inst = patch_inst(dis_line, temp_inst, offset_targets)
                            except:
                                log.error("No offset exists")
                                # break
                            if replace_inst != None:
                                patch_count += 1
                                line = replace_inst
                                log.info(line)
                                print(line, end='')
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
            log.critical("Patch count %d", patch_count)
                                
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

class BinAnalysis:
    # Patch targets resulting from analysis of the current working function
    patch_tgts      = set()
    
    # Patch targets from utilizing the analysis result of the current working function
    cur_fun_tgts    = list()
    
    # Offset to table offset set of the current working function
    off_to_table    = set()
    
    def __init__(self, bv):
        self.bv = bv
        self.fun = None
        
    def search_var_tgts(self, expr, var_targets):
        log.debug("Searching %s", expr)
        # pprint(var_targets)
        for item in var_targets:
            if expr == item.offset:
                # print(expr, item.offset)
                return True
        return False
    
    def search_var(self, inst_ssa):
        mapped_MLLIL = inst_ssa.mapped_medium_level_il 
        # print(mapped_MLLIL)
        if mapped_MLLIL.operation != MediumLevelILOperation.MLIL_VAR:
            return self.search_var(inst_ssa.src)
        else:
            return mapped_MLLIL
        
    def find_var(self, var):
        for item in self.patch_tgts:
            if var == item[0]:
                log.critical("Found var")
                return True
        return False

    def find_off(self, offset, var_targets, ignore_targets):
        # spec_log.warning("\t%s", offset)
        try:
            offset_pattern = r'(\b[qword ptr|dword ptr]+\b)\s\[(%.*)([*+\/-]0x[a-z,0-9].*)\]'
            offset_regex = re.search(offset_pattern, offset)
            expr = str()
            expr = str(int(offset_regex.group(3),base=16)) + "(" + offset_regex.group(2) + ")"
            for item in ignore_targets:
                # print("Checking ignore: ", expr, item)
                if expr == item:
                    log.error("Found ignore target")
                    # spec_log.error("\tIgnore/Skip")
                    return False, None
            
            # pprint(var_targets)
            # What was the purpose of patch_tgts? var vs offset only
            # Purpose was to reduce the "overapproximation" of offset that is found if I don't check for the variable. Factor -> 229 variables vs 299 variables
            # Question: is it possible to reduce the overapproximation without relying on the variable?
            # pprint(self.patch_tgts)
            # for item in self.patch_tgts:
            #     if expr == item[1]:
            #         log.critical("Found the var")
            #         # spec_log.critical("Found the var")
            #         for tgt in var_targets:
            #             if expr == tgt.offset:
            #                 log.critical("Found the offset")
            #                 # spec_log.critical("Found the offset")
            #                 return True, expr
                    # return True, expr
            #  Question to ask(?) - Do I need to do variable check or just use the offset directly?
            for tgt in var_targets:
                if expr == tgt.offset:
                    log.critical("Found the offset")
                    # spec_log.critical("Found the offset")
                    return True, expr
            
            return False, None
        except:
            return False, None
    
    def calc_offset(self, inst_ssa, var_targets):
        arrow = 'U+21B3'
        log.info("Finding the offset of %s %s", inst_ssa, type(inst_ssa)) 
        try:
            if type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
                log.debug("%s LoadSSA", chr(int(arrow[2:], 16)))
                if inst_ssa.src_memory != None:
                    try:
                        if inst_ssa.src.left.src.reg == "fsbase": 
                            # log.warning("Found segment %s %s %s", inst_ssa.src.left, inst_ssa.src.right, inst_ssa.src.left.src.reg)
                            reg = inst_ssa.src.left.src.reg.__str__().split('base')
                            reg = ''.join(reg)
                            expr = str()
                            expr = reg + ":" + str(int(str(inst_ssa.src.right), 16))
                            return None
                        else:
                            # print("Not segment")
                            mapped_MLLIL = inst_ssa.mapped_medium_level_il # This is done to get the var (or find if not)
                            if mapped_MLLIL != None:
                                result = self.calc_offset(inst_ssa.src, var_targets)
                                if result != None:
                                    return result
                            else:
                                log.error("No variable assigned, skip")
                    except Exception as error:
                        if type(inst_ssa.src) == binaryninja.lowlevelil.LowLevelILConstPtr:
                            log.error("Global value, skip")
                            return None
                        else:
                            log.error("Error: %s", error)
            elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsa:
                try:
                    log.debug("%s SetRegSSA",  chr(int(arrow[2:], 16)))
                    result = self.calc_offset(inst_ssa.src, var_targets)
                    if result != None:
                        return result
                except Exception as error:
                    log.error("Error: %s", error)
            elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILStoreSsa:
                log.debug("%s StoreSSA",  chr(int(arrow[2:], 16)))
                try:
                    try:
                        result = self.calc_offset(inst_ssa.dest, var_targets)
                        if result != None:
                            return result
                    except Exception as error:
                        log.error("Error: %s", error)
                except Exception as error:
                    log.error("Error: %s", error)
            elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsaPartial:
                log.debug("%s RegSSAPartial %s",  chr(int(arrow[2:], 16)), inst_ssa.full_reg)
                result = self.calc_offset(inst_ssa.function.get_ssa_reg_definition(inst_ssa.full_reg), var_targets)
                return result
            elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
                log.debug("%s Arithmetic",  chr(int(arrow[2:], 16)))
                try:
                    reg = inst_ssa.left.src.reg.__str__()
                except:
                    reg = inst_ssa.left.__str__()
                if reg == "%rsp":
                    return None # We do not want any RSP
                
                if type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILLoadSsa:
                    result = self.calc_offset(inst_ssa.right, var_targets)
                    if result != None:
                        return result
                    else:
                        return None
                offset = str(int(inst_ssa.right.__str__(), base=16))
                # If the offset is part of "variable targets", then we try to return expr, else, 
                # we just return None
                log.debug("Offset: %s", offset)
                expr = offset + "(" + reg + ")"
                
                # os.system(f"pkill -f {os.path.basename(__file__)}")
                if self.search_var_tgts(expr, var_targets):
                    log.debug("Offset: %s", offset)
                    log.critical("Expr: %s", expr)
                    return expr
                else:
                    return None
        except:
            try:
                return self.calc_offset(inst_ssa.src, var_targets)
            except: 
                return None
        else:
            return None
        
    # Need debug info to handle static functions
    def analyze_binary(self, funlist):
        print("Step: Binary Ninja")
        total_var_count = 0
        for func in self.bv.functions:
            self.fun = func.name
            if func.name in funlist:            
                log.info("Function: %s | begin: %s", func.name, hex(func.start))
                spec_log.info("Function: %s | begin: %s", func.name, hex(func.start))
                # hlil_fun = func.high_level_il # Unused atm
                mlil_fun = func.medium_level_il
                llil_fun = func.low_level_il
                instr_fun = func.instructions
                var_targets = None  # Variable targets obtained from DWARF
                try:
                    if (fun_entry_to_args[hex(func.start)] is not None):
                        var_targets = fun_var_info[func.name]
                    ignore_targets = fun_ignore_info[func.name]
                    for item in var_targets:
                        spec_log.info("\tFun: %s | %s", func.name, item)
                    self.backward_slice(func.name, mlil_fun, llil_fun, instr_fun, var_targets, ignore_targets)
                    fun_patch_tgts[func.name] = self.cur_fun_tgts.copy()
                    for item in self.cur_fun_tgts:
                        log.debug(item)
                    fun_off_to_table[func.name] = self.off_to_table.copy()
                    spec_log.debug("Offset to table count: %d", len(self.off_to_table))
                    for item in self.off_to_table:
                        total_var_count += 1
                        spec_log.debug("Fun: %s | %s", func.name, item)
                    self.off_to_table.clear()
                    self.cur_fun_tgts.clear()
                except Exception as error:
                    log.error("No variable targets: %s", error)
        spec_log.critical("Total variable count: %d", total_var_count)
        log.info("Total variable count: %d", total_var_count)
        time.sleep(3)
                
    def backward_slice(self, name, medium, low, instr, var_targets, ignore_targets):
        """
        - Workflow of backward slice starts from the MLIL as it is the most intuitive way of observing the behavior
        After obtaining the informations (e.g., where malloc()'d variable is being used, register offset for local var)
        We start digging deeper into the lower level as intricate information is omitted in the MLIL.
         For example, you would not be able to know if malloc'd string of "test" is used later in printf function in the MLIL
        MLIL -> LLIL
        - MLIL used in this case is for the sake of gathering information; We will work on LLIL level to utilize the information
        gathered.
        """
        for mlil_bb in medium:
            for inst in mlil_bb:
                inst_ssa = inst.ssa_form
                log.warning("%s | %s", inst_ssa, inst_ssa.operation)
                # print(inst_ssa, inst_ssa.operation, inst_ssa.vars_address_taken, inst_ssa.vars_written[0].var, len(inst_ssa.vars_read), inst_ssa.vars_written[0].var.core_variable.source_type)
                # These operations are highest level of variable assignments are one we care about.
                if inst_ssa.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                    # First analyze any function call instructions (e.g., malloc/calloc) to find potential patch targets
                    # var_10 -> -8(%rbp), this information is going to be used and saved in the case when we analyze the LLIL
                    # To-do: Is there a need to analyze parameters of call instruction? Or not necessary.
                    patch_tgt = self.analyze_call_inst(inst_ssa, medium, var_targets, ignore_targets)
                    if patch_tgt != None:
                        # Try to find the Patch target: (<var int64_t var_28>, '-32(%rbp)') so it can be used in the find_var() to see if offset exists. Offset can be None which means it is useless.
                        self.patch_tgts.add(patch_tgt)
                        log.debug("Patch target: %s", patch_tgt)
                        # spec_log.info("Analyze Call Inst | Patch target: %s", patch_tgt)
                    else:
                        for param_var in inst_ssa.params:
                            # print(param_var)
                            patch_tgt = self.analyze_params(inst_ssa, param_var, medium, var_targets, ignore_targets)
                            if patch_tgt != None:
                                self.patch_tgts.add(patch_tgt)
                                log.debug("Patch target: %s", patch_tgt)
                                # spec_log.info("Analyze Params | Patch target: %s", patch_tgt)
                    None
                elif inst_ssa.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA or \
                     inst_ssa.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
                # Check if variable name exists for this MLIL instruction, and see whether it has been already checked
                # What does it mean if it doesn't exist (e.g., arg1#83 = &var_1d1 and [%rsp#15 - 8].q = &var_1d1)
                    try:
                        var = None
                        if len(inst_ssa.vars_address_taken) != 0:
                            # Ex: %rsi#1 = &var_1c
                            var = inst_ssa.vars_address_taken[0]
                        # elif len(inst_ssa.vars_read) == 0:
                        #     continue
                        elif inst_ssa.vars_written[0].var.core_variable.source_type == VariableSourceType.StackVariableSourceType:
                            # Ex: var_18#1 = %rax_1#2
                            var = inst_ssa.vars_written[0].var
                        elif inst_ssa.vars_read[0].var.core_variable.source_type == VariableSourceType.StackVariableSourceType:
                            # Ex: %rax_7#8 = var_1c
                            var = inst_ssa.vars_read[0].var
                        elif len(inst_ssa.vars_read) == 0:
                            continue
                            
                        # If variable is not found, then analyze the instruction
                        # print("Variable: ", var)

                        if self.find_var(var):
                            log.error("Found variable %s, skip", var)
                            continue
                        else:
                            log.info("%s | Analyze inst: %s", self.fun, inst_ssa)
                            # spec_log.info("%s | Analyze inst: %s", self.fun, inst_ssa)
                            patch_tgt = self.analyze_inst(inst_ssa, medium, var_targets, ignore_targets)
                            if patch_tgt != None:
                                self.patch_tgts.add(patch_tgt)
                                log.debug("Patch target: %s", patch_tgt)
                    except Exception as error:
                        log.error("%s", error)
                        # spec_log.error("%s | inst: %s", error, inst_ssa)
                elif inst_ssa.operation == MediumLevelILOperation.MLIL_STORE_SSA:
                    # [%rsp_5#9 - 8].q = &var_1d1 @ mem#68 -> mem#69
                    try:
                        var = None
                        if len(inst_ssa.vars_address_taken) != 0:
                            var = inst_ssa.vars_address_taken[0]
                            log.critical(var)
                        elif len(inst_ssa.vars_read) == 0:
                            continue
                        if self.find_var(var):
                            log.error("Found variable %s, skip", var)
                            continue
                        else:
                            log.info("%s | Analyze inst: %s", self.fun, inst_ssa)
                            # spec_log.info("%s | Analyze inst: %s", self.fun, inst_ssa)
                            patch_tgt = self.analyze_inst(inst_ssa, medium, var_targets, ignore_targets)
                            if patch_tgt != None:
                                self.patch_tgts.add(patch_tgt)
                                log.debug("Patch target: %s", patch_tgt)
                    except Exception as error:
                        log.error("%s", error)
                        
        # After all analysis is done with the MLIL level, find patch targets by dissecting disassembly of LLIL
        for llil_bb in low:
            for inst in llil_bb:
                self.find_patch_tgts(inst.address, var_targets, ignore_targets)
                
        # Offset-based checking
        for item in instr:
            # print(type(item[0][0]))
            # print(item)
            # if item[0][0].__str__() == "cmp":
            addr = item[1]
            self.find_patch_tgts(addr, var_targets, ignore_targets)
        # exit()
                
    # This function is the one that is used to add patch targets to be found in disassembly file
    def find_patch_tgts(self, addr, var_targets, ignore_targets):
        # pprint(var_targets)
        global table_offset
        dis_inst = self.bv.get_disassembly(addr)
        if dis_inst == None:
            return None
        log.warning("%s | Find patching tgt: %s", self.fun, dis_inst)
        # spec_log.info("%s | Find patching tgt: %s", self.fun, dis_inst)
        # Example: mov     qword [rbp-0x8], rax 
        dis_inst_pattern    = re.search(r"(\b[a-z]+\b)\s*(.*),\s(.*)", dis_inst)
        s_dis_inst_pattern  = re.search(r"(\b[a-z]+\b)\s*(.*)", dis_inst)
        inst_type           = str()
        src                 = str()
        dest                = str()
        if dis_inst_pattern != None:
            inst_type   = dis_inst_pattern.group(1)
            src         = dis_inst_pattern.group(2)
            dest        = dis_inst_pattern.group(3)
        elif s_dis_inst_pattern != None:
            inst_type   = s_dis_inst_pattern.group(1)
            src         = s_dis_inst_pattern.group(2)
        else:
            log.error("Regex failed %s", dis_inst)
        
        # spec_log.warning("\t%s %s %s", inst_type, src, dest)
        # Either source or dest can be ptr, so whichever one passes through, find offset in the set
        tgt_inst = None
        expr = None
        suffix = None
        # if re.search(r'(\b[qword ptr|dword ptr|byte ptr]+\b)', src):
        if re.search(r'(qword ptr|dword ptr|byte ptr)', src):
            log.debug("ptr Source")
            # spec_log.warning("\tSource")
            suffix_regex = re.search(r'(qword ptr|dword ptr|byte ptr)', src)
            if suffix_regex != None:
                suffix = suffix_regex.group(1)
            result, expr = self.find_off(src, var_targets, ignore_targets)
            if result and dest == None:
                tgt_inst = PatchingInst(inst_type=inst_type, dest=None, src=conv_imm(expr), offset=expr, suffix=conv_suffix(suffix)) # 
            elif result:
                tgt_inst = PatchingInst(inst_type=inst_type, dest=conv_imm(dest), src=conv_imm(expr), offset=expr, suffix=conv_suffix(suffix)) # expr -> None
        else:
            log.debug("ptr Dest")
            # spec_log.warning("\tDest")
            suffix_regex = re.search(r'(qword ptr|dword ptr|byte ptr)', dest)
            if suffix_regex != None:
                suffix = suffix_regex.group(1)
            result, expr = self.find_off(dest, var_targets, ignore_targets)
            if result:
                tgt_inst = PatchingInst(inst_type=inst_type, dest=conv_imm(expr), src=conv_imm(src), offset=expr, suffix=conv_suffix(suffix)) # expr -> None
        
        if tgt_inst != None:
            # Note: offset can already exist in the cur_fun_tgts as there are variety of ways offset can be used. Need to first check whether the offset exists, then decide to update offset or not.
            update = True
            cur_offset = int()
            for item in self.cur_fun_tgts:
                if tgt_inst.offset == item.offset:
                    update = False        
                    for offset in self.off_to_table:
                        # print(offset)
                        if offset[0] == tgt_inst.offset:
                            cur_offset = offset[1]
                    if not log_disable:
                        print(colored("Offset should not be updated", 'red', attrs=['reverse']))
                    break
                else:
                    cur_offset = table_offset
            # cur_offset is basically used to either ensure previously inserted instructions have the same offset, or we need to use the new offset
            
            log.debug("%s | offset: %d", tgt_inst, cur_offset)
            if tgt_inst.src == "%rsp" or tgt_inst.dest == "%rsp":
                log.error("Ignore RSP %s", tgt_inst)
                return
    
            if tgt_inst not in self.cur_fun_tgts:    
                log.critical(("Target inst not in cur fun target"))        
                if update:
                    if not log_disable:
                        print(colored("Offset is updating", 'green', attrs=['reverse']))
                        print(colored("Adding %s | Next table offset %s" % (tgt_inst, str(tgt_inst.offset)), 'blue', attrs=['reverse']))
                    self.cur_fun_tgts.append(tgt_inst)
                    self.off_to_table.add((tgt_inst.offset, table_offset))
                    table_offset += 8
                else:
                    # tgt_inst.offset = cur_offset
                    if not log_disable:
                        print(colored("Adding %s | Next table offset %s" % (tgt_inst, str(tgt_inst.offset)), 'blue', attrs=['reverse']))
                    self.cur_fun_tgts.append(tgt_inst)
            else:
                if not log_disable:
                    print(colored("Overlap %s" % (tgt_inst), 'red', 
                attrs=['reverse']))

                
    # ------------------------------ Analysis Methods ------------------------------ #           
    def analyze_params(self, inst_ssa, param_var, medium, var_targets, ignore_targets):
        # Takes in SSA parameters
        # pprint("analyze param: ", var_targets)
        log.info("%s | %s", inst_ssa, param_var)
        if param_var.operation == MediumLevelILOperation.MLIL_VAR_SSA or \
        param_var.operation == MediumLevelILOperation.MLIL_VAR or \
        param_var.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
            var = None
            offset = None
            use_ref = medium.ssa_form.get_ssa_var_definition(param_var.src)
            try:
                # In the case of scanf (or anything that takes reference of variable)
                # use_ref should result in something like rsi#1 (arg) = &var_1c (var name)
                var = use_ref.vars_read[0]
                # From here, we need to convert MLIL to LLIL to figure out the offset value
                # that is stored in the "rax" register
                print("Var", use_ref.llil.src, type(use_ref.llil.dest.src))
                if type(use_ref.llil.src) == LowLevelILRegSsa:
                    reg = use_ref.llil.src.src # LowLevelILRegSsa type -> get reg
                    offset = inst_ssa.llil.function.get_ssa_reg_definition(reg)
                elif type(use_ref.llil.dest.src) == LowLevelILRegSsa:
                    reg = use_ref.llil.dest.src # LowLevelILRegSsa type -> get reg
                    offset = inst_ssa.llil.function.get_ssa_reg_definition(reg)
                if offset != None:
                    return (var, self.analyze_llil_inst(offset, offset.function, var_targets, ignore_targets))
            except:
                None
            else:
                # print(var, use_ref)
                if binaryninja.commonil.Arithmetic in use_ref.__class__.__bases__:
                    offset = self.analyze_llil_inst(use_ref.llil, use_ref.llil.function, var_targets, ignore_targets)
                    if offset == None:
                        return None
                    else:
                        log.debug(use_ref.llil)
                        if self.find_var(var):
                            log.info("Exists")
                            return None
                        else:
                            return (var, offset)
                elif type(use_ref.llil.src.src) == LowLevelILRegSsaPartial:
                    # %rdi#43 = zx.q(%rdx#38.%edx) <class 'binaryninja.lowlevelil.LowLevelILZx'>
                    print(use_ref.llil, type(use_ref.llil.src))
                    reg = use_ref.llil.src.src.full_reg
                    reg_def = inst_ssa.llil.function.get_ssa_reg_definition(reg)
                    try:
                        mapped_MLLIL = reg_def.src.src.mapped_medium_level_il # This is done to get the var name
                        var = mapped_MLLIL.vars_read[0]
                    except Exception as error:
                        log.error("%s", error)
                        return None

                    offset = self.analyze_llil_inst(use_ref.llil.src, use_ref.llil.function, var_targets, ignore_targets)
                    if offset == None:
                        return None
                    else:
                        log.debug(use_ref.llil)
                        if self.find_var(var):
                            log.info("Exists")
                            return None
                        else:
                            return (var, offset)
                    
        elif param_var.operation == MediumLevelILOperation.MLIL_CONST:
            # print(param_var)
            if len(param_var.llils) > 0:
                for llil in param_var.llils:
                    if llil.operation == LowLevelILOperation.LLIL_SET_REG_SSA:
                        offset = self.analyze_llil_inst(llil, llil.function, var_targets, ignore_targets)
                        if offset != None:
                            var = self.search_var(llil)
                            if self.find_var(var):
                                log.info("Exists")
                                return None
                            else:
                                return (var, offset)
                            exit()
                            
                            
    
    def analyze_call_inst(self, inst_ssa, medium, var_targets, ignore_targets):
        # Call instruction either can be malloc which stores the address in rax register or
        # scanf that uses the parameter of the function.
        # returns -> Tuples
        log.info(inst_ssa)
        try:
            var = inst_ssa.vars_written[0]
            log.info("Analyzing call inst\t%s %s", inst_ssa, inst_ssa.vars_written[0])
            use_ref = medium.ssa_form.get_ssa_var_uses(var)
            if use_ref is not None:
                # log.debug("%s %s", self.analyze_llil_inst(use_ref[0].llil, use_ref[0].llil.function), use_ref[0].vars_written[0])
                return (use_ref[0].vars_written[0].var, self.analyze_llil_inst(use_ref[0].llil, use_ref[0].llil.function, var_targets, ignore_targets))
            else:
                return None
        except:
            return None
        
    
    def analyze_inst(self, inst_ssa, mlil_fun, var_targets, ignore_targets):
        # Only interested in instruction with the disassembly code as we gathered supposedly all necessary information from 
        # previous analysis
        log.info("%s | Analyzing inst\t%s %s", self.fun, inst_ssa, inst_ssa.operation)
        # spec_log.info("%s | Analyzing inst\t%s %s", self.fun, inst_ssa, inst_ssa.operation)
        # log.debug(var_targets)
        if inst_ssa.operation == MediumLevelILOperation.MLIL_VAR_SSA or \
            inst_ssa.operation == MediumLevelILOperation.MLIL_VAR:
            log.debug("Instruction: %s %s %s", inst_ssa, type(inst_ssa.src), type(inst_ssa.dest))
        elif inst_ssa.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA or \
            inst_ssa.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED or \
            inst_ssa.operation == MediumLevelILOperation.MLIL_STORE_SSA:
            log.debug("Instruction: %s", inst_ssa)
            # First condition is to check whether either src or dest is address of (&var_c)
            # log.debug(inst_ssa.src.vars_address_taken[0])
            offset = None
            addr_of_var = None
            var = None
            if type(inst_ssa.src) == binaryninja.mediumlevelil.MediumLevelILAddressOf:
                addr_of_var = inst_ssa.src
            elif type(inst_ssa.dest) == binaryninja.mediumlevelil.MediumLevelILAddressOf:
                addr_of_var = inst_ssa.dest
            elif type(inst_ssa.src) == binaryninja.mediumlevelil.SSAVariable:
                inst_var = mlil_fun.get_ssa_var_definition(inst_ssa.src)                
            elif type(inst_ssa.dest) == binaryninja.mediumlevelil.SSAVariable:
                inst_var = mlil_fun.get_ssa_var_definition(inst_ssa.dest)
            
            # if it turns out addr_of_var is not none, then handle the case, otherwise it will go thru
            if addr_of_var != None:
                addr_var = addr_of_var.vars_address_taken[0]
                # Instead of using the MLIL (as this camouflages register name as Variable), lower it to LLIL to get the actual reg
                if type(inst_ssa.llil.src) == LowLevelILRegSsa:
                    reg = inst_ssa.llil.src.src # LowLevelILRegSsa type -> get reg
                    offset = inst_ssa.llil.function.get_ssa_reg_definition(reg)
                if offset != None:
                    return (addr_var, self.analyze_llil_inst(offset, offset.function, var_targets, ignore_targets))
            elif inst_var != None:
            # else if variable simply exists, then we analyze the LLIL to get the offset
            # Example: %rax_131 = [%rbp_1 - 0x450].q
                var = None
                if inst_ssa.vars_written[0].var.core_variable.source_type == VariableSourceType.StackVariableSourceType:
                    # Ex: var_18#1 = %rax_1#2
                    var = inst_ssa.vars_written[0].var
                elif inst_ssa.vars_read[0].var.core_variable.source_type == VariableSourceType.StackVariableSourceType:
                    # Ex: %rax_7#8 = var_1c
                    var = inst_ssa.vars_read[0].var
                
                if var != None:
                    return (var, self.analyze_llil_inst(inst_var.llil, inst_var.llil.function, var_targets, ignore_targets))
                
        
    def analyze_llil_inst(self, inst_ssa, llil_fun, var_targets, ignore_targets):
        log.debug("%s | Analyze LLIL inst %s %s", self.fun, inst_ssa, type(inst_ssa))
        if type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsa:
            log.debug("RegSSA")
            reg = inst_ssa.src.reg.__str__()
            return reg
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsa:
            log.debug("SetSSA")
            offset = self.calc_offset(inst_ssa, var_targets)
            return offset
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILStoreSsa:
            log.debug("StoreSSA")
            offset = self.calc_offset(inst_ssa, var_targets)
            return offset
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            log.debug("LoadSSA")
            offset = self.calc_offset(inst_ssa, var_targets)
            return offset
        elif type(inst_ssa) == binaryninja.lowlevelil.SSARegister:
            log.debug("SSARegister")
            reg_def = llil_fun.get_ssa_reg_definition(inst_ssa)
            if reg_def != None:
                log.debug("Reg ref %s", reg_def)
                if type(reg_def.src) == binaryninja.lowlevelil.LowLevelILConstPtr:
                    log.error("Global")
                    return None
                else:
                    return reg_def
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsaPartial:
            log.debug("RegisterSSAPartial")
            reg_def = llil_fun.get_ssa_reg_definition(inst_ssa.full_reg)
            if reg_def != None:
                log.debug("Reg ref %s", reg_def)
                if type(reg_def.src) == binaryninja.lowlevelil.LowLevelILConstPtr:
                    log.error("Global")
                    return None
                else:
                    return reg_def
        elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
            log.debug("ArithSSA")
            offset = self.calc_offset(inst_ssa, var_targets)
            return offset
if __name__ == '__main__':
    process_argument(sys.argv[1:])
    