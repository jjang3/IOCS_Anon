from __future__ import print_function
from tkinter import N
from termcolor import colored
from configparser import NoSectionError
from posixpath import basename
from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture, ArchitectureHook
from typing import NamedTuple
from typing import Optional
import sys
from enum import Enum
if (sys.version[0] == '2'):
    import Queue 
else:
    import queue as Queue
from collections import deque
import sys, getopt
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

class CustomFormatter(logging.Formatter):

    # FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s | %(levelname)s"
    # logging.basicConfig(level=os.environ.get("LOGLEVEL", "DEBUG"), format=FORMAT)
    blue = "\x1b[33;34m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_green = "\x1b[42;1m"
    reset = "\x1b[0m"
    # format = "%(funcName)5s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    format = "[%(filename)s:%(lineno)s - %(funcName)18s() ] %(levelname)9s    %(message)s "

    FORMATS = {
        logging.DEBUG: yellow + format + reset,
        logging.INFO: blue + format + reset,
        logging.WARNING: yellow + format + reset,
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

class SizeType(Enum):
    CHAR = 1
    INT = 4
    CHARPTR = 8
    
def generate_table(varcount, target_dir):
    varlist = list()
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
    while count < varcount:
        varentry = "\tvoid *addr_%d;" % count
        mmapentry = """
    addr_%d = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_32BIT, -1, 0);     
    if (addr_%d == MAP_FAILED) {     
        fprintf(stderr, "mmap() failed\\n");     
        exit(EXIT_FAILURE);
    }
    table[%d] = addr_%d;\n
""" % (count, count, count, count)
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

def conv_suffix(suffix):
    match suffix:
        case "b":
            return "BYTE PTR" # 8-bit
        case "w":
            return "WORD PTR" #16-bit
        case "l":
            return "DWORD PTR" # 32-bit
        case "q":
            return "QWORD PTR" # 64-bit
    
def process_argument(argv):
    inputfile = ''
    funfile = ''
    dirloc = ''
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
        target_dir = None        
        if dirloc != None:
            target_dir = os.path.join(os.path.dirname(os.path.abspath(filename)), dirloc)
            filename = os.path.join(target_dir, filename)
            funfile = os.path.join(target_dir, funfile)
        else:
            target_dir= os.path.dirname(os.path.abspath(filename))
        target_file = os.path.splitext((os.path.basename(filename)))[0] + ".s"

        if funfile != "":
            with open(funfile) as c:
                for line in c:
                    funlist = line.split(",")
                    
        dir_list = os.listdir(target_dir)
        print(filename, funfile, target_dir)
        # --- DWARF analysis --- #
        dwarf_analysis(funlist, filename, target_dir)
        
        # --- Binary Ninja Analysis --- #
        with load(filename, options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:                  
            arch = Architecture['x86_64']
            bn = BinAnalysis(bv)
            bn.analyze_binary(funlist)

        # if dirloc != '':
        #     for dir_file in dir_list:
        #         if (dir_file.endswith('.s')):
        #             process_file(funlist, target_dir, dir_file)
        # else:
        #     process_file(funlist, target_dir, target_file)
            
def analyze_temp_inst(temp_inst, patch_targets):
    inst_type = False
    src = False
    dest = False
    offset = False
    found = False
    pattern = r'(\b[|BYTE PTR|DWORD PTR|QWORD PTR]+\b)\s(.*[0-9]\[.*\])'
    ptr_regex = re.search(pattern, temp_inst.dest)
    target = str()
    # print(temp_inst.inst_type, temp_inst.dest)
    if ptr_regex != None:
        target = "dest"
    else:
        target = "src"
        
    
    # print("Target:", target)
    for item in patch_targets:
        # print(item)
        if temp_inst.inst_type == item.inst_type:
            # print(temp_inst.inst_type, item.inst_type)
            inst_type = True
        # if target == "dest":
        #     print(temp_inst.dest, item.dest)
        #     if temp_inst.dest == item.dest:
        #         dest = True
        # else:
        #     print(temp_inst.src, item.src)
        #     try:
        #         if int(temp_inst.src) == int(item.src):
        #             src = True
        #     except:
        #         if temp_inst.src == item.src:
        #             src = True
                
        if temp_inst.offset == item.offset:
            # print(temp_inst.offset, item.offset)
            offset = True
        
        # print(inst_type, offset)
        # if inst_type and src and offset:
        #     found = True
        #     break
        # elif inst_type and dest and offset:
        #     found = True
        #     break
        if inst_type and offset:
            found = True
            break
        
    return (found, target)

struct_set = list()
fun_var_info = dict()
@dataclass(unsafe_hash = True)
class StructData:
    name: str = None
    member_list: Optional[set] = None
    
@dataclass(unsafe_hash = True)
class VarData:
    name: str = None
    struct_type: str = None
    offset: str = None

@dataclass
class PatchingInst:
    inst_type: Optional[str] = None
    dest: Optional[str] = None
    src: Optional[str] = None       
    offset: Optional[str] = None
    
def dwarf_analysis(funlist, filename, target_dir):
    dwarf_var_count     = 0
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
        var_list = list()
        for CU in dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                # Check if this attribute contains location information
                if (DIE.tag == None and DIE.size == 1 and len(var_list) != 0 and funname is not None):
                    print("Store var_list for", funname)
                    fun_var_info[funname] = var_list.copy()
                    var_list.clear()
                    
                if (DIE.tag == "DW_TAG_subprogram"):
                    target_fun = False
                    fun_frame_base = None
                    print("Target fun: ", target_fun)
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
                            print("Function name:", funname, "\t| Begin: ", hex(lowpc), "\t| End:", hex(highpc))
                            if funname in funlist:
                                target_fun = True
                            print('  Found a compile unit at offset %s, length %s' % (
                                CU.cu_offset, CU['unit_length']))
                            loc = loc_parser.parse_from_attribute(attr, CU['version'])
                            if isinstance(loc, list):
                                for loc_entity in loc:
                                    if isinstance(loc_entity, LocationEntry):
                                        offset = describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, CU.cu_offset)
                                        if "rbp" in offset:
                                            if rbp_offset := re.search(rbp_regex, offset):
                                                fun_frame_base = int(rbp_offset.group(1))
                                                # print(fun_frame_base)
                    
                if (DIE.tag == "DW_TAG_variable"):
                    var_name = None
                    reg_offset = None
                    struct_name = None
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
                                    reg_offset = "rbp" + str(var_offset)
                                    print("\t\tStarting offset: ", reg_offset)
                        if (attr.name == "DW_AT_type" and target_fun == True):
                            try:
                                refaddr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
                                type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, DIE.cu)
                                print(type_die)
                                if type_die.tag == "DW_TAG_structure_type":
                                    if 'DW_AT_name' in type_die.attributes:
                                        struct_name = type_die.attributes['DW_AT_name'].value.decode()
                                        print("\t\tStruct type found: ", struct_name)
                                        for struct_item in struct_set:
                                            if struct_name == struct_item.name:
                                                dwarf_var_count += len(struct_item.member_list)
                                if type_die.tag == "DW_TAG_pointer_type":
                                    print(hex(type_die.attributes['DW_AT_type'].value))
                                    ptr_ref = type_die.attributes['DW_AT_type'].value + type_die.cu.cu_offset
                                    ptr_type_die = dwarfinfo.get_DIE_from_refaddr(ptr_ref, type_die.cu)
                                    print("Pointer:", ptr_type_die.tag)
                                    if 'DW_AT_name' in ptr_type_die.attributes:
                                        struct_name = ptr_type_die.attributes['DW_AT_name'].value.decode()
                                        print("\t\tPointer type found: ", struct_name)
                                        for struct_item in struct_set:
                                            if struct_name == struct_item.name:
                                                dwarf_var_count += len(struct_item.member_list)
                                else:
                                    dwarf_var_count += 1
                            except Exception  as err:
                                print(err)
                    temp_var = VarData(var_name, struct_name, reg_offset)
                    if temp_var.name is not None:
                        print(temp_var)
                        var_list.append(temp_var)
                
                if (DIE.tag == "DW_TAG_structure_type"):
                    for attr in DIE.attributes.values():
                        if (attr.name == "DW_AT_name"):
                            struct_name = DIE.attributes["DW_AT_name"].value.decode()
                            print("Struct name: ", struct_name)
                            temp_struct = StructData(struct_name, set())
                if (DIE.tag == "DW_TAG_member"):
                    attr_name = None
                    offset = None
                    for attr in DIE.attributes.values():
                        if(attr.name == "DW_AT_name"):
                            attr_name = DIE.attributes["DW_AT_name"].value.decode()
                        if loc_parser.attribute_has_location(attr, CU['version']):
                            loc = loc_parser.parse_from_attribute(attr,
                                                                CU['version'])
                            if(attr.name == "DW_AT_data_member_location"):
                                # print(attr)
                                if isinstance(loc, LocationExpr):
                                    offset = re.search(off_regex, describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset))
                            if(attr.form == "DW_FORM_block1"):
                                # print(describe_form_class(attr.form))
                                # print(attr.udata_value())
                                None
                    if offset != None: 
                        print("\tMember name %s |\tOffset %s\n" % (attr_name, offset.group(1)))
                        temp_struct.member_list.add((attr_name, offset.group(1)))
                if temp_struct not in struct_set and temp_struct is not None:
                    struct_set.append(temp_struct)
            print("----------------------------------------------------------------------------\n")
            # ------- After DIE ------- #  
    
    for item in struct_set:
        print(item)
    
    # for item in fun_var_info:
    #     print("Variables for:", item)
    #     for var in fun_var_info[item]:
    #         print(var)
    print("Variable count: ", dwarf_var_count)
    generate_table(dwarf_var_count, target_dir)

def process_file(funlist, target_dir, target_file):
        # if (target_file.endswith('.asm')):
        print(target_file)
        # print(os.path.join(target_dir, target_file))
        with fileinput.input(os.path.join(target_dir, target_file), inplace=False, encoding="utf-8", backup='.bak') as f:
            fun_begin_regex = r'(?<=.type\t)(.*)(?=,\s@function)'
            fun_end_regex   = r'(\t.cfi_endproc)'
            dis_line_regex  = r'\t(mov|lea|sub|add|cmp)([a-z])\t(.*),\s(.*)'
            offset_regex    = r'(\b[|BYTE PTR|DWORD PTR|QWORD PTR]+\b)\s(.*[0-9]\[.*\]|(\b[a-z]+\b:\b[0-9]+\b))'
            lea_regex       = r'(\s*|.*)\[(.*)\]'
            calc_offset_regex = r'(-\b[0-9,a-z]+\b)\[(.*)\]'
            check = False
            currFun = str()
            patch_targets = list()
            offset_targets = dict()
            struct_targets = set()
            # print(funlist)
            for line in f:
                # print('\t.file\t"%s.c"' % target_file.rsplit('.', maxsplit=1)[0])
                if line.startswith('\t.file\t"%s.c"' % target_file.rsplit('.', maxsplit=1)[0]):
                    print("""
    .macro lea_gs dest, offset
		mov	r11, [gs:[\offset]]
		lea \dest, [r11]
	.endm
	.macro mov_set_gs src, offset
		xor r11, r11
		mov	r11, [gs:[\offset]]
		mov qword PTR [r11], \src
	.endm
    .macro mov_load_gs dest, offset
		mov	\dest, [gs:[\offset]]
		mov \dest, [\dest]
	.endm
 	.macro add_gs value, offset
		mov	r11, [gs:[\offset]]
		mov r11, [r11]
		add r11, \\value
		mov	r12, [gs:[\offset]]
		mov qword PTR [r12], r11
	.endm
	.macro cmp_gs value, offset
		mov	r11, [gs:[\offset]]
		mov r11, [r11]
		cmp r11, \\value
	.endm
	.macro mov_str_mem_gs dest, src, offset
        xor r11d, r11d
		mov	r11d, [gs:[\offset]]
		mov r12d, r11d
		mov dword PTR [r11d], \src
		lea r14, \dest
		mov [r14], r11d
	.endm
	.macro load_str_mem_gs dest, src
		mov	r11d, \src
		mov \dest, [r11d]
	.endm
""", end='')
                fun_begin = re.search(fun_begin_regex, line)
                if fun_begin is not None:
                    if fun_begin.group(1) in funlist:
                        currFun = fun_begin.group(1)
                        try:
                            patch_targets = fun_patch_tgts[currFun]
                            offset_targets = prog_offset_set[currFun]   
                            struct_targets = struct_offset_set[currFun]
                            check = True
                        except Exception as err:
                            print("Skipping", type(err))
                            check = False
                
                fun_end = re.search(fun_end_regex, line)
                if fun_end is not None:
                    check = False
                
                if check == True:
                    dis_line = line.rstrip('\n')
                    print(patch_targets)
                    # print(line, end='')
                    # mnemonic source, destination AT&T
                    dis_regex = re.search(dis_line_regex, dis_line)
                    temp_inst = None
                    # off_regex = None
                    if dis_regex is not None:
                        inst_type   = dis_regex.group(1)
                        suffix      = dis_regex.group(2)
                        src         = dis_regex.group(3)
                        dest        = dis_regex.group(4)
                        print("Inst Type: ", inst_type, "\t|\tSuffix: ", conv_suffix(suffix), "\t| src: ", src,"\t| dest: ", dest)
                        # if inst_type == "lea":
                        #     off_regex = re.search(lea_regex, dest)
                        #     if off_regex is not None and off_regex.group(1) != "":  
                        #         offset = off_regex.group(2)
                        #         temp_inst = PatchingInst(inst_type, dest, src, offset)
                        #     else:
                        #         off_regex = re.search(lea_regex, src)
                        #         offset = off_regex.group(2)
                        #         temp_inst = PatchingInst(inst_type, dest, src, offset)
                        # else:
                        #     off_regex = re.search(offset_regex, dest)
                        #     if off_regex is not None:
                        #         calc_regex = re.search(calc_offset_regex, dest)
                        #         if calc_regex is not None:
                        #             offset = calc_regex.group(2) + calc_regex.group(1)
                        #             temp_inst = PatchingInst(inst_type, dest, src, offset)
                        #     else:
                        #         off_regex = re.search(offset_regex, src)
                        #         calc_regex = re.search(calc_offset_regex, src)
                        #         if calc_regex is not None:
                        #             offset = calc_regex.group(2) + calc_regex.group(1)
                        #             temp_inst = PatchingInst(inst_type, dest, src, offset)
                        print("Temp:", temp_inst)
                        
                    if temp_inst != None:
                        result = analyze_temp_inst(temp_inst, patch_targets)
                        if result[0] == True:
                            # print("Found candidate", dis_line, result[1], temp_inst)
                            # Need to work from here.
                            try:
                                table_offset = offset_targets[temp_inst.offset]
                                replace_inst = str()
                            except:
                                # print("No offset exists")
                                break
                            
                            if temp_inst.offset in struct_targets and off_regex is not None:
                                # print("Struct found", temp_inst.offset)
                                if result[1] == "dest":
                                    replace_inst = "mov_str_mem_gs"
                                    # print(replace_inst, off_regex.group(2), temp_inst.src, table_offset)
                                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %s, %d\t" % (replace_inst, off_regex.group(2), temp_inst.src, table_offset), line)
                                elif result[1] == "src":
                                    replace_inst = "load_str_mem_gs"
                                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %s\t" % (replace_inst, (temp_inst.dest), off_regex.group(2)), line)
                            else:    
                                if temp_inst.inst_type == "lea":
                                    replace_inst = "lea_gs"
                                    line = re.sub(r"(\b[a-z]+\b).*(?!\b)", "%s\t%s, %d\t" % (replace_inst, conv_reg(temp_inst.dest), table_offset), line)
                                    # print("New line:", line)
                                elif temp_inst.inst_type == "add":
                                    replace_inst = "add_gs"
                                    line = re.sub(r"(\b[a-z]+\b).*(\b)", "%s\t%s, %d\t" % (replace_inst, conv_reg(temp_inst.src), table_offset), line)
                                elif temp_inst.inst_type == "cmp":
                                    replace_inst = "cmp_gs"
                                    line = re.sub(r"(\b[a-z]+\b).*(\b)", "%s\t%s, %d\t" % (replace_inst, conv_reg(temp_inst.src), table_offset), line)
                                elif result[1] == "dest": # mov_gs_set "Destination" is the ptr, hence need to use the src
                                    replace_inst = "mov_set_gs"
                                    # print("Target line: ", line)
                                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %d\t" % (replace_inst, conv_reg(temp_inst.src), table_offset), line)
                                    # print("New line:", line)
                                    None
                                elif result[1] == "src": # mov_gs_load "Source" is the ptr, need to "load" the value from the table back
                                    replace_inst = "mov_load_gs" 
                                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s, %d\t" % (replace_inst, conv_reg(temp_inst.dest), table_offset), line)

                            print(line, end='')
                        else:
                            # print(line, end='')
                            None
                    else:
                        # print(line, end='')
                        None
                else:
                    # print(line, end='')
                    None

def find_struct(fun_name, var_targets, var):
    offset_regex = r"(\b[a-z]+\b)(.*)"
    output = set()
    # for tgt in patching_targets:
    if var_targets != None:
        # print("Ignore based on entire variable targets; Find struct object offset and include members")
        for var in var_targets:
            if var.struct_type != None:
                for struct_item in struct_set:    
                    print("Struct found")
                    offset_target = var.offset
                    if var.struct_type == struct_item.name:
                        for member in struct_item.member_list:
                            if rbp_offset := re.search(offset_regex, offset_target):
                                fun_frame_base = int(rbp_offset.group(2))
                                offset = fun_frame_base + int(member[1])
                                new_offset = "rbp" + str(offset)
                                # print(new_offset)
                                output.add(new_offset)
    elif var_targets == None and var != None:
        print("Find a struct based on individual variable")
        if var.struct_type != None:
            for struct_item in struct_set:    
                print("Struct found")
                offset_target = var.offset
                if var.struct_type == struct_item.name:
                    for member in struct_item.member_list:
                        if rbp_offset := re.search(offset_regex, offset_target):
                            fun_frame_base = int(rbp_offset.group(2))
                            offset = fun_frame_base + int(member[1])
                            new_offset = "rbp" + str(offset)
                            print(new_offset)
                            output.add(new_offset)
    # for item in output:
    #     print("output", item)
    return output
                                
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(CustomFormatter())
log.addHandler(ch)

class BinAnalysis:
    # Patch targets resulting from analysis of the current working function
    patch_tgts      = set()
    
    # Patch targets from utilizing the analysis result of the current working function
    cur_fun_tgts    = list()
    
    # Offset to table offset set of the current working function
    off_to_table    = set()
    
    def __init__(self, bv):
        self.bv = bv
        
    def find_var(self, var):
        for item in self.patch_tgts:
            if var == item[0]:
                log.critical("Found var")
                return True
        return False

    def find_off(self, offset):
        try:
            offset_pattern = r'(\b[qword ptr|dword ptr]+\b)\s\[(%.*)([*+\/-]0x[0-9].*)\]'
            offset_regex = re.search(offset_pattern, offset)
            expr = str()
            expr = str(int(offset_regex.group(3),base=16)) + "(" + offset_regex.group(2) + ")"
            for item in self.patch_tgts:
                if expr == item[1]:
                    log.critical("Found offset")
                    return True, expr
            return False, None
        except:
            return False, None
        # for item in self.patch_tgts:
        #     if offset == item[1]:
        #         log.critical("Found offset")
        #         return True
        # return False
    
    def calc_offset(self, inst_ssa):
        log.info("Finding the offset of %s %s", inst_ssa, type(inst_ssa)) 
        try:
            if type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
                if inst_ssa.src_memory != None:
                    try:
                        if inst_ssa.src.left.src.reg == "fsbase": 
                            log.warning("Found segment %s %s %s", inst_ssa.src.left, inst_ssa.src.right, inst_ssa.src.left.src.reg)
                            reg = inst_ssa.src.left.src.reg.__str__().split('base')
                            reg = ''.join(reg)
                            expr = str()
                            expr = reg + ":" + str(int(str(inst_ssa.src.right), 16))
                            return None
                        else:
                            result = self.calc_offset(inst_ssa.src)
                            if result != None:
                                return result
                    except Exception as error:
                        if type(inst_ssa.src) == binaryninja.lowlevelil.LowLevelILConstPtr:
                            log.error("Global value, skip")
                            return None
                        else:
                            log.error("Error: %s", error)
            elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsa:
                try:
                    log.debug("SetRegSSA")
                    result = self.calc_offset(inst_ssa.src)
                    if result != None:
                        return result
                except Exception as error:
                    log.error("Error: %s", error)
            elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILStoreSsa:
                try:
                    try:
                        result = self.calc_offset(inst_ssa.dest)
                        if result != None:
                            return result
                    except Exception as error:
                        log.error("Error: %s", error)
                except Exception as error:
                    log.error("Error: %s", error)
            elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsaPartial:
                log.debug(inst_ssa.full_reg)
                result = self.calc_offset(inst_ssa.function.get_ssa_reg_definition(inst_ssa.full_reg))
                return result
            elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
                try:
                    reg = inst_ssa.left.src.reg.__str__()
                except:
                    reg = inst_ssa.left.__str__()
                if type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILLoadSsa:
                    result = self.calc_offset(inst_ssa.right)
                    if result != None:
                        return result
                    else:
                        return None
                offset = str(int(inst_ssa.right.__str__(), base=16))
                log.debug("Offset: %s", offset)
                expr = offset + "(" + reg + ")"
                log.critical("Expr: %s", expr)
                return expr
        except:
            try:
                return self.calc_offset(inst_ssa.src)
            except: 
                return None
        else:
            return None
        
    def analyze_binary(self, funlist):
        print("Step: Binary Ninja")
        for func in self.bv.functions:
            print ("\tFunction:", func.name)
            if func.name in funlist:
                hlil_fun = func.high_level_il
                mlil_fun = func.medium_level_il
                llil_fun = func.low_level_il
                lift_fun = func.lifted_il
                var_targets = None  # Variable targets obtained from DWARF
                try:
                    var_targets = fun_var_info[func.name]
                    self.backward_slice(hlil_fun, mlil_fun, llil_fun, lift_fun, var_targets)
                    for item in self.cur_fun_tgts:
                        log.debug(item)
                    for item in self.off_to_table:
                        log.debug(item)
                except Exception as error:
                    log.error("%s", error)
                    
    def backward_slice(self, high, medium, low, lift, var_targets):
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
                # These operations are highest level of variable assignments are one we care about.
                if inst_ssa.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                    # First analyze any function call instructions (e.g., malloc/calloc) to find potential patch targets
                    # var_10 -> -8(%rbp), this information is going to be used and saved in the case when we analyze the LLIL
                    # To-do: Is there a need to analyze parameters of call instruction? Or not necessary.
                    patch_tgt = self.analyze_call_inst(inst_ssa, medium)
                    if patch_tgt != None:
                        self.patch_tgts.add(patch_tgt)
                        log.debug("Patch target: %s", patch_tgt)
                elif inst_ssa.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA or \
                     inst_ssa.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
                    # Check if variable name exists for this MLIL instruction, and see whether it has been already checked
                    try:
                        var = inst_ssa.vars_written[0].var
                        if self.find_var(var):
                            continue
                        else:
                            # log.debug("Analyze %s", inst_ssa)
                            None
                    except Exception as error:
                        log.error("%s", error)
                        
        for llil_bb in low:
            for inst in llil_bb:
                self.find_patch_tgts(inst)
                
                
    def find_patch_tgts(self, inst):
        global table_offset
        dis_inst = self.bv.get_disassembly(inst.address)
        if dis_inst == None:
            return None
        log.debug("Find patching tgt: %s", dis_inst)
        # Example: mov     qword [rbp-0x8], rax 
        dis_inst_pattern    = re.search(r"(\b[a-z]+\b)\s*(.*),\s(.*)", dis_inst)
        inst_type           = str()
        src                 = str()
        dest                = str()
        if dis_inst_pattern != None:
            inst_type   = dis_inst_pattern.group(1)
            src         = dis_inst_pattern.group(2)
            dest        = dis_inst_pattern.group(3)
        else:
            log.error("Regex failed %s", dis_inst)
        
        # Either source or dest can be ptr, so whichever one passes through, find offset in the set
        patch_inst = None
        expr = None
        if re.search(r'(\b[qword ptr|dword ptr]+\b)', src):
            result, expr = self.find_off(src)
            if result:
                patch_inst = PatchingInst(inst_type=inst_type, dest=dest, src=src, offset=expr)
        else:
            result, expr = self.find_off(dest)
            if result:
                patch_inst = PatchingInst(inst_type=inst_type, dest=dest, src=src, offset=expr)
        
        
        if patch_inst != None:
            if patch_inst not in self.cur_fun_tgts:
                update = True
                for item in self.cur_fun_tgts:
                    if patch_inst.offset == item.offset:
                        log.debug("Table offset should not be updated")
                        update = False

                if update:
                    self.cur_fun_tgts.append(patch_inst)
                    self.off_to_table.add((patch_inst.offset, table_offset))
                    table_offset += 8
                else:
                    self.cur_fun_tgts.append(patch_inst)
                    
                print(colored("Adding %s | Next table offset %d" % (patch_inst, table_offset), 'blue', attrs=['reverse']))
            else:
                print(colored("Overlap %s" % (patch_inst), 'red', 
                attrs=['reverse']))

                
    # ------------------------------ Analysis Methods ------------------------------ #           
    def analyze_params(self, inst_ssa, medium):
        # Takes in SSA parameters
        log.info(inst_ssa)
        for param_var in inst_ssa.params:
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
                    if type(use_ref.llil.src) == LowLevelILRegSsa:
                        reg = use_ref.llil.src.src # LowLevelILRegSsa type -> get reg
                        offset = inst_ssa.llil.function.get_ssa_reg_definition(reg)
                    if offset != None:
                        return (var, self.analyze_llil_inst(offset, offset.function))
                except:
                    None
                else:
                    if type(use_ref.llil.src.src) == LowLevelILRegSsaPartial:
                        reg = use_ref.llil.src.src.full_reg
                        reg_def = inst_ssa.llil.function.get_ssa_reg_definition(reg)
                        try:
                            mapped_MLLIL = reg_def.src.src.mapped_medium_level_il # This is done to get the var name
                            var = mapped_MLLIL.vars_read[0]
                        except Exception as error:
                            log.error("%s", error)
                            return None

                        offset = self.analyze_llil_inst(use_ref.llil.src, use_ref.llil.function)
                        if offset == None:
                            continue
                        else:
                            log.debug(use_ref.llil)
                            if self.find_var(var):
                                log.info("Exists")
                                return None
                            else:
                                return (var, offset)
                            
    
    def analyze_call_inst(self, inst_ssa, medium):
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
                return (use_ref[0].vars_written[0].var, self.analyze_llil_inst(use_ref[0].llil, use_ref[0].llil.function))
            else:
                return None
        except:
            return self.analyze_params(inst_ssa, medium)
        
    
    def analyze_inst(self, inst_ssa, mlil_fun, var_targets):
        # Only interested in instruction with the disassembly code as we gathered supposedly all necessary information from 
        # previous analysis
        
        log.info("Analyzing inst\t%s", inst_ssa)
        # mem_ref_result = self.mem_ref_chk(inst_ssa.dest, mlil_fun)
        
    def mem_ref_chk(self, inst_ssa, mlil_fun):
        try:
            log.debug("%s", inst_ssa)
            cand = None
            if type(inst_ssa) == binaryninja.mediumlevelil.SSAVariable:
                cand = mlil_fun.get_ssa_var_definition(inst_ssa)
                log.debug("Candidate (MLIL) %s", cand)
            
            if cand != None:
                log.debug("Candidate exists %s %s %s", cand.llil,  type(cand.llil.src),  type(cand.llil.dest))
                target_llil_src     = self.analyze_llil_inst(cand.llil.src, cand.llil.function)
                target_llil_dest    = self.analyze_llil_inst(cand.llil.dest, cand.llil.function)
                target_cand = (target_llil_src, target_llil_dest)
                if None not in target_cand:
                    log.critical("Target cand (LLIL) %s", target_cand)
            else:
                log.error("No candidate")
        except Exception as error:
            log.error("%s", error)
            return None
        
    def analyze_llil_inst(self, inst_ssa, llil_fun):
        log.debug("Analyze LLIL inst %s %s", inst_ssa, type(inst_ssa))
        if type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsa:
            log.debug("RegSSA")
            reg = inst_ssa.src.reg.__str__()
            return reg
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsa:
            log.debug("SetSSA")
            offset = self.calc_offset(inst_ssa)
            return offset
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILStoreSsa:
            log.debug("StoreSSA")
            offset = self.calc_offset(inst_ssa)
            return offset
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            log.debug("LoadSSA")
            offset = self.calc_offset(inst_ssa)
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
            offset = self.calc_offset(inst_ssa)
            return offset
if __name__ == '__main__':
    process_argument(sys.argv[1:])
    