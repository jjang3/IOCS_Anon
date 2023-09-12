from __future__ import print_function
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
# import regex

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

def conv_reg(reg_name):
    match reg_name:
        case "eax":
            return "rax"
        case "ebx":
            return "rbx"
        case "ecx":
            return "rcx"
        case "edx":
            return "rdx"
        case "esi":
            return "rsi"
        case "edi":
            return "rdi"
        case "r8d":
            return "r8"
        case "r9d":
            return "r9"
        case "r10d":
            return "r10"
        case "r11d":
            return "r11"
        case "r12d":
            return "r12"
        case "r13d":
            return "r13"
        case "r14d":
            return "r14"
        case "r15d":
            return "r15"
        case _:
            return reg_name
    
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
        with open_view(filename) as bv:                
            arch = Architecture['x86_64']
            # bn = BinAnalysis(bv)
            # bn.analyze_binary(funlist)

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
                    # print("Target fun: ", target_fun)
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
                                        print("\t\tStruct type found: ", struct_name)
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
        with fileinput.input(os.path.join(target_dir, target_file), inplace=True, encoding="utf-8", backup='.bak') as f:
            fun_begin_regex = r'(?<=.type\t)(.*)(?=,\s@function)'
            fun_end_regex   = r'(\t.cfi_endproc)'
            dis_line_regex  = r'(\b[a-z]+\b)(.*),\s(.*)'
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
                    print("""	.macro lea_gs dest, offset
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
                        except:
                            # print("Skipping")
                            check = False
                
                fun_end = re.search(fun_end_regex, line)
                if fun_end is not None:
                    check = False

                if check == True:
                    dis_line = line.rstrip('\n')
                    # print(line, end='')
                    # print(line)
                    dis_regex = re.search(dis_line_regex, dis_line)
                    temp_inst = None
                    off_regex = None
                    if dis_regex is not None:
                        inst_type = dis_regex.group(1)
                        dest = dis_regex.group(2)
                        src = dis_regex.group(3).strip()
                        # print("Old: ", inst_type, "| dest: ", dest, "| src:", src)
                        if inst_type == "lea":
                            off_regex = re.search(lea_regex, dest)
                            if off_regex is not None and off_regex.group(1) != "":  
                                offset = off_regex.group(2)
                                temp_inst = PatchingInst(inst_type, dest, src, offset)
                            else:
                                off_regex = re.search(lea_regex, src)
                                offset = off_regex.group(2)
                                temp_inst = PatchingInst(inst_type, dest, src, offset)
                        else:
                            off_regex = re.search(offset_regex, dest)
                            if off_regex is not None:
                                calc_regex = re.search(calc_offset_regex, dest)
                                if calc_regex is not None:
                                    offset = calc_regex.group(2) + calc_regex.group(1)
                                    temp_inst = PatchingInst(inst_type, dest, src, offset)
                            else:
                                off_regex = re.search(offset_regex, src)
                                calc_regex = re.search(calc_offset_regex, src)
                                if calc_regex is not None:
                                    offset = calc_regex.group(2) + calc_regex.group(1)
                                    temp_inst = PatchingInst(inst_type, dest, src, offset)
                        # print("Temp:", temp_inst)
                        
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
                            print(line, end='')
                            None
                    else:
                        print(line, end='')
                        None
                else:
                    print(line, end='')
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
                                
        

class BinAnalysis:
    avoid_targets       = set()
    patching_targets    = list()
    fun_offset_set      = dict()
    fun_ignore_set      = set()
    vars_written_stack  = list()
    fun_struct_set      = set()
    def __init__(self, bv):
        self.bv = bv
        
    def find_offset(self, inst_ssa):
        print("Find offset:", inst_ssa, type(inst_ssa)) 
        try:
            if type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
                if inst_ssa.src_memory != None:
                    # Memory reading operation 
                    try:
                        if inst_ssa.src.left.src.reg == "fsbase": 
                            print("Found segment", inst_ssa.src.left, inst_ssa.src.right, inst_ssa.src.left.src.reg)
                            reg = inst_ssa.src.left.src.reg.__str__().split('base')
                            reg = ''.join(reg)
                            expr = str()
                            expr = reg + ":" + str(int(str(inst_ssa.src.right), 16))
                            print(expr)
                            return ("segment", expr)
                        else:
                            result = self.find_offset(inst_ssa.src)
                            if result != None:
                                return result
                    except Exception as error:
                        print(error)
            elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsa:
                try:
                    # print(type(inst_ssa.src))
                    result = self.find_offset(inst_ssa.src)
                    if result != None:
                        return result
                except Exception as error:
                    print(error)
            elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILStoreSsa:
                try:
                    try:
                        result = self.find_offset(inst_ssa.dest)
                        if result != None:
                            return result
                    except Exception as error:
                        print(error)
                except Exception as error:
                    print(error)
            elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
                try:
                    reg = inst_ssa.left.src.reg.__str__()
                except:
                    reg = inst_ssa.left.__str__()
                if type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILLoadSsa:
                    result = self.find_offset(inst_ssa.right)
                    if result != None:
                        return result
                    else:
                        return None
                offset = str(int(inst_ssa.right.__str__(), base=16))
                # print("Offset:", offset)
                if type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSub:
                    expr = reg + "-"+ offset 
                elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILAdd \
                    and inst_ssa.right.constant > -1:
                    expr = reg + "+"+ offset 
                # Currently do not see the need for offset calculation besides Sub/Add
                elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILAdd \
                    and inst_ssa.right.constant < 0:
                    expr = reg + offset
                # else:
                #     print("Not add nor sub", inst_ssa.right.constant )
                #     expr = reg + offset
                print("Expr: ", expr)
                return expr
        except:
            try:
                return self.find_offset(inst_ssa.src)
            except: 
                return None
        else:
            return None
       
    def check_for_mem_ref(self, inst_ssa, mlil_fun):
        try: 
            print("Checking mem ref", type(inst_ssa), inst_ssa)
            mem_ref = None
            cand = None
            result = None
            if type(inst_ssa) == binaryninja.mediumlevelil.MediumLevelILVarSsa:
                result = self.check_for_mem_ref(inst_ssa.src, mlil_fun)
            
            if result != None:
                return result
            elif type(inst_ssa) == binaryninja.mediumlevelil.SSAVariable:
                cand = mlil_fun.get_ssa_var_definition(inst_ssa)
                print("Finding cand", cand)
                
            if cand != None:
                # print(type(cand.llil.src), cand.llil.dest)
                target_cand = None
                if type(cand.llil.src) != binaryninja.lowlevelil.LowLevelILConst:
                    target_cand = cand.llil.src
                else:
                    target_cand = cand.llil.dest
                print("Target cand", target_cand, type(target_cand))
                
                if type(target_cand) == binaryninja.lowlevelil.LowLevelILLoadSsa:
                    offset = self.find_offset(target_cand)
                    return offset
                elif binaryninja.commonil.Arithmetic in target_cand.__class__.__bases__:
                    offset = self.find_offset(target_cand)
                    print(offset)
                    return offset
                else:
                    if type(target_cand.src) == binaryninja.lowlevelil.SSARegister:
                        mem_ref = cand.llil.function.get_ssa_reg_definition(target_cand.src)
                    elif type(target_cand.src) == binaryninja.lowlevelil.LowLevelILRegSsaPartial:
                        mem_ref = cand.llil.function.get_ssa_reg_definition(target_cand.src.full_reg)
                
                print("Mem ref", mem_ref)
                if mem_ref != None:
                    if type(mem_ref.src) == binaryninja.lowlevelil.LowLevelILConstPtr:
                        # This means it is NOT a stack variable, but global variable
                        return "global"
                    else:
                        print(self.bv.get_disassembly(mem_ref.address), "\n\tMemory ref exists: ", mem_ref, type(mem_ref), type(mem_ref.src), "\n")
                        offset = self.analyze_mem_ref_inst(mem_ref)
                        # offset = self.find_offset(mem_ref)
                        return offset
                else:
                    if type(cand.src.src.ssa_form) == binaryninja.mediumlevelil.MediumLevelILLoadSsa:
                        if cand.src.src.ssa_form.src.operation == MediumLevelILOperation.MLIL_CONST_PTR or MediumLevelILOperation.MLIL_CONST:
                            global_cand = self.bv.get_data_var_at(cand.src.src.src.constant)
                            for code_refs in global_cand.code_refs:
                                # Global variables
                                print("Omit these instructions for patching: ", hex(code_refs.address))
                                self.avoid_targets.add(code_refs.address)
            else:
                return None
        except Exception as error:
            print("Not SSA Variable: ", error, "\n")
            return None
    
    def analyze_mem_ref_inst(self, inst_ssa):
        global table_offset
        if inst_ssa == False:
            return False
        
        print("Analyze mem ref inst:", type(inst_ssa), hex(inst_ssa.address))
        dis_inst = self.bv.get_disassembly(inst_ssa.address)
        if dis_inst == None:
            return None
        print("Analyzing", dis_inst, "\t| SSA: ", inst_ssa)
        # pattern = r"(\b[a-z]+\b).*(\b[a-z]+\b)(?=,)"
        pattern = r"(\b[mov|lea]+\b)\s*(.*),\s(.*)"
        offset_pattern = r".*\[(.*)\]"
        find_type_target = re.search(pattern, dis_inst)
        # print(find_type_target)
        i_type      = str()
        dest        = str()
        src         = str()
        if find_type_target != None:
            i_type = find_type_target.group(1)
            dest = conv_reg(find_type_target.group(2))
            src = find_type_target.group(3)
        print("Check:", i_type, dest, src)
        # Note: Not putting table offset here because this should be already taken care of by other instructions (may need to add it here later though)
        off = self.find_offset(inst_ssa)
        if off[0] == "segment" or off[1] in self.fun_ignore_set or off in self.fun_ignore_set:
            print("Ignore offset address", off)
            return off
        elif off != None and off != False:
            patch_inst = PatchingInst(inst_type=i_type, dest=dest, offset=off)
            if patch_inst not in self.patching_targets:
                if off != None and off not in self.fun_offset_set and off not in self.fun_ignore_set:
                    print("Add offset")
                    self.fun_offset_set[off] = table_offset
                    print(colored("Adding %s" % patch_inst, 'green', attrs=['reverse']))
                    self.patching_targets.append(patch_inst)   
                    table_offset += 8
   
    
    def find_add_offset(self, inst_ssa_expr, i_type, dest, src, offset):
        global table_offset
        expr = None
        if offset == None:
            expr = self.find_offset(inst_ssa_expr)
        else:
            expr = offset
        print(inst_ssa_expr, expr, self.fun_offset_set)
        if expr != None and expr not in self.fun_offset_set and expr != False and expr not in self.fun_ignore_set:
            print("Add offset")
            self.fun_offset_set[expr] = table_offset
            try:
                src = int(src, 16)
                patch_inst = PatchingInst(inst_type=i_type, dest=dest, src=int(src,16),offset=expr)
            except:
                
                patch_inst = PatchingInst(inst_type=i_type, dest=conv_reg(dest), src=conv_reg(src),offset=expr)
            print(colored("Adding %s" % patch_inst, 'green', attrs=['reverse']))
            self.patching_targets.append(patch_inst)
            table_offset += 8
        elif expr in self.fun_offset_set:
            print("Offset found", self.fun_offset_set[expr])
            patch_inst = PatchingInst(inst_type=i_type, dest=dest, src=src ,offset=expr)
            if patch_inst not in self.patching_targets:
                print(colored("Adding %s" % patch_inst, 'blue', attrs=['reverse']))
                self.patching_targets.append(patch_inst)
            # exit()
        elif inst_ssa_expr == None and expr != None and expr not in self.fun_ignore_set:
            patch_inst = PatchingInst(inst_type=i_type, dest=dest, src=src, offset=expr)
            print("Adding", patch_inst)
            self.patching_targets.append(patch_inst)
        None
    
    def analyze_inst(self, inst_ssa, llil_fun, mlil_fun, ignore, var_targets):
        dis_inst = self.bv.get_disassembly(inst_ssa.address)
        print("Analyzing inst", dis_inst)
        if dis_inst == None:
            return None
        pattern = r"(\b[a-z]+\b)\s*(.*),\s(.*)"
        offset_pattern = r".*\[(.*)\]"
        find_type_target = re.search(pattern, dis_inst)
        i_type      = str()
        dest        = str()
        src         = str()
        if find_type_target != None:
            i_type = find_type_target.group(1)
            dest = find_type_target.group(2)
            src = find_type_target.group(3)
        
        if inst_ssa.address in self.avoid_targets:
            # Avoid this target
            return None
        
        result = self.check_for_mem_ref(inst_ssa.dest, mlil_fun)
        if result != None:
            if result == "global":
                return None
            
            # try:
            if result[0] == "segment":
                # print(dis_inst, "Add ignore offset target", result[1])
                if result[1] not in self.fun_ignore_set:
                    print(colored("Ignoring %s" % result[1], 'red', attrs=['reverse']))
                    self.fun_ignore_set.add(result[1])
                else:
                    target = str()
                    ignore_expr = str()
                    if re.search(offset_pattern, dest):
                        target = re.search(offset_pattern, dest).group(1)
                    if re.search(offset_pattern, src):
                        target = re.search(offset_pattern, src).group(1)
                    ignore_expr = conv_expr(target)
                    if ignore_expr not in self.fun_ignore_set:
                        print(colored("Ignoring %s" % ignore_expr, 'red', attrs=['reverse']))
                        self.fun_ignore_set.add(ignore_expr)
            elif result != None:
                print("Got the expression: ", result)
                self.find_add_offset(None, i_type, dest, src, result)
            # except:
                
            # try:
            #     mem_ref_result = self.analyze_mem_ref_inst(result)
            #     if mem_ref_result[0] == "segment": 
            #         print(dis_inst, "Add ignore offset target", mem_ref_result[1])
            #         self.fun_ignore_set.add(mem_ref_result[1])
            #         exit()
            # except:
            #     if result != None:
                    # print("Got the expression: ", result)
                    # self.find_add_offset(None, i_type, dest, src, result)
            # exit()
        else:
            for llil_bb in llil_fun.ssa_form:
                for llil_inst in llil_bb:
                    # print("Target", target_offset)
                    if llil_inst == inst_ssa.llil:
                        print("Target: ", llil_inst, llil_inst.operation, result)
                        if llil_inst.operation == LowLevelILOperation.LLIL_SET_REG_SSA:
                            if binaryninja.commonil.Arithmetic in llil_inst.src.__class__.__bases__:
                                self.find_add_offset(llil_inst.src, i_type, dest, src, None)
                        elif llil_inst.operation == LowLevelILOperation.LLIL_STORE_SSA:
                            if re.search(offset_pattern, dest):
                                target = re.search(offset_pattern, dest).group(1)
                            if re.search(offset_pattern, src):
                                target = re.search(offset_pattern, src).group(1)
                            expr = conv_expr(target)
                            if ignore == True:
                                # print("Ignore this")
                                for var in var_targets:
                                    if var.offset == expr:
                                        self.fun_ignore_set.add(expr)
                                        print(var, var.struct_type)
                                        if var.struct_type != None:
                                            print("Ignore other member variables too", llil_fun.source_function.name, var_targets)
                                            find_struct_result = find_struct(llil_fun.source_function.name, None, var)
                                        for item in find_struct_result:
                                            self.fun_ignore_set.add(item)
                                        print(colored("Ignoring %s" % self.fun_ignore_set, 'red', attrs=['reverse']))
                            if binaryninja.commonil.Arithmetic in llil_inst.dest.__class__.__bases__ and expr not in self.fun_ignore_set:
                                self.find_add_offset(llil_inst.dest, i_type, dest, src, None)
                            
         
    def analyze_llil_inst(self, inst_ssa, dis_inst):
        print("Analyzing llil inst", inst_ssa, type(inst_ssa), dis_inst)
        try:
            if binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
                print("Here", inst_ssa)
                offset = self.find_offset(inst_ssa)
                if offset != None:
                    pattern = r"(\b[a-z]+\b)\s*(.*),\s(.*)"
                    print("dis:",dis_inst)
                    find_type_target = re.search(pattern, dis_inst)
                    i_type  = str()
                    dest    = str()
                    src     = str()
                    if find_type_target != None:
                        i_type = find_type_target.group(1)
                        dest = find_type_target.group(2)
                        src = find_type_target.group(3)
                    print("info:", i_type, dest, src, offset)
                    self.find_add_offset(None, i_type, dest, src, offset)
            else:
                self.analyze_llil_inst(inst_ssa.src, dis_inst)
        except Exception as error:
            print(error, "\n")
            return None   
                 
    def analyze_params(self, src_ssa, mlil_fun):
        # Takes in SSA parameters
        for param_var in src_ssa.params:
            print(param_var.operation, param_var)
            if param_var.operation == MediumLevelILOperation.MLIL_VAR_SSA or \
            param_var.operation == MediumLevelILOperation.MLIL_VAR or \
            param_var.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA or \
            param_var.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
                result = self.check_for_mem_ref(param_var, mlil_fun)
                if result != None:                    
                    self.analyze_mem_ref_inst(result)
                    
    def analyze_call_inst(self, inst_ssa, llil_fun, mlil_fun, var_targets):
        try:
            if type(inst_ssa.dest) == binaryninja.mediumlevelil.MediumLevelILConstPtr:
                called_fun =  self.bv.get_function_at(inst_ssa.dest.constant)
                # print("Function", type(called_fun), called_fun.name)
                if (called_fun.name == "calloc" or called_fun.name == "malloc"):
                    print("Found heap fun")
                    result = inst_ssa.vars_written[0]
                    # print("Dest", result, "\n\t",  mlil_fun.get_ssa_var_uses(result))
                    for item in mlil_fun.get_ssa_var_uses(result):
                        if type(item) == binaryninja.mediumlevelil.MediumLevelILSetVar:
                            result = self.analyze_inst(item, llil_fun, mlil_fun, True, var_targets)
                            print(result)
                            # print(item.src)
                            # print(hex(item.address), self.bv.get_disassembly(item.address))
                            # result = self.check_for_mem_ref(item, mlil_fun)
                            # print(result)
        except Exception as error:
            print(error, "\n")
            # None
        # exit()
        # result = self.check_for_mem_ref(inst_ssa, mlil_fun)
        # print(result)

    def backward_slice(self, high, medium, low, lift, var_targets):
        
        
                            # 
                    # print(type(inst.left), inst.right)
                    # print(inst.ssa_form)
                    
        # This is disabled, no need fo rHLIL
        # for hlil_bb in high:
        #     for inst in hlil_bb:
        #         try: 
        #             if type(inst.src) == HighLevelILCall:
        #                 # print("Register:", inst.dest, self.bv.get_disassembly(inst.address))
        #                 test = self.bv.get_code_refs(inst.src)
        #                 print("Register:", inst.dest, inst, test)
        #         except:
        #             None

        for mlil_bb in medium:
            for inst in mlil_bb:
                
                inst_ssa = inst.ssa_form
                # If I were to only target taint function (not all variables), build off from this:
                # print(inst, inst_ssa, inst_ssa.operation)
                if inst_ssa.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                    # Disabling for now since I don't quite see the need
                    None 
                    print("Call instruction analysis", inst)
                    # self.analyze_params(inst_ssa, medium)
                    self.analyze_call_inst(inst_ssa, low, medium, var_targets)
                elif inst_ssa.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA or \
                        inst_ssa.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
                    # This is where I try to analyze instruction that doesn't refer to memory (hard set)
                    # None
                    # if inst_ssa.address == 6918:
                        #  print(inst_ssa.vars_written[0])
                    #     print("Analyzing: ", inst_ssa, type(inst_ssa.src), type(inst_ssa.dest))
                    print(inst_ssa, inst_ssa.vars_written[0])
                    print(colored("Checking %s %s" % (inst_ssa,inst_ssa.vars_written[0]), 'yellow', attrs=['reverse']))
                    self.analyze_inst(inst_ssa, low, medium, False, var_targets)
                    # print("\n")
                    None
        for llil_bb in low.ssa_form:
            for llil_inst in llil_bb:
                if llil_inst.operation == LowLevelILOperation.LLIL_SET_REG_SSA:
                    # print(type(llil_inst.src))
                    if binaryninja.lowlevelil.LowLevelILUnaryBase in llil_inst.src.__class__.__bases__: 
                        dis_inst = self.bv.get_disassembly(llil_inst.address)
                        if dis_inst == None:
                            break
                        self.analyze_llil_inst(llil_inst, dis_inst)
        
        for lift_bb in lift:
            for inst in lift_bb:
                if inst.operation == LowLevelILOperation.LLIL_SUB:
                    if type(inst.left) == binaryninja.lowlevelil.LowLevelILLoad:
                        off = self.find_offset(inst.left.src)
                        if off != None and off != False:
                            try:
                                dis_inst = self.bv.get_disassembly(inst.address)
                                pattern = r"(\b[cmp]+\b)\s*(.*),\s(.*)"
                                find_type_target = re.search(pattern, dis_inst)
                                # print(find_type_target)
                                i_type      = str()
                                src         = str()
                                if find_type_target != None:
                                    i_type = find_type_target.group(1)
                                    dest = find_type_target.group(2)
                                    src = find_type_target.group(3)
                                    patch_inst = PatchingInst(inst_type=i_type, dest=dest, src=src, offset=off)
                                    if patch_inst not in self.patching_targets:
                                        # print(self.fun_ignore_set)
                                        if off != None and off not in self.fun_ignore_set:
                                            self.patching_targets.append(patch_inst)
                                            print(colored("Adding %s" % patch_inst, 'green', attrs=['reverse']))
                            except Exception as Err:
                                print("No disassembly inst", Err)
        

    def analyze_binary(self, funlist):
        print("Step: Binary Ninja")
        # print(self.bv.get_data_refs_for_type_field("myStruct", 4))
        # print(self.bv.get_code_refs_for_type_field("badStruct", 0))
        # # for item in refs:
        # #     print(item)
        for func in self.bv.functions:
            print ("Function:", func.name)
            if func.name in funlist:
                hlil_fun = func.high_level_il
                mlil_fun = func.medium_level_il
                llil_fun = func.low_level_il
                lift_fun = func.lifted_il
                var_targets = None
                try:
                    var_targets = fun_var_info[func.name]
                    self.backward_slice(hlil_fun, mlil_fun, llil_fun, lift_fun, var_targets)
                    fun_patch_tgts[func.name] = self.patching_targets.copy()
                    prog_offset_set[func.name] = self.fun_offset_set.copy()
                    struct_offset_set[func.name] = find_struct(func.name, var_targets, None).copy()
                    
                    print("\n\nClearing\n\n")
                    self.patching_targets.clear()
                    self.fun_offset_set.clear()
                    self.fun_ignore_set.clear()
                except:
                    print("No var_targets")
                # print(var_targets)
                
                # Think about how to handle "cmp" instruction.
                # It's basically same as sub, but doesn't store the result.
                # Use lifted_IL, get SUB, the reason why tihs is fine is because
                # it doesn't store the info, so just being SUB implies comparison.
if __name__ == '__main__':
    process_argument(sys.argv[1:])
    