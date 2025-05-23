from email import generator
import sys, getopt
import logging, os
import re
import pprint
import copy
from tkinter import FALSE
from binaryninja.types import MemberName

from elftools import *
from elftools.dwarf.die import DIE
from elftools.elf.elffile import DWARFInfo, ELFFile
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
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field



@dataclass(unsafe_hash = True)
class MemberData:
    name: str = None
    offset: str = None
    var_type: str = None
    base_type: Optional[str] = None
    offset_expr: str = None

struct_list = list()
@dataclass(unsafe_hash = True)
class StructData:
    name: Optional[str] = None
    offset: str = None
    size: int = None
    line: int = None
    member_list: Optional[list] = None
    # fun_name: str = None
    # begin: Optional[str] = None
    # end: Optional[str] = None
    # offset_expr: str = None

var_list = list()
@dataclass(unsafe_hash=True)
class VarData:
    name: Optional[str] = None
    offset: str = None
    base_type: Optional[str] = None
    var_type: str = None    
    # fun_name: str = None
    offset_expr: str = None
    struct: Optional[StructData] = None
    type_size: Optional[str] = None
    local: bool = False

fun_list = list()
@dataclass(unsafe_hash=True)
class FunData:
    name: str = None
    var_list: list[VarData] = None
    # struct_list: list[StructData] = None
    # var_count: Optional[int] = None
    begin: Optional[str] = None
    end: Optional[str] = None
    frame: Optional[int] = None
    
type_dict = dict()
type_dict["float"] = 4  # Manually adding float because for some reason, DWARF puts this at last
type_dict["double"] = 8 # Manually adding double because for some reason, DWARF puts this at last
type_dict["char"] = 1   # Manually adding double because for some reason, DWARF puts this at last

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('main')

class DwarfAnalysis:
    def __init__(self, input_binary):
        self.input_binary = input_binary
        self.target_dir = Path(os.path.abspath(input_binary)).parent
        self.type_dict = {}
        self.file_stream = open(input_binary, 'rb')  # Open file stream and keep it open
        self.elffile = ELFFile(self.file_stream)  # ELFFile is now associated with the open file stream
        self.dwarfinfo = self.load_dwarf_info()
        self.arrow = 'U+21B3'
        self.currFun: FunData = None
        self.currVar: VarData = None
        self.temp_struct: StructData = None
        self.var_list = list()
        self.last_DIE_tag = list()

    def load_dwarf_info(self):
        if not self.elffile.has_dwarf_info():
            logger.error('File has no DWARF info')
            return None

        dwarfinfo = self.elffile.get_dwarf_info()
        return dwarfinfo

    def process_dwarf_info(self):
        if not self.dwarfinfo:
            return

        location_lists = self.dwarfinfo.location_lists()
        set_global_machine_arch(self.elffile.get_machine_arch())
        loc_parser = LocationParser(location_lists)

        for CU in self.dwarfinfo.iter_CUs():
            length = sum(1 for _ in CU.iter_DIEs()) - 1
            for idx, DIE in enumerate(CU.iter_DIEs()):
                self.process_die(DIE, loc_parser, CU, idx, length)

    def process_die(self, DIE, loc_parser, CU, idx, size):
        last_tag = None
        # print(DIE.tag, self.currVar)
        if len(self.last_DIE_tag) > 0:
            last_tag = self.last_DIE_tag.pop()
        if DIE.tag == "DW_TAG_base_type":
            self.process_base_type(DIE)
        elif DIE.tag == "DW_TAG_subprogram":
            self.process_subprogram(DIE, loc_parser, CU)
        elif DIE.tag == "DW_TAG_formal_parameter":
            self.process_variable(DIE, loc_parser, CU)
        elif DIE.tag == "DW_TAG_variable":
            self.process_variable(DIE, loc_parser, CU)
        elif DIE.tag == "DW_TAG_structure_type":
            self.process_struct(DIE)
        elif DIE.tag == "DW_TAG_member":
            self.process_member(DIE, loc_parser, CU)
        elif DIE.tag == None and idx == size:
            # Final function at the end of DWARF information
            if self.currFun != None:
                self.currFun.var_list = self.var_list
                pprint.pprint(self.currFun)
                logger.critical("Fun %s finished", self.currFun.name)
                self.var_list.clear()
        elif DIE.tag == None and last_tag == "DW_TAG_member":
            # Finished the struct analysis
            self.temp_struct.member_list = self.var_list.copy()
            pprint.pprint(self.temp_struct)
            struct_list.append(self.temp_struct)
            self.temp_struct = None
            self.var_list.clear()
            # exit()
        
        self.last_DIE_tag.append(DIE.tag)

    def process_subprogram(self, DIE, loc_parser, CU):
        if self.currFun != None:
            self.currFun.var_list = self.var_list
            pprint.pprint(self.currFun)
            logger.critical("Fun %s finished", self.currFun.name)
            self.var_list.clear()
        rbp_regex = r"(?<=\(DW_OP_breg.\s\(rbp\):\s)(.*)(?=\))"
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
                
                fun_name = self.get_attribute_value(DIE, 'DW_AT_name')
                logger.error("Function name: %s", fun_name)
                loc = loc_parser.parse_from_attribute(attr, CU['version'])
                self.currFun = FunData(name=fun_name, var_list=None, 
                                       begin=hex(lowpc), end=hex(highpc))
                if isinstance(loc, list):
                    for loc_entity in loc:
                        if isinstance(loc_entity, LocationEntry):
                            offset = describe_DWARF_expr(loc_entity.loc_expr, self.dwarfinfo.structs, CU.cu_offset)
                            if "rbp" in offset:
                                if rbp_offset := re.search(rbp_regex, offset):
                                    # This will result in function frame value that will be used to calculate the offset
                                    fun_frame_base = int(rbp_offset.group(1))
                                    self.currFun.frame = fun_frame_base
        # Further processing for subprogram here...
        
    def process_base_type(self, DIE):
        type_name = self.get_attribute_value(DIE, 'DW_AT_name')
        type_size = self.get_attribute_value(DIE, 'DW_AT_byte_size', integer=True)
        if type_name and type_size and type_name not in self.type_dict:
            self.type_dict[type_name] = type_size
            logger.critical("%s %s", type_name, type_size)

    def process_variable(self, DIE, loc_parser, CU):
        logger.info("Processing: %s", DIE.tag)
        self.currVar = VarData()
        var_name = None
        for var_attr in DIE.attributes.values():
            if (var_attr.name == "DW_AT_name"):
                # Getting the name of a variable (skip a variable which doesn't have name)
                var_name = self.get_attribute_value(DIE, 'DW_AT_name')
                self.currVar.name = var_name
                logger.debug("%s Name: %s",chr(int(self.arrow[2:], 16)), var_name)
            if (loc_parser.attribute_has_location(var_attr, CU['version'])):
                # Calculating the offset of a variable
                loc = loc_parser.parse_from_attribute(var_attr, CU['version'])
                var_offset = self.get_offset(DIE, loc, CU)
                if self.currVar.local == True:
                    # Global
                    hex_var_offset = hex(var_offset)
                    reg_offset = str(var_offset) + "(%rbp)" 
                    self.currVar.offset = var_offset
                    self.currVar.offset_expr = reg_offset
                    logger.debug("\t Offset: %s (hex: %s)", reg_offset, hex_var_offset)
                else:
                    # Global
                    logger.debug("\t Offset: %s", var_offset)
            if (var_attr.name == "DW_AT_type"):
                # Getting the type of a variable
                self.get_dwarf_type(DIE)
        if var_name != None:
            # Only consider a variable with name
            logger.info(self.currVar)
            logger.warning("Finished: %s\n", var_name)
            self.var_list.append(self.currVar)
        self.currVar = None

    def process_member(self, DIE, loc_parser, CU):
        off_regex = r"(?<=\(DW_OP_plus_uconst:\s)(.*)(?=\))"
        logger.info("Processing: %s", DIE.tag)
        self.currVar = MemberData()
        member_name = None
        for mem_attr in DIE.attributes.values():
            if (mem_attr.name == "DW_AT_name"):
                # Getting the name of a variable (skip a variable which doesn't have name)
                member_name = self.get_attribute_value(DIE, 'DW_AT_name')
                self.currVar.name = member_name
                logger.debug("%s Name: %s",chr(int(self.arrow[2:], 16)), member_name)
            if (loc_parser.attribute_has_location(mem_attr, CU['version'])):
                loc = loc_parser.parse_from_attribute(mem_attr, CU['version'])
                if(mem_attr.name == "DW_AT_data_member_location"):
                    if isinstance(loc, LocationExpr):
                        offset = re.search(off_regex, describe_DWARF_expr(loc.loc_expr, self.dwarfinfo.structs,
                                                                          CU.cu_offset))
                        var_offset = offset.group(1)
                        logger.debug("\t Offset: %s", var_offset)
                        self.currVar.offset = var_offset
                # Calculating the offset of a variable
            if (mem_attr.name == "DW_AT_type"):
                # Getting the type of a variable
                self.get_dwarf_type(DIE)
        logger.info(self.currVar)
        logger.warning("Finished: %s\n", member_name)
        self.var_list.append(self.currVar)
        self.currVar = None
        # exit()

    def process_struct(self, DIE):
        """
        Recursively resolve the type until a non-pointer or non-array type is found.
        """
        struct_name = self.get_attribute_value(DIE, 'DW_AT_name')
        byte_size = None
        line_num = None
        if struct_name != None:
            logger.debug("StructName: %s", struct_name)
        if 'DW_AT_byte_size' in DIE.attributes:
            byte_size   = DIE.attributes['DW_AT_byte_size'].value
        if 'DW_AT_decl_line' in DIE.attributes:
            line_num    = DIE.attributes['DW_AT_decl_line'].value
        if byte_size != None and line_num != None:
            logger.warning("Creating temp_struct: %s %s %s", struct_name, byte_size, line_num)
            self.temp_struct = StructData(name=struct_name, size=byte_size, line=line_num)

    def resolve_ptr_type(self, type_die):
        """
        Recursively resolve the type until a non-pointer or non-array type is found.
        """
        current_die = type_die
        while True:
            if 'DW_AT_type' in current_die.attributes:
                try:
                    refaddr = current_die.attributes['DW_AT_type'].value + current_die.cu.cu_offset
                    current_die = self.dwarfinfo.get_DIE_from_refaddr(refaddr, current_die.cu)
                    if current_die.tag not in ["DW_TAG_pointer_type", "DW_TAG_array_type"]:
                        # If it's another pointer or array type, continue resolving.
                        continue
                except KeyError:
                    logger.error("Type resolution failed, attribute DW_AT_type not found.")
                    break
            else:
                # No more type attributes to resolve; current_die is the final type DIE.
                break
        return current_die
    
    def resolve_struct_type(self, type_die):
        byte_size = None
        line_num = None
        if 'DW_AT_byte_size' in type_die.attributes:
            byte_size   = type_die.attributes['DW_AT_byte_size'].value
        if 'DW_AT_decl_line' in type_die.attributes:
            line_num    = type_die.attributes['DW_AT_decl_line'].value
        for struct_item in struct_list:
            if (byte_size == struct_item.size and line_num == struct_item.line):
                pprint.pprint(struct_item)
                self.currVar.struct = copy.deepcopy(struct_item)
                # exit()
                
    
    def get_dwarf_type(self, DIE):
        """ Retrieves and logs the primary type of a DIE and attempts to resolve pointers if present. """
        refaddr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
        type_die = self.dwarfinfo.get_DIE_from_refaddr(refaddr, DIE.cu)
        logger.debug("BaseType: %s", type_die.tag)
        self.currVar.base_type = type_die.tag
        if type_die.tag != "DW_TAG_base_type":
            resolved_type = self.resolve_ptr_type(type_die)
            if resolved_type:
                logger.debug("ResolvedType: %s", resolved_type.tag)
                self.currVar.var_type = resolved_type.tag
                if resolved_type.tag == "DW_TAG_base_type":
                    type_name = self.get_attribute_value(resolved_type, 'DW_AT_name')
                    if type_name != None:
                        self.currVar.type_size = str(self.type_dict[type_name])
                elif resolved_type.tag == "DW_TAG_structure_type":
                    self.resolve_struct_type(resolved_type)
                    # exit()
                    None
            else:
                logger.error("Failed to resolve type for DIE at CU offset: %d", DIE.cu.cu_offset)
        elif type_die.tag == "DW_TAG_base_type":
            type_name = self.get_attribute_value(type_die, 'DW_AT_name')
            if type_name != None:
                self.currVar.type_size = str(self.type_dict[type_name])
        elif type_die.tag == "DW_TAG_structure_type":
            self.resolve_struct_type(type_die)
            # exit()
            None
            
            # type_name = self.get_attribute_value(type_die, 'DW_AT_name')
            # if type_name != None:
            #     logger.debug("StructName: %s", type_name)

    def get_offset(self, DIE, loc, CU):
        reg_regex = r"DW_OP_fbreg:\s*(-?\d+)"
        gv_regex  = r"(?<=\(DW_OP_addr:\s)(.*)(?=\))"
        if isinstance(loc, LocationExpr):
            offset = describe_DWARF_expr(loc.loc_expr, self.dwarfinfo.structs, CU.cu_offset)
            if offset_regex := re.search(reg_regex, offset):
                self.currVar.local = True
                var_offset = self.currFun.frame + int(offset_regex.group(1))
                return var_offset
            elif global_regex := re.search(gv_regex, offset):
                self.currVar.local = False
                var_offset = global_regex.group(1)
                return var_offset

    def get_attribute_value(self, DIE, attr_name, integer=False):
        value = DIE.attributes.get(attr_name)
        if value:
            return value.value.decode() if not integer else int(value.value)
        return None

    def save_dwarf_output(self, filename):
        dwarf_outfile = self.target_dir.joinpath(f"{filename}.dwarf")
        with open(dwarf_outfile, "w") as fp:
            # Write the processed information to file
            pass

def process_argument(argv):
    inputfile = ''
    try:
        opts, args = getopt.getopt(argv, "hb:", ["binary="])
    except getopt.GetoptError:
        print('Usage: dwarf_analysis.py --binary <binary>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('Usage: dwarf_analysis.py --binary <binary>')
            sys.exit()
        elif opt in ("-b", "--binary"):
            inputfile = arg
    if inputfile:
        analyzer = DwarfAnalysis(inputfile)
        analyzer.process_dwarf_info()
        analyzer.save_dwarf_output("output_filename")
    else:
        print('Usage: dwarf_analysis.py --binary <binary>')
        sys.exit(2)

if __name__ == '__main__':
    process_argument(sys.argv[1:])