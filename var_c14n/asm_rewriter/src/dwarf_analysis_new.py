import sys, getopt
import logging, os
import re
import pprint
import copy
from tkinter import FALSE
from binaryninja.types import MemberName

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



var_list = list()
@dataclass(unsafe_hash=True)
class VarData:
    name: Optional[str] = None
    offset: str = None
    var_type: str = None    
    base_type: Optional[str] = None
    fun_name: str = None
    offset_expr: str = None
    # struct: Optional[StructData] = None
    type_size: Optional[str] = None

fun_list = list()
@dataclass(unsafe_hash=True)
class FunData:
    name: str = None
    var_list: list[VarData] = None
    # struct_list: list[StructData] = None
    var_count: Optional[int] = None
    begin: Optional[str] = None
    end: Optional[str] = None
    
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
            for DIE in CU.iter_DIEs():
                self.process_die(DIE, loc_parser, CU)

    def process_die(self, DIE, loc_parser, CU):
        if DIE.tag == "DW_TAG_base_type":
            self.process_base_type(DIE)
        elif DIE.tag == "DW_TAG_subprogram":
            self.process_subprogram(DIE, loc_parser, CU)
        elif DIE.tag == "DW_TAG_formal_parameter":
            self.process_variable(DIE, loc_parser, CU)
        elif DIE.tag == "DW_TAG_variable":
            self.process_variable(DIE, loc_parser, CU)
            # var_name = self.get_attribute_value(DIE, 'DW_AT_name')
            # logger.debug("Variable finished: %s", var_name)


    def process_base_type(self, DIE):
        type_name = self.get_attribute_value(DIE, 'DW_AT_name')
        type_size = self.get_attribute_value(DIE, 'DW_AT_byte_size', integer=True)
        if type_name and type_size and type_name not in self.type_dict:
            self.type_dict[type_name] = type_size
            logger.critical("%s %s", type_name, type_size)

    def process_variable(self, DIE, loc_parser, CU):
        logger.info("Processing: %s", DIE.tag)
        var_name = None
        for var_attr in DIE.attributes.values():
            if (var_attr.name == "DW_AT_name"):
                var_name = DIE.attributes["DW_AT_name"].value.decode()
                logger.debug("%s Name: %s",chr(int(self.arrow[2:], 16)), var_name)

        logger.warning("Finished: %s\n", var_name)
        
    def process_subprogram(self, DIE, loc_parser, CU):
        fun_name = self.get_attribute_value(DIE, 'DW_AT_name')
        logger.info("Function name: %s\n", fun_name)
        # Further processing for subprogram here...

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