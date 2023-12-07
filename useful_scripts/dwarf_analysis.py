import sys, getopt
import logging, os
import re
import pprint

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
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

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

struct_list = list()
@dataclass(unsafe_hash = True)
class StructData:
    name: Optional[str] = None
    size: int = None
    line: int = None
    member_list: Optional[list] = None

def dwarf_analysis(input_binary):
    target_dir = Path(os.path.abspath(input_binary))
    c14n_regex = r"(fun\_c14n|var\_c14n)"
    c14n_type = re.search(c14n_regex, target_dir.__str__())
    if c14n_type != None:
        if c14n_type.group(1) == "fun_c14n":
            log.info("fun_c14n input\n")
        elif c14n_type.group(1) == "var_c14n":
            log.info("var_c14n input\n")
        else:
            log.error("c14n type unknown")
            exit()    
    # log.info(target_dir.parent)
    dwarf_outfile = target_dir.parent.joinpath("dwarf.out")
    fp = open(dwarf_outfile, "w") 
    
    with open(input_binary, 'rb') as f:
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
        reg_regex = r"(?<=\(DW_OP_fbreg:\s)(.*)(?=\))"
        rbp_regex = r"(?<=\(DW_OP_breg.\s\(rbp\):\s)(.*)(?=\))"
        off_regex = r"(?<=\(DW_OP_plus_uconst:\s)(.*)(?=\))"
        
        for CU in dwarfinfo.iter_CUs():

            # print(DIE_count)
            last_die_tag = []
            temp_struct = None
            temp_struct_members = list()
            for DIE in CU.iter_DIEs():
                if (DIE.tag == "DW_TAG_subprogram"):
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
                            log.info("Function name: %s", funname)
                            fp.write("Function name: %s\n" % funname)
                            loc = loc_parser.parse_from_attribute(attr, CU['version'])
                            if isinstance(loc, list):
                                for loc_entity in loc:
                                    if isinstance(loc_entity, LocationEntry):
                                        offset = describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, CU.cu_offset)
                                        if "rbp" in offset:
                                            if rbp_offset := re.search(rbp_regex, offset):
                                                fun_frame_base = int(rbp_offset.group(1))
                
                if (DIE.tag == "DW_TAG_variable"):
                    # This is used for variable that is declared within the function
                    var_name = None
                    reg_offset = None   
                    for attr in DIE.attributes.values():
                        offset = None
                        if (attr.name == "DW_AT_name"):
                            var_name = DIE.attributes["DW_AT_name"].value.decode()
                            log.debug("\tVar name: %s", var_name)
                            fp.write("\tVar name: %s\n" % var_name)
                        if (loc_parser.attribute_has_location(attr, CU['version'])):
                            loc = loc_parser.parse_from_attribute(attr,
                                                                CU['version'])
                            if isinstance(loc, LocationExpr):
                                offset = describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset)
                                if offset_regex := re.search(reg_regex, offset):
                                    var_offset = int(offset_regex.group(1))
                                    var_offset += fun_frame_base
                                    # print(offset_regex.group(1))
                                    hex_var_offset = hex(var_offset)
                                    reg_offset = str(var_offset) + "(%rbp)" 
                                    log.debug("\tOffset:\t%s (hex: %s)", reg_offset, hex_var_offset)
                                    fp.write("\tOffset:\t%s (hex: %s)\n\n" % (reg_offset, hex_var_offset))
                            print()
                        if (attr.name == "DW_AT_type"):
                            try:
                                refaddr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
                                type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, DIE.cu)
                                if type_die.tag == "DW_TAG_structure_type":
                                    if 'DW_AT_name' in type_die.attributes:
                                        struct_name = type_die.attributes['DW_AT_name'].value.decode()
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
                            except Exception  as err:
                                    print(err)
                # This is used to catch struct name in a global fashion.
                if DIE.tag == "DW_TAG_structure_type":
                    pprint.pprint(DIE.attributes, width=1)
                    byte_size   = DIE.attributes['DW_AT_byte_size'].value
                    line_num    = DIE.attributes['DW_AT_decl_line'].value
                    temp_struct = StructData(None, byte_size, line_num, None)
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
                                print(attr)
                                if isinstance(loc, LocationExpr):
                                    offset = re.search(off_regex, describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset))
                                    # log.debug(offset.group(1))
                        # if(attr.name == "DW_AT_type"):
                        #     print(attr
                    # log.debug("Struct member name: %s\t| Offset: %s\n", attr_name, offset.group(1))
                    temp_struct_members.append((attr_name, offset.group(1)))
                if (DIE.tag == None):
                    last_tag = last_die_tag.pop()
                    if (last_tag == "DW_TAG_member"):
                         # Put members into the struct object
                        temp_struct.member_list = temp_struct_members.copy()
                        # log.debug("Inserting temp_struct")
                        # print(temp_struct)
                        struct_list.append(temp_struct)
                        temp_struct_members.clear()
                        temp_struct = None
                last_die_tag.append(DIE.tag)
    
    print("Struct list")
    for item in struct_list:
        print(item)
                        
                        
    fp.close()
    

def process_argument(argv):
    inputfile = ''
    try:
        opts, args = getopt.getopt(argv,"hfic:",["binary="])
    except getopt.GetoptError:
        print ('dwarf_analysis.py --binary <binary>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('dwarf_analysis.py --binary <binary>')
            sys.exit()
        elif opt in ("-b", "--binary"):
            inputfile = arg
    dwarf_analysis(inputfile)
    
if __name__ == '__main__':
    process_argument(sys.argv[1:])