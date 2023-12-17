import sys, getopt
import logging, os
import re
import pprint
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

var_list = list()
@dataclass(unsafe_hash = True)
class VarData:
    name: Optional[str] = None
    offset: str = None
    var_type: str = None    
    base_type: Optional[str] = None
    fun_name: str = None

struct_list = list()
@dataclass(unsafe_hash = True)
class StructData:
    name: Optional[str] = None
    offset: str = None
    size: int = None
    line: int = None
    member_list: Optional[list] = None
    fun_name: str = None

@dataclass(unsafe_hash = True)
class StructMember:
    name: str = None
    offset: str = None
    var_type: str = None
    base_type: Optional[str] = None
    begin: Optional[str] = None
    end: Optional[str] = None

fun_list = list()
@dataclass(unsafe_hash=True)
class FunData:
    name: str = None
    var_list: list[VarData] = None
    struct_list: list[StructData] = None

def get_base_type(dwarfinfo: DWARFInfo, dwarf_die_atts, dwarf_die_cu, dwarf_die_cu_offset):
    # print(dwarf_die_atts)
    dwarf_name = None
    if 'DW_AT_type' in dwarf_die_atts:
        refaddr = dwarf_die_atts['DW_AT_type'].value + dwarf_die_cu_offset
        type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, dwarf_die_cu)
        # print(type_die)
        dwarf_name = get_base_type(dwarfinfo, type_die.attributes, dwarf_die_cu, dwarf_die_cu_offset)
        if dwarf_name != None:
            return dwarf_name
        else:
            get_base_type(dwarfinfo, type_die.attributes, dwarf_die_cu, dwarf_die_cu_offset)
    else:
        # print(dwarf_die_atts)
        if 'DW_AT_name' in dwarf_die_atts:
            dwarf_name = dwarf_die_atts['DW_AT_name'].value.decode()
            # print("Returning", dwarf_name)
            return dwarf_name

def get_dwarf_type(dwarfinfo: DWARFInfo, dwarf_die_atts, dwarf_die_cu, dwarf_die_cu_offset):
    if 'DW_AT_type' in dwarf_die_atts:
        refaddr = dwarf_die_atts['DW_AT_type'].value + dwarf_die_cu_offset
        type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, dwarf_die_cu)
        if (type_die.tag == "DW_TAG_typedef"):
            type_die = get_dwarf_type(dwarfinfo, type_die.attributes, dwarf_die_cu, dwarf_die_cu_offset)
            if type_die.tag != "DW_TAG_typedef":
                return type_die
            else: 
                get_dwarf_type(dwarfinfo, type_die.attributes, dwarf_die_cu, dwarf_die_cu_offset)
        else:
            return type_die

    

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
    log.info(target_dir.parent)
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
            last_var = []
            last_die_tag = []
            funname = None
            temp_fun = None
            temp_struct = None
            temp_struct_members = list()
            for DIE in CU.iter_DIEs():
                if (DIE.tag == "DW_TAG_subprogram"):
                    if temp_fun != None:
                        fun_list.append(temp_fun)
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
                            temp_fun = FunData(funname, None, None)
                            # fp.write("Function name: %s\n" % funname)
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
                    var_name    = None
                    reg_offset  = None
                    struct_var  = None
                    base_var    = None
                    for attr in DIE.attributes.values():
                        offset = None
                        if (attr.name == "DW_AT_name"):
                            var_name = DIE.attributes["DW_AT_name"].value.decode()
                            log.debug("\tVar name: %s", var_name)
                            # fp.write("\tVar name: %s\n" % var_name)
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
                                    # fp.write("\tOffset:\t%s (hex: %s)\n\n" % (reg_offset, hex_var_offset))
                                    # We found struct_variable, update its begin / end member
                                    if struct_var == True:
                                        working_var = last_var.pop()
                                        # print("Working var: ", working_var)
                                        # print(working_var.size)
                                        working_var.fun_name = funname
                                        working_var.offset = hex_var_offset
                                        for i, member in enumerate(working_var.member_list):
                                            # begin = 
                                            if i+1 < len(working_var.member_list):
                                                # print(working_var.offset, member.offset)
                                                begin   = hex(int(var_offset) + int(member.offset))
                                                end     = hex(int(var_offset) + int(working_var.member_list[i+1].offset))
                                                member.begin    = begin
                                                member.end      = end
                                            else:
                                                begin   = hex(int(var_offset) + int(member.offset))
                                                end     = hex(int(var_offset) + int(working_var.size))
                                                member.begin    = begin
                                                member.end      = end
                                        # pprint.pprint(working_var, width=1)
                                    # This is just a base variable, update its offset like regular
                                    elif base_var == True:
                                        working_var = last_var.pop()
                                        working_var.offset = hex(var_offset)
                                        var_list.append(working_var)
                                        # print(working_var)
                                    
                            print()
                        if (attr.name == "DW_AT_type"):
                            refaddr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
                            type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, DIE.cu)
                            typedef_name    = None
                            type_name       = None
                            # typedef structure variable)
                            if type_die.tag == "DW_TAG_typedef" or type_die.tag == "DW_TAG_structure_type":
                                typedef_name = type_die.attributes['DW_AT_name'].value.decode()
                            # type* or type[] variable
                            elif type_die.tag == "DW_TAG_array_type" or type_die.tag == "DW_TAG_pointer_type":
                                arr_ptr_type_die = get_dwarf_type(dwarfinfo, type_die.attributes, type_die.cu, type_die.cu.cu_offset)
                                # print(type_die.tag, arr_ptr_type_die.tag)
                                # This will return base type such as char or int
                                if 'DW_AT_name' in arr_ptr_type_die.attributes:
                                    type_name = arr_ptr_type_die.attributes['DW_AT_name'].value.decode()    
                                # This is for double pointer
                                elif 'DW_AT_type' in arr_ptr_type_die.attributes:
                                    double_ptr_die = get_dwarf_type(dwarfinfo, arr_ptr_type_die.attributes, arr_ptr_type_die.cu, arr_ptr_type_die.cu.cu_offset)
                                    if double_ptr_die.tag == "DW_TAG_base_type":
                                        type_name = double_ptr_die.attributes['DW_AT_name'].value.decode()    
                            elif type_die.tag == "DW_TAG_const_type":
                                const_die = get_dwarf_type(dwarfinfo, type_die.attributes, type_die.cu, arr_ptr_type_die.cu.cu_offset)
                                if const_die.tag == "DW_TAG_array_type" or const_die.tag == "DW_TAG_pointer_type":
                                    # print(const_die.tag)
                                    const_type_die = get_dwarf_type(dwarfinfo, const_die.attributes, const_die.cu, type_die.cu.cu_offset)
                                    if 'DW_AT_type' in const_type_die.attributes:
                                        const_base_ptr_die = get_dwarf_type(dwarfinfo, const_type_die.attributes, const_type_die.cu, const_type_die.cu.cu_offset)
                                        if 'DW_AT_name' in const_base_ptr_die.attributes:
                                            const_type_name = const_base_ptr_die.attributes['DW_AT_name'].value.decode() 
                                            type_name = const_type_name
                                            # print(const_type_name)
                                # exit()
                            else:
                                # if not typedef, then it's going to be base type name (e.g., int)
                                print(type_die)
                                type_name = type_die.attributes['DW_AT_name'].value.decode()
                            
                            rec_type_die = get_dwarf_type(dwarfinfo, DIE.attributes, DIE.cu, DIE.cu.cu_offset)
                            # print("Rec:", rec_type_die)
                            # We recurisvely go through type to figure out whether typedef is a struct or base type (reg)
                            if rec_type_die.tag == "DW_TAG_structure_type":                            
                                log.debug("\tStruct found: %s", typedef_name)
                                struct_var = True
                                byte_size   = rec_type_die.attributes['DW_AT_byte_size'].value
                                line_num    = rec_type_die.attributes['DW_AT_decl_line'].value
                                # We use byte size + line number to match the struct object
                                # print(byte_size, line_num)
                                for item in struct_list:
                                    # This is to match the struct object
                                    if item.size == byte_size and item.line == line_num:
                                        # This is to update struct name
                                        if typedef_name != None:
                                            item.name = typedef_name
                                            last_var.append(item)
                            elif rec_type_die.tag == "DW_TAG_pointer_type" and arr_ptr_type_die.tag == "DW_TAG_pointer_type":  
                                log.debug("\tDouble Ptr var found: %s", type_name)
                                temp_var = VarData(var_name, None, type_name, "DW_TAG_dbl_pointer_type", funname)
                                last_var.append(temp_var)
                                base_var = True
                            elif rec_type_die.tag == "DW_TAG_pointer_type" and arr_ptr_type_die.tag == "DW_TAG_structure_type":
                                # This is for struct pointer variables
                                if 'DW_AT_name' in arr_ptr_type_die.attributes:
                                    typedef_name = arr_ptr_type_die.attributes['DW_AT_name'].value.decode()
                                # print(arr_ptr_type_die.tag, rec_type_die.tag)   
                                log.debug("\tStruct ptr var found: %s", type_name)
                                struct_var = True
                                byte_size   = arr_ptr_type_die.attributes['DW_AT_byte_size'].value
                                line_num    = arr_ptr_type_die.attributes['DW_AT_decl_line'].value
                                # We use byte size + line number to match the struct object
                                print(byte_size, line_num)
                                for item in struct_list:
                                    # This is to match the struct object
                                    if item.size == byte_size and item.line == line_num:
                                        print(item, typedef_name)
                                        # This is to update struct name
                                        if typedef_name != None:
                                            item.name = typedef_name
                                            last_var.append(item)
                            elif rec_type_die.tag == "DW_TAG_pointer_type": 
                                log.debug("\tPointer var found: %s", type_name)
                                temp_var = VarData(var_name, None, type_name, rec_type_die.tag, funname)
                                last_var.append(temp_var)
                                base_var = True
                            elif type_die.tag == "DW_TAG_typedef" and rec_type_die.tag == "DW_TAG_base_type": 
                                log.debug("\tTypedef var found: %s", typedef_name)
                                if 'DW_AT_name' in rec_type_die.attributes:
                                    type_name = rec_type_die.attributes['DW_AT_name'].value.decode() 
                                temp_var = VarData(var_name, None, type_name, rec_type_die.tag, funname)
                                last_var.append(temp_var)
                                base_var = True
                            elif rec_type_die.tag == "DW_TAG_base_type":   
                                print(rec_type_die)
                                log.debug("\tVariable found: %s", type_name)
                                temp_var = VarData(var_name, None, type_name, rec_type_die.tag, funname)
                                last_var.append(temp_var)
                                base_var = True
                            elif rec_type_die.tag == "DW_TAG_const_type":
                                log.debug("\tConst var found: %s", type_name)
                                temp_var = VarData(var_name, None, type_name, rec_type_die.tag, funname)
                                last_var.append(temp_var)
                                base_var = True
                
                # This is used to catch struct name in a global fashion.
                if DIE.tag == "DW_TAG_structure_type":
                    # pprint.pprint(DIE.attributes, width=1)
                    byte_size = None
                    line_num = None
                    if 'DW_AT_byte_size' in DIE.attributes:
                        byte_size   = DIE.attributes['DW_AT_byte_size'].value
                    if 'DW_AT_decl_line' in DIE.attributes:
                        line_num    = DIE.attributes['DW_AT_decl_line'].value
                    if byte_size != None and line_num != None:
                        temp_struct = StructData(None, None, byte_size, line_num, None)
                # This is used to catch member variables of a struct =
                if (DIE.tag == "DW_TAG_member"):
                    temp_member = StructMember(None, None, None, None)
                    attr_name = None
                    offset = None
                    for attr in DIE.attributes.values():
                        if(attr.name == "DW_AT_name"):
                            attr_name = DIE.attributes["DW_AT_name"].value.decode()
                            # log.debug("\tStruct member found: %s", attr_name)
                            temp_member.name = attr_name
                        if loc_parser.attribute_has_location(attr, CU['version']):
                            loc = loc_parser.parse_from_attribute(attr,
                                                                CU['version'])
                            if(attr.name == "DW_AT_data_member_location"):
                                # print(attr)
                                if isinstance(loc, LocationExpr):
                                    offset = re.search(off_regex, describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset))
                                    temp_member.offset = offset.group(1)
                                    # log.debug(offset.group(1))
                        if (attr.name == "DW_AT_type"):
                            refaddr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
                            type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, DIE.cu)
                            # print(type_die.tag)
                            # Tries to find the base type of variable recursively (e.g., long unsigned int, char)
                            # print(type_die, attr_name)
                            base_type_name = get_base_type(dwarfinfo, DIE.attributes, DIE.cu, DIE.cu.cu_offset)
                            # print(attr, base_type_name)
                            if base_type_name != None:
                                temp_member.var_type = ''.join(map(str, base_type_name))
                                # print(type(base_type_name))
                                # Base type such as whether it is an array (e.g., DW_TAG_array_type)
                                temp_member.base_type = type_die.tag
                    log.debug(temp_member)
                    temp_struct_members.append(temp_member)
                if (DIE.tag == None):
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
                    if temp_fun != None:
                        fun_list.append(temp_fun)
                        temp_fun = None
                last_die_tag.append(DIE.tag)
    
    log.info("Struct list")
    fp.write("Structs:\n")
    pprint.pprint(struct_list, width=100, depth=4, compact=True)
    # print(vars(struct_list))

    # Iterate through function list once to populate the list
    for fun in fun_list:
        print(fun.name)
        temp_struct_list = list()
        temp_var_list = list()
        for idx, struct in enumerate(struct_list):
            if struct.fun_name == fun.name:
                temp_struct_list.append(struct)
        for idx, var in enumerate(var_list):
            if var.fun_name == fun.name:
                temp_var_list.append(var)
        fun.struct_list = temp_struct_list.copy()
        fun.var_list = temp_var_list.copy()


    # In second iteration, we will write it to the file pointer
    for fun in fun_list:
        fp.write("\n-------------Begin-----------------\nFunction Name: %s\n" % fun.name)
        for idx, struct in enumerate(struct_list):
            print(getattr(struct, "offset"))
            fp.write("\n    ------------------------------\n\tName: %s\n" % struct.name)
            fp.write("\tOffset: %s\n" % struct.offset)
            fp.write("\tMembers:\n")
            for m_idx, member in enumerate(struct.member_list):
                fp.write("        __________________________\n\t\tName: %s\n" % member.name)
                fp.write("\t\tVarType: %s\n" % member.var_type)
                fp.write("\t\tBaseType: %s\n" % member.base_type)
                fp.write("\t\tBegin: %s\n" % member.begin)
                fp.write("\t\tEnd: %s\n" % member.end)
            for idx, var in enumerate(var_list):
                fp.write("\n    ------------------------------\n\tName: %s\n" % var.name)
                fp.write("\tOffset: %s\n" % var.offset)
                fp.write("\tVarType: %s\n" % var.var_type)
                fp.write("\tBaseType: %s\n" % var.base_type)
        
        fp.write("\n--------------End------------------\n")
    # test = None
    fp.write("\n")
    None
                        
    # print("Variable list")
    # fp.write("\nVariables:\n")
    # pprint.pprint(var_list, width=1)

    #     None
    
    pprint.pprint(fun_list, width=1)

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