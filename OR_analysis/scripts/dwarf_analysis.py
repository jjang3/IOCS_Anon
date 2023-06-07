from __future__ import print_function
from binaryninja import *
import sys
import re
import pprint

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

sys.path.insert(0, '/home/jaewon/binaryninja')

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

def create_mem_inst_token(input):
    inst = ""
    inst += "mov dword [" + input + "], 0x*"
    print(inst)
    return inst

bninja_fun_insts = dict() # dictionary for binary ninja analysis
dwarf_frame_bases = dict() # dictionary for DWARF analysis which contains addr_range, expr per fun.
dwarf_var_info = dict() # dictionary for DWARF analysis which contains variable information per fun.
def process_file(filename):
    with open_view(filename) as bv:                
        arch = Architecture['x86_64']
        print("Step: Binary Ninja")
        print("Number of functions: ", len(bv.functions))
        for fun in bv.functions:
            fun_name = ""
            for bb in fun:
                inst_list = list()
                for inst in bb.get_disassembly_text():
                    parsed_inst = "" # This is needed in order to avoid adding annotation
                    annot = False
                    for token in inst.tokens:
                        #print(token.text, token.type)
                        #print("Annot: ", annot)
                        if token.type == InstructionTextTokenType.AnnotationToken:
                            annot = True  
                        elif (token.type == InstructionTextTokenType.EndMemoryOperandToken):
                            annot = False
                        elif (annot == True):
                            continue

                        if (annot == False):
                            parsed_inst += token.text
                    parsed_inst = ' '.join(parsed_inst.split())
                    #print(parsed_inst)
                    regex = re.search(r'(.*)(?=:)', parsed_inst)
                    if regex:
                        #print(inst)
                        fun_name = regex.group(0)
                    else:
                        inst_list.append(parsed_inst)
                    #print("Parsed: ", parsed_inst)
                #for parsed_i in inst_list:
                #    print(parsed_i)
                bninja_fun_insts[fun_name] = inst_list
            print("\n")

    
    for item in bninja_fun_insts:
        print("Fun: ", item)
        for inst in bninja_fun_insts[item]:
            print("\tInst: " , inst)

    print('Processing file:', filename)
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

        for CU in dwarfinfo.iter_CUs():
            # DWARFInfo allows to iterate over the compile units contained in
            # the .debug_info section. CU is a CompileUnit object, with some
            # computed attributes (such as its offset in the section) and
            # a header which conforms to the DWARF standard. The access to
            # header elements is, as usual, via item-lookup.
            print('  Found a compile unit at offset %s, length %s' % (
                CU.cu_offset, CU['unit_length']))

            # A CU provides a simple API to iterate over all the DIEs in it.
            local_var_to_locs = list()
            global_var_to_locs = list()
            inside_fun = False
            for DIE in CU.iter_DIEs():
                funname = ""
                # Go over all attributes of the DIE. Each attribute is an
                # AttributeValue object (from elftools.dwarf.die), which we
                # can examine.
                var_to_loc = tuple()
                if (DIE.tag == "DW_TAG_subprogram"):
                    lowpc = DIE.attributes['DW_AT_low_pc'].value
                    # DWARF v4 in section 2.17 describes how to interpret the
                    # DW_AT_high_pc attribute based on the class of its form.
                    # For class 'address' it's taken as an absolute address
                    # (similarly to DW_AT_low_pc); for class 'constant', it's
                    # an offset from DW_AT_low_pc.
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
                    inside_fun = True
                    funname = DIE.attributes["DW_AT_name"].value.decode()
                    print("\n----------------------------------------------------------------------------")
                    print("Function name:", funname, "\t| Begin: ", hex(lowpc), "\t| End:", hex(highpc))
                    var_to_loc = (funname, "Function")
                    local_var_to_locs.append(var_to_loc)

                tuple_exists = False                    
                varname = ""
                for attr in DIE.attributes.values():
                    # Check if this DIE is a variable + contains name infomation.
                    if (DIE.tag == "DW_TAG_variable" and
                        attr.name == "DW_AT_name"):
                        print("Variable name:", DIE.attributes["DW_AT_name"].value.decode())
                        varname = DIE.attributes["DW_AT_name"].value.decode()
                    #if (DIE.tag == "DW_TAG_formal_parameter" and
                    #    attr.name == "DW_AT_name"):
                    #    print("Param name:", DIE.attributes["DW_AT_name"].value.decode())
                    
                    # Check if this attribute contains location information
                    
                    if loc_parser.attribute_has_location(attr, CU['version']):
                        #print('   DIE Tag: %s\t attr: %s.' % (DIE.tag,attr.name))
                        loc = loc_parser.parse_from_attribute(attr,
                                                              CU['version'])
                        # We either get a list (in case the attribute is a
                        # reference to the .debug_loc section) or a LocationExpr
                        # object (in case the attribute itself contains location
                        # information).
                        # DW_OP_addr or DW_OP_fbreg
                        if isinstance(loc, LocationExpr):
                            if (DIE.tag == "DW_TAG_variable"):
                                variable_loc = describe_DWARF_expr(loc.loc_expr,
                                                        dwarfinfo.structs, CU.cu_offset)
                                op_fbreg_regex = re.search(r'(?<=DW_OP_fbreg:\s)(.*)(?=\))', variable_loc)
                                op_addr_regex = re.search(r'(?<=DW_OP_addr:\s)(.*)(?=\))', variable_loc)
                                if op_fbreg_regex:
                                    #print('      %s\n' % (variable_loc))
                                    print("\tLocation:", hex(int(op_fbreg_regex.group(0))), varname)
                                    var_to_loc = (varname, hex(int(op_fbreg_regex.group(0))))
                                    tuple_exists = True
                                elif op_addr_regex:
                                    print("\tLocation:", op_addr_regex.group(0), varname)
                                    var_to_loc = (varname, op_addr_regex.group(0))
                                    tuple_exists = True
               
                        # LocationEntry (need to parse this properly)
                        elif isinstance(loc, list):
                            print(show_loclist(loc,dwarfinfo,'', CU.cu_offset, lowpc, funname))
                    if (tuple_exists and inside_fun):
                        local_var_to_locs.append(var_to_loc)
                if (tuple_exists and inside_fun == False):
                    global_var_to_locs.append(var_to_loc)
                
        # ------- After DIE ------- #   
        print("\n")             
        
        
        var_list = {}
        var_list.setdefault("global", [])
        for item in global_var_to_locs:
            #print(item)
            var_list.setdefault("global", []).append(item)
        
        fun_name = ""
        for item in local_var_to_locs:
            if item[1] == "Function":
                #print("Function key found")
                fun_name = item[0]
                var_list.setdefault(fun_name, [])
            else:
                #print(fun_name, item)
                var_list.setdefault(fun_name, []).append(item)
                
        for item in var_list:
            print(item, var_list[item])
        
        for item in dwarf_frame_bases:
            print(item)
            for addr_range in dwarf_frame_bases[item]:
                print("\t",addr_range)
        
        for item in dwarf_var_info:
            print(item)
            for var_info in dwarf_var_info[funname]:
                print("\t", var_info)
                        

def show_loclist(loclist, dwarfinfo, indent, cu_offset, entryaddr, funname):
    """ Display a location list nicely, decoding the DWARF expressions
        contained within.
    """
    d = []
    input_entry = entryaddr
    index = 0
    addr_to_exprs = list()
    for loc_entity in loclist:
        index += 1
        if isinstance(loc_entity, LocationEntry):
            
            parse_expr = describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, cu_offset)
            #regex = re.search(r'(?<=DW_OP_[a-z,A-Z,0-9]....\s)(?=\((.*)\))|(?<=:\s([0-99]))', parse_expr)
            offset_diff = loc_entity.end_offset - loc_entity.begin_offset    
            addr_range = ""            
            if (index == 1):
                input_entry += offset_diff
                #print("   Offset diff: ", offset_diff, "\tSA: ", hex(entryaddr),
                #    "\tEA: ", hex(input_entry),"\t| Offset: ", parse_expr)
                addr_range += hex(entryaddr) + "-" + hex(input_entry)
            else:
                end_entry = input_entry
                end_entry += offset_diff
                #print("   Offset diff: ", offset_diff, "\tSA: ", hex(input_entry),
                #    "\tEA: ", hex(end_entry),"\t| Offset: ", parse_expr)
                addr_range += hex(input_entry) + "-" + hex(end_entry)
                input_entry += offset_diff
            dw_op_regex = re.search(r'(?<=\(DW_OP_[a-z,A-Z,0-9]....\s\()(.*)(?=\):\s(.*)(?=\)))', parse_expr)
            addr_to_expr = tuple()
            if (dw_op_regex):
                parsed_expr = ""
                parsed_expr += dw_op_regex.group(1) + "+" + str(int(dw_op_regex.group(2)))
                #print(addr_range, parsed_expr)
                addr_to_expr = (addr_range, parsed_expr)
                addr_to_exprs.append(addr_to_expr)
    dwarf_frame_bases[funname] = addr_to_exprs
    #for item in addr_to_exprs:
    #    print(item)
           

            
    return '\n'.join(indent + s for s in d)

if __name__ == '__main__':
    if sys.argv[1] == '--test':
        for filename in sys.argv[2:]:
            process_file(filename)