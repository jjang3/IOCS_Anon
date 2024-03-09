import sys, getopt
import logging, os
import re
import pprint
import copy
from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture, ArchitectureHook
from typing import Optional

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

@dataclass(unsafe_hash=True)
class BnVarData:
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
    flow_distance:  Optional[int] = None
    arg_use:        Optional[bool] = False 
    # How is a variable used throughout the function, should I expand on this somehow?
    sec_sensitive:  Optional[bool] = False
    
fun_var_dict    = dict()

def display_var(var: BnVarData):
    log.info("Variable name: %s", var.name)
    log.debug("\tOffset: %s", var.offset_expr)
    log.debug("\tExposure num: %d", var.exposure)
    log.debug("\tUsed as an arg: %s", var.arg_use)
    log.debug("\tOrigin: %s", var.origin)
    log.debug("\tSecurity sensitive: %s", var.sec_sensitive)
    # pprint.pprint(var.dis_insts)
    print()
    
def get_ssa_reg(inst_ssa):
        arrow = 'U+21B3'
        log.info("Getting the SSA register of %s %s", inst_ssa, type(inst_ssa)) 
        if type(inst_ssa) == binaryninja.lowlevelil.SSARegister:
            return inst_ssa
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsa:
            return get_ssa_reg(inst_ssa.src)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsaPartial:
            return get_ssa_reg(inst_ssa.full_reg)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            log.debug("%s LoadReg", chr(int(arrow[2:], 16)))
            return inst_ssa
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILZx:
            return get_ssa_reg(inst_ssa.src.full_reg)
        elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
            # this is where we should handle %rax#3 + 4 case;
            return get_ssa_reg(inst_ssa.left.src)
            # return inst_ssa
        else:
            None
            # print(inst_ssa.__class__.__bases__)
            
def update_var(**kwargs):
    log.info("Updating variable")
    for var in kwargs["set"]:
        if isinstance(var, BnVarData):
            if var.name == kwargs["var_name"]:
                # log.debug("Found the variable")
                var.exposure += 1
                if kwargs.get("offset") is not None and var.offset_expr == None:
                    var.offset_expr = kwargs["offset"]
                
                if kwargs.get("var_type") is not None and var.var_type == None:
                    var.var_type = kwargs["var_type"]
                
                if kwargs.get("dis_inst") is not None:
                    var.dis_insts.append(kwargs["dis_inst"])    
                    
                if kwargs.get("arg_use") is not None:
                    var.arg_use = kwargs["arg_use"]
                    
                if kwargs.get("origin") is not None:
                    var.origin = kwargs["origin"]
    None

def calc_ssa_off_expr(inst_ssa):
    # This is for binary ninja diassembly
    arrow = 'U+21B3'
    log.info("Calculating the offset of %s %s", inst_ssa, type(inst_ssa)) 
    offset_expr_regex = r'(\-[0-9].*)\((.*)\)'
    # try:
    if type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
        log.debug("%s LoadReg", chr(int(arrow[2:], 16)))
        mapped_MLLIL = inst_ssa.mapped_medium_level_il # This is done to get the var (or find if not)
        if mapped_MLLIL != None:
            result = calc_ssa_off_expr(inst_ssa.src)
            if result != None:
                return result
        else:
            log.error("No variable assigned, skip")
    elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILStoreSsa:
        log.debug("%s StoreSSA",  chr(int(arrow[2:], 16)))
        result = calc_ssa_off_expr(inst_ssa.dest)
        if result != None:
            return result
    elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsa:
        log.debug("%s SetRegSSA",  chr(int(arrow[2:], 16)))
        result = calc_ssa_off_expr(inst_ssa.src)
        if result != None:
            return result
    elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsaPartial:
        log.debug("%s SetRegSSAPartial",  chr(int(arrow[2:], 16)))
        # reg_def = llil_fun.get_ssa_reg_definition(llil_inst.full_reg)
        result = calc_ssa_off_expr(inst_ssa.src)
        if result != None:
            return result
    elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILZx:
        log.debug("%s ZeroExtendSSA",  chr(int(arrow[2:], 16)))
        result = calc_ssa_off_expr(inst_ssa.src)
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
        
        if type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            # print("Here 3")
            offset = calc_ssa_off_expr(inst_ssa.right)
            expr = offset
        elif (binaryninja.commonil.Arithmetic in inst_ssa.left.__class__.__bases__ and 
                type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILConst):
            print("Array access found")
            base_reg    = inst_ssa.left.left.src.reg.__str__()
            array_reg   = inst_ssa.left.right.src.reg.__str__()
            offset      = inst_ssa.right.constant
            expr = str(offset) + "(" + base_reg + "," + array_reg + ")"
        else:
            offset = str(int(inst_ssa.right.__str__(), base=16))
            expr = offset + "(" + reg.reg.__str__() + ")"
        log.critical(expr)
        return expr

def c14n_analysis(bv: binaryninja.BinaryView, bn_fun: binaryninja.Function):
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

    var_set = set()
    
    for var in bn_fun.vars:
        if (var.source_type == VariableSourceType.StackVariableSourceType and 
            "var" in var.name):
            # There are duplicate variable names (e.g., var_14 vs var_14_1), so we first create BnVarData for all names, then if they are empty
            # at the end, we will clean them up.
            new_var = BnVarData(name=var.name, dis_insts=list(), exposure=0, var_type=var.type)
            # <TypeClass.IntegerTypeClass: 2>
            
            # This is used to find whether variable in this function is used or value is from security-sensitive functions
            for ref in bn_fun.get_hlil_var_refs(var):
                if bn_fun.is_call_instruction(ref.address):
                    call_ref = bn_fun.get_llil_at(ref.address)
                    try:
                        call_fun_name = bv.get_function_at(call_ref.dest.constant).name
                        # print(var, call_fun_name)
                        if call_fun_name in sec_sen_funs:
                            log.error("%s Security-sensitive fun detected", var)
                            new_var.sec_sensitive = True
                    except:
                        None

            var_set.add(new_var)
    
    # exit()
    for llil_bb in bn_fun.low_level_il:
        # if bn_fun.name == "client_error": # debug
        if True:
        # This part analyzes the exposure count and calculates the offset for each bninja variable
            for llil_inst in llil_bb:
                # This is going to be used to find definitions
                # try:
                #     ssa_reg = get_ssa_reg(llil_inst.src.ssa_form)
                #     if type(ssa_reg) != binaryninja.lowlevelil.LowLevelILLoadSsa:
                #         def_llil_inst = bn_fun.low_level_il.get_ssa_reg_definition(ssa_reg).ssa_form
                #         log.debug("%s\nDefinition: %s", llil_inst, def_llil_inst)
                # except:
                #     None
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
                                    offset_expr = calc_ssa_off_expr(llil_inst.ssa_form)
                                    update_var(set=var_set, var_name=var_name, 
                                            offset=offset_expr, dis_inst=dis_inst)
                                except:
                                    log.error("Can't calculate offset")
                                    update_var(set=var_set, var_name=var_name, 
                                            offset=None, dis_inst=dis_inst)
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
                            offset_expr = calc_ssa_off_expr(llil_inst.ssa_form)
                            update_var(set=var_set, var_name=var_name, 
                                    offset=offset_expr, dis_inst=dis_inst)
                            if src_reg_name in arg_regs:
                                update_var(set=var_set, var_name=var_name, 
                                           origin="Argument")
                            print()
        
    # print(bn_fun.callee_addresses)
    # for callee_address in bn_fun.callee_addresses:
    #     callee_fun = bv.get_function_at(callee_address)
    #     # print(callee_fun.name)
    #     # for var in bn_fun.vars:
    #     #     for item in bn_fun.get_mlil_var_refs(var):
    #     #         print(bv.get_disassembly(item.address))
    #     # print(callee_fun.get_mlil_var_refs_from(callee_fun.lowest_address))
    #     # print(callee_fun.high_level_il)
    
    for var in var_set:
        display_var(var)

    return var_set

def main(input_binary):
    target_dir = Path(os.path.abspath(input_binary))
    with load(target_dir.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
        arch = Architecture['x86_64']
        for fun in bv.functions:
            fun_name = fun.name
            log.warning("Function: %s", fun_name)           
            fun_var_set = c14n_analysis(bv, fun)
            fun_var_dict[fun.name] = fun_var_set.copy()

def process_argument(argv):
    input_bin = ''
    try:
        opts, args = getopt.getopt(argv,"hfic:",["binary="])
    except getopt.GetoptError:
        print ('c14n_analysis.py --binary <binary>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('c14n_analysis.py --binary <binary>')
            sys.exit()
        elif opt in ("-b", "--binary"):
            input_bin = arg
    main(input_bin)
    
if __name__ == '__main__':
    process_argument(sys.argv[1:])