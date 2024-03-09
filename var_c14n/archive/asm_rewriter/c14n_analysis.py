import sys, getopt
import logging, os
import pprint
import inspect
from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture, ArchitectureHook
from typing import Optional

import binary_patch

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
class c14nVarData:
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
    arg_use:        Optional[bool] = False 
    # How is a variable used throughout the function, should I expand on this somehow?
    sec_sensitive:  Optional[bool] = False
    score:          Optional[int] = 0
    llil_insts:     Optional[list[LowLevelILInstruction]] = field(default_factory=set, compare=False, hash=False)
    
    def calc_c14n(self):
        # Initial score is 0
        aggregate_score = 0

        # Example: Add 10 points if the variable is security-sensitive
        if self.sec_sensitive:
            aggregate_score += 10

        # Use of the variable in arguments might increase its importance
        if self.arg_use:
            aggregate_score += 5

        # Add exposure points directly if available
        if self.exposure is not None:
            aggregate_score += self.exposure

        # Additional logic can be applied based on origin, var_type, etc.
        # For example, add points if the origin is not local
        if self.origin != "Local":
            aggregate_score += 3

        # Set the score
        self.score = aggregate_score
    
fun_var_dict    = dict()

        
def display_var(var: c14nVarData):
    log.info("Variable name: %s", var.name)
    log.debug("\tOffset: %s", var.offset_expr)
    log.debug("\tExposure num: %d", var.exposure)
    log.debug("\tUsed as an arg: %s", var.arg_use)
    log.debug("\tOrigin: %s", var.origin)
    log.debug("\tSecurity sensitive: %s", var.sec_sensitive)
    # pprint.pprint(var.dis_insts)
    print()

def update_var(**kwargs):
    log.info("Updating variable")
    for var in kwargs["set"]:
        if isinstance(var, c14nVarData):
            if var.name == kwargs["var_name"]:
                # log.debug("Found the variable")
                
                if kwargs.get("offset") is not None and var.offset_expr == None:
                    var.offset_expr = kwargs["offset"]
                
                if kwargs.get("var_type") is not None and var.var_type == None:
                    var.var_type = kwargs["var_type"]
                
                if kwargs.get("dis_inst") is not None:
                    var.exposure += 1
                    var.dis_insts.append(kwargs["dis_inst"])    
                    
                if kwargs.get("arg_use") is not None:
                    var.arg_use = kwargs["arg_use"]
                    
                if kwargs.get("origin") is not None:
                    var.origin = kwargs["origin"]
                    
                if kwargs.get("llil_inst") is not None:
                    var.llil_insts.append(kwargs["llil_inst"])

def find_call(inst):
    try:
        if inst.operation == LowLevelILOperation.LLIL_CALL:
            return inst
        if inst.operation == HighLevelILOperation.HLIL_CALL:
            return inst
        if inst.operation == LowLevelILOperation.LLIL_IF:
            inst = find_call(inst.hlil)
            if inst != None:
                return inst
        if inst.operation == HighLevelILOperation.HLIL_IF:
            inst = find_call(inst.operands[0].left)
            if inst != None:
                return inst
        inst = None
    except:
        return None
    

def c14n_analysis(bv: binaryninja.BinaryView, bn_fun: binaryninja.Function):
    log.info("Calc. c14n metric for the function: %s", bn_fun.name)
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
    
    var_set: set[c14nVarData] = set()
    
    bn = binary_patch.BinAnalysis(bv)
    fun_name = bn_fun.name
    call_insts = list()
    for var in bn_fun.vars:
        if (var.source_type == VariableSourceType.StackVariableSourceType and 
            "var" in var.name):
            # There are duplicate variable names (e.g., var_14 vs var_14_1), so we first create BnVarData for all names, then if they are empty
            # at the end, we will clean them up.
            new_var = c14nVarData(name=var.name, dis_insts=list(), exposure=0, var_type=var.type, llil_insts=list())
            # <TypeClass.IntegerTypeClass: 2>
            
            # This is used to find whether variable in this function is used or value is from security-sensitive functions
            
            for ref in bn_fun.get_hlil_var_refs(var):
                # Need to recursively check ref_inst to find call instruction
                ref_inst = bn_fun.get_low_level_il_at(ref.address)
                # for item in bv.get_code_refs_from(ref.address):
                #     print(hex(item))
                #     print(bv.get_disassembly(item))
                
                # print(bv.get_code_refs(ref.address).hlil)
                call_inst = find_call(ref_inst)
                try:
                    if (bn_fun.is_call_instruction(ref_inst.address)):
                        call_ref = bn_fun.get_llil_at(ref.address)
                        print(call_ref)
                        try:
                            call_fun_name = bv.get_function_at(call_ref.dest.constant).name
                            # log.debug(call_fun_name)
                            if call_fun_name in sec_sen_funs:
                                log.error("%s Security-sensitive fun detected", var)
                                new_var.sec_sensitive = True
                        except:
                            None
                    elif (call_inst.operation == HighLevelILOperation.HLIL_CALL and 
                        bn_fun.is_call_instruction(call_inst.address)):
                        call_ref = bn_fun.get_llil_at(call_inst.address)
                        print(call_ref)
                        try:
                            call_fun_name = bv.get_function_at(call_ref.dest.constant).name
                            # log.debug(call_fun_name)
                            if call_fun_name in sec_sen_funs:
                                log.error("%s Security-sensitive fun detected", var)
                                new_var.sec_sensitive = True
                        except:
                            None
                except:
                    log.error("NoneType")

            var_set.add(new_var)
    
    for callee_address in bn_fun.callee_addresses:
        callee_fun = bv.get_function_at(callee_address)
        print(callee_fun.name)
        
    # if False:
    if True:
        for llil_bb in bn_fun.low_level_il:
            # if bn_fun.name == "client_error": # debug
            if True:
            # This part analyzes the exposure count and calculates the offset for each bninja variable
                for llil_inst in llil_bb:
                    # This is going to be used to find definitions
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
                                        offset_expr = bn.calc_ssa_off_expr(llil_inst.ssa_form)
                                        update_var(set=var_set, var_name=var_name, 
                                                offset=offset_expr, dis_inst=dis_inst, llil_inst=llil_inst)
                                    except:
                                        log.error("Can't calculate offset")
                                        update_var(set=var_set, var_name=var_name, 
                                                offset=None, dis_inst=dis_inst, llil_inst=llil_inst)
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
                                offset_expr = bn.calc_ssa_off_expr(llil_inst.ssa_form)
                                update_var(set=var_set, var_name=var_name, 
                                        offset=offset_expr, dis_inst=dis_inst, llil_inst=llil_inst)
                                if src_reg_name in arg_regs:
                                    update_var(set=var_set, var_name=var_name, 
                                            origin="Argument")
                    elif llil_inst.operation == LowLevelILOperation.LLIL_CALL:
                        call_fun = bv.get_function_at(llil_inst.dest.constant)
                        if call_fun.symbol.type is not SymbolType.ImportedFunctionSymbol:
                            # print(call_fun.symbol)
                            call_insts.append(llil_inst)
                        
                    else:
                        log.error("%s, %s", llil_inst, llil_inst.operation)
                        None
    # Compute the score
    to_remove = set()
    for var in var_set:
        if var.offset_expr == None:
            log.error("Removing: %s", var)
            to_remove.add(var)
        elif var.offset_expr != None:
            var.calc_c14n()
    # calc_c14n(var_set)
    # bin_analysis.custom_pprint(var_set)
    var_set.difference_update(to_remove)
    bn.fun_call_insts[fun_name] = call_insts.copy()
    call_insts.clear()
    
    return var_set