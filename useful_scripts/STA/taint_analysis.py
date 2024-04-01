from cgi import parse_multipart
import cgitb
import sys, getopt
import logging
import shutil
import pprint
import inspect
import os
import webbrowser
import time
import traceback

from binaryninja import *
from binaryninja.mediumlevelil import MediumLevelILInstruction 
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture, ArchitectureHook
from binaryninja.interaction import get_save_filename_input, show_message_box, TextLineField, ChoiceField, SaveFileNameField, get_form_input
from binaryninja.settings import Settings
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, MessageBoxButtonResult, InstructionTextTokenType, BranchType, DisassemblyOption, FunctionGraphType, ThemeColor
from binaryninja.function import DisassemblySettings
from binaryninja.plugin import PluginCommand
from termcolor import colored

import export_cg

class PtrOffsetTreeNode:
    def __init__(self, fun_name, params, reg_offset, index=0):
        self.fun_name = fun_name            # The current node (caller function)
        self.params = params                # Parameter variables of the current function
        self.reg_offset = reg_offset        # Register offset of the variable that will be tracked from the caller
        self.child = None                   # The next node (callee function)
        self.index = index                  # The index of where the reg_offset will be passed to callee

    def add_child(self, child_node):
        self.child = child_node

class PtrOffsetTree:
    def __init__(self, root=None):
        self.root = root

    def add_node(self, new_node):
        if not self.root:
            self.root = new_node
        else:
            # Find the last node and add the new node as a child
            current_node = self.root
            while current_node.child is not None:
                current_node = current_node.child
            current_node.add_child(new_node)

    def print_tree(self):
        node = self.root
        while node is not None:
            print(f"Index: {node.index}, Function: {node.fun_name}, Parameters: {node.params}, Register Offset: {node.reg_offset}")
            node = node.child

# @dataclass(unsafe_hash=True)
# class OperandData:
#     callee_fun_name:   str = None
#     oper_idx:   int = None
#     taint_inst: binaryninja.lowlevelil.LowLevelILSetRegSsa = None
#     offset:     int = None

# @dataclass(unsafe_hash=True)
# class CalleeFunData:
#     callee_fun_name:    str = None                  # Callee fun name
#     oper_list:          list[OperandData] = None    # Operand data of arguments being sent to callee fun
    
#     def add_operand(self, operand: OperandData):
#         self.oper_list.append(operand)
    
# @dataclass
# class FunctionNode:
#     function_name:      str
#     param_list: List[OperandData] = field(default_factory=list)  # Default value provided
#     callee_funs: List[CalleeFunData] = field(default_factory=list)  # Default value provided
#     # param_list:         list[OperandData] = None
    
#     # callee_funs:        List[CalleeFunData] = field(default_factory=list)  # List of callee functions
   
#     def add_callee_function(self, callee_function: CalleeFunData):
#         self.callee_funs.append(callee_function)
    
#     def add_param(self, param: OperandData):
#         self.param_list.append(param)
        
#     def print_structure(self, indent=""):
#         # Print the current function's name
#         print(f"{indent}Function: {self.function_name}")
#         # Print parameters for the current function
#         # for param in self.param_list:
#         #     print(f"{indent}  Param: {param.callee_fun_name}, Offset: {param.offset}")
#         # Recursively print callee functions and their parameters
#         for callee in self.callee_funs:
#             print(f"{indent}  Calls: {callee.callee_fun_name}")
#             for op in callee.oper_list:
#                 print(f"{indent}    Operand: {op.callee_fun_name}, OperIdx: {op.oper_idx}, Offset: {op.offset}")
#             # Assuming CalleeFunData could potentially have its own callee functions for a deeper hierarchy
#             # This part is hypothetical unless CalleeFunData is adapted to include callee functions itself
#             # for nested_callee in callee.callee_funs:
#             #     nested_callee.print_structure(indent + "    ")  # This would require CalleeFunData to be similar to FunctionNode
@dataclass
class OperandData:
    callee_fun_name: Optional[str] = None
    oper_idx: Optional[int] = None
    taint_inst: Optional[binaryninja.lowlevelil.LowLevelILSetRegSsa] = None
    offset: Optional[int] = None
    pointer: Optional[bool] = False

@dataclass
class LocalData:
    var_name: Optional[str] = None
    param_idx: Optional[int] = None
    offset: Optional[int] = None

@dataclass
class FunctionNode:
    fun: Function
    function_name: str
    operands: List[OperandData] = field(default_factory=list)  # Direct operands of the function
    callee_funs: List['FunctionNode'] = field(default_factory=list)  # Nested callee functions
    checked: bool = False
    params:     List[LocalData]  = field(default_factory=list)  # Direct operands of the function
    local_vars: List[LocalData]  = field(default_factory=list)  # Direct operands of the function

    def add_operand(self, operand: OperandData):
        self.operands.append(operand)

    def add_callee_function(self, callee_function: 'FunctionNode'):
        self.callee_funs.append(callee_function)

    def print_structure(self, indent=""):
        print(f"{indent}Function: {self.function_name}")
        for param in self.params:
            print(f"{indent}  Param: {param.param_idx}, Offset: {param.offset}")
        for var in self.local_vars:
            print(f"{indent}  Var: {var.var_name}, Offset: {var.offset}")
        for operand in self.operands:
            print(f"{indent}  OperIdx: {operand.oper_idx}, Offset: {operand.offset}, Pointer: {operand.pointer}")
        for callee in self.callee_funs:
            print(f"{indent}  Calls: {callee.function_name}")
            callee.print_structure(indent + "    ")


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

def custom_pprint(obj, color='blue', attrs=['reverse']):
    # Get the current frame and then the outer frame (caller's frame)
    frame = inspect.currentframe()
    outer_frame = inspect.getouterframes(frame)[1]
    filename = outer_frame.filename

    # Extract the base filename from the full path
    base_filename = filename.split('/')[-1]

    # Create the message prefix with the base filename
    message_prefix = f"{base_filename}:\n"

    # Prepare the object for pretty printing as a string
    obj_str = pprint.pformat(obj)

    # Combine the message prefix and the pretty printed object
    combined_message = message_prefix + obj_str

    # Print the combined message with color and attributes
    print(colored(combined_message, color, attrs=attrs))

    # Cleanup to avoid reference cycles
    del frame, outer_frame
    
def process_binary(input_item):
    with load(input_item.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
        arch = Architecture['x86_64']
        # List of taint source funs and index of taint source
        taint_src_funs = {('__isoc99_sscanf', 0), ('__isoc99_scanf', 1), ('__isoc99_fscanf', 0), 
                          ('fgets', 0), ('gets', 0), ('read', 1), ('recv', 1), ('recvfrom', 1)}
        bn = BinTaintAnalysis(bv, taint_src_funs, None)
        return bn.analyze_binary()
        
def process_offset(input_item, dwarf_info):
    with load(input_item.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
        arch = Architecture['x86_64']
        bn = BinTaintAnalysis(bv, None, dwarf_info)
        return bn.analyze_offset()

class BinTaintAnalysis:
    
    callee_funs_op_info = dict()
    fun_to_check = list()
    fun_param_info = set(())
    
    def __init__(self, bv, taint_src_funs, dwarf_info):
        self.bv = bv
        self.fun = None
        self.currFunNode = FunctionNode(None, None)
        self.rootFun = None
        self.currFun = None
        self.taint_list = list()
        self.taint_funs = taint_src_funs
        self.taint_var = None
        self.taint_inst = None
        self.dwarf_info = dwarf_info
        self.fun_set = set()
        self.fun_graph = list()
        
    def calc_ssa_off_expr(self, inst_ssa):
        # This is for binary ninja diassembly
        arrow = 'U+21B3'
        log.info("Calculating the offset of %s %s", inst_ssa, type(inst_ssa)) 
        offset_expr_regex = r'(\-[0-9].*)\((.*)\)'
        if type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            log.debug("%s LoadReg", chr(int(arrow[2:], 16)))
            mapped_MLLIL = inst_ssa.mapped_medium_level_il # This is done to get the var (or find if not)
            if mapped_MLLIL != None:
                result = self.calc_ssa_off_expr(inst_ssa.src)
                if result != None:
                    return result
            else:
                log.error("No variable assigned, skip")
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILStoreSsa:
            log.debug("%s StoreSSA",  chr(int(arrow[2:], 16)))
            result = self.calc_ssa_off_expr(inst_ssa.dest)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsa:
            log.debug("%s SetRegSSA",  chr(int(arrow[2:], 16)))
            result = self.calc_ssa_off_expr(inst_ssa.src)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsaPartial:
            log.debug("%s SetRegSSAPartial",  chr(int(arrow[2:], 16)))
            # reg_def = llil_fun.get_ssa_reg_definition(llil_inst.full_reg)
            result = self.calc_ssa_off_expr(inst_ssa.src)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILZx:
            log.debug("%s ZeroExtendSSA",  chr(int(arrow[2:], 16)))
            result = self.calc_ssa_off_expr(inst_ssa.src)
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
            if (binaryninja.commonil.Arithmetic in inst_ssa.left.__class__.__bases__ and 
                  type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILConst):
                print("Array access found")
                base_reg    = inst_ssa.left.left.src.reg.__str__()
                array_reg   = inst_ssa.left.right.src.reg.__str__()
                offset      = inst_ssa.right.constant
                expr = str(offset) + "(" + base_reg + "," + array_reg + ")"
            else:
                # print(inst_ssa.right, type(inst_ssa.right))
                offset = str(int(inst_ssa.right.__str__(), base=16))
                expr = offset + "(" + reg.reg.__str__() + ")"
            
            log.debug(expr)
            return expr
    
    def get_ssa_reg(self, inst_ssa):
        arrow = 'U+21B3'
        log.info("Getting the SSA register of %s %s", inst_ssa, type(inst_ssa)) 
        if type(inst_ssa) == binaryninja.lowlevelil.SSARegister:
            return inst_ssa
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsa:
            return self.get_ssa_reg(inst_ssa.src)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsa:
            return self.get_ssa_reg(inst_ssa.src)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsaPartial:
            return self.get_ssa_reg(inst_ssa.full_reg)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            log.debug("%s LoadReg", chr(int(arrow[2:], 16)))
            # return inst_ssa
            return self.get_ssa_reg(inst_ssa.src)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILZx:
            # print(type(inst_ssa.src))
            try:
                return self.get_ssa_reg(inst_ssa.src.full_reg)
            except:
                # If type is LoadSSA
                return self.get_ssa_reg(inst_ssa.src)
        elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
            # this is where we should handle %rax#3 + 4 orcase;
            if inst_ssa.left.src.reg == "%rbp":
                return None
            else:
                return self.get_ssa_reg(inst_ssa.left.src)
            # return inst_ssa
        else:
            print(inst_ssa.__class__.__bases__)

    # Function to search for a given string and return the string along with its associated numerical value if found
    def search_fun_indx(self, search_str):
        for func_name, value in self.taint_funs:
            if func_name == search_str:
                return value
        return None
    
    def get_or_set_call_node(self, callgraph, function_nodes, function):
        # create a new node if one doesn't exist already
        if function not in function_nodes:
            node = FlowGraphNode(callgraph)

            function_nodes[function] = node

            if function.symbol.type == SymbolType.ImportedFunctionSymbol:
                token_type = InstructionTextTokenType.ImportToken
            else:
                token_type = InstructionTextTokenType.CodeSymbolToken

            # Set the node's text to be the name of the function
            node.lines = [
                DisassemblyTextLine(
                    [
                        InstructionTextToken(
                            token_type,
                            function.name,
                            function.start
                        )
                    ]
                )
            ]
            callgraph.append(node)
        else:
            node = function_nodes[function]

        return node

    def collect_calls(self, view, rootFun):
        log.info("collect_calls")
        #  dict containing callee -> set(callers)    
        calls = {}
        if (self.rootFun == None):
            funs = view.functions
            log.debug(funs)
            rootlines = ['ROOT']
        else:
            funs = map(lambda x: x.function, view.get_code_refs(self.rootFun.start))
            rootlines = [self.rootFun.name]
            
        for fun in self.bv.functions:
            for ref in self.bv.get_code_refs(fun.start):
                caller = ref.function
                calls[fun] = calls.get(fun, set())
                call_il = caller.get_low_level_il_at(ref.address)
                if isinstance(call_il, Call) and isinstance(call_il.dest, Constant):
                    calls[fun].add(caller)
        
        callgraph = FlowGraph()
        callgraph.function = view.get_function_at(view.entry_point)
        root_node = FlowGraphNode(callgraph)
        root_node.lines = rootlines
        callgraph.append(root_node)
        function_nodes = {}
    
        for callee in view.functions:
        # create a new node if one doesn't exist already
            callee_node = self.get_or_set_call_node(callgraph, function_nodes, callee)

            # create nodes for the callers, and add edges
            callers = calls.get(callee, set())

            if not callers:
                root_node.add_outgoing_edge(
                    BranchType.FalseBranch, callee_node
                )
            for caller in callers:
                caller_node = self.get_or_set_call_node(callgraph, function_nodes, caller)

                # Add the edge between the caller and the callee
                if ctypes.addressof(callee_node.handle.contents) not in [
                    ctypes.addressof(edge.target.handle.contents)
                    for edge in caller_node.outgoing_edges]:
                        caller_node.add_outgoing_edge(
                            BranchType.TrueBranch,
                            callee_node
                        )
        callgraph.layout_and_wait()
        return callgraph

    def check_import_fun(self, func_name):
        symbol = self.bv.symbols[func_name]
        if len(symbol) > 1:
            for sym_type in symbol:
                if sym_type.type == SymbolType.ImportedFunctionSymbol:
                    return True
                else:
                    return False
    
    def find_root_fun(self, start_fun):
        # Find the function which has caller to the entry point, this will be the root function
        for func in self.bv.functions:
            func: Function
            if start_fun in func.callers:
                return func
            
    def visit(self, illest, expr, operations):
        # print(illest, expr)
        # print(expr.operation)
        log.debug(expr)
        # print(operations[expr.operation])
        for field in operations[expr.operation]:
            print(field, getattr(expr, field[0]))
            if field[1] == "expr":
                self.visit(illest, getattr(expr, field[0]), operations)
        illest.add(expr.operation)
    
    def taint_prop_fw(self):
        arrow = 'U+21B3'
        # taint_uses = self.rootFun.mlil.ssa_form.get_ssa_var_uses(self.taint_var)    
        # print(taint_uses, self.taint_list)
        visited = list()
        log.info("Taint propagation forward")
        while len(self.taint_list) > 0:
            self.taint_inst = self.taint_list.pop()
            if self.taint_inst in visited:
                continue
            elif type(self.taint_inst) == binaryninja.mediumlevelil.SSAVariable:
                log.debug("%s", self.taint_inst)
                print()
                taint_uses = self.currFun.mlil.ssa_form.get_ssa_var_uses(self.taint_inst)
                for use in taint_uses:
                    use: MediumLevelILInstruction
                    log.warning("%s", use)
                    log.warning("%s %s", chr(int(arrow[2:], 16)), use.operation)
                    print()
                    self.taint_list.append(use)
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                use_refs = self.currFun.mlil.ssa_form.get_ssa_var_uses(self.taint_inst.dest)
                for ref in use_refs:
                    ref: MediumLevelILInstruction
                    log.warning("%s", ref)
                    log.warning("%s %s", chr(int(arrow[2:], 16)), ref.operation)
                    print()
                    self.taint_list.append(ref)
                # Update the taint_var as the taint variable gets propagated.
                self.taint_var = self.taint_inst
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                # print(self.taint_var)
                dest_fun = self.bv.get_function_at(self.taint_inst.dest.constant)
                dest_fun_name = dest_fun.name
                
                if self.check_import_fun(dest_fun_name):
                    log.error("Import fun: %s", dest_fun_name)
                else:
                    fun_param_len = len(self.taint_inst.params)-1
                    # Need to add the function into the function set with proper argument
                    found = False
                    for oper_idx, param in enumerate(self.taint_inst.params):
                        if self.taint_var.dest in param.operands:
                            inner_idx = param.operands.index(self.taint_var.dest)
                            # print(f"Here at operand {oper_idx}, inner idx {inner_idx}")
                            found = True
                            idx = oper_idx
                            break  # Stop searching after the first match
                    if not found:
                        print("Element not found")
                    else:
                        print("Inserting: ", type(dest_fun), idx)
                        self.fun_param_info.add((dest_fun, fun_param_len))
                        self.fun_set.add((dest_fun, idx))
                    log.critical("Fun to visit: %s", dest_fun_name)
                print()
                
                if dest_fun_name in self.taint_funs:
                    log.error("Danger fun found")                   
                else:
                    # IF output register exists for the call inst (i.e., var = atoi)
                    if len(self.taint_inst.output) > 0:
                        # log.warning("Inserting %s", self.taint_inst.output[0])
                        self.taint_list.append(self.taint_inst.output[0])
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_VAR_PHI:
                # var_c#4 = ϕ(var_c#1, var_c#2, var_c#3) 
                # log.debug(self.taint_inst.dest)
                use_refs = self.currFun.mlil.ssa_form.get_ssa_var_uses(self.taint_inst.dest)
                for ref in use_refs:
                    ref: MediumLevelILInstruction
                    log.warning("%s", ref)
                    log.warning("%s %s", chr(int(arrow[2:], 16)), ref.operation)
                    print()
                    self.taint_list.append(ref)
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                # This is because mlil_fun.get_var_uses cannot be used for address of variable taken
                log.debug("Search through address of variable uses")
                for bb in self.currFun.mlil.ssa_form:
                    for inst in bb:
                        # log.debug("%s %s", self.taint_inst, inst)
                        self.taint_inst.vars_address_taken[0]
                        if len(inst.vars_address_taken) > 0:
                            if self.taint_inst.src == inst.vars_address_taken[0]:
                                # log.critical(inst)
                                self.taint_list.append(inst)
                
    def taint_prop_bw(self):
        arrow = 'U+21B3'
        log.info("Taint propagation backward")
        # for caller_fun in self.callee_funs_op_info:
        #     log.info("Caller: %s", caller_fun)
        # for op in self.callee_funs_op_info[self.currFun.name]:
        #     ssa_reg = self.get_ssa_reg(op.taint_inst)
        #     log.warning("%s %s", op.taint_inst, ssa_reg)
        #     if ssa_reg == None:
        #         # this means we don't need to find the definition
        #         op.offset = self.calc_ssa_off_expr(op.taint_inst)
        #     else:
        #         taint_defs = self.currFun.llil.ssa_form.get_ssa_reg_definition(ssa_reg)  
        #         op.offset = self.calc_ssa_off_expr(taint_defs)
        #     print(op)
        # caller_fun = self.currFun.name
        # for callee_fun in self.currFunNode.callee_funs:
            
        # for callee_fun in self.callee_funs_op_info[caller_fun]:
        for op in self.currFunNode.operands:
            ssa_reg = self.get_ssa_reg(op.taint_inst)
            log.warning("%s %s", op.taint_inst, ssa_reg)
            if ssa_reg == None:
                # this means we don't need to find the definition
                op.offset = self.calc_ssa_off_expr(op.taint_inst)
            else:
                taint_defs = self.currFun.llil.ssa_form.get_ssa_reg_definition(ssa_reg)  
                op.offset = self.calc_ssa_off_expr(taint_defs)
            print(op)
        
    
    def dwarf_fun_analysis(self, fun_name):
        for fun in self.dwarf_info:
            print(fun, fun_name)
            if fun == fun_name:
                log.critical("Found")
                temp_list = list()
                temp_list = self.dwarf_info[fun].copy()
                return temp_list
                # temp_list = self.dwarf_info[fun].var_list.copy()
                # return temp_list
    
    def fun_taint_analysis(self, fun, oper_idx):
        # First need to convert arg# to ssa variable
        fun: Function
        self.currFun = fun
        for index, param in enumerate(fun.parameter_vars): 
            if index == oper_idx:
                # print(param, type(param))
                self.taint_var = param
        
        for bb in fun.medium_level_il:
            for inst in bb:
                try:
                    if self.taint_var == inst.src.vars_read[0]:
                        self.taint_var = inst.ssa_form.dest
                        break
                except:
                    pass
        # If taint variable is established by then, insert it into taint list
        if self.taint_var != None:
            # print(self.taint_var)
            self.taint_list.append(self.taint_var)
        self.taint_prop_fw()
    
    def analyze_callee(self):
        # print(self.currFun.callee_addresses)
        # for addr in self.currFun.callee_addresses:
        #     callee_fun = self.bv.get_function_at(addr)
        #     print(callee_fun.name)

        
        # redprint(temp_fun)
        temp_fun = self.currFunNode
        log.info("Analyzing callee for %s | %d", temp_fun.function_name, temp_fun.checked)
        # dwarf_var_list = self.dwarf_fun_analysis(self.currFun.name)
        # pprint.pprint(var_list)
        
        var_list = self.dwarf_fun_analysis(self.currFun.name)
        pprint.pprint(var_list)
        local_list = []
        param_list = []
        param_idx = 0
        for var in var_list:
            if var.tag == "DW_TAG_variable":
                log.debug("Local variable %s", var)
                temp_data = LocalData(var.name, None, var.offset)
                local_list.append(temp_data)
            if var.tag == "DW_TAG_formal_parameter":
                log.debug("Formal parameter %s", var)
                temp_data = LocalData(var.name, param_idx, var.offset)
                param_list.append(temp_data)
                param_idx += 1
        visited = list()
        temp_fun.local_vars = local_list.copy()
        temp_fun.params = param_list.copy()
        # for idx, fun in enumerate(temp_fun.callee_funs):
            
        #     if fun.checked == False:
        # log.debug("Function check: %s - Index: %d", fun.function_name, idx)
        if temp_fun.checked == False:
            for callee_addr in self.currFun.callee_addresses:
                # print(hex(callee_addr))
                callee_fun = self.bv.get_function_at(callee_addr)
                symbol = self.bv.symbols[callee_fun.name]                
                if len(symbol) > 0:
                    # for sym_type in symbol:
                    if symbol[0].type != SymbolType.ImportedFunctionSymbol:
                        log.debug("Adding: %s", callee_fun.name)
                        # self.fun_to_check.add(callee_fun)
                        for ref in self.bv.get_code_refs(callee_addr):
                            if ref not in visited:
                                visited.append(ref)
                                call_il = self.currFun.get_low_level_il_at(ref.address)
                                if call_il != None:
                                    if call_il.mlil.ssa_form.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                                        # print(call_il.mlil)
                        #                 # callee_fun_data = CalleeFunData(callee_fun.name, list())
                                        callee_fun_data = FunctionNode(fun=callee_fun, function_name=callee_fun.name)
                                        for oper_idx, param in enumerate(call_il.mlil.params):
                                            if (type(param.ssa_form) == binaryninja.mediumlevelil.MediumLevelILVarSsa):
                                                var_def = self.currFun.mlil.ssa_form.get_ssa_var_definition(param.ssa_form.src)
                        #                         # log.debug(param)
                                                if var_def != None:
                                                # try:
                                                    self.taint_var = var_def.low_level_il.ssa_form
                                                    pointer = False
                                                    if var_def.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                                                        pointer = True
                                                # except:
                                                    log.warning("%s %s", var_def.src, var_def.src.operation)
                                                    # exit()
                        #                             # callee_fun_data.oper_list.append(OperandData(callee_fun, oper_idx, self.taint_var, None))
                                                    callee_fun_data.add_operand(OperandData(callee_fun, oper_idx, self.taint_var, None, pointer))
                        #                             # param_set.append(OperandData(callee_fun.name, oper_idx, self.taint_var, None))
                        #                 # callee_fun_list.append(callee_fun_data)
                        #                 # temp_fun.add_callee_function(callee_fun_data)
                                        self.currFunNode = callee_fun_data
                                        self.taint_prop_bw()
                                        self.fun_to_check.append(callee_fun_data)
                                        temp_fun.add_callee_function(callee_fun_data)
                    temp_fun.checked = True
                
        # self.callee_funs_op_info[self.currFun.name] = callee_fun_list
        # self.currFunNode = temp_fun
        # self.taint_prop_bw()
        # temp_fun.print_structure()
        # exit()
    
    def analyze_offset(self):
        log.info("Analyze offset")
        self.bv: BinaryView
        arrow = 'U+21B3'
        #  dict containing callee -> set(callers)    
        # Extract the first element of each tuple to create a set of function names
        calls = {}
        for fun in self.bv.functions:
            symbol = self.bv.symbols[fun.name]
            if len(symbol) > 0:
                for sym_type in symbol:
                    if sym_type.type != SymbolType.ImportedFunctionSymbol:
                        for ref in self.bv.get_code_refs(fun.start):
                            caller = ref.function
                            calls[fun] = calls.get(fun, set())
                            call_il = caller.get_low_level_il_at(ref.address)
                            if isinstance(call_il, Call) and isinstance(call_il.dest, Constant):
                                calls[fun].add(caller)
        
        for fun in calls:
            if False:
                if len(calls[fun]) > 0:
                    log.info("Callee: %s", fun.name)
                    for caller in calls[fun]:
                        log.debug("Caller %s", caller)
        
        # Get the entry point function
        start_fun = self.bv.get_function_at(self.bv.entry_point)
        start_fun: Function
        
        self.rootFun: Function
        self.rootFun = self.find_root_fun(start_fun)
        self.currFun = self.rootFun
        
        var_list = self.dwarf_fun_analysis(self.currFun.name)
        pprint.pprint(var_list)
        local_list = []
        param_list = []
        param_idx = 0
        for var in var_list:
            if var.tag == "DW_TAG_variable":
                log.debug("Local variable %s", var)
                temp_data = LocalData(var.name, None, var.offset)
                local_list.append(temp_data)
            if var.tag == "DW_TAG_formal_parameter":
                log.debug("Formal paramter %s", var)
                temp_data = LocalData(var.name, param_idx, var.offset)
                param_list.append(temp_data)
                param_idx += 1
                
        # pprint.pprint(local_list)
        # exit()
        root_fun = FunctionNode(fun=self.currFun,function_name=self.currFun.name,local_vars=local_list)
        root_fun.checked = True
        callee_fun_list = list()
        visited = list()
        for callee_addr in self.rootFun.callee_addresses:
            fun = self.bv.get_function_at(callee_addr)
            callee_fun = self.bv.get_function_at(callee_addr)
            symbol = self.bv.symbols[callee_fun.name]
            if len(symbol) > 0:
                # for sym_type in symbol:
                if symbol[0].type != SymbolType.ImportedFunctionSymbol:
                    for ref in self.bv.get_code_refs(callee_addr):
                        if ref not in visited:
                            visited.append(ref)
                            call_il = self.rootFun.get_low_level_il_at(ref.address)
                            if call_il != None:
                                print("Here")
                                if call_il.mlil.ssa_form.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                                    callee_fun_data = FunctionNode(fun=callee_fun, function_name=callee_fun.name)
                                    for oper_idx, param in enumerate(call_il.mlil.params):
                                        if (type(param.ssa_form) == binaryninja.mediumlevelil.MediumLevelILVarSsa):
                                            var_def = self.rootFun.mlil.ssa_form.get_ssa_var_definition(param.ssa_form.src)
                                            # log.debug(var_def)
                                            self.taint_var = var_def.low_level_il.ssa_form
                                            pointer = False
                                            try:
                                                if var_def.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                                                    pointer = True
                                            except:
                                                None
                                            # callee_fun_data.oper_list.append(OperandData(callee_fun, oper_idx, self.taint_var, None))
                                            callee_fun_data.add_operand(OperandData(callee_fun.name, oper_idx, self.taint_var, None, pointer))
                                    # callee_fun_list.append(callee_fun_data)
                                    # self.currFun = self.rootFun
                                    self.currFunNode = callee_fun_data
                                    self.taint_prop_bw()
                                    self.fun_to_check.append(self.currFunNode)
                                    root_fun.add_callee_function(callee_fun_data)
                                # self.callee_funs_op_info[self.rootFun.name] = callee_fun_list
                                    # callee_fun_list.clear()
        
        root_fun.print_structure()
        # self.currFunNode = root_fun
        # exit()
        # self.callee_funs_op_info[self.rootFun.name] = callee_fun_list
        # exit()
        # self.taint_prop_bw()
        # exit()
        # pprint.pprint(self.callee_funs_op_info[self.rootFun.name])
        # exit()
        while len(self.fun_to_check) > 0:
            # self.taint_prop_bw()
            # print(self.fun_to_check)
            
            # self.currFunNode = FunctionNode(function_name=self.currFun.name)
            try:
                self.currFunNode = self.fun_to_check.pop()
                self.currFun = self.currFunNode.fun
                log.debug("Checking %s", self.currFunNode.function_name)
                self.analyze_callee()
                
                # self.taint_prop_bw()
                # exit()
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
                traceback.print_exc()
            # except :
            #     log.error("%s doesn't have any callees", self.currFun.name)
            
            # print(self.currFun)
        # pprint.pprint(self.callee_funs_op_info)
        root_fun.print_structure()
        exit()
        
    
    def analyze_binary(self):
        self.bv: BinaryView
        arrow = 'U+21B3'
        #  dict containing callee -> set(callers)    
        # Extract the first element of each tuple to create a set of function names
        fun_names = {t[0] for t in self.taint_funs}
        calls = {}
        for fun in self.bv.functions:
            for ref in self.bv.get_code_refs(fun.start):
                caller = ref.function
                calls[fun] = calls.get(fun, set())
                call_il = caller.get_low_level_il_at(ref.address)
                if isinstance(call_il, Call) and isinstance(call_il.dest, Constant):
                    calls[fun].add(caller)
                    
        for callee in calls:
            # Need to check available callee functions of all functions in a program, for dangerous functions
            # Put those callers into the list of functions
            if callee.name in fun_names:
                log.warning(callee.name)    
                for fun in calls[callee]:
                    log.debug(fun.name)
                    self.fun_to_check.add(fun.name)
            else:
                log.error("Not in %s", callee.name)
        
        # Get the entry point function
        start_fun = self.bv.get_function_at(self.bv.entry_point)
        start_fun: Function
        
        self.rootFun: Function
        self.rootFun = self.find_root_fun(start_fun)
        self.currFun = self.rootFun
        
        
        # Temporary "graph" set:
        self.bv.get_function_at(self.rootFun.lowest_address)
        
        for index, param in enumerate(self.rootFun.parameter_vars): 
            # print(self.rootFun.parameter_vars)
            # exit()
            if param.type is not None and param.type.type_class == TypeClass.PointerTypeClass:
                if param.name == "argv":
                    # print(type(param), index)
                    self.taint_var = param
                    # self.fun_graph.append((self.bv.get_function_at(self.rootFun.lowest_address), index))
                    # exit()
        # To-do: At the moment, we are only considering argv as the taint variable
        for bb in self.rootFun.medium_level_il:
            for inst in bb:
                try:
                    if self.taint_var == inst.src.vars_read[0]:
                        self.taint_var = inst.ssa_form.dest
                        break
                except:
                    pass
        
        
        
        # If taint variable is established by then, insert it into taint list
        if (self.taint_var != None and 
            type(self.taint_var) == binaryninja.mediumlevelil.SSAVariable):
            self.taint_list.append(self.taint_var)
        else:
        # In this case, argv is empty and we need to search for other potential source of taint funs
        # Add sensitive functions creating potential taint sources
            log.info("Search for sensitive functions")
            for callee_addr in self.rootFun.callee_addresses:
                callee_fun = self.bv.get_function_at(callee_addr).name
                if callee_fun in fun_names:
                    # What if it is multi-source? How to handle this case? Allow multiple taint src var?
                    log.critical("Track it's taint variable")
                    param_idx = self.search_fun_indx(callee_fun)
                    for ref in self.bv.get_code_refs(callee_addr):
                        # print(hex(ref.address))
                        call_il = self.rootFun.get_low_level_il_at(ref.address)
                        if call_il.mlil.ssa_form.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                            # print(call_il.mlil)
                            for oper_idx, param in enumerate(call_il.mlil.params):
                                # print(type(param.ssa_form))
                                if (type(param.ssa_form) == binaryninja.mediumlevelil.MediumLevelILVarSsa and
                                    oper_idx == param_idx):
                                    var_def = self.rootFun.mlil.ssa_form.get_ssa_var_definition(param.ssa_form.src)
                                    self.taint_var = var_def.src
                                    self.taint_list.append(self.taint_var)
                                    
                                    
        
        
        # custom_pprint(self.mlillest)
        
        print(self.taint_var)
        # exit()
        # taint_def = self.rootFun.mlil.ssa_form.get_ssa_var_definition(self.taint_var)
        # log.warning("Taint def: %s", taint_def)
        # First rootFun taint propagation to poulate self.fun_set
        self.taint_prop_fw()
        while len(self.fun_set) > 0:
            target_fun = self.fun_set.pop()
            # Temporary "graph" set:
            self.fun_graph.append(target_fun)

            print(target_fun[0], "idx: ", target_fun[1])
            self.fun_taint_analysis(target_fun[0], target_fun[1])
            
        for fun in self.fun_graph:
            log.critical("%s: Operand Index: %d", fun[0].name, fun[1])
        return self.fun_graph