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
from functools import partial

import export_cg

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
            
    def print_fun_structure(self, indent=""):
        print(f"{indent}Function: {self.function_name}")
        for param in self.params:
            print(f"{indent}  Param: {param.param_idx}, Offset: {param.offset}")
        for var in self.local_vars:
            print(f"{indent}  Var: {var.var_name}, Offset: {var.offset}")
        for callee in self.callee_funs:
            print(f"{indent}  Calls: {callee.function_name}")
            for operand in callee.operands:
                print(f"{indent}  OperIdx: {operand.oper_idx}, Offset: {operand.offset}, Pointer: {operand.pointer}")
            
    def traverse_callees(self, action: Optional[Callable[['FunctionNode', Any], None]] = None, *args, **kwargs):
        """
        Recursively traverse all callee functions from this function node.
        Optionally, an action can be performed on each visited FunctionNode, with additional arguments.

        Args:
        - action: A callable that takes a FunctionNode as its first argument, followed by any number of additional arguments.
        - *args, **kwargs: Additional arguments to pass to the action callable.
        """
        if action:
            action(self, *args, **kwargs)

        for callee in self.callee_funs:
            callee.traverse_callees(action, *args, **kwargs)

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
    format = "[%(filename)s: Line:%(lineno)4s - %(funcName)20s()] %(levelname)7s    %(message)s "

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
        log.info(input_item.__str__())
        # exit()
        arch = Architecture['x86_64']
        bn = BinTaintAnalysis(bv, None, dwarf_info)
        return bn.analyze_offset()

class PtrOffsetTreeNode:
    def __init__(self, fun_name, reg_offset, index):
        self.fun_name = fun_name            # The current node (caller function)
        self.local_offset = reg_offset        # Register offset of the variable that will be tracked from the caller
        self.child = None                   # The next node (callee function)
        self.callee_arg_idx = index                  # The index of where the reg_offset will be passed to callee in the argument

    def add_child(self, child_node):
        self.child = child_node
        
    def print_node(self):
        """Prints the details of this node in a readable format."""
        print(f"Caller Function Name: {self.fun_name}")
        print(f"Local Offset: {self.local_offset}")
        print(f"Callee Argument Index: {self.callee_arg_idx}")

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

    def print_tree(self, node=None, prefix=""):
        if node is None:
            node = self.root
            if node is None:  # If the tree is empty
                print("Root Function: (empty)")
                return
            else:
                # Directly print the root node with its details without prefix
                print(f"Root Function: {node.fun_name}, Register Offset: {node.local_offset}")
                # Set the prefix for the child nodes of the root
                prefix = "   "
        else:
            # For non-root nodes, print with └─ prefix
            print(f"{prefix}└─ Function: {node.fun_name}, Register Offset: {node.local_offset}")

        # If this node has a child, recursively print the child with an updated prefix
        if node.child is not None:
            # Increase the indentation for the child node recursively
            self.print_tree(node.child, prefix + "   ")
            
    def find_parent(self, child_node, find_root=False):
        """
        Returns the parent node of the given child node if it exists, otherwise None.
        If find_root is True, returns the root node of the tree instead.
        
        Args:
        - child_node: The child node whose parent or root is to be found.
        - find_root: A boolean flag that determines whether to return the immediate parent (False) 
                     or the root of the tree (True).

        Returns:
        - The immediate parent node or the root node, depending on find_root. None if not found.
        """
        # If find_root is True, simply return the root, as it's the topmost parent of any node.
        if find_root:
            return self.root

        # The root node does not have a parent
        if self.root == child_node or self.root is None:
            return None

        current_node = self.root
        while current_node.child is not None:
            if current_node.child == child_node:
                return current_node
            current_node = current_node.child

        # If the child_node is not found as a child of any nodes, return None
        return None
    
    def get_outermost_node(self):
        """Returns the outermost (last) node in the tree."""
        if not self.root:
            return None

        current_node = self.root
        while current_node.child is not None:
            current_node = current_node.child
        return current_node

    def find_node_by_fun_name_and_offset(self, fun_name, local_offset, node=None):
        """
        Recursively searches for a node with the given function name and local offset.

        Args:
        - fun_name: The function name to search for.
        - local_offset: The local offset to search for.
        - node: The current node being inspected (used for recursive calls).

        Returns:
        - The PtrOffsetTreeNode if found, or None if no such node exists in the tree.
        """
        if node is None:
            node = self.root
        
        # Proper base case: stop if the current node is None.
        if node is None:
            return None
        
        # Check if the current node matches the criteria.
        if node.fun_name == fun_name and node.local_offset == local_offset:
            return node
        
        # Recursively proceed to the child node if it exists.
        if node.child is not None:
            return self.find_node_by_fun_name_and_offset(fun_name, local_offset, node.child)
        else:
            # Explicitly handle reaching the end of the chain.
            return None



def compare_trees(tree1: PtrOffsetTree, tree2: PtrOffsetTree) -> bool:
    if tree1 == None:
        return False
    log.info("Comparing: ")
    tree1.print_tree()
    tree2.print_tree()
    def compare_nodes(node1, node2):
        # Base case: both nodes are None
        if node1 is None and node2 is None:
            return True
        # If one node is None but the other isn't, trees are not equal
        if node1 is None or node2 is None:
            return False
        # Check if current nodes are equal in terms of fun_name and local_offset
        if node1.fun_name != node2.fun_name or node1.local_offset != node2.local_offset:
            return False
        # Recursively compare the children of the current nodes
        return compare_nodes(node1.child, node2.child)

    # Start the comparison from the root of both trees
    return compare_nodes(tree1.root, tree2.root)


def pop_ptr_offset_tree(node: FunctionNode, input_tree: PtrOffsetTree, indent=""):    
    log.info("%s", node.function_name)
    recent_node: PtrOffsetTreeNode
    recent_node = input_tree.get_outermost_node()
    recent_node.print_node()
    print("\n")
    node.print_fun_structure()
    # exit()
    try:
        offset = node.params[recent_node.callee_arg_idx].offset
    except:
        offset = None
    # log.debug(offset)
    # exit()
    # First creat a node because this will always be true. Index will be None at first because it will be determined if we need to 
    # further explored
    new_node = PtrOffsetTreeNode(fun_name=node.function_name, reg_offset=int(offset), index=None)
    recent_node.add_child(new_node)
    child = False # if this flag is True, then child exists, if it remains false, then this is the end.
    # recent_node.print_fun_structure()
    for callee_fun in node.callee_funs:
        # log.debug(callee_fun)
        for operand in callee_fun.operands:
            log.debug("%d %d", new_node.local_offset, operand.offset)
            if new_node.local_offset == operand.offset:
                child = True
                log.critical("Found")
                log.debug("%s Callee Fun: %s | OperIdx: %s, Offset: %s, Pointer: %s", 
                        indent, callee_fun.function_name, operand.oper_idx, operand.offset, operand.pointer)
                new_node.callee_arg_idx = operand.oper_idx
                callee_fun.traverse_callees(pop_ptr_offset_tree, input_tree, indent + "    ")
    if child == False:
        log.warning("Finished creating a tree")
        return True  # Indicates to stop and start a new tree
    return False  # Indicates that traversal can continue

ptr_offset_trees = set()

def gen_ptr_offset_tree(node: FunctionNode, indent=""):
    global ptr_offset_trees
    root_tree = None    
    is_unique = None
    log.info("Analyzing: %s", node.function_name)
    for var in node.local_vars:
        log.debug(var)
        for callee_fun in node.callee_funs:
            for operand in callee_fun.operands:
                # log.debug("%d %d %d", var.offset, operand.offset, operand.pointer)
                if var.offset == operand.offset and operand.pointer == True:
                    log.critical("Found")
                    log.debug("%s Var: %s, Offset: %s", indent, var.var_name, var.offset)
                    log.debug("%s Callee Fun: %s | OperIdx: %s, Offset: %s, Pointer: %s", 
                        indent, callee_fun.function_name, operand.oper_idx, operand.offset, operand.pointer)
                    if not root_tree:
                        root_node = PtrOffsetTreeNode(fun_name=node.function_name, reg_offset=operand.offset, index=operand.oper_idx)
                        root_tree = PtrOffsetTree(root=root_node)
                        # Directly iterate over callee_funs instead of using traverse_callees
                        stop = pop_ptr_offset_tree(callee_fun, root_tree, indent + "    ")
                        if stop:
                            log.warning("Stopping early due to a condition met in pop_ptr_offset_tree")
                            continue
                    is_unique = True
                    for existing_tree in ptr_offset_trees:
                        if compare_trees(existing_tree, root_tree):
                            is_unique = False
                            break
                    if is_unique:
                        ptr_offset_trees.add(root_tree)
                        log.info("Adding unique tree")
    
    if is_unique == None:
        is_unique = True
        if len(ptr_offset_trees) > 0:
            for existing_tree in ptr_offset_trees:
                if root_tree != None:
                    root_tree.print_tree()
                    if compare_trees(existing_tree, root_tree):
                        is_unique = False
                        break
        elif is_unique:
            ptr_offset_trees.add(root_tree)
            log.info("Adding unique tree")

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
        
    def gen_ptr_offset_tree(self, root_fun: FunctionNode):
        root_fun.print_structure()
        root_fun.traverse_callees(gen_ptr_offset_tree)

        # for tree in ptr_offset_trees:
        #     tree.print_tree()
        # exit()    
        return ptr_offset_trees
        
            
    def extract_offset(self, operand: str) -> int:
        """
        Extracts the offset from a string like '-4(%rbp)'.

        Args:
        - operand: The operand string to extract the offset from.

        Returns:
        - The offset as an integer, or None if the pattern does not match.
        """
        try:
            match = re.search(r'([+-]?\d+)\(%rbp\)', operand)
            if match:
                return int(match.group(1))  # Convert the matched offset to an integer
            else:
                return None  # or raise an exception, depending on how you want to handle unmatched cases
        except:
            return None

        
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
                log.debug("Expression")
                reg: SSARegister
                reg = inst_ssa.left.src
                if (binaryninja.commonil.Arithmetic in inst_ssa.left.__class__.__bases__ and 
                  type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILConst):
                    log.debug("Array access found")
                    base_reg    = inst_ssa.left.left.src.reg.__str__()
                    array_reg   = inst_ssa.left.right.src.reg.__str__()
                    offset      = inst_ssa.right.constant
                    expr = str(offset) + "(" + base_reg + "," + array_reg + ")"
                else:
                    log.debug("Not array access %s", reg.reg.name)
                    if reg.reg.name != "%rbp":
                        try:
                            reg_defs = self.currFun.llil.ssa_form.get_ssa_reg_definition(reg)
                            log.warning("Struct access %s", reg_defs)
                            base_offset = self.calc_ssa_off_expr(reg_defs)
                            base_offset = self.extract_offset(base_offset)
                            log.debug("Base offset: %d", base_offset)
                            new_offset = base_offset + int(inst_ssa.right.constant)
                            expr = str(new_offset) + "(" + "%rbp" + ")" 
                            # exit() 
                        except:
                            log.error("Can't find the definition")
                    else:
                        # log.debug("Return offset")
                        offset = str(int(inst_ssa.right.__str__(), base=16))
                        expr = offset + "(" + reg.reg.__str__() + ")"
                # reg = inst_ssa.left.src
            except:
                # Single register
                reg = inst_ssa.left
            # if (binaryninja.commonil.Arithmetic in inst_ssa.left.__class__.__bases__ and 
            #       type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILConst):
            #     print("Array access found")
            #     base_reg    = inst_ssa.left.left.src.reg.__str__()
            #     array_reg   = inst_ssa.left.right.src.reg.__str__()
            #     offset      = inst_ssa.right.constant
            #     expr = str(offset) + "(" + base_reg + "," + array_reg + ")"
            # else:
            #     try:
            #     # print(inst_ssa.right, type(inst_ssa.right))
            #         offset = str(int(inst_ssa.right.__str__(), base=16))
            #         expr = offset + "(" + reg.reg.__str__() + ")"
            #     except:
            #         return None
            
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
        # exit()
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
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_IF:
                # May need to revamp this part.
                # print()
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_RET:
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_STORE_SSA:
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD:
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_JUMP_TO:
                visited.append(self.taint_inst)
            else:
                log.error("Not taken consideration")
                log.debug("%s %s", self.taint_inst.operation, self.taint_inst)
                exit()
                
                # self.taint_list.append(inst)
                # exit()
                
    def taint_prop_bw(self):
        arrow = 'U+21B3'
        log.info("Taint propagation backward")
        for op in self.currFunNode.operands:
            ssa_reg = self.get_ssa_reg(op.taint_inst)
            log.warning("%s %s", op.taint_inst, ssa_reg)
            if ssa_reg == None:
                # this means we don't need to find the definition
                offset = self.calc_ssa_off_expr(op.taint_inst)
                op.offset = self.extract_offset(offset)
            else:
                taint_defs = self.currFun.llil.ssa_form.get_ssa_reg_definition(ssa_reg)  
                offset = self.calc_ssa_off_expr(taint_defs)
                op.offset = self.extract_offset(offset)
            log.debug(op)
        
    
    def dwarf_fun_analysis(self, fun_name):
        for fun in self.dwarf_info:
            # print(fun, fun_name)
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
            print(self.taint_var)
            self.taint_list.append(self.taint_var)
        # exit()
        self.taint_prop_fw()
    
    def analyze_callee(self):
        temp_fun = self.currFunNode
        log.info("Analyzing callee for %s | %d", temp_fun.function_name, temp_fun.checked)
        
        var_list = self.dwarf_fun_analysis(self.currFun.name)
        pprint.pprint(var_list)
        local_list = []
        param_list = []
        param_idx = 0
        for var in var_list:
            if var.tag == "DW_TAG_variable":
                log.debug("Local variable %s", var)
                if var.base_type == "DW_TAG_structure_type":
                    # Still need to add actual variable because of the case where struct object is passed
                    temp_data = LocalData(var.name, None, int(var.offset))
                    local_list.append(temp_data)
                    for idx, member in enumerate(var.struct.member_list):
                        if idx != 0:
                            temp_data = LocalData(member.name, None, int(member.offset))
                            local_list.append(temp_data)    
                else:
                    temp_data = LocalData(var.name, None, var.offset)
                    local_list.append(temp_data)
            if var.tag == "DW_TAG_formal_parameter":
                log.debug("Formal parameter %s", var)
                temp_data = LocalData(var.name, param_idx, int(var.offset))
                param_list.append(temp_data)
                param_idx += 1
        visited = list()
        temp_fun.local_vars = local_list.copy()
        temp_fun.params = param_list.copy()

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
                                        callee_fun_data = FunctionNode(fun=callee_fun, function_name=callee_fun.name)
                                        for oper_idx, param in enumerate(call_il.mlil.params):
                                            if (type(param.ssa_form) == binaryninja.mediumlevelil.MediumLevelILVarSsa):
                                                var_def = self.currFun.mlil.ssa_form.get_ssa_var_definition(param.ssa_form.src)
                                                if var_def != None:
                                                    self.taint_var = var_def.low_level_il.ssa_form
                                                    pointer = False
                                                    if var_def.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                                                        pointer = True
                                                    log.warning("%s %s", var_def.src, var_def.src.operation)
                                                    callee_fun_data.add_operand(OperandData(callee_fun, oper_idx, self.taint_var, None, pointer))
                                        self.currFunNode = callee_fun_data
                                        self.taint_prop_bw()
                                        self.fun_to_check.append(callee_fun_data)
                                        temp_fun.add_callee_function(callee_fun_data)
                    temp_fun.checked = True
        
    def analyze_offset(self):
        log.info("Analyze offset")
        self.bv: BinaryView
        arrow = 'U+21B3'
        #  dict containing callee -> set(callers)    
        # Extract the first element of each tuple to create a set of function names
        calls = {}
        # for fun in self.bv.functions:
        #     for bb in fun.low_level_il:
        #         for inst in bb:
        #             print(inst)
        # exit()
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
                if var.base_type == "DW_TAG_structure_type":
                    # Still need to add actual variable because of the case where struct object is passed
                    temp_data = LocalData(var.name, None, int(var.offset))
                    local_list.append(temp_data)
                    for idx, member in enumerate(var.struct.member_list):
                        if idx != 0:
                            temp_data = LocalData(member.name, None, int(member.offset))
                            local_list.append(temp_data)    
                else:
                    temp_data = LocalData(var.name, None, var.offset)
                    local_list.append(temp_data)
            if var.tag == "DW_TAG_formal_parameter":
                # log.debug("Formal paramter %s", var)
                temp_data = LocalData(var.name, param_idx, var.offset)
                param_list.append(temp_data)
                param_idx += 1
        # exit()
                
        root_fun = FunctionNode(fun=self.currFun,function_name=self.currFun.name,local_vars=local_list)
        root_fun.checked = True
        visited = list()
        for callee_addr in self.rootFun.callee_addresses:
            fun = self.bv.get_function_at(callee_addr)
            callee_fun = self.bv.get_function_at(callee_addr)
            symbol = self.bv.symbols[callee_fun.name]
            if len(symbol) > 0:
                if symbol[0].type != SymbolType.ImportedFunctionSymbol:
                    for ref in self.bv.get_code_refs(callee_addr):
                        if ref not in visited:
                            visited.append(ref)
                            call_il = self.rootFun.get_low_level_il_at(ref.address)
                            if call_il != None:
                                # print("Here")
                                if call_il.mlil.ssa_form.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                                    callee_fun_data = FunctionNode(fun=callee_fun, function_name=callee_fun.name)
                                    for oper_idx, param in enumerate(call_il.mlil.params):
                                        if (type(param.ssa_form) == binaryninja.mediumlevelil.MediumLevelILVarSsa):
                                            var_def = self.rootFun.mlil.ssa_form.get_ssa_var_definition(param.ssa_form.src)
                                            self.taint_var = var_def.low_level_il.ssa_form
                                            pointer = False
                                            try:
                                                if var_def.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                                                    pointer = True
                                            except:
                                                None
                                            callee_fun_data.add_operand(OperandData(callee_fun.name, oper_idx, self.taint_var, None, pointer))
                                    self.currFunNode = callee_fun_data
                                    self.taint_prop_bw()
                                    self.fun_to_check.append(self.currFunNode)
                                    root_fun.add_callee_function(callee_fun_data)
                                
        root_fun.print_structure()
        # exit()
        while len(self.fun_to_check) > 0:
            try:
                self.currFunNode = self.fun_to_check.pop()
                self.currFun = self.currFunNode.fun
                log.debug("Checking %s", self.currFunNode.function_name)
                self.analyze_callee()
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
                traceback.print_exc()
        # Finished creating full tree of caller-callee
        root_fun.print_structure()
        exit()
        ptr_offset_trees = self.gen_ptr_offset_tree(root_fun)
        print(ptr_offset_trees)
        # exit()
        # for tree in ptr_offset_trees:
        #     tree.print_tree()
        # exit()
        return ptr_offset_trees
    
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
                    self.fun_to_check.append(fun.name)
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
        self.taint_prop_fw()
        # exit()
        index = 0
        while len(self.fun_set) > 0 or index < 1:
            index += 1
            target_fun = self.fun_set.pop()
            print(target_fun[0].name)
            
            # Temporary "graph" set:
            self.fun_graph.append(target_fun)
            print(target_fun[0], "idx: ", target_fun[1])
            # exit()
            self.fun_taint_analysis(target_fun[0], target_fun[1])
            
            
        for fun in self.fun_graph:
            log.critical("%s: Operand Index: %d", fun[0].name, fun[1])
            
        return self.fun_graph