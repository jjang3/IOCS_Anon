import fileinput
import time
import os, sys
import logging

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('main')

# Add the parent directory to sys.path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from main import *

from asm_analysis import *

asm_macros = """# var_c14n macros
# Load effective address macro
.macro lea_gs dest, offset
\trdgsbase %r11
\tmov   \offset(%r11), %r11
\tlea   (%r11), \dest
.endm

.macro lea_store_gs src, offset
\tleaq  \src, %r11
\tmovq  (%r11), %r10
\trdgsbase %r11
\tmovq  \offset(%r11), %r11
\tmovq  %r10, (%r11)
.endm

# Data movement macros
.macro mov_store_gs src, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovb \src, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tmovw \src, (%r11)  # 16-bit
\t.elseif \\value == 32
\t\tmovl \src, (%r11)  # 32-bit
\t.elseif \\value == 64
\t\tmovq \src, (%r11)  # 64-bit
\t.endif
.endm

.macro mov_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovb (%r11), \dest  # 8-bit 
\t.elseif \\value == 16
\t\tmovw (%r11), \dest  # 16-bit
\t.elseif \\value == 32
\t\tmovl (%r11), \dest  # 32-bit
\t.elseif \\value == 64
\t\tmovq (%r11), \dest  # 64-bit
\t.endif
.endm

.macro mov_arr_store_gs src, offset, disp, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tadd \disp, %r11
\t.if \\value == 8
\t\tmovb \src, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tmovw \src, (%r11)  # 16-bit 
\t.elseif \\value == 32
\t\tmovl \src, (%r11)  # 32-bit 
\t.elseif \\value == 64
\t\tmovq \src, (%r11)  # 64-bit 
\t.endif
.endm

.macro mov_arr_load_gs src, offset, disp, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tadd \disp, %r11
\t.if \\value == 8
\t\tmovb (%r11), \dest  # 8-bit
\t.elseif \\value == 16
\t\tmovw (%r11), \dest  # 16-bit
\t.elseif \\value == 32
\t\tmovl (%r11), \dest  # 32-bit
\t.elseif \\value == 64
\t\tmovq (%r11), \dest  # 64-bit
\t.endif
.endm

.macro movss_store_gs src, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t\tmovss \src, (%r11)  # 64-bit
.endm

.macro movss_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tmovss (%r11), \dest  # 64-bit
.endm

.macro movzx_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovzbl (%r11), \dest  # 8-bit 
\t.elseif \\value == 16
\t\tmovzx (%r11), \dest  # 16-bit
\t.endif
.endm

# Comparison / Shift macros
# ---- Comparison ---- #
.macro cmp_store_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tcmpb \operand, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tcmpw \operand, (%r11)  # 16-bit
\t.elseif \\value == 32
\t\tcmpl \operand, (%r11)  # 32-bit
\t.elseif \\value == 64
\t\tcmpq \operand, (%r11)  # 64-bit
\t.endif
.endm

.macro cmp_load_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tcmpb (%r11), \operand  # 8-bit 
\t.elseif \\value == 16
\t\tcmpw (%r11), \operand  # 16-bit
\t.elseif \\value == 32
\t\tcmpl (%r11), \operand  # 32-bit
\t.elseif \\value == 64
\t\tcmpq (%r11), \operand  # 64-bit
\t.endif
.endm

.macro and_store_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tandb \operand, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tandw \operand, (%r11)  # 16-bit
\t.elseif \\value == 32
\t\tandl \operand, (%r11)  # 32-bit
\t.elseif \\value == 64
\t\tandq \operand, (%r11)  # 64-bit
\t.endif
.endm

.macro and_load_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tandb (%r11), \operand  # 8-bit 
\t.elseif \\value == 16
\t\tandw (%r11), \operand  # 16-bit
\t.elseif \\value == 32
\t\tandl (%r11), \operand  # 32-bit
\t.elseif \\value == 64
\t\tandq (%r11), \operand  # 64-bit
\t.endif
.endm

# Arithmetic macros
# ---- Addition ---- #
.macro add_store_gs operand, offset, value
\trdgsbase %r10
\tmov	\offset(%r10), %r10 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\tadd \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r10)
\t.elseif \\value == 16
\tadd \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r10)
\t.elseif \\value == 32
\tadd \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r10)
\t.elseif \\value == 64
\tadd \\operand, %r11   # 64-bit 
\tmov %r11, (%r10)
\t.endif
.endm

.macro add_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r11b
\tadd %r11b, \dest  # 8-bit 
\t.elseif \\value == 16
\tmov (%r11), %r11w
\tadd %r11w, \dest  # 16-bit 
\t.elseif \\value == 32
\tmov (%r11), %r11d
\tadd %r11d, \dest  # 32-bit 
\t.elseif \\value == 64
\tmov (%r11), %r11
\tadd %r11, \dest   # 64-bit 
\t.endif
.endm

# ---- Subtraction ---- #
.macro sub_store_gs operand, offset, value
\trdgsbase %r10
\tmov	\offset(%r10), %r10 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\tsub \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r10)
\t.elseif \\value == 16
\tsub \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r10)
\t.elseif \\value == 32
\tsub \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r10)
\t.elseif \\value == 64
\tsub \\operand, %r11   # 64-bit 
\tmov %r11, (%r10)
\t.endif
.endm

.macro sub_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r11b
\tsub %r11b, \dest  # 8-bit 
\t.elseif \\value == 16
\tmov (%r11), %r11w
\tsub %r11w, \dest  # 16-bit 
\t.elseif \\value == 32
\tmov (%r11), %r11d
\tsub %r11d, \dest  # 32-bit 
\t.elseif \\value == 64
\tmov (%r11), %r11
\tsub %r11, \dest   # 64-bit 
\t.endif
.endm

# ---- Multiplication ---- #
.macro imul_store_gs operand, offset, value
\trdgsbase %r10
\tmov	\offset(%r10), %r10 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\timul \\operand, %r9b  # 8-bit 
\tmov %r9b, (%r10)
\t.elseif \\value == 16
\timul \\operand, %r9w  # 16-bit 
\tmov %r9w, (%r10)
\t.elseif \\value == 32
\timul \\operand, %r9d  # 32-bit 
\tmov %r9d, (%r10)
\t.elseif \\value == 64
\timul \\operand, %r9   # 64-bit 
\tmov %r9, (%r10)
\t.endif
.endm

.macro imul_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r12b
\timul %r12b, \dest  # 8-bit 
\t.elseif \\value == 16
\tmov (%r11), %r12w
\timul %r12w, \dest  # 16-bit 
\t.elseif \\value == 32
\tmov (%r11), %r12d
\timul %r12d, \dest  # 32-bit 
\t.elseif \\value == 64
\tmov (%r11), %r10
\timul %r10, \dest   # 64-bit 
\t.endif
.endm

.macro shl_store_gs operand, offset, value
\trdgsbase %r10
\tmov	\offset(%r10), %r10 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\tshl \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r10)
\t.elseif \\value == 16
\tshl \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r10)
\t.elseif \\value == 32
\tshl \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r10)
\t.elseif \\value == 64
\tshl \\operand, %r11   # 64-bit 
\tmov %r11, (%r10)
\t.endif
.endm
"""

def traverse_ast(tgt_ast, bn_var_info, depth):
    # logger.debug("Traversing the AST to patch")
    # parse_ast(tgt_ast)
    # print("Depth = ", depth)
    
    if repr(tgt_ast.right) == 'BnSSAOp':
        return traverse_ast(tgt_ast.right, bn_var_info, depth+1)
                        
    if repr(tgt_ast.left) == 'RegNode' and depth != 0:
        for var in bn_var_info:
            var_ast = var.asm_syntax_tree
            try:
                if var_ast.left.value == tgt_ast.left.value:
                    # print("Found", tgt_ast.left.value)
                    return var
            except Exception as err:
                None
    else:
        return None
    
# This list will contain lea_store_gs insts that will be used to update the value after reference returns
lea_list = list()
patch_inst_list = list()

def patch_inst(dis_inst, temp_inst: PatchingInst, bn_var, bn_var_info: list, tgt_offset, dwarf_var_info, offset_targets: set):
    logger.critical("Patch the instruction %s | Offset: %d", dis_inst, tgt_offset)
    # parse_ast(bn_var.asm_syntax_tree)
    off_regex       = r"(-|\$|)(-?[0-9].*\(%r..*\))"
    array_regex = r"(-\d+)\((%\w+)(?:\+(%\w+))?\)"
    #offset_expr_regex = r'(\-[0-9].*)\((.*)\)'
    offset_expr_regex = r'(-[0-9]+)\((%rbp)(,%r[a-d]x)?\)'
    store_or_load   = str()
    if re.search(off_regex, bn_var.patch_inst.src):
        store_or_load = "load"
    elif re.search(off_regex, bn_var.patch_inst.dest):
        store_or_load = "store"

    arr_regex = None
    # print(bn_var.patch_inst.dest)
    if store_or_load == "load":
        arr_regex = re.search(array_regex, bn_var.patch_inst.src)
    elif store_or_load == "store":
        arr_regex = re.search(array_regex, bn_var.patch_inst.dest)
        
    tgt_ast = bn_var.asm_syntax_tree
    # print(bn_var, store_or_load)
    line = None
    patch_inst_line = None
    # print(bn_var.patch_inst.inst_print())
    
    ssa_var = traverse_ast(tgt_ast, bn_var_info, 0)
    if ssa_var != None:
        # Found SSA register    
        if ssa_var.patch_inst.inst_type == "lea":
            new_inst_type = "lea_gs"
            logger.info("Patching with lea_gs w/ base obj")
            line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d" % 
                        (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, temp_inst.dest, tgt_offset)
            # logger.debug(temp_inst.inst_print())
            # logger.debug(bn_var)
    else:
        if bn_var.patch_inst.inst_type == "lea":
            new_inst_type = "lea_gs"
            logger.info("Patching with lea_gs w/o base obj")
            # If there is no stack offset being set as a value, we cannot use the LEA_GS for such case
            for var_item in bn_var_info:
                # print(bn_var)
                if var_item.offset_expr == temp_inst.dest:
                    if repr(var_item.asm_syntax_tree.left) == 'BnSSAOp':
                        # If left is a stack offset, extract the offset value and check whether it is being set
                        offset_num = var_item.asm_syntax_tree.left.right.value
                        offset_reg = re.search(offset_expr_regex, var_item.offset_expr)
                        base_offset = offset_reg.group(1)
                        array_indx  = offset_reg.group(3)
                        if array_indx != None:
                            logger.critical("Array found")
                        if offset_num == base_offset:
                            # If stack offset is set before, then it is safe to use the new macro
                            line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d" % 
                            (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
                            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, temp_inst.dest, tgt_offset)
                else:
                    # Else, we need to use the original stack offset.
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t#%s\t%s, %d" % 
                            (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, temp_inst.dest, tgt_offset)
                    
            # line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d" % 
            #             (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
    # logger.debug(bn_var)
    if bn_var.arg == True and bn_var.patch_inst.inst_type != "lea":
        return dis_inst
    elif bn_var.arg == True and bn_var.patch_inst.inst_type == "lea":
        logger.debug("Here")
        new_inst_type = "lea_store_gs" 
        line = ""
        for var in dwarf_var_info:
            if var.offset_expr == bn_var.offset_expr:
                # Found that base struct object is being passed as an argument, need to lea_store_gs all the members as well
                logger.error("Found struct object")
                if var.struct != None:
                    for member in var.struct.member_list:
                        # logger.debug(offset_targets)
                        offset_value = 0
                        for offset in offset_targets:
                            if offset[0] == member.offset_expr:
                                offset_value = offset[1]
                        if offset_value != None and member.offset_expr != None:
                            line = "\t%s\t%s, %d\n" % (new_inst_type, member.offset_expr, offset_value)
                            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, member.offset_expr, offset_value)
                        
                        if line != "" and line not in lea_list:
                            lea_list.append(line)
                            patch_inst_list.append(patch_inst_line)
        if line == "" and bn_var.offset_expr != None:
            line = "\t%s\t%s, %d\n" % (new_inst_type, bn_var.offset_expr, tgt_offset)
            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, bn_var.offset_expr, tgt_offset)
            if line != "" and line not in lea_list:
                lea_list.append(line)
                patch_inst_list.append(patch_inst_line)
        logger.debug(bn_var)
        logger.debug(lea_list)
        return dis_inst

    if line == None:
        # If line is None by now, it means patching without any context register
        value = 0
        if bn_var.patch_inst.suffix == "b":
            value = 8
        elif bn_var.patch_inst.suffix == "w":
            value = 16
        elif bn_var.patch_inst.suffix == "l":
            value = 32
        elif bn_var.patch_inst.suffix == "q":
            value = 64
        # Only store should comment out macro to update value, loading value should be from the page
        if bn_var.patch_inst.inst_type == "mov":
            logger.debug(store_or_load)
            # if arr_regex != None and arr_regex.group(3) == None: # Disabling array support due to challenge of not being able to update specific array value
            logger.info("Patching with mov_gs")
            if arr_regex != None and arr_regex.group(3) != None:
                logger.info("Patching with mov_arr_gs")
                if store_or_load == "store":
                    new_inst_type = "mov_arr_store_gs"
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %s, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, arr_regex.group(3), value), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d, %s, %d" % (new_inst_type, temp_inst.src, tgt_offset, arr_regex.group(3), value)
                elif store_or_load == "load":
                    new_inst_type = "mov_arr_load_gs"
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %s, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, arr_regex.group(3), value), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d, %s, %d" % (new_inst_type, temp_inst.dest, tgt_offset, arr_regex.group(3), value)
            else:
                if store_or_load == "store":
                    new_inst_type = "mov_store_gs"
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
                elif store_or_load == "load":
                    new_inst_type = "mov_load_gs"
                    logger.debug(bn_var)
                    for var in dwarf_var_info:
                        if var.offset_expr == bn_var.offset_expr:
                            # Found that base struct object is being copied into a value, then, just load stack offset
                            if var.struct != None:
                                logger.error("Found struct object")
                                line = re.sub(r"(\b[a-z]+\b).*", "%s\t#%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
                            else:
                                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
                    if line == None:
                        line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                        patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "movss":
            if store_or_load == "store":
                new_inst_type = "movss_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "movss_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "movzx":
            logger.info("Patching with movzx_gs")
            if store_or_load == "store":
                new_inst_type = "movzx_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "movzx_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "add":
            logger.info("Patching with add_gs")
            if store_or_load == "store":
                new_inst_type = "add_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "add_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "sub":
            logger.info("Patching with sub_gs")
            if store_or_load == "store":
                new_inst_type = "sub_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "sub_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "imul": # Signed multiply (two's comp arith)
            logger.info("Patching with imul_gs")
            if store_or_load == "store":
                new_inst_type = "imul_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "imul_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "shl": # shift left
            logger.info("Patching with shl_gs")
            if store_or_load == "store":
                new_inst_type = "shl_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "shl_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "cmp":
            logger.info("Patching with cmp_gs")
            if store_or_load == "store":
                new_inst_type = "cmp_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "cmp_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t#%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "and":
            logger.info("Patching with and_gs")
            if store_or_load == "store":
                new_inst_type = "and_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "and_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
            
    if line != None:
        patch_inst_list.append(patch_inst_line)
        return line
    
def remove_duplicate_lines(lines):
    """
    Remove duplicate lines from a list while preserving the order.
    
    :param lines: List of lines (strings)
    :return: List of lines with duplicates removed
    """
    seen = set()
    result = []
    for line in lines:
        if line not in seen:
            result.append(line)
            seen.add(line)
    return result
  
def rewriter(funlist, target_dir, target_file, dwarf_fun_var_info, bn_fun_var_info, fun_table_offsets):
    patch_count = 0
    file_path = None
    if target_dir != None:
        # This is for a single binary c14n. 
        file_path = os.path.join(target_dir, target_file)
        print(file_path)
        debug_file = target_file + ".bak"
        if os.path.isfile(os.path.join(target_dir, debug_file)):
            print("Copying debug file")
            shutil.copyfile(os.path.join(target_dir, debug_file), os.path.join(target_dir, target_file))
        else:
            print("No debug file exists")
    elif target_dir == None:
        # This is for a binary with multiple object files and they are in their own separate location
        file_path = target_file.asm_path
        file_path_dir = os.path.dirname(file_path)
        debug_file = file_path + ".bak"
        if os.path.isfile(debug_file):
            print("Copying debug file")
            shutil.copyfile(debug_file, file_path)
            time.sleep(2)
        else:
            print("No debug file exists")
        # print(file_path, file_path_dir, debug_file)
        # exit()
        
    
    debug = False
    with fileinput.input(file_path, 
                            inplace=(not debug), encoding="utf-8", backup='.bak') as f:
        file_pattern = re.compile(r'\.file\s+"([^"]+)"')
        fun_begin_regex = r'(?<=.type\t)(.*)(?=,\s@function)'
        fun_end_regex   = r'(\t.cfi_endproc)'
        
        dis_line_regex = r'(mov|movz|lea|sub|add|cmp|sal|and|imul|call|movss)([l|b|w|q|bl|xw|wl]*)\s+(\S+)(?:,\s*(\S+))?(?:,\s*(\S+))?\n'
        # sing_line_regex = r'\t(div)([a-z]*)\t(.*)'
        check = False
        currFun = str()
        patch_targets = list()
        offset_targets = list()
        struct_targets = set()
        
        for line in f:
            if file_pattern.findall(line): #.startswith('\t.file\t"%s.c"' % target_file.rsplit('.', maxsplit=1)[0]):
                print(asm_macros, end='')
            fun_begin = re.search(fun_begin_regex, line)
            if fun_begin is not None:
                if fun_begin.group(1) in funlist:
                    currFun = fun_begin.group(1)
                    logger.warning(currFun)
                    try:
                        dwarf_var_info   = dwarf_fun_var_info[currFun]
                        bninja_info     = bn_fun_var_info[currFun]
                        offset_targets  = fun_table_offsets[currFun]
                        check = True
                    except Exception as err:
                        logger.error("Skipping", type(err))
                        check = False
                        
                    if debug:
                        # if currFun != "sort": # Debug
                        #     check = False
                        # else:
                        #     check = True
                        None
                        custom_pprint(dwarf_var_info)
                        custom_pprint(bninja_info)
                        custom_pprint(offset_targets)
                    else:
                        if offset_targets != None:
                            for tgt in offset_targets:
                                logger.warning(tgt)
            fun_end = re.search(fun_end_regex, line)
            if fun_end is not None:
                lea_list.clear() # Clear the lea_list per function and also after rewriting the call instruction
                check = False
                dwarf_var_info = None
                bninja_info = None
                offset_targets = None
        
            if check == True:
                # dis_line = line.rstrip('\n')
                dis_line = line
                # mnemonic source, destination AT&T
                logger.debug(dis_line)
                dis_regex   = re.search(dis_line_regex, dis_line)
                if dis_regex is not None:
                    inst_type   = dis_regex.group(1)
                    suffix      = dis_regex.group(2)
                    src         = dis_regex.group(3)
                    dest        = dis_regex.group(4)
                    # temp_inst = PatchingInst(conv_instr(inst_type), src, dest, expr, suffix)
                    logger.debug("%s %s %s %s", inst_type, suffix, src, dest)
                    # Need to convert movzbl and movzxw to movzx + suffix (b or w)
                    if inst_type == "movz":
                        inst_type = "movzx"
                    elif inst_type == "call" and len(lea_list) > 0:
                        uniq_lea_list = remove_duplicate_lines(lea_list)
                        logger.critical("Patch the instruction %s", dis_line)
                        lea_set_line = ""
                        for lea_inst in uniq_lea_list:
                            lea_set_line += lea_inst
                            patch_count += 1
                        # print(lea_set_line)
                        new_inst = re.sub(r"(\b[a-z]+\b).*", "%s%s" % (dis_line, lea_set_line), dis_line)
                        # Clear the list once your done patching
                        if new_inst != None:
                            print(new_inst, end='')
                        else:
                            print(line, end='')
                        lea_list.clear()
                        uniq_lea_list.clear()
                        continue
                        
                    if suffix == "bl":
                        suffix = "b"
                    elif suffix == "xw" or suffix == "wl":
                        suffix = "w"
                    
                    if dest != None:
                        temp_inst = PatchingInst(inst_type=inst_type, suffix=suffix,
                                                    dest=conv_imm(dest), src=conv_imm(src), ptr_op="")
                    else:
                        # For a single operand assembly instruction (e.g., salq)
                        if inst_type == "sal":
                            temp_inst = PatchingInst(inst_type="shl", suffix=suffix,
                                                    dest=conv_imm(src), src="$1", ptr_op="")
                        
                    if debug:
                        logger.warning(temp_inst.inst_print())
                        if src != None:
                            for offset in offset_targets:
                                if conv_imm(src) == offset[0]:
                                    # logger.warning(temp_inst.inst_print())
                                    logger.warning("Debug found")
                        if dest != None:
                            for offset in offset_targets:
                                if conv_imm(dest) == offset[0]:
                                    # logger.warning(temp_inst.inst_print())
                                    logger.warning("Debug found")
                    new_inst = None
                    for idx, bn_var in enumerate(bninja_info):
                        # logger.warning(bn_var.patch_inst.inst_print())
                        if debug:
                            logger.warning(temp_inst.inst_print())
                            logger.warning(bn_var.offset_expr)
                            logger.warning(bn_var.patch_inst.inst_print())
                            None
                        if temp_inst.inst_check(bn_var.patch_inst):
                            # print("Found\n", temp_inst.inst_print(), "\n", bn_var.patch_inst.inst_print())
                            offset_expr = bn_var.offset_expr
                            offset_regex = r"(-\d+)\((%\w+)(?:,(%\w+))?\)"
                            offset_search = re.search(offset_regex, str(offset_expr))
                            if offset_search and offset_search.group(3) != None:
                                logger.error("Fix offset")
                                offset = offset_search.group(1)
                                new_offset = str(offset) + "(" + offset_search.group(2) + ")"
                                offset_expr = new_offset
                            for offset in offset_targets:
                                if offset_expr == offset[0]:
                                    # Found the offset target; need to patch this instruction
                                    logger.warning("Offset found")
                                    logger.warning(bn_var)
                                    new_inst = patch_inst(dis_line, temp_inst, bn_var, bninja_info, offset[1], dwarf_var_info, offset_targets)
                                    # bninja_info.pop(idx) # problem: for all patch, i'm popping rdx
                                    if new_inst != None:
                                        # logger.debug("\n%s",new_inst)
                                        break
                                    else:
                                        # Exit out of entire script if we find a missing instruction
                                        import signal
                                        logger.error(temp_inst.inst_print())
                                        os.kill(os.getppid(),signal.SIGTERM)
                                        sys.exit(2)
                            else:
                                continue
                            break
                        # print("Here")
                            # if offset_expr in 
                            # parse_ast(bn_var.asm_syntax_tree)
                    if new_inst != None:
                        patch_count += 1
                        logger.debug("\n%s",new_inst)
                        print(new_inst, end='')
                    else:
                        if debug != True:
                            print(line, end='')
                        None
                else:
                    if debug != True:
                        print(line, end='')
                    None
            else:
                if debug != True:
                    print(line, end='')
                None
    
    return patch_count