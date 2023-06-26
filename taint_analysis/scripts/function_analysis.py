import argparse
import pprint
from binaryninja import *
from dataclasses import dataclass, field

# Data class
@dataclass(unsafe_hash=True)
class fun_dataclass:
    name: str
    addr_range: list = field(default_factory=list,hash=False)
    taint_srcs: set = field(default_factory=set,hash=False)
    taint_sinks: set = field(default_factory=set,hash=False)

parser = argparse.ArgumentParser(description="Running reassembly tool for the example")
# ----- Parser arguments ----- #
parser.add_argument('-i', '--input', required=True)             # testing application to rewrite
parser.add_argument('-b', '--binary', required=True)             # testing application to rewrite
args                = parser.parse_args()

tainted_vars_local      = set()
tainted_vars_global     = set()
sink_funs               = set()

def main():
    fun_analysis(args.input, args.binary)

def find_taint_variables(bbs, src_addrs, bv):
    for bb in bbs:
        for inst in bb:
            if inst.address in src_addrs:
                print("Source MILI instruction found at", hex(inst.address))
                src_ssa = inst.ssa_form
                if src_ssa.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                    for param_var in src_ssa.params:
                        print(param_var.operation, param_var)
                        if  param_var.operation == MediumLevelILOperation.MLIL_VAR_SSA or \
                            param_var.operation == MediumLevelILOperation.MLIL_VAR or \
                            param_var.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
                                cand = param_var.function.get_ssa_var_definition(param_var.src)
                                if type(cand.src.src) == binaryninja.function.Variable:
                                    tainted_vars_local.add(cand.src.src)
                                    print("Taint variable added to local: ", cand.src.src, hex(cand.address))
                        elif param_var.operation == MediumLevelILOperation.MLIL_CONST_PTR or \
                            param_var.operation == MediumLevelILOperation.MLIL_CONST:
                                global_var = bv.get_data_var_at(param_var.constant)
                                print(global_var)
                                for global_ref in global_var.code_refs:
                                    if global_ref.function.get_llil_at(global_ref.address).mlil is not None:
                                        oper = global_ref.function.get_llil_at(global_ref.address).mlil.operation
                                        if oper is MediumLevelILOperation.MLIL_CALL:
                                            if global_ref.function.get_llil_at(global_ref.address).hlil.operation is HighLevelILOperation.HLIL_CALL:
                                                for op in global_ref.function.get_llil_at(global_ref.address).hlil.operands:
                                                    if str(op) in sink_funs:
                                                        print("Taint variable added to global: ", hex(global_var.address))
                                                        tainted_vars_global.add(global_var.address)

def check_taint_param(target_fun, param_index):
    # if target_fun == None:
    #     return None
    # var = target_fun.ssa_form.params[param_index].src
    # def_ref = target_fun.function.get_ssa_var_definition(var)
    print(target_fun.mlil.source_function.parameter_vars)
    for var in target_fun.mlil.source_function.parameter_vars:
        print(target_fun.mlil.get_var_definitions(var))
    for bb in target_fun.mlil_basic_blocks:
        for inst in bb:
            print(inst)
    #print(target_fun.get_low_level_il_at(target_fun.start).ssa_form)
    


def forward_taint_analysis(currFun, trace_list):
    visited = set()
    while len(trace_list) > 0:
        trace_var = trace_list.pop()
        #print(trace_var.src)
        if trace_var in visited:
            return
        if  trace_var.operation == MediumLevelILOperation.MLIL_VAR or \
            trace_var.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            cand = trace_var.function.get_ssa_var_definition(trace_var.src)
            print(trace_var.dest, cand.address)
            #for item in cand.operands:
            #    if type(item) != binaryninja.mediumlevelil.SSAVariable:
            #        print(item, item.src.type)
            # print(trace_var.ssa_form)
            # if  cand.operation == MediumLevelILOperation.MLIL_SET_VAR or \
            #     cand.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA or \
            #     cand.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
            #         var = cand.ssa_form.dest
            #         src_var = cand.src
            #         use_ref = cand.ssa_form.function.get_ssa_var_uses(var)
            #         #print(src_var, use_ref)
            #         for refs in use_ref:
            #             print(refs)
            # #print(trace_var.function)
            
def fun_analysis(input_name, binary_name):
    # ----- Setup file name ------ #
    cwd             = os.path.dirname(__file__)
    parent          = os.path.dirname(cwd)
    test_folder     = os.path.join(parent, "tests/results")
    in_folder       = os.path.join(test_folder, input_name)
    bin_file        = os.path.join(in_folder, input_name)
    in_file         = os.path.join(in_folder, "dft.out")
    out_file        = os.path.join(in_folder, "list.out")
    #print(cwd, parent, test_folder, in_folder)
    #exit()
    #nm_file         = os.path.join(in_folder, input_name+".nm")

    out_file_open   = open(out_file, "w")

    # ----- Start of binary ninja ----- #
    fun_class_set = set()

    tainted_srcs_addr   = set()
    tainted_sinks_addr  = set()
    
    tainted_srcs_funs   = set()
    tainted_sinks_funs  = set()
    tainted_total_funs  = set()
    exclude_funs        = set() # This is list of functions that will be excluded
    
    with open(in_file, "r") as infile:
        for line in infile:
            taint_type_regex = re.search(r'(?<=Taint\s).*(?=\s[a-z,0-9].*\(.*\))', line)
            taint_addr_regex =  re.search(r'(?<=:\s)(.*)', line)
            taint_type = taint_type_regex.group(0)
            addr_int = int(taint_addr_regex.group(0), base=16)
            #print(taint_fun_regex.group(0))
            # print(addr.start, addr.end)
            if taint_type == "source" and addr_int not in tainted_srcs_addr:
                #tainted_sources[addr_int] = taint_fun
                print(taint_type, "addr: ", addr_int)
                tainted_srcs_addr.add(addr_int)
            elif taint_type == "sink" and addr_int not in tainted_sinks_addr:
                #tainted_sinks[addr_int] = taint_fun
                print(taint_type, "addr: ", addr_int)
                tainted_sinks_addr.add(addr_int)
                
    if (binary_name != None):
        with open_view(bin_file) as bv:                
            print("Step: Binary Ninja")
            print("Number of functions: ", len(bv.functions))
            # Initialization of function classes to analyze with dft.out
            for item in tainted_sinks_addr:
                for item_fun in bv.get_functions_containing(item):
                    sink_funs.add(item_fun.name)
            for (fun_index, fun) in enumerate(bv.functions):
                fun_class = fun_dataclass(fun.name, fun.address_ranges, set(), set()) # initializing 
                fun_class_set.add(fun_class)  # Adding dataclass to a set
                find_taint_variables(fun.mlil_basic_blocks, tainted_srcs_addr, bv)
                potential_sinks = set()
                print("Analyzing at function:", fun.name)
                for callee_fun in fun.callees:
                    symbol = bv.symbols[callee_fun.name]
                    #print(callee_fun.name)
                    if len(symbol) <= 1 and callee_fun.name not in sink_funs:
                        potential_sinks.add(callee_fun)
                        for index, param in enumerate(callee_fun.parameter_vars):
                            if param.type is not None and param.type.type_class == TypeClass.PointerTypeClass:
                                print(param.index)
                        #         check_taint_param(callee_fun, param.index)
                                #print(callee_fun.get_mlil_var_refs(param))
                                #call_instr = callee_fun.get_low_level_il_at(callee_fun.start).mlil
                                #print(call_instr)
                for mlil_bb in fun.mlil_basic_blocks:
                    for mlil_inst in mlil_bb:
                        inst_ssa = mlil_inst.ssa_form
                        if inst_ssa.operation == MediumLevelILOperation.MLIL_CALL_SSA or inst_ssa.operation == MediumLevelILOperation.MLIL_CALL:
                            call_addr   = inst_ssa.dest.operands[0]
                            #call_fun    = bv.get_function_at(call_addr)
                            #print("Call found", mlil_inst, mlil_inst.params, mlil_inst.operation)
                            if type(call_addr) == int:
                                call_fun = bv.get_function_at(call_addr)
                                if call_fun != None:
                                    if call_fun in potential_sinks:
                                        param_list = call_fun.parameter_vars
                                        print(inst_ssa.params)
                                        for param in inst_ssa.params:
                                            print(param.operation)
                                            if  param.operation == MediumLevelILOperation.MLIL_VAR or \
                                                param.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                                                cand = param.function.get_ssa_var_definition(param.src)
                                                print(call_fun, cand.src.src, cand.src, hex(cand.address))
                                                if cand.src.src in tainted_vars_local or cand.src.src in tainted_vars_global:
                                                    print("Found taint variable, adding function: ", call_fun.start)
                                                    tainted_sinks_funs.add(call_fun.name)
                                            elif param.operation == MediumLevelILOperation.MLIL_CONST_PTR or \
                                                param.operation == MediumLevelILOperation.MLIL_CONST: 
                                                global_var = bv.get_data_var_at(param.constant)
                                                if global_var != None:
                                                    if global_var.address in tainted_vars_global:
                                                        tainted_sinks_funs.add(call_fun.name)
                            for param in mlil_inst.params:
                                if param.operation == MediumLevelILOperation.MLIL_CONST_PTR or \
                                    param.operation == MediumLevelILOperation.MLIL_CONST: 
                                    global_var = bv.get_data_var_at(param.constant)
                                    if global_var != None:
                                        if global_var.address in tainted_vars_global:
                                            tainted_sinks_funs.add(fun.name)
                # for bb in fun.basic_blocks:
                #     for inst in bb:
                #         print(inst)
                                        # for param_var in param_list:
                                        #     print(param_var)
                                            #for ref in call_fun.get_mlil_var_refs(param_var):
                                            #    print(ref)
                                                        # for mlil_param in mlil_inst.params:
                            #     if mlil_param.operation == MediumLevelILOperation.MLIL_VAR:
                            #         ssa_var = SSAVariable(mlil_param.src, 0) 
                            #         print(fun.mlil.ssa_form.get_ssa_var_definition(ssa_var))
                                    

                        # if  param_var.operation == MediumLevelILOperation.MLIL_VAR_SSA or \
                        #     param_var.operation == MediumLevelILOperation.MLIL_VAR:
                        #         cand = param_var.function.get_ssa_var_definition(param_var.src)
                    # else:
                    #     print(callee_fun)
                # for reg_bb in fun.llil_basic_blocks:
                #     for reg_inst in reg_bb:
                #         print(reg_inst)
                #print(type(fun.mlil_basic_blocks))
                
                                    
                                # src_fun = bv.get_function_at(ssa.dest.operands[0])
                                # print(ssa.dest.operands[0])
                                # param_list = src_fun.parameter_vars
                                # print(param_list)
                                # # call_taint_list = set()
                                # for param_var in ssa.params:
                                #     if  param_var.operation == MediumLevelILOperation.MLIL_VAR or \
                                #         param_var.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                                #             var = param_var.operation
                                #             print(var_src = var.src)
                                #print(call_taint_list)
                        #         print(src_fun)
                        #         trace_list = set()
                        #         for trace_candidate in ssa.params:
                        #             print(trace_candidate.operation)
                        #             trace_list.add(trace_candidate)
                        # #         trace_list = set()
                        # #         for trace_candidate in ssa.params:
                        #         forward_taint_analysis(fun, trace_list)
                        #         # """
                                # param_list = src_fun.parameter_vars
                                # for param_var in param_list:
                                #     print(type(param_var.operation))
                                #                                 for ref in src_fun.get_mlil_var_refs(param_var):
                                #         call_taint_list.add(src_fun.get_low_level_il_at(ref.address).mlil.ssa_form)
                                # """
                                # #print(call_taint_list)
                                # #forward_taint_analysis(call_taint_list)
                
                
    # print(tainted_srcs_addr)

    # ----- Parsing dft.out file to organize everything ----- #
    #tainted_sources = dict()    # if routine name (w/ @plt) is available
    #tainted_sinks = dict()      # if routine name (w/ @plt) is available



    for fun_class in fun_class_set:
        for addr in fun_class.addr_range:
            # print(fun_class.name + ": " + str(addr.start) + " - " + str(addr.end))
            for srcs_addr in tainted_srcs_addr:
                if (srcs_addr > addr.start) and (srcs_addr < addr.end):
                    # print("added: " + str(srcs_addr))
                    tainted_srcs_funs.add(fun_class.name)
            for sinks_addr in tainted_sinks_addr:
                if (sinks_addr > addr.start) and (sinks_addr < addr.end):
                    # print("added: " + str(sinks_addr))
                    tainted_sinks_funs.add(fun_class.name)
        if (fun_class.name not in (tainted_sinks_funs or tainted_srcs_funs)):
            if ("sub_" not in fun_class.name):
                exclude_funs.add(fun_class.name)

    tainted_total_funs = tainted_sinks_funs.union(tainted_srcs_funs)

    #nm_funs         = set()
    #nm_file_open    = open(nm_file, "r")
    #for line in nm_file_open:
    #    nm_regex = re.search(r'(?<=[0-9,a-z]\s[a-z,A-Z]\s)(.*)(?!=)', line)
    #    if(nm_regex):
    #        #print(nm_regex.group(0))
    #        if (str(nm_regex.group(0)) not in exclude_funs):
    #            exclude_funs.add(str(nm_regex.group(0)))

    for item in exclude_funs:
        if str(item) in tainted_total_funs:
            print("Found")
            
    uniq_funs = exclude_funs.difference(tainted_total_funs)
    #uniq_funs = exclude_funs
    #for item in uniq_funs:
    #    if str(item) in tainted_total_funs:
    #        print("Removed") # Need to not show

    sum_iterator = 0
    #total_write = "Summary: ["
    total_write = ""
    for item in tainted_total_funs:
        sum_iterator += 1
        if (sum_iterator == len(tainted_total_funs)):
            #total_write += "\""+item+"\""
            total_write += item
            break
        total_write += item+","
    out_file_open.write(total_write)

    """
    src_write = "Sources: { " 
    for item in tainted_srcs_funs:
        print("Source: ", item)
        src_write += item + " "
    src_write += "}" + "\n\n"
    out_file_open.write(src_write)

    sink_write = "Sinks: { " 
    for item in tainted_sinks_funs:
        print("Sink: ", item)
        sink_write += item + " "
    sink_write += "}" + "\n\n"
    out_file_open.write(sink_write)
    
    exclude_write="Exclude: "
    iterator = 0
    for item in uniq_funs:
        iterator += 1
        if (iterator == len(uniq_funs)):
            exclude_write += item + "\n"
            break
        exclude_write += item + ","
    out_file_open.write(exclude_write)
    """
    
    out_file_open.close()

if __name__ == "__main__":
    main()