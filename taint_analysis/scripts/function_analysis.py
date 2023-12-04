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
parser.add_argument('-d', '--dft', required=True)             # testing application to rewrite
parser.add_argument('-b', '--bin', required=True)             # testing application to rewrite
args                = parser.parse_args()

tainted_vars_local      = set()
tainted_vars_global     = set()
sink_funs               = set()

def main():
    fun_analysis(args.dft, args.bin)

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
            
def fun_analysis(dft_path, bin_path):
    # ----- Setup file name ------ #
    work_dir            = os.path.dirname(dft_path)
    out_file            = os.path.join(work_dir, "taint.in")
    print(dft_path, bin_path, work_dir)
    
    out_file_open       = open(out_file, "w")

    # # ----- Start of binary ninja ----- #
    fun_class_set = set()

    tainted_srcs_addr   = set()
    tainted_sinks_addr  = set()
    
    tainted_srcs_funs   = set()
    tainted_sinks_funs  = set()
    tainted_total_funs  = set()
    exclude_funs        = set() # This is list of functions that will be excluded
    
    with open(dft_path, "r") as dft_file:
        for line in dft_file:
            taint_type_regex = re.search(r'(?<=Taint\s).*(?=\s[a-z,0-9].*\(.*\))', line)
            taint_addr_regex =  re.search(r'(?<=:\s)(.*)', line)
            taint_type = taint_type_regex.group(0)
            addr_int = int(taint_addr_regex.group(0), base=16)
            # print(addr.start, addr.end)
            if taint_type == "source" and addr_int not in tainted_srcs_addr:
                #tainted_sources[addr_int] = taint_fun
                print(taint_type, "addr: ", addr_int)
                tainted_srcs_addr.add(addr_int)
            elif taint_type == "sink" and addr_int not in tainted_sinks_addr:
                #tainted_sinks[addr_int] = taint_fun
                print(taint_type, "addr: ", addr_int)
                tainted_sinks_addr.add(addr_int)
                    
    print("Step: Binary Ninja")
    with open_view(bin_path) as bv:        
        print("Number of functions: ", len(bv.functions))
        # Initialization of function classes to analyze with dft.out
        for item in tainted_sinks_addr:
            for item_fun in bv.get_functions_containing(item):
                sink_funs.add(item_fun.name)
        for (fun_index, fun) in enumerate(bv.functions):
            fun_class = fun_dataclass(fun.name, fun.address_ranges, set(), set()) # initializing 
            fun_class_set.add(fun_class)  # Adding dataclass to a set

    for fun_class in fun_class_set:
        for addr in fun_class.addr_range:
            # print(fun_class.name + ": " + str(addr.start) + " - " + str(addr.end))
            for srcs_addr in tainted_srcs_addr:
                if (srcs_addr > addr.start) and (srcs_addr < addr.end):
                    print("added: " + str(srcs_addr))
                    tainted_srcs_funs.add(fun_class.name)
            for sinks_addr in tainted_sinks_addr:
                if (sinks_addr > addr.start) and (sinks_addr < addr.end):
                    print("added: " + str(sinks_addr))
                    tainted_sinks_funs.add(fun_class.name)
        if (fun_class.name not in (tainted_sinks_funs or tainted_srcs_funs)):
            if ("sub_" not in fun_class.name):
                print("Excluded: ", fun_class.name)
                exclude_funs.add(fun_class.name)

    print(tainted_srcs_funs, tainted_sinks_funs)
    tainted_total_funs = tainted_sinks_funs.union(tainted_srcs_funs)
    

    for item in exclude_funs:
        if str(item) in tainted_total_funs:
            print("Found")
            
    uniq_funs = exclude_funs.difference(tainted_total_funs)

    sum_iterator = 0
    total_write = ""
    for item in tainted_total_funs:
        sum_iterator += 1
        if (sum_iterator == len(tainted_total_funs)):
            total_write += item
            break
        total_write += item+","
    out_file_open.write(total_write)
    out_file_open.close()

if __name__ == "__main__":
    main()