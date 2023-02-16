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
parser.add_argument('-b', '--binary', required=False)             # testing application to rewrite
args            = parser.parse_args()

# ----- Setup file name ------ #
cwd             = str(os.getcwd())
parent          = os.path.dirname(cwd)
in_folder       = os.path.join(cwd, args.input)
in_file         = os.path.join(in_folder, "dft.out")
out_file        = os.path.join(in_folder, args.input+"_list.out")

out_file_open   = open(out_file, "w")

# ----- Start of binary ninja ----- #
fun_class_set = set()

if (args.binary != None):
    bin_folder      = os.path.join(parent, "tests")
    bin_file        = os.path.join(bin_folder, args.binary)
    with open_view(bin_file) as bv:                
        print("Step: Binary Ninja")
        print("Number of functions: ", len(bv.functions))
        for (fun_index, fun) in enumerate(bv.functions):
            range_list = fun.address_ranges
            fun_class = fun_dataclass(fun.name, range_list, set(), set())   # Initializing function dataclass
            fun_class_set.add(fun_class)                                    # Adding dataclass to a set

# ----- Parsing dft.out file to organize everything ----- #
tainted_sources = dict()
tainted_sinks = dict()
with open(in_file, "r") as infile:
    for line in infile:
        taint_type_regex = re.search(r'(?<=Taint\s).*(?=:)', line)
        taint_fun_regex =  re.search(r'(?<=:\s)(.*)(?=@plt)', line)
        taint_addr_regex =  re.search(r'(?<=@plt\s)(.*)(?=\s[0-9].*)', line)
        taint_type = taint_type_regex.group(0)
        taint_fun = taint_fun_regex.group(0)
        addr_int = int(taint_addr_regex.group(0), base=16)
        for addr in fun_class.addr_range:
            # print(addr.start, addr.end)
            if taint_type == "source":
                tainted_sources[addr_int] = taint_fun
                #print("Source: ", taint_fun, addr_int)
            else:
                tainted_sinks[addr_int] = taint_fun
                #print("Sink", taint_fun, addr_int)


for fun_class in fun_class_set:
    for addr in fun_class.addr_range:
        for src in tainted_sources:
            if (src > addr.start) and (src < addr.end):
                fun_class.taint_srcs.add(tainted_sources[src])
        for sink in tainted_sinks:
            if (sink > addr.start) and (sink < addr.end):
                fun_class.taint_sinks.add(tainted_sinks[sink])
    if len(fun_class.taint_srcs) != 0 or len(fun_class.taint_sinks) != 0 :
        print(fun_class.name, fun_class.taint_srcs, fun_class.taint_sinks)


"""
    start_addr = ""
        
"""