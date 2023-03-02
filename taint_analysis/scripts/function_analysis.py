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
            #print(range_list)

# ----- Parsing dft.out file to organize everything ----- #
#tainted_sources = dict()    # if routine name (w/ @plt) is available
#tainted_sinks = dict()      # if routine name (w/ @plt) is available

tainted_srcs_addr   = set()
tainted_sinks_addr  = set()
with open(in_file, "r") as infile:
    for line in infile:
        taint_type_regex = re.search(r'(?<=Taint\s).*(?=\s[a-z,0-9].*\(.*\))', line)
        #taint_fun_regex =  re.search(r'(?:(?<=source\s)|(?<=sink\s))(.*)(?=:)', line)
        taint_addr_regex =  re.search(r'(?<=:\s)(.*)', line)
        taint_type = taint_type_regex.group(0)
        addr_int = int(taint_addr_regex.group(0), base=16)
        #print(taint_fun_regex.group(0))
        for addr in fun_class.addr_range:
            # print(addr.start, addr.end)
            if taint_type == "source":
                #tainted_sources[addr_int] = taint_fun
                #print(taint_type, "addr: ", addr_int)
                tainted_srcs_addr.add(addr_int)
            else:
                #tainted_sinks[addr_int] = taint_fun
                #print(taint_type, "addr: ", addr_int)
                tainted_sinks_addr.add(addr_int)

tainted_srcs_funs   = set()
tainted_sinks_funs  = set()
tainted_total_funs  = set()
exclude_funs        = set() # This is list of functions that will be excluded

for fun_class in fun_class_set:
    #print(fun_class.name)
    for addr in fun_class.addr_range:
         for srcs_addr in tainted_srcs_addr:
            if (srcs_addr > addr.start) and (srcs_addr < addr.end):
                tainted_srcs_funs.add(fun_class.name)
         for sinks_addr in tainted_sinks_addr:
            #print(sinks_addr)
            if (sinks_addr > addr.start) and (sinks_addr < addr.end):
                tainted_sinks_funs.add(fun_class.name)
    if (fun_class.name not in (tainted_sinks_funs or tainted_srcs_funs)):
        if ("sub_" not in fun_class.name):
            exclude_funs.add(fun_class.name)

tainted_total_funs = tainted_sinks_funs.union(tainted_srcs_funs)

#print(tainted_total_funs)

src_write = "\tSources: { " 
for item in tainted_srcs_funs:
    print("Source: ", item)
    src_write += item + " "
src_write += "}" + "\n"
out_file_open.write(src_write)

sink_write = "\tSinks: { " 
for item in tainted_sinks_funs:
    print("Sink: ", item)
    sink_write += item + " "
sink_write += "}" + "\n"
out_file_open.write(sink_write)

total_write = "\tSummary: "
for item in tainted_total_funs:
    total_write += item + " "
total_write += "\n"
out_file_open.write(total_write)

exclude_write="\tExclude: "
iterator = 0
for item in exclude_funs:
    iterator += 1
    if (iterator == len(exclude_funs)):
        exclude_write += item + "\n"
        break
    exclude_write += item + ","
out_file_open.write(exclude_write)

out_file_open.close()

