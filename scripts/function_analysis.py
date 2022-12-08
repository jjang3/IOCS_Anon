import argparse
import pprint
from binaryninja import *

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

target_functions = set()
tainted_insts_to_fun = dict()
rtn_collections = dict()
with open(in_file, "r") as infile:
    start_addr = ""
    for line in infile:
        rtn_regex = re.search(r'(0x[0-9].*)(?=\s\>).+(0x[0-9].*)(?=\s-).+(?<=\[)(.+?)(?=\])', line)
        if rtn_regex != None:            
            if start_addr != "":
                if len(target_functions) != 0:
                    print(start_addr, target_functions)
                    tainted_insts_to_fun[int(start_addr, base=16)] = target_functions.copy()
            target_functions.clear()
            start_addr = rtn_regex.group(1)
            #print(rtn_regex.group(1), "->", rtn_regex.group(2))
            rtn_collections[rtn_regex.group(2)] = rtn_regex.group(3)
        else:
            if (line.find(':') != -1):
                #print("Taint")
                fun_name = line.split(':')[1]
                addr = line.split('|')[1]
                #if (addr[3] == "7"):   # Initially, ignore libc function which will have an address of 0x7
                #    continue           # Can't ignore anymore because a libc routine function may
                                        # call a outside functions to acess the tagged memory
                fun_name_regex = re.search(r'(.*)(?=\s\|)', fun_name)
                target_functions.add(fun_name_regex.group(0))

pprint.pprint(tainted_insts_to_fun)

# ----- Start of binary ninja ----- #
tainted_funs = set()
bin_debug           = 0
# Before update
pprint.pprint(rtn_collections)
if (args.binary != None):
    bin_folder      = os.path.join(parent, "tests")
    bin_file        = os.path.join(bin_folder, args.binary)

    with open_view(bin_file) as bv:                
        print("Step: Binary Ninja")
        for (fun_index, fun) in enumerate(bv.functions):
            range_list = fun.address_ranges
            if (hex(fun.start)) in rtn_collections:
                rtn_collections[hex(fun.start)] = fun.name
            for item in range_list:
                #tainted_insts_to_fun
                for tainted_item in tainted_insts_to_fun:
                    if (tainted_item > item.start) and (tainted_item < item.end):
                        tainted_funs.add(fun.name)

# After update
#pprint.pprint(rtn_collections)
print("============Tainted functions============")
pprint.pprint(tainted_funs)