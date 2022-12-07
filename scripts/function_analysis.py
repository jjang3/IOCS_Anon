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
rtn_collections = dict()
with open(in_file, "r") as infile:
    for line in infile:
        if (line.find(':') != -1):
            fun_name = line.split(':')[1]
            addr = line.split('|')[1]
            if (addr[3] == "7"): # Ignore libc function which will have an address of 0x7
                continue
            fun_name_regex = re.search(r'(.*)(?=\s\|)', fun_name)
            print(fun_name_regex)
            target_functions.add(fun_name_regex.group(0))
        else:
            rtn_regex = re.search(r'([0-9].*)(?=\s-).+(?<=\[)(.+?)(?=\])', line)
            if rtn_regex:
                rtn_collections[rtn_regex.group(1)] = rtn_regex.group(2)

# ----- Start of binary ninja ----- #
bin_debug           = 0
# Before update
# print(rtn_collections)
if (args.binary != None):
    bin_folder      = os.path.join(parent, "tests")
    bin_file        = os.path.join(bin_folder, args.binary)

    with open_view(bin_file) as bv:                
        print("Step: Binary Ninja")
        for (fun_index, fun) in enumerate(bv.functions):
            #print(fun.name, hex(fun.start))
            if (hex(fun.start)) in rtn_collections:
                rtn_collections[hex(fun.start)] = fun.name

# After update
pprint.pprint(rtn_collections)