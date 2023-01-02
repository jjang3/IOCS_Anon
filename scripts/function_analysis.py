import argparse
import pprint
from binaryninja import *
from dataclasses import dataclass

# Data class
@dataclass
class FunItems:
    name: str
    vulnFuns: set


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

target_functions = set()
tainted_insts_to_fun = dict()
vuln_collections = dict()
rtn_collections = dict() # routine
origin_addrs = set()

vuln_funs_in_tainted_funs = dict()
vuln_functions = set()
with open(in_file, "r") as infile:
    start_addr = ""
    for line in infile:
        rtn_regex = re.search(r'(0x[0-9].*)(?=\s\>).+(0x[0-9].*)(?=\s-).+(?<=\[)(.+?)(?=\])', line)
        if rtn_regex != None:            
            if start_addr != "":
                if len(target_functions) != 0:
                    #print(start_addr, target_functions)
                    tainted_insts_to_fun[int(start_addr, base=16)] = target_functions.copy()
            target_functions.clear()
            start_addr = rtn_regex.group(1)
            #print(rtn_regex.group(1), "->", rtn_regex.group(3))
            #print(rtn_regex.group(1), "->", rtn_regex.group(2))
            vuln_collections[rtn_regex.group(1)] = rtn_regex.group(2)
            #vuln_funs_in_tainted_funs[start_addr] = vuln_functions.add(int(rtn_regex.group(2), base=16))
            rtn_collections[rtn_regex.group(2)] = rtn_regex.group(3)
        else:
            if (line.find(':') != -1):
                #print("Taint")
                #print(line)
                fun_name = line.split(':')[1]
                addr = line.split('|')[1]
                origin = ""
                if '>' in line:
                    origin = line.split('>')[1]
                if (origin != ""):
                    origin_addr = re.search(r'(0x[0-9].*)', str(origin))
                    print(int(origin_addr.group(0), 16))
                #if (addr[3] == "7"):   # Initially, ignore libc function which will have an address of 0x7
                #    continue           # Can't ignore anymore because a libc routine function may
                                        # call a outside functions to acess the tagged memory
                fun_name_regex = re.search(r'(.*)(?=\s\|)', fun_name)
                target_functions.add(fun_name_regex.group(0))

pprint.pprint(tainted_insts_to_fun)

# ----- Start of binary ninja ----- #
tainted_funs = set()
vuln_funs = set()
funDataList = list()

bin_debug           = 0
# Before update
pprint.pprint(rtn_collections)


if (args.binary != None):
    bin_folder      = os.path.join(parent, "tests")
    bin_file        = os.path.join(bin_folder, args.binary)
    with open_view(bin_file) as bv:                
        print("Step: Binary Ninja")
        print("Number of functions: ", len(bv.functions))
        for (fun_index, fun) in enumerate(bv.functions):
            funClass = FunItems(fun.name, set())
            range_list = fun.address_ranges
            if (hex(fun.start)) in rtn_collections:
                rtn_collections[hex(fun.start)] = fun.name
            for item in range_list:
                #tainted_insts_to_fun
                for tainted_item in tainted_insts_to_fun:
                    if (tainted_item > item.start) and (tainted_item < item.end):
                        #print("Tainted item: ", hex(tainted_item))
                        #print(vuln_collections[hex(tainted_item)])
                        vuln_funs.add(vuln_collections[hex(tainted_item)])
                        funClass.vulnFuns.add(rtn_collections[vuln_collections[hex(tainted_item)]])
                        #print("Fun name: ", rtn_collections[vuln_collections[hex(tainted_item)]])
                        tainted_funs.add(fun.name)
            #print(funClass.name, funClass.vulnFuns)
            funDataList.append(funClass)

#for item in funDataList:
#    print(item.name, item.vulnFuns)

# After update
pprint.pprint(rtn_collections)
print("============Tainted functions============")
pprint.pprint(tainted_funs)
count = 0
funCount = 0
for item in tainted_funs:
    count += 1
    out_file_open.write(item)
    out_file_open.write(": ")
    for fun in funDataList:
        if fun.name == item:
            print(fun.vulnFuns)
            for funs in fun.vulnFuns:
                out_file_open.write(funs)
                if funCount != len(fun.vulnFuns):
                    out_file_open.write(" ")
    if count != len(tainted_funs):
        out_file_open.write("\n")

out_file_open.close()