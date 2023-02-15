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
        taint_type_regex = re.search(r'(?<=Taint\s).*(?=:)', line)
        if taint_type_regex.group(0) == "source":
            print("Source")
            print(line)
        else:
            print("Sink")
            print(line)