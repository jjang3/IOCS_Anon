import collections
import importlib
import os
import os.path
import argparse
import subprocess
import re
import fileinput
import functools
import operator 
import codecs
import time
import shutil

from pprint import pprint
from pathlib import Path
from ropper import RopperService
from math import ceil, e, log
from operator import itemgetter 
from bitarray import bitarray
from textwrap import wrap
from io import BytesIO
from os import path
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

with open(in_file, "r") as infile:
    for line in infile:
        print(line)
        """
        fun_name = line.split(':')[1]
        #print(fun_name)
        addr = line.split('|')[1]
        if (addr[3] == "7"): # Ignore libc function which will have an address of 0x7
            continue
        fun_name_regex = re.search(r'(.*)(?=\s\|)', fun_name)        
        target_functions.add(fun_name_regex.group(0))
        """

#print(len(target_functions))
#for item in target_functions:
#    print(item)


# ----- Start of binary ninja ----- #
bin_debug           = 0

if (args.binary != None):
    bin_folder      = os.path.join(parent, "tests")
    bin_file        = os.path.join(bin_folder, args.binary)

    with open_view(bin_file) as bv:                
        print("Step: Binary Ninja")
        for (fun_index, fun) in enumerate(bv.functions):
            print(fun.name, hex(fun.start))
            # ----- Indirect call analysis ----- #
            """
            for block in fun.medium_level_il:
                for inst in block:
                    #print(inst)
                    None
            """