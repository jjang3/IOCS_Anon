#!/usr/bin/env python3

import os
import os.path
import argparse
import subprocess
import re

from io import BytesIO
from os import path

parser = argparse.ArgumentParser(description="Running reassembly tool for the example")
# ----- Parser arguments ----- #
parser.add_argument('-p', '--patch', required=True)             # patch
parser.add_argument('-i', '--input', required=True)             # input file
args            = parser.parse_args()

#fun_list=["ngx_http_core_root","ngx_http_write_filter","ngx_http_core_location","ngx_http_keepalive_handler","ngx_exec_new_binary","ngx_http_core_server_name","ngx_http_header_filter","ngx_http_subrequest","ngx_event_pipe","ngx_http_lingering_close_handler","ngx_http_alloc_large_header_buffer","ngx_http_upstream_add","ngx_http_init_request","ngx_http_internal_redirect","ngx_http_core_try_files","ngx_http_upstream_init_round_robin"]

# ----- Setup file name ------ #
home            = os.getcwd()
in_bin_dir      = os.path.join(home, "inputs")
out_bin_dir     = os.path.join(home, "outputs")
patch_dir       = os.path.join(home, "e9bin")

parent          = os.path.abspath(os.path.join(home, os.pardir))
e9patch_dir     = os.path.join(parent, "e9patch") 
e9tool          = os.path.join(e9patch_dir, "e9tool")
e9patch         = os.path.join(home, "e9patch.sh")

taint_dir       = os.path.join(parent, "taint_analysis", "scripts")
tainted_in_dir  = os.path.join(taint_dir, args.input) 
tainted_in_file = os.path.join(tainted_in_dir, args.input+"_list.out")

in_file         = os.path.join(in_bin_dir, args.input+".out")
out_file        = os.path.join(out_bin_dir, args.input+".out")
temp_file       = os.path.join(patch_dir, "a.out")

'''
parse_taint_file = open(tainted_in_file, 'r')
for line in parse_taint_file:
    taint_type_regex = re.search(r'(?<=Summary:\s\[).*(?=\])', line)
    if (taint_type_regex != None):
        functions = (taint_type_regex.group(0))
fun_list = list(functions.split(","))
'''

print("Step: E9Patch")
subprocess.call([e9patch, args.patch])
os.chdir(patch_dir)
args = list()
args.append("-M call and target = &_init")
args.append("-P before entry(offset,asm,\"protect\",&\".text\")@init_mprotect")
args.append("-M call and target = &__cyg_profile_func_enter")
args.append("-P before entry(offset,asm,\"entry\")@init_mprotect")
#for item in fun_list:
    #args.append("-M call and target = &"+item)
    #args.append("-P print")
    #args.append("-M call and target = &_init")
    #args.append("-P before entry(offset,asm,base,&\".text\")@print")
args.append("-M call and target = &__cyg_profile_func_exit")
args.append("-P before entry(offset,asm,\"exit\")@init_mprotect")

subprocess.call([e9tool, *args, in_file])

subprocess.call(["mv", temp_file, out_file])
