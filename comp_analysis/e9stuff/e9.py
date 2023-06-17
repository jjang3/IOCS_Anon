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
parser.add_argument('-i', '--input', required=True)             # input file
parser.add_argument('-p', '--patch', required=True)             # patch
args            = parser.parse_args()

#fun_list=["ngx_http_core_root","ngx_http_write_filter","ngx_http_core_location","ngx_http_keepalive_handler","ngx_exec_new_binary","ngx_http_core_server_name","ngx_http_header_filter","ngx_http_subrequest","ngx_event_pipe","ngx_http_lingering_close_handler","ngx_http_alloc_large_header_buffer","ngx_http_upstream_add","ngx_http_init_request","ngx_http_internal_redirect","ngx_http_core_try_files","ngx_http_upstream_init_round_robin"]

input_name = args.input
patch_name = args.patch

def main():
    e9_rewrite(input_name, patch_name)

def e9_rewrite(input_name, patch_name):
    # ----- Setup file name ------ #
    #home            = os.getcwd()
    home            = os.path.dirname(__file__)
    out_bin_dir     = os.path.dirname(input_name)
    patch_dir       = os.path.join(home, "e9bin")

    parent          = os.path.abspath(os.path.join(home, os.pardir))
    e9patch_dir     = os.path.join(parent, "e9patch") 
    e9tool          = os.path.join(e9patch_dir, "e9tool")
    e9patch         = os.path.join(home, "e9patch.sh")

    in_file         = input_name
    out_file        = os.path.join(out_bin_dir, input_name+"_waterfall")

    '''
    parse_taint_file = open(tainted_in_file, 'r')
    for line in parse_taint_file:
        taint_type_regex = re.search(r'(?<=Summary:\s\[).*(?=\])', line)
        if (taint_type_regex != None):
            functions = (taint_type_regex.group(0))
    fun_list = list(functions.split(","))
    '''

    print("Step: E9Patch")
    subprocess.call([e9patch, patch_name])
    os.chdir(patch_dir)
    args = list()
    args.append("-M call and target = &.init.start")
    args.append("-P before entry(offset,asm,\"protect\",&.text.start,(static)&.text.start)@init_mprotect")
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


if __name__ == "__main__":
    main()