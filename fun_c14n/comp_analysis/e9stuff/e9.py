#!/usr/bin/env python3

import os
import os.path
import argparse
import subprocess
import re
import logging

from io import BytesIO
from os import path
from pprint import pprint

class CustomFormatter(logging.Formatter):

    # FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s | %(levelname)s"
    # logging.basicConfig(level=os.environ.get("LOGLEVEL", "DEBUG"), format=FORMAT)
    blue = "\x1b[33;34m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_green = "\x1b[42;1m"
    purp = "\x1b[38;5;13m"
    reset = "\x1b[0m"
    # format = "%(funcName)5s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    format = "[Line:%(lineno)4s -%(funcName)18s()] %(levelname)7s    %(message)s "

    FORMATS = {
        logging.DEBUG: yellow + format + reset,
        logging.INFO: blue + format + reset,
        logging.WARNING: purp + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_green + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Debug options here
debug_level = logging.DEBUG
ch = logging.StreamHandler()
ch.setLevel(debug_level) 
ch.setFormatter(CustomFormatter())

log = logging.getLogger(__name__)
log.setLevel(debug_level)

# create console handler with a higher log level
log_disable = False
log.addHandler(ch)
log.disabled = log_disable

parser = argparse.ArgumentParser(description="Running reassembly tool for the example")
# ----- Parser arguments ----- #
parser.add_argument('-i', '--input', required=True)             # input file
parser.add_argument('-p', '--patch', required=True)             # patch
parser.add_argument('-t', '--taint', required=False)            # taint files
args            = parser.parse_args()

#fun_list=["ngx_http_core_root","ngx_http_write_filter","ngx_http_core_location","ngx_http_keepalive_handler","ngx_exec_new_binary","ngx_http_core_server_name","ngx_http_header_filter","ngx_http_subrequest","ngx_event_pipe","ngx_http_lingering_close_handler","ngx_http_alloc_large_header_buffer","ngx_http_upstream_add","ngx_http_init_request","ngx_http_internal_redirect","ngx_http_core_try_files","ngx_http_upstream_init_round_robin"]

input_name  = args.input
patch_name  = args.patch
taint_name  = args.taint

def main():
    e9_rewrite(input_name, patch_name, taint_name)

def e9_rewrite(input_name, patch_name, taint_name):
    # ----- Setup file name ------ #
    #home            = os.getcwd()
    home            = os.path.dirname(__file__)
    input_dir       = os.path.dirname(input_name)
    taint_file      = None
    if taint_name == None:
        taint_file      = os.path.join(input_dir, "taint.in")
    else:
        taint_file      = os.path.join(input_dir, taint_file)
    patch_dir       = os.path.join(home, "e9bin")
    log.debug("\ninput:\t%s\npatch:\t%s\ntaint:\t%s", input_dir, patch_dir, taint_file)

    parent_dir      = os.path.abspath(os.path.join(home, os.pardir))
    e9patch_dir     = os.path.join(parent_dir, "e9patch") 
    e9tool          = os.path.join(e9patch_dir, "e9tool")
    e9patch         = os.path.join(home, "e9patch.sh")
    log.debug("\nparent:\t%s\n e9pat:\t%s\ne9tool:\t%s", parent_dir, e9patch, e9tool)


    in_file         = input_name
    parse_taint_file = open(taint_file, 'r')
    
    for line in parse_taint_file:
        fun_list = line.split(",")
    pprint(fun_list)

    print("Step: E9Patch", patch_dir)
    # For debugging
    # patch_name = "print"
    subprocess.call([e9patch, patch_name])
    os.chdir(patch_dir)
    args = list()
    
    # for item in fun_list:
    #     args.append("-M call and target = &"+item)
    #     args.append("-P print")

    args.append("-M call and target = &.init.start")
    args.append("-P before entry(offset,F.name,\"protect\",&.text.start,(static)&.text.start)@init_mprotect")
    args.append("-M call and target = &__cyg_profile_func_enter")
    args.append("-P before entry(offset,F.name,\"entry\")@init_mprotect")        
    args.append("-M call and target = &__cyg_profile_func_exit")
    args.append("-P before entry(offset,F.name,\"exit\")@init_mprotect")
    
    subprocess.call([e9tool, *args, in_file])


if __name__ == "__main__":
    main()