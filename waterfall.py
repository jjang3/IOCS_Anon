#!/usr/bin/env python3

from simple_term_menu import TerminalMenu
import re
import subprocess
import sys, os.path
# ----- Setup file name ------ #
home                = os.getcwd()
taint_dir           = os.path.join(home, "taint_analysis")
taint_script_dir    = os.path.join(taint_dir, "scripts")
taint_analysis      = os.path.join(taint_script_dir, "taint_analysis.sh")
sys.path.append(taint_script_dir)

e9_dir              = os.path.join(home, "e9stuff")
sys.path.append(e9_dir)

import function_analysis
import e9

def taint():
    print("Taint analysis")
    taint_file = input("Input file: ")
    subprocess.call([taint_analysis, taint_file])

def fun():
    print("Function analysis")
    input_name = input("Input name: ")
    bin_name = input("Binary name: ")
    function_analysis.fun_analysis(input_name, bin_name)

def e9patch():
    print("E9Patching")
    input_name = input("Input name: ")
    patch_name = input("Patch name (e.g., init_mprotect): ")
    e9.e9_rewrite(input_name, patch_name)

options = ["taint analysis", "fun analysis", "e9patch"]
def main():
    terminal_menu = TerminalMenu(options)
    menu_entry_index = terminal_menu.show()
    print(f"You have selected {options[menu_entry_index]}!")
    match options[menu_entry_index]:
        case "taint analysis":
            taint()
        case "fun analysis":
            fun()
        case "e9patch":
            e9patch()

if __name__ == "__main__":
    main()