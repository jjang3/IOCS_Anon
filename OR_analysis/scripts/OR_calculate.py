import re
import os
import sys, getopt
from collections import defaultdict
import itertools
from pprint import pprint

compartment_set = set()
fun_privileges  = defaultdict(list)
privilege       = set()
fun_to_size     = dict()
comp_ratio_set  = set()

def calculate_overprivilege(tuple_input):
    #print("Calculate overprivilege")
    overprivilege = 0
    for item in tuple_input:
        for priv in fun_privileges[item]:
            priv_regex = re.search(r'(Call|Return|Read|Write)(\s)([^\n]+)', priv)
            filtered_set = list(set(tuple_input) - set([item]))
            if (priv_regex.group(1) == "Call" or priv_regex.group(1) == "Return"):
                #print("\t"+priv_regex.group(1), priv_regex.group(3))
                if priv_regex.group(3) not in filtered_set:
                    #print("Found")
                    overprivilege += 1
            elif (priv_regex.group(1) == "Read" or priv_regex.group(1) == "Write"):
                var_regex = re.search(r'(global)(_)([^\n]+)', priv)
                if var_regex:
                    #print("Global write found", priv)
                    for fun in filtered_set:
                        if priv not in fun_privileges[fun]:
                            overprivilege += 1
    print("\tIncrease in privilege: ", overprivilege)
    return overprivilege

def cost_fun(tuple_input):
    print("Cost fun")
    num_of_exposed = 0
    for item in tuple_input:
        print("Function: ", item)
        pprint( fun_privileges[item])
        for priv in fun_privileges[item]:
            priv_regex = re.search(r'(Call|Return|Read|Write)(\s)([^\n]+)', priv)
            filtered_set = list(set(tuple_input) - set([item]))
            if (priv_regex.group(1) == "Call" or priv_regex.group(1) == "Return"):
                #print("\t"+priv_regex.group(1), priv_regex.group(3))
                if priv_regex.group(3) not in filtered_set:
                    #print("Found")
                    num_of_exposed += 1
            elif (priv_regex.group(1) == "Read" or priv_regex.group(1) == "Write"):
                var_regex = re.search(r'(global)(_)([^\n]+)', priv)
                if var_regex:
                    #print("Global write found", priv)
                    for fun in filtered_set:
                        if priv not in fun_privileges[fun]:
                            num_of_exposed += 1
    return num_of_exposed

def utility_fun(tuple_input):
    num_of_calls = 0
    print("Utility fun")
    pprint(tuple_input)
    for item in tuple_input:
        # pprint(item, width=1)
        # print("Function: ", item)
        # print("Privileges:")
        # pprint(fun_privileges[item])
        for priv in fun_privileges[item]:
            priv_regex = re.search(r'(Call|Return)(\s)([^\n]+)', priv)
            if priv_regex:
                filtered_set = list(set(tuple_input) - set([item]))
                if priv_regex.group(3) in filtered_set:
                    # print("Found")
                    num_of_calls += 1
    return num_of_calls

def calculate_ratio(tuple_input):    
    print("\n----- Calculate ratio -----")
    # Need to define utility function
        # ---- number of cross-compartment calls / returns found between two compartments
    cross_comp_calls = utility_fun(tuple_input[1])
    print("Utility function:", cross_comp_calls)
    # Need to define cost function 
        # ---- increase in privilege in terms of potentially sharing read/write to global variable or 
        # ---- returning / calling to another function outside of its compartment
    print("")
    privilege_increase = cost_fun(tuple_input[1])
    print("Cost function: ", privilege_increase)
    
    if privilege_increase != 0:
        comp_ratio = cross_comp_calls / privilege_increase
        print("Comp ratio: ", comp_ratio)
        if comp_ratio != 0:
            comp_ratio_set.add((comp_ratio, tuple_input))

def calculate_size(tuple_input):
    #print("Calculating size")
    total_size = 0
    for item in tuple_input:
        total_size += int(fun_to_size[item])
    return total_size
        

def process_argument(argv):
    funfile = ''
    localORfile = ''
    customfile = ''
    try:
        opts, args = getopt.getopt(argv,"hfic:",["fun=","input=","custom="])
    except getopt.GetoptError:
        print ('OR_calculate.py --fun <fun.out> --input <*_local_OR.out> --custom <custom.out>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('OR_calculate.py --fun <fun.out> --input <*_local_OR.out> --custom <custom.out>')
            sys.exit()
        elif opt in ("-f", "--fun"):
            funfile = arg
        elif opt in ("-i", "--input"):
            localORfile = arg
        elif opt in ("-c", "--custom"):
            customfile = arg
    process_file(funfile, localORfile, customfile)

def process_file(funfile, localORfile, customfile):
    print(funfile)    
    print(localORfile)
    print(customfile)
    #fun_regex = re.search(r'(.*[a-z,A-Z,0-9])(?=:)')
    least_priv = 0
    with open(localORfile) as l:
        fun_name = ""
        for index, line in enumerate(l):
            fun_regex = re.search(r'(.*[a-z,A-Z,0-9])(?=:)', line)
            priv_regex = re.search(r'(Call|Read|Return|Write)(\s)([^\n]+)', line)
            if fun_regex:
                print("Function: ", fun_regex.group(0))
                fun_name = fun_regex.group(0)
            if priv_regex:
                if (priv_regex.group(1) == "Call" or priv_regex.group(1) == "Return"):
                    #print("\t"+priv_regex.group(1), priv_regex.group(3))
                    fun_privileges[fun_name].append(priv_regex.group(1)+" "+priv_regex.group(3))
                    least_priv += 1
                elif (priv_regex.group(1) == "Read" or priv_regex.group(1) == "Write"):
                    var_regex = re.search(r'(global|local|localH)(_)([^\n]+)', line)
                    #print("\t",line)    
                    if (var_regex.group(1) == "global" or var_regex.group(1) == "local" 
                        or var_regex.group(1) == "localH"): # We don't consider local yet for the algorithm
                    #if (var_regex.group(1) == "global"):
                        #print("\t"+priv_regex.group(1), var_regex.group(1)+"_"+var_regex.group(3))
                        fun_privileges[fun_name].append(priv_regex.group(1)+" "+var_regex.group(1)+"_"+var_regex.group(3))
                        least_priv += 1
    
    compart_max_size = 0
    with open(funfile) as f:
        for index, line in enumerate(f):
            fun_regex = re.search(r'(.*[a-z,A-Z,0-9])(?=:)', line)
            size_regex = re.search(r'(?<=:\s)([0-9].*)', line)
            if (fun_regex and size_regex):
                #print(fun_regex.group(0), size_regex.group(0))
                if (fun_regex.group(0) in fun_privileges):
                    fun_to_size[fun_regex.group(0)] = size_regex.group(0)
                    compart_max_size += int(size_regex.group(0))
    
    print("Max compart size: ", compart_max_size)            
    
    for item in fun_privileges:
        for L in range(len(fun_privileges) + 1):
            for subset in itertools.combinations(fun_privileges, L):
                #pprint(subset)
                size = calculate_size(subset)
                #print(size)
                if (size != 0 and len(subset) > 1):
                    compartment_set.add((size,subset))
    
    index = 0
    for compartment in sorted(compartment_set):
        #print(compartment)
        calculate_ratio(compartment)
        # if index == 20:
        #    break
        # index += 1
    print("\n")
    
    print("Least privilege (Minimal number of privileges required to run the program): ", least_priv, "\n")
    
    custom_tuple = tuple()
    if customfile != "":
        with open(customfile) as c:
            for line in c:
                split_line = line.split(", ")
                custom_tuple = tuple(split_line)
        
    for (index, item) in enumerate(sorted(comp_ratio_set, reverse=True)):
        if index > 5:
            break
        if len(custom_tuple) < 1 or custom_tuple == item[1][1]:
            print("==========================================")
            print("Compartment Ratio (Higher the better): ", "{:.2f}".format(item[0]))
            print("Compartment Info: ")
            print("\tSize: ", hex(item[1][0])+" bytes" + " (" +  str(item[1][0]) + ")")
            print("\tFunctions: ", item[1][1])
            privileges_allowed = calculate_overprivilege((item[1][1]))
            for fun in item[1][1]:
                privileges_allowed += len(fun_privileges[fun])
            OR_ratio = privileges_allowed / least_priv
            print("OR Ratio (Lower the better): ", OR_ratio)
            print("==========================================")
            print("")
        
if __name__ == '__main__':
    process_argument(sys.argv[1:])