import re
import os
import sys, getopt

def process_argument(argv):
    funfile = ''
    localORfile = ''
    try:
        opts, args = getopt.getopt(argv,"hfi:",["fun=","input="])
    except getopt.GetoptError:
        print ('OR_calculate.py --fun <fun.out> --input <*_local_OR.out>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('OR_calculate.py --fun <fun.out> --input <*_local_OR.out>')
            sys.exit()
        elif opt in ("-f", "--fun"):
            funfile = arg
        elif opt in ("-i", "--input"):
            localORfile = arg
    process_file(funfile, localORfile)

fun_to_size = dict()

def process_file(funfile, localORfile):
    print(funfile)    
    print(localORfile)
    #fun_regex = re.search(r'(.*[a-z,A-Z,0-9])(?=:)')
    compart_max_size = 0
    with open(funfile) as f:
        for index, line in enumerate(f):
            fun_regex = re.search(r'(.*[a-z,A-Z,0-9])(?=:)', line)
            size_regex = re.search(r'(?<=:\s)([0-9].*)', line)
            if (fun_regex and size_regex):
                #print(fun_regex.group(0), size_regex.group(0))
                fun_to_size[fun_regex.group(0)] = size_regex.group(0)
                compart_max_size += int(size_regex.group(0))
    
    print("Max compart size: ", compart_max_size)
    
    with open(localORfile) as l:
        for index, line in enumerate(l):
            fun_regex = re.search(r'(.*[a-z,A-Z,0-9])(?=:)', line)
            print("Line {}: {}".format(index, line.strip()))
    
    
if __name__ == '__main__':
    process_argument(sys.argv[1:])