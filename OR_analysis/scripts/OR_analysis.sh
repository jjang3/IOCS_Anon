#!/bin/bash

CC=gcc
PS3="Select options: "
input=$1
input_file=$1.c

PIN_ROOT=$HOME/Waterfall/OR_analysis/pin-3.27_build
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
lib_path=${parent_path}/sources/obj-intel64
test_path=${parent_path}/tests
source_path=${test_path}/sources
result_path=${test_path}/results
result_input_path=${result_path}/${input}
options=("Compile" "DWARF Analysis" "PINTool" "All")

compile() {
    echo "Compiling the source file:" ${source_path}/${input_file}
    echo "Result directory:" ${result_input_path}
    if [ ! -d "$result_path" ]; then
      mkdir $result_path
    fi
    if [ ! -d "$result_input_path" ]; then
      mkdir $result_input_path
    fi
    gcc -gdwarf-2 ${source_path}/${input_file} -o ${result_input_path}/${input}
}

dwarf() {
    echo "Running DWARF Analysis"
    if [ ! -d "$result_input_path" ]; then
      echo "Compile first!"
      exit
    fi
    python3 $current_path/dwarf_analysis.py --test ${result_input_path}/${input}
}

pin() {
    echo "Running PINTool"
    if [ ! -d "$result_input_path" ]; then
      echo "Compile first!"
      exit
    fi
    $PIN_ROOT/pin -t $lib_path/dyn_OR.so -o $result_input_path/${input}_OR.out -- ${result_input_path}/${input}
}

all() {
    echo "All options"
    compile
    dwarf
    pin
}

while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            1) echo "Selected $option"; compile; break;;
            2) echo "Selected $option"; dwarf; break;;
            3) echo "Selected $option"; pin; break;;
            4) echo "Selected $option"; all; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
