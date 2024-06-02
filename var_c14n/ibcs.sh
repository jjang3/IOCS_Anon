# This script is used for ARCS
#!/bin/bash


PS3="Select options: "
input=$1

CFLAGS="-O0 -gdwarf-2"

options=("Build" "Analyze" "Rewrite")

# This is used to setup test path
grandp_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

useful_path=$parent_path/useful_scripts

ibcs_input_path=${current_path}/input

ibcs_result_path=${current_path}/result
ibcs_i_result_path=${ibcs_result_path}/$1

rewrite_path=${current_path}/asm_rewriter

build()
{
    echo "Build" 

    if [ ! -d "$arcs_result_path" ]; then
        echo "Result directory doesn't exist"
        mkdir $ibcs_result_path
    fi

    if [ ! -d "$arcs_i_result_path" ]; then
        echo "Input result directory doesn't exist"
        mkdir $ibcs_i_result_path
    fi

    cd ${ibcs_input_path} && make ${input}.out
    cp table.c ${ibcs_i_result_path}
}

analyze()
{
    echo "Analyze"
    cd ${rewrite_path} && cd src
    #pwd
    python3 dwarf_analysis.py --binary ${ibcs_i_result_path}/${input}.out
}

rewrite()
{
    echo "Assembly rewriting the application" 
    cd ${rewrite_path} && python3 main.py --binary ${input}.out 
    cd ${ibcs_i_result_path} && make lib && make ${input}.new
}

while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            1) echo "Selected $option"; build; break;;
            2) echo "Selected $option"; analyze; break;;
            3) echo "Selected $option"; rewrite; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
