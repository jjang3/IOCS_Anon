# This script is used for ARCS
#!/bin/bash

PS3="Select options: "
input=$1

options=("Build" "Analyze" "Rewrite")

# This is used to setup test path
grandp_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

static_path=${current_path}/static_analysis

arcs_build_path=${static_path}/build
arcs_lib_path=${arcs_build_path}/lib

arcs_input_path=${current_path}/input

arcs_result_path=${current_path}/result
arcs_i_result_path=${arcs_result_path}/$1
arcs_ll_file=${arcs_i_result_path}/$1.ll
arcs_bc_file=${arcs_i_result_path}/$1.bc
arcs_out_file=${arcs_i_result_path}/${1}_arcs.out
arcs_analysis_file=${arcs_i_result_path}/analysis.txt

rewrite_path=${current_path}/asm_rewriter

LLVM_BUILD_DIR=$LLVM_DIR

build()
{
    echo "Build" 
    if [ ! -d "$arcs_build_path" ]; then
        echo "Build directory doesn't exist"
        mkdir $arcs_build_path
    fi
    cd $arcs_build_path
    cmake ..
    make
    # make -j ${nproc}
    # make
}

analyze()
{
    echo "Analyze using the ARCS pass"
    if [ ! -d "$arcs_result_path" ]; then
        echo "Result directory doesn't exist"
        mkdir $arcs_result_path
    fi
    if [ ! -d "$arcs_i_result_path" ]; then
        echo "Input result directory doesn't exist"
        mkdir $arcs_i_result_path
    fi
    if [ ! -f "$arcs_ll_file" ]; then
        echo "LLVM IR (.ll) file doesn't exist"
        $LLVM_BUILD_DIR/bin/clang -emit-llvm -S -o ${arcs_ll_file} ${arcs_input_path}/${input}.c
    fi
    if [ ! -f "$arcs_bc_file" ]; then
        echo "LLVM IR (.bc) file doesn't exist"
        $LLVM_BUILD_DIR/bin/clang -emit-llvm -c -o ${arcs_bc_file} ${arcs_input_path}/${input}.c
    fi
    if [ ! -f "${arcs_i_result_path}/taint.in" ]; then
        printf "main" >> ${arcs_i_result_path}/taint.in
    fi
    $LLVM_BUILD_DIR/bin/opt -load $arcs_lib_path/libarcs.so -load-pass-plugin $arcs_lib_path/libarcs.so -passes=arcs -S ${arcs_bc_file} -taint ${arcs_i_result_path}/taint.in  -o ${arcs_out_file}
    #  &> ${arcs_analysis_file}
}

rewrite()
{
    echo "Assembly rewriting the application" 
    cd ${arcs_input_path} && make ${input}.out
    # echo ${current_path}
    cd ${rewrite_path} && python3 binary_patch.py --binary ${input}.out --fun taint.in
    cd ${arcs_i_result_path} && make lib && make ${input}.new
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
