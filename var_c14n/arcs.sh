# This script is used for ARCS
#!/bin/bash

PS3="Select options: "
input=$1

options=("Build" "Taint" "Analyze" "Rewrite")

# This is used to setup test path
grandp_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

PIN_ROOT=$parent_path/pin-3.27_build

taint_path=$parent_path/taint_analysis

static_path=${current_path}/static_analysis

arcs_build_path=${static_path}/build
arcs_lib_path=${arcs_build_path}/lib

arcs_input_path=${current_path}/input

arcs_result_path=${current_path}/result
arcs_i_result_path=${arcs_result_path}/$1
arcs_ll_file=${arcs_i_result_path}/$1.ll
arcs_bc_file=${arcs_i_result_path}/$1.bc
arcs_bin_file=${arcs_i_result_path}/$1.out
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
}

taint()
{
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
    if [ ! -f "$arcs_bin_file" ]; then
        echo "Input binary file doesn't exist"
        $LLVM_BUILD_DIR/bin/clang -o ${arcs_bin_file} ${arcs_input_path}/${input}.c
    fi
    $PIN_ROOT/pin -follow-execv -t $taint_path/lib/libdft-mod.so -- ${arcs_bin_file}
    mv dft.out ${arcs_i_result_path}
    echo "$taint_path/scripts/function_analysis.py"
    python3 $taint_path/scripts/function_analysis.py --dft ${arcs_i_result_path}/dft.out --bin ${arcs_bin_file}
}

analyze()
{
    echo "Analyze using the ARCS pass"
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
            2) echo "Selected $option"; taint; break;;
            3) echo "Selected $option"; analyze; break;;
            4) echo "Selected $option"; rewrite; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
