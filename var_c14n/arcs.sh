# This script is used for ARCS
#!/bin/bash


PS3="Select options: "
input=$1

CFLAGS="-O0 -gdwarf-2"

options=("Build" "Taint" "Analyze" "Rewrite")

# This is used to setup test path
grandp_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

# Need to streamline this somehow
suture_path=/home/jaewon/Downloads/suture

PIN_ROOT=$parent_path/pin-3.27_build

taint_path=$parent_path/taint_analysis

useful_path=$parent_path/useful_scripts

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
arcs_config_file=${arcs_i_result_path}/$1.config
arcs_dwarf_file=${arcs_i_result_path}/dwarf.out
arcs_analysis_file=${arcs_i_result_path}/$1.analysis
arcs_vuln_file=${arcs_i_result_path}/vuln.txt

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

    cd ${taint_path}/sources && bash compile.sh
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
        # $LLVM_BUILD_DIR/bin/clang
        gcc ${CFLAGS} -o ${arcs_bin_file} ${arcs_input_path}/${input}.c
        rm ${arcs_input_path}/${input}.s.bak
    fi

    sleep 1
    # python3 $useful_path/dwarf_analysis.py --binary ${arcs_bin_file} ${arcs_dwarf_file}
    # file ${arcs_dwarf_file}
    $PIN_ROOT/pin -follow-execv -t $taint_path/lib/libdft-mod.so -- ${arcs_bin_file} 
    #$PIN_ROOT/pin -follow-execv -t $taint_path/lib/libdft-mod.so -- ${arcs_bin_file} -c ~/Downloads/nginx-1.3.9/conf/nginx_taint.conf
    #mv dft.out ${arcs_i_result_path} 
    mv dft.out ${arcs_analysis_file}
    # --custom_arg ${arcs_dwarf_file}

}

analyze()
{
    echo "Find vulnerable data"

    python3 $useful_path/STA/main.py --binary ${arcs_bin_file}
    cat $arcs_config_file
    ${suture_path}/suture_build/llvm/build/bin/clang -emit-llvm -g -c -o ${arcs_bc_file} ${arcs_input_path}/${input}.c
    cp ${arcs_bc_file} $arcs_config_file $suture_path/benchmark
    cd $suture_path
    pwd
    source env.sh
    local bc_name=$(basename ${arcs_bc_file})
    local config_name=$(basename ${bc_name} .bc)
    local current_date=$(date "+%Y-%m-%d")
    local config_folder="warns-$config_name.config-$current_date"
    if [ -d "./benchmark/$config_folder" ]; then
        echo "Delete the existing folder"
        rm -rf "./benchmark/$config_folder"
    fi
    # echo $config_name.config
    ./run_nohup.sh ./benchmark/$bc_name ./benchmark/$config_name.config
    sleep 10
    ./ext_warns.sh ./benchmark/$config_name.config.log

    # Use grep to extract matching lines and awk to parse and format the output correctly
    local input_file="./benchmark/$config_folder/all"
    if [ -f "$arcs_vuln_file" ]; then
        echo "Delete the existing vuln file"
        rm "$arcs_vuln_file"
    fi
    grep -oP "([^ ]+) says: ([^@]+)@([0-9]+) \(([^:]+) :(.+)" "$input_file" |
    awk -F' : ' '{
        # Use regex matching to extract vuln_type, file, line_num, fun_name, and the instruction
        match($0, /([^ ]+) says: ([^@]+)@([0-9]+) \(([^:]+) :(.+)/, matches);
        vuln_type = matches[1];
        file = matches[2];
        line_num = matches[3];
        fun_name = matches[4];
        instruction = matches[5];
        
        # Remove the trailing parenthesis from the instruction
        gsub(/\)$/, "", instruction);
        
        # Print the captured information including the instruction without the trailing parenthesis
        print "file: " file " - line_num: " line_num " - fun_name: " fun_name "\n\t\t\t- vuln_type: " vuln_type "\n\t\t\t- instruction: " instruction "\n";
    }' > $arcs_vuln_file

}

rewrite()
{
    echo "Assembly rewriting the application" 
    cd ${arcs_input_path} && make ${input}.out
    # echo ${current_path}
    # cd ${rewrite_path} && python3 binary_patch.py --binary ${input}.out 
    cd ${rewrite_path} && python3 main.py --binary ${input}.out 
    #--fun fun.list
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
