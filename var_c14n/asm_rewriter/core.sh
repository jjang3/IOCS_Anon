# This script is used for coreutils rewriting purpose (e.g., could be expanded for other applications?)
#!/bin/bash

PS3="Select options: "
input=$1

options=("Migrate" "Analyze" "Patch" "Compile")

# Need to streamline this somehow
suture_path=/home/jaewon/Downloads/suture

# This is coreutils path
# coreutils_build_path="/home/jaewon/coreutils/new_build"
# coreutils_src_path="/home/jaewon/coreutils/new_build/src"
coreutils_build_path="/home/jaewon/coreutils/"
coreutils_src_path="/home/jaewon/coreutils/src"
coreutils_config_file=${coreutils_src_path}/${input}.config
coreutils_bc_path="/home/jaewon/coreutils/src"

# This is used to setup test path
grandp_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
input_path=${parent_path}/input
test_path=${parent_path}/result
result_path=${test_path}/$1

useful_path=$grandp_path/useful_scripts

rewrite_path=${grandp_path}/var_c14n/asm_rewriter

arcs_bc_file=${result_path}/$1.bc
arcs_vuln_file=${result_path}/$1.vuln
arcs_taint_file=${result_path}/$1.taint

# https://www.maizure.org/projects/decoded-gnu-coreutils/index.html

migrate()
{
    echo "Migrate select assembly file (if input file exists)" 
    if [ -z ${coreutils_src_path}/${input}.s ]
    then
        echo "No source file, please use other option"
        exit
    fi

    if [ ! -d "$result_path" ]; then
        mkdir $result_path
    fi
    cp ${coreutils_src_path}/${input} ${coreutils_src_path}/${input}.def
    cp ${coreutils_src_path}/${input}.def $result_path/${input}.out
    cp ${coreutils_src_path}/${input}.def $result_path/${input}.def
    cp ${coreutils_src_path}/${input}.s ${coreutils_src_path}/${input}.s.bak
    cp ${coreutils_src_path}/${input}.s.bak $result_path
    cp ${coreutils_bc_path}/${input}.bc $result_path
    cp ${coreutils_bc_path}/${input}.ll $result_path
    # if [ ! -e ${result_path}/list.out ] 
	# then 
	# 	echo "Doesn't exist" 
	# else
	# 	rm ${result_path}/list.out
	# fi 
    # printf "main" >> $result_path/list.out
}

analyze()
{
    echo "Find vulnerable data"
    echo $grandp_path
    file ${coreutils_src_path}/${input}.def
    python3 $useful_path/STA/main.py --binary $result_path/${input}.out
    cat $result_path/${input}.config
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
    cp $input_file $arcs_taint_file
    if [ -f "$arcs_vuln_file" ]; then
        echo "Delete the existing vuln file"
        rm "$arcs_vuln_file"
    fi
    grep -oP "([^ ]+) says: ([^@]+)@([0-9]+) \(([^:]+) :(.+)" "$arcs_taint_file" |
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

patch()
{
    echo "Patch"
    if [ -f ${result_path}/${input}.s.bak ]
    then 
        echo "Original file found, overwrite the existing asm file"
        cp ${result_path}/${input}.s.bak ${result_path}/${input}.s
    fi
    sleep 1.5
    cd ${rewrite_path} && python3 main.py --binary ${result_path}/${input}.out 
    # python3 binary_patch.py --binary ${input}.def --fun fun.list
    #--fun list.out --dir=tests/${input}
}

compile()
{
    echo "Migrate back to coreutils and compile" 
    if [ -z ${result_path}/${input}.s ]
    then
        echo "No source file, please use other option"
        exit
    fi
    cp ${input_path}/libMakefile ${result_path}/Makefile
    cd ${result_path}
    make lib
    cp -rf ${result_path}/lib ${coreutils_src_path}
    echo ${result_path}/${input}.s
    as -o ${coreutils_src_path}/${input}.o ${result_path}/${input}.s
    sleep 3
    cd ${coreutils_build_path}
    pwd
    make src/${input}
}

while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            1) echo "Selected $option"; migrate; break;;
            2) echo "Selected $option"; analyze; break;;
            3) echo "Selected $option"; patch; break;;
            4) echo "Selected $option"; compile; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
