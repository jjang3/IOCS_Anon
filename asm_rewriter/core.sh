# This script is used for coreutils rewriting purpose (e.g., could be expanded for other applications?)
#!/bin/bash

PS3="Select options: "
input=$1

options=("Migrate" "Patch" "Compile")

# This is coreutils path
coreutils_build_path="/home/jaewon/coreutils/new_build"
coreutils_src_path="/home/jaewon/coreutils/new_build/src"

# This is used to setup test path
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
test_path=${current_path}/tests
result_path=${test_path}/$1

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
    cp ${coreutils_src_path}/${input} $result_path/${input}.out
    cp ${coreutils_src_path}/${input}.s $result_path

    if [ ! -e ${result_path}/list.out ] 
	then 
		echo "Doesn't exist" 
	else
		rm ${result_path}/list.out
	fi 
    printf "main" >> $result_path/list.out
}

patch()
{
    echo "Patch"
    python3 binary_patch.py --binary ${input}.out --fun list.out --dir=tests/${input}
}

compile()
{
    echo "Migrate back to coreutils and compile" 
    if [ -z ${result_path}/${input}.s ]
    then
        echo "No source file, please use other option"
        exit
    fi
    cp ${test_path}/libMakefile ${result_path}/Makefile
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
            2) echo "Selected $option"; patch; break;;
            3) echo "Selected $option"; compile; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
