# This script is used for coreutils rewriting purpose (e.g., could be expanded for other applications?)
#!/bin/bash

PS3="Select options: "
input=$1

options=("Patch" "Compile")

# This is coreutils path
nginx_path="/home/jaewon/Downloads/nginx-1.3.9/objs/src"

# This is used to setup test path
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
input_path=${parent_path}/input
test_path=${parent_path}/result
result_path=${test_path}/$1

patch()
{
    echo "Patch"
    python3 binary_patch.py --fun fun.list --dir ${nginx_path}
}

compile()
{
    echo "Compile"
    # echo "Migrate back to coreutils and compile" 
    # if [ -z ${result_path}/${input}.s ]
    # then
    #     echo "No source file, please use other option"
    #     exit
    # fi
    # cp ${input_path}/libMakefile ${result_path}/Makefile
    # cd ${result_path}
    # make lib
    # cp -rf ${result_path}/lib ${coreutils_src_path}
    # echo ${result_path}/${input}.s
    # as -o ${coreutils_src_path}/${input}.o ${result_path}/${input}.s
    # sleep 3
    # cd ${coreutils_build_path}
    # pwd
    # make src/${input}
}

while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            # 1) echo "Selected $option"; migrate; break;;
            1) echo "Selected $option"; patch; break;;
            2) echo "Selected $option"; compile; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done


