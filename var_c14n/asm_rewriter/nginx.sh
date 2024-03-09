# This script is used for coreutils rewriting purpose (e.g., could be expanded for other applications?)
#!/bin/bash

PS3="Select options: "
input=$1

options=("Patch" "Compile")

# This is coreutils path
nginx_path="/home/jaewon/Downloads/nginx-1.3.9/objs/src"
nginx_home_path="/home/jaewon/Downloads/nginx-1.3.9/"
nginx_install_path="/home/jaewon/Downloads/nginx-1.3.9/debug_x86_64/sbin"

# This is used to setup test path
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
input_path=${parent_path}/input
test_path=${parent_path}/result
result_path=${test_path}/$1

patch()
{
    # Copy original backup files every time before rewriting
    find "$nginx_path" -type f -name "*.s.bak" -exec bash -c 'file_path="$1"; 
    dir_path=$(dirname "$file_path"); 
    file_name=$(basename "$file_path" .s.bak); 
    new_file_path="$dir_path/${file_name}.s";
    object_file_path="$dir_path/${file_name}.o"; 
    cp "$file_path" "$new_file_path";
    as "$new_file_path" -o "$object_file_path"' _ {} \;
    echo "Patch"
    #python3 binary_patch_old.py --fun fun.list --dir ${nginx_path}
    #python3 binary_patch.py --fun fun.list --dir ${nginx_path}
    python3 main.py --binary nginx.out --directory ${nginx_path}
    cp ${input_path}/libMakefile ${nginx_path}/Makefile
    cd ${nginx_path}
    make lib
}

compile()
{
    echo "Compile nginx app" 
    cd ${nginx_home_path}
    make && make install
    cp ${nginx_install_path}/nginx ${result_path}/nginx
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


