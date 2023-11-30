# This script is used for fun_c14n
#!/bin/bash

PS3="Select options: "
input=$1

options=("Compile" "Instrument")

# This is used to setup test path
grandp_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

comp_path=${current_path}/comp_analysis
e9stuff_path=${comp_path}/e9stuff
e9patch_path=${comp_path}/e9patch
instru_path=${comp_path}/instrument-attribute-gcc-plugin
pku_path=${comp_path}/pku

or_path=${current_path}/OR_analysis

fun_input_path=${current_path}/input

fun_lib_path=${current_path}/lib

fun_result_path=${current_path}/result
fun_i_result_path=${fun_result_path}/$1
fun_i_file=${fun_i_result_path}/$1
fun_o_file=${fun_i_result_path}/$1"_fun_c14n"


# lib_path=${parent_path}/lib
# test_path=${parent_path}/tests
# source_path=${test_path}/sources
# source_output_path=${test_path}/sources/${input}
# result_path=${test_path}/results
# result_input_path=${result_path}/${input}

compile()
{
  echo "Compile file (if input file exists)" 
  if [ ! -d "$fun_lib_path" ]; then
      echo "Input result directory doesn't exist"
      mkdir $fun_lib_path
  fi
  cd $pku_path && make lib
  if [ ! -d "$fun_result_path" ]; then
      echo "Result directory doesn't exist"
      mkdir $fun_result_path
    fi
  if [ ! -d "$fun_i_result_path" ]; then
      echo "Input result directory doesn't exist"
      mkdir $fun_i_result_path
      if [ ! -f "${fun_i_result_path}/taint.in" ]; then
        printf "main" >> ${fun_i_result_path}/taint.in
      fi
  fi
  # if [ ! -f "$fun_i_file" ]; then
      # echo "Input file doesn't exist"
  cd $fun_input_path && make ${input} INPUT=${input} && mv ${input} ${fun_i_file} 
  objdump -d ${fun_i_file} &> ${fun_i_result_path}/${input}.objdump
  # fi
}

e9patch()
{
  if [ ! -f "${e9patch_path}/e9compile.sh.bak" ]; then
    echo "Backup doesn't exist"
    cp ${e9patch_path}/e9compile.sh ${e9patch_path}/e9compile.sh.bak
  fi
  cp ${e9stuff_path}/src/e9compile.sh ${e9patch_path}/e9compile.sh
  echo "Instrument"
  cd ${e9stuff_path} && python3 e9.py -p init_mprotect -i ${fun_i_file}
  echo "Moving a.out to respective folder"
  mv ${e9stuff_path}/e9bin/a.out ${fun_o_file}
}


while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            1) echo "Selected $option"; compile; break;;
            2) echo "Selected $option"; e9patch; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
