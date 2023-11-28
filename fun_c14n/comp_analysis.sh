# This script is used for fun_c14n
#!/bin/bash

PS3="Select options: "
input=$1

options=("Compile" "PKU" "Instrument")

# This is used to setup test path
grandp_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

comp_path=${current_path}/comp_analysis
e9stuff_path=${comp_path}/e9stuff
instru_path=${comp_path}/instrument-attribute-gcc-plugin
pku_path=${comp_path}/pku

or_path=${current_path}/OR_analysis

fun_input_path=${current_path}/input

fun_lib_path=${current_path}/lib

fun_result_path=${current_path}/result
fun_i_result_path=${fun_result_path}/$1
fun_i_file=${fun_i_result_path}/$1


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
  fi
  if [ ! -f "$fun_i_file" ]; then
      echo "Input file doesn't exist"
      # $LLVM_BUILD_DIR/bin/clang -emit-llvm -S -o ${arcs_ll_file} ${arcs_input_path}/${input}.c
  fi
  # if [ -z ${input} ]
  # then
  #   echo "No source file, please use other option"
  #   exit
  # fi
  
  # if [ ! -d "$result_path" ]; then
  #   mkdir $result_path
  # fi

  # if [ ! -d "$result_input_path" ]; then
  #   mkdir $result_input_path
  # fi

  # cd $source_path && pwd && make ${input}
  # mv $source_output_path $result_input_path
  # objdump -d $result_input_path/$input &> $result_input_path/$input.objdump
}

# pku()
# {
#   echo "PKU"
#   cd $parent_path/pku && make
# }

# e9patch()
# {
#   echo "Instrument"
#   cd $parent_path/e9stuff && python3 e9.py -p init_mprotect -i $result_input_path/$input
#   mv $parent_path/e9stuff/e9bin/a.out $result_input_path/$input"_waterfall"
# }


while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            1) echo "Selected $option"; compile; break;;
            # 2) echo "Selected $option"; pku; break;;
            # 3) echo "Selected $option"; e9patch; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
