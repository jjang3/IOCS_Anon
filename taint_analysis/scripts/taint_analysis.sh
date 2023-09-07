#!/bin/bash

PS3="Select options: "
input=$1

current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
root_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
PIN_ROOT=$root_path/pin-3.27_build
lib_path=${parent_path}/lib
test_path=${parent_path}/tests
script_path=${parent_path}/scripts
source_path=${test_path}/sources
source_output_path=${test_path}/sources/${input}
result_path=${test_path}/results
result_input_path=${result_path}/${input}
options=("Compile" "Taint analysis" "Function analysis")

compile()
{
  echo "Compile file (if input file exists)" 
  if [ -z ${input} ]
  then
    echo "No source file, please use other option"
    exit
  fi
  
  if [ ! -d "$result_path" ]; then
    mkdir $result_path
  fi

  if [ ! -d "$result_input_path" ]; then
    mkdir $result_input_path
  fi

  cd $source_path && pwd && make ${input}
  mv $source_output_path $result_input_path
  objdump -d $result_input_path/$input &> $result_input_path/$input.objdump
}

taint()
{
  echo "Result directory:" ${result_input_path}
  if [ ! -d "$result_path" ]; then
    mkdir $result_path
  fi

  if [ ! -d "$result_input_path" ]; then
    mkdir $result_input_path
    mv $test_path/$input $result_input_path
  fi
  $PIN_ROOT/pin -follow-execv -t $lib_path/libdft-mod.so -- ${result_input_path}/${input} 1111
  objdump -d $test_path/$input &> $result_input_path/$input.objdump
  mv dft.out $result_input_path
}

fun()
{
  echo "Function analysis:" ${result_input_path}
  cd $script_path
  python3 $(pwd)/function_analysis.py --input ${input} --binary ${input}
}


while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            1) echo "Selected $option"; compile; break;;
            2) echo "Selected $option"; taint; break;;
            3) echo "Selected $option"; fun; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
