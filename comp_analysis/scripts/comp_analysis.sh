#!/bin/bash

PS3="Select options: "
input=$1

current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
root_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
lib_path=${parent_path}/lib
test_path=${parent_path}/tests
source_path=${test_path}/sources
source_output_path=${test_path}/sources/${input}
result_path=${test_path}/results
result_input_path=${result_path}/${input}
options=("Compile" "PKU" "Instrument")

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

pku()
{
  echo "PKU"
  cd $parent_path/pku && make
}

e9patch()
{
  echo "Instrument"
  cd $parent_path/e9stuff && python3 e9.py -p init_mprotect -i $result_input_path/$input
  mv $parent_path/e9stuff/e9bin/a.out $result_input_path/$input"_waterfall"
}


while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            1) echo "Selected $option"; compile; break;;
            2) echo "Selected $option"; pku; break;;
            3) echo "Selected $option"; e9patch; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
