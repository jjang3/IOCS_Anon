#!/bin/bash

PS3="Select options: "
input=$1

current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
root_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
lib_path=${parent_path}/lib
test_path=${parent_path}/tests
source_path=${test_path}/sources
result_path=${test_path}/results
result_input_path=${result_path}/${input}
options=("PKU" "e9patch")

pku()
{
  echo "Result directory:" ${result_input_path}
  if [ ! -d "$result_path" ]; then
    mkdir $result_path
  fi

  if [ ! -d "$result_input_path" ]; then
    mkdir $result_input_path
    mv $test_path/$input $result_input_path
  fi
}

e9patch()
{
  echo "Function analysis:" ${result_input_path}
  python3 function_analysis.py --input ${input} --binary ${input}
}


while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            1) echo "Selected $option"; pku; break;;
            2) echo "Selected $option"; e9patch; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
