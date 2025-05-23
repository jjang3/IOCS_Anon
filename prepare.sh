#!/bin/sh
git submodule init && git submodule update

grandp_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

# SVF seems to handle this by default
# wget https://github.com/Z3Prover/z3/archive/refs/tags/z3-4.8.8.zip
# unzip z3-4.8.8.zip
# cd z3-z3-4.8.8 && mkdir build && cd build
# cmake .. && make -j ${nproc}
# echo "Make sure to set ${grandp_path} as Z3_BUILD variable!"
# cd ${grandp_path}

# Taint analysis preparation - both fun/var c14n
cd ${current_path}/taint_analysis
make

# Fun c14n preparation - e9patch
cd ${current_path}/fun_c14n && cd comp_analysis/e9patch && bash build.sh
cd ${current_path}/fun_c14n && cd comp_analysis/instrument-attribute-gcc-plugin && make

# Set up LLVM
cd ${current_path}/var_c14n/static_analysis && make

# Modifying the SVF-related files to preapre to build the SVF
echo ${current_path}
sed -i 's/off/on/g' ${current_path}/var_c14n/static_analysis/SVF/build.sh
sed -i 's/${llvm_libs}//g' ${current_path}/var_c14n/static_analysis/SVF/svf-llvm/CMakeLists.txt
cd ${current_path}/var_c14n/static_analysis/SVF
bash build.sh