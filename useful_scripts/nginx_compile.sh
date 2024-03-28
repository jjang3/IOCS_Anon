./configure --with-cc-opt="-O0 -W -Wpointer-arith -Wno-unused -g -gdwarf-2 -save-temps=obj -gno-variable-location-views -masm=intel"
sed -i '/-Werror/d' ./objs/Makefile
make -j4
find /home/jaewon/Downloads/nginx-1.3.9/objs -type f -name "*.s" -exec sh -c 'mv "$0" "${0%.s}.intel"' {} \;