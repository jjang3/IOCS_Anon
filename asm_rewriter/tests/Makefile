# Library-related                                                                                                                                                                                                                      
SHELL           = /bin/zsh
CC              = gcc
PIEFLAGS = 		-no-pie -fno-pie
ASMFLAGS		= -O0 -gdwarf-2 -c -save-temps=obj

PARENT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../)


%.new: %
	$(eval name := $(basename $@))	;\
	# $(CC) $(LIBFLAGS) ${name}/table.c -o ${name}/table.so $(LIBLDFLAGS)
	# if [ ! -d ${name}/lib ]; then mkdir -p $(name)/lib; fi
	# mv ${name}/table.so $(name)/lib
	as ${name}/$<.s -o ${name}/$(name).o ;\
	gcc ${name}/$(name).o -o ${name}/$@

%.out: %.c	# This is for one file
	$(eval name := $(basename $@))	;\
	if [ ! -d ${name} ]; then \
		mkdir ${name} ;\
	fi ;\
	cp libMakefile ${name}/Makefile ;\
	$(CC) $(ASMFLAGS) $< -o ${name}/$@ ;\
	as ${name}/${name}.s -o ${name}/${name}.o
	$(CC) -O0 -gdwarf-2 ${name}/${name}.o -o ${name}/$@
	printf "main" >> ${name}/list.out

clean:
		rm -rf lib *.o *.out *.i hello.s
