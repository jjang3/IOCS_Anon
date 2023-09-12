# Library-related                                                                                                                                                                                                                      
SHELL           = /bin/zsh
CC              = gcc
PIEFLAGS = -no-pie -fno-pie
ASMFLAGS		= -O0  -gdwarf-2 -save-temps -masm=intel -c -fno-stack-protector -fno-asynchronous-unwind-tables
LIBFLAGS	    = -Wall -fPIC -shared
LIBLDFLAGS      = -ldl -mfsgsbase
LIBTARGET       = table.so

PARENT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../)

all: lib exec

lib: $(LIBTARGET)
		echo $(PWD)
		if [ ! -d $(PWD)/lib ]; then mkdir -p $(PWD)/lib; fi
		mv $(LIBTARGET) $(PWD)/lib

$(LIBTARGET): 
		$(CC) $(LIBFLAGS) table.c -o $@ $(LIBLDFLAGS)

%.new: %.s
	$(eval name := $(basename $@))	;\
	as $< -o $(name).o ;\
	gcc $(PIEFLAGS) $(name).o -o $@

%.out: %.c	# This is for one file
	$(eval name := $(basename $@))	;\
	$(CC) $(PIEFLAGS) $(ASMFLAGS) $< ;\
	as $(name).s -o $(name).o ;\
	gcc $(name).o $(PIEFLAGS) -o $@
# 	#@echo ${name}	;\

clean:
		rm -rf lib *.o *.out *.i hello.s
