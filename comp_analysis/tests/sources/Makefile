# Library-related
SHELL 		= /bin/zsh
CC			= gcc
FLAGS		= -std=gnu99
CFLAGS		= -gdwarf-2
ROOT_DIR=${PWD}
PARENT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../)
FUN_LIST := ${ROOT_DIR}/list.out
FUN_VAR := $(shell cat ${FUN_LIST})
# Patching-related

INSTFLAGS	= -finstrument-functions -fplugin=$(PARENT_DIR)/instrument-attribute-gcc-plugin/instrument_attribute.so -fplugin-arg-instrument_attribute-include-function-list=$(FUN_VAR)

% : %.c
	$(CC) $(CFLAGS) $(INSTFLAGS) -T linker_script.ld -o $@ $<