# Library-related
SHELL 		= /bin/zsh
CC			= gcc
DEBUGFLAGS	= -Wa,-ahlms=temp.lst
FLAGS		= -std=gnu99
CFLAGS		= -fPIC -g -Wall $(DEBUGFLAGS)
LDFLAGS 	= -shared

TARGET  	= libpkuapi.so
SOURCES 	= $(shell echo src/*.c)
HEADERS 	= $(shell echo include/*.h)
OBJECTS 	= $(SOURCES:.c=.o)
PARENT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../)
GPARENT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../)

all: lib

lib: $(TARGET)
	if [ ! -d ${GPARENT_DIR}/lib ]; then mkdir -p ${GPARENT_DIR}/lib; fi
	echo $(TARGET)
	mv $(OBJECTS) ${GPARENT_DIR}/lib 
	mv $(TARGET) ${GPARENT_DIR}/lib

$(TARGET): $(OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

clean:
	rm -rf $(OBJECTS) lib outputs