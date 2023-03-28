# Library-related
SHELL 		= /bin/zsh
CC			= gcc
FLAGS		= -std=gnu99
CFLAGS		= -fPIC -g -Wall
LDFLAGS 	= -shared

TARGET  	= libpkuapi.so
SOURCES 	= $(shell echo src/*.c)
HEADERS 	= $(shell echo include/*.h)
OBJECTS 	= $(SOURCES:.c=.o)

# Patching-related
INSTFLAGS	= -O1 -Wall -finstrument-functions -fplugin=/home/jaewon/Downloads/instrument-attribute-gcc-plugin/instrument_attribute.so -fplugin-arg-instrument_attribute-include-function-list=process_more_tainted_data
LIBDIR 		= -L$(HOME)/Waterfall/pku/lib
LIBS 		= -lpkuapi

all: lib

lib: $(TARGET)
	@mkdir -p lib
	mv $(TARGET) lib

$(TARGET): $(OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)
#-T inputs/linker_script.ld $(LIBDIR) $(LIBS)
%.out : inputs/%.o
	$(CC) $(CFLAGS) $(INSTFLAGS) -T src/linker_script.ld $(LIBDIR) $< -o $@ $(LIBS)
	@mkdir -p outputs
	objdump -d $@ &> outputs/temp.objdump
	mv $@ outputs

inputs/%.o : inputs/%.c
	$(CC) $(CFLAGS) $(INSTFLAGS) -c $< -o $@ 

clean:
	rm -rf $(OBJECTS) lib outputs