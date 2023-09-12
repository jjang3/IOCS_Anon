PROJ_NAME=main.out

CC              = gcc
CFLAGS			= -O0 -gdwarf-2 -save-temps -c -fno-asynchronous-unwind-tables
C_FILES=$(shell find . -name "*.c")
S_OBJ=$(patsubst %.c, %_update.o, $(C_FILES))

.SECONDARY:

all: $(PROJ_NAME)
		@echo Running application
	
$(PROJ_NAME): $(S_OBJ)
		$(CC) $^ -o $@

%_update.o: %.s
		as $< -o $@

%.s: %.c
		$(CC) $(CFLAGS) $<

# main.o: main.c
# 		@echo Compiling and generating object $@ ...
# 		$(CC) $(CFLAGS) $< -o $@

clean:
		rm -rf *.o *.out *.i *.s