CC		= gcc
CFLAGS	= -g -O1 -Wall -finstrument-functions
EXFLAGS	= -finstrument-functions-exclude-function-list=init,main,foo
LIBDIR 	= -L/home/jaewon/Waterfall/pku
LIBS 	= -lpkuapi

.PHONY: all %.out clean

all: $(TARGET)

%.out : %.o
	$(CC) $(CFLAGS) $(LIBDIR)  -T linker_script.ld  $< -o $@  $(LIBS)

%.o : %.c
	$(CC) $(EXFLAGS) $(CFLAGS) -c $< -o $@ 

clean:
	rm -f *.out *.o