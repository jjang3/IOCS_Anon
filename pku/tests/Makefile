CC		= gcc
CFLAGS	= -fPIC -g -Wall
LIBDIR 	= -L/home/jaewon/Waterfall/pku
LDFLAGS = -lpkuapi

all: $(TARGET)

clean:
	rm -f *.out

%.out : %.c
	$(CC) -T linker_script.ld $(LIBDIR) $(CFLAGS) $< -o $@ $(LDFLAGS)