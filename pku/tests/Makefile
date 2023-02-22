CC		= gcc
CFLAGS	= -fPIC -g -Wall
LIBDIR 	= -L/home/jaewon/Waterfall/pku
LDFLAGS = -lpkuapi

all: $(TARGET)

clean:
	rm -f *.out

%.out : %.c
	$(CC) $(LIBDIR) $(CFLAGS) $< -o $@ $(LDFLAGS)