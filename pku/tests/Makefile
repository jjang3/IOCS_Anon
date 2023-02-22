CC		= gcc
CFLAGS	= -fPIC -g -Wall
LIBDIR 	= -L/home/jaewon/Waterfall/pku
LDFLAGS = -lpkuapi

all: $(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)

%.out : %.c
	$(CC) $(LIBDIR) $(CFLAGS) $< -o $@ $(LDFLAGS)