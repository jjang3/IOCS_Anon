SHELL 	= /bin/zsh
CC		= gcc
FLAGS	= -std=gnu99
CFLAGS	= -fPIC -g -Wall
LDFLAGS = -shared

TARGET  = libpkuapi.so
SOURCES = $(shell echo src/*.c)
HEADERS = $(shell echo include/*.h)
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)