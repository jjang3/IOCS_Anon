SHELL 	= /bin/zsh
CC		= gcc
FLAGS	= -std=gnu99
CFLAGS	= -fPIC -g -Wall
LDFLAGS = -shared

TARGET  = lib/libpkuapi.so
SOURCES = $(shell echo src/*.c)
HEADERS = $(shell echo include/*.h)
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

clean:
	rm -rf $(OBJECTS) $(TARGET) lib

$(TARGET): $(OBJECTS)
	@mkdir -p lib
	$(CC) $(FLAGS) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)