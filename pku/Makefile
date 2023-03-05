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
INSTFLAGS	= -O1 -Wall -finstrument-functions
EXCLUDE		= process_new_data,__bswap_16,pkey_free,pkey_mprotect,pkey_disable_access,pkey_all_access,wrpkru,pkey_set,pkey_alloc,init,socket,listen,frame_dummy,register_tm_clones,epoll_ctl,_fini,printf,fcntl,dynamically_unreachable,abort,perror,memset,_start,write,__errno_location,__libc_csu_init,open,getnameinfo,setsockopt,epoll_wait,epoll_create1,fflush,close,accept,calloc,_dl_relocate_static_pie,deregister_tm_clones,_init,__libc_csu_fini,strlen,strcmp,fprintf,htons,accept_and_add_new,make_socket_non_blocking,read,__do_global_dtors_aux,exit,socket_create_bind_local,bind,main

EXCFLAGS	= -finstrument-functions-exclude-function-list=$(EXCLUDE)
LIBDIR 		= -L$(HOME)/Waterfall/pku/lib
LIBS 		= -lpkuapi

all: lib

lib: $(TARGET)
	@mkdir -p lib
	mv $(TARGET) lib

$(TARGET): $(OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

%.out : inputs/%.o
	$(CC) $(CFLAGS) $(INSTFLAGS) $(LIBDIR) -T inputs/linker_script.ld  $< -o $@ $(LIBS)
	@mkdir -p outputs
	mv $@ outputs

inputs/%.o : inputs/%.c
	$(CC) $(EXCFLAGS) $(CFLAGS) $(INSTFLAGS) -c $< -o $@ 

clean:
	rm -rf $(OBJECTS) lib outputs