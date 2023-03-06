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
EXC_DEFAU	= __bswap_16,pkey_free,pkey_mprotect,pkey_disable_access,pkey_all_access,wrpkru,pkey_set,pkey_alloc,init,
EXCLUDE		= read,bind,setsockopt,memset,deregister_tm_clones,accept_and_add_new,abort,__libc_csu_fini,__do_global_dtors_aux,write,strcmp,_start,getnameinfo,exit,fflush,fcntl,main,perror,htons,epoll_create1,printf,socket_create_bind_local,_init,_fini,listen,epoll_ctl,close,register_tm_clones,_dl_relocate_static_pie,open,__errno_location,frame_dummy,socket,accept,strlen,epoll_wait,calloc,dynamically_unreachable,__libc_csu_init,make_socket_non_blocking,fprintf

EXCFLAGS	= -finstrument-functions-exclude-function-list=$(EXC_DEFAU)$(EXCLUDE)
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
	objdump -d $@ &> outputs/temp.objdump
	mv $@ outputs

inputs/%.o : inputs/%.c
	$(CC) $(EXCFLAGS) $(CFLAGS) $(INSTFLAGS) -c $< -o $@ 

clean:
	rm -rf $(OBJECTS) lib outputs