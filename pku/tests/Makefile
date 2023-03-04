CC		= gcc
CFLAGS	= -g -O1 -Wall -finstrument-functions
EXCL	= process_new_data,__bswap_16,pkey_free,pkey_mprotect,pkey_disable_access,pkey_all_access,wrpkru,pkey_set,pkey_alloc,init,socket,listen,frame_dummy,register_tm_clones,epoll_ctl,_fini,printf,fcntl,dynamically_unreachable,abort,perror,memset,_start,write,__errno_location,__libc_csu_init,open,getnameinfo,setsockopt,epoll_wait,epoll_create1,fflush,close,accept,calloc,_dl_relocate_static_pie,deregister_tm_clones,_init,__libc_csu_fini,strlen,strcmp,fprintf,htons,accept_and_add_new,make_socket_non_blocking,read,__do_global_dtors_aux,exit,socket_create_bind_local,bind,main

EXFLAGS	= -finstrument-functions-exclude-function-list=$(EXCL)
LIBDIR 	= -L/home/jaewon/Waterfall/pku
LIBS 	= -lpkuapi

.PHONY: all %.out clean

all: %.out

%.out : %.o
	$(CC) $(CFLAGS) $(LIBDIR)  -T linker_script.ld  $< -o $@  $(LIBS)

%.o : %.c
	$(CC) $(EXFLAGS) $(CFLAGS) -c $< -o $@ 

clean:
	rm -f *.out *.o