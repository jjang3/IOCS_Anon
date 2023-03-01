CC		= gcc
CFLAGS	= -g -O1 -Wall -finstrument-functions
EXCL	= setsockopt,fcntl,epoll_wait,__libc_csu_init,socket_create_bind_local,close,main,memset,__libc_csu_fini,accept,_fini,epoll_create1,perror,fprintf,_start,_init,strcmp,getnameinfo,fflush,__do_global_dtors_aux,make_socket_non_blocking,listen,bind,write,frame_dummy,register_tm_clones,read,strlen,open,printf,dynamically_unreachable,accept_and_add_new,deregister_tm_clones,exit,socket,abort,epoll_ctl,__errno_location,htons,calloc,_dl_relocate_static_pie
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