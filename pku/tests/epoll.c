#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <errno.h>

#include "../include/pkuapi.h"

#define MAXEVENTS	64
#define PORT		5000
#define PAGESIZE 	4096

static int socket_fd, epoll_fd;

//void process_new_data(int fd) __attribute__((aligned(PAGESIZE))) __attribute__ ((section ("isolate_target")));
void process_new_data(int fd) __attribute__((aligned(PAGESIZE))) __attribute__ ((section ("isolate_target")));
//void process_more_tainted_data(char *str) __attribute__((aligned(PAGESIZE)))  __attribute__ ((section ("isolate_target")));

static void socket_create_bind_local()
{
	struct sockaddr_in server_addr;
	int opt = 1;

        if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            perror("Socket");
            exit(1);
        }

        if (setsockopt(socket_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(int)) == -1) {
            perror("Setsockopt");
            exit(1);
        }

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(PORT);
        server_addr.sin_addr.s_addr = INADDR_ANY;
        bzero(&(server_addr.sin_zero),8);

        if (bind(socket_fd, (struct sockaddr *)&server_addr,
					sizeof(struct sockaddr)) == -1) {
            perror("Unable to bind");
            exit(1);
        }

}

static int make_socket_non_blocking(int sfd)
{
	int flags;

	printf("server fd: %d\n", sfd);
	flags = fcntl(sfd, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl");
		return -1;
	}

	flags |= O_NONBLOCK;
	if (fcntl(sfd, F_SETFL, flags) == -1) {
		perror("fcntl");
		return -1;
	}

	return 0;
}

void accept_and_add_new()
{
	struct epoll_event event;
	struct sockaddr in_addr;
	socklen_t in_len = sizeof(in_addr);
	int infd;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	printf("socket fd %d, epoll fd: %d, in_addr size %lu, in_len %d\n",
	       socket_fd, epoll_fd, sizeof(in_addr), in_len);

	while ((infd = accept(socket_fd, &in_addr, &in_len)) != -1) {
#if 1
		if (getnameinfo(&in_addr, in_len,
				hbuf, sizeof(hbuf),
				sbuf, sizeof(sbuf),
				NI_NUMERICHOST | NI_NUMERICHOST) == 0) {
			printf("Accepted connection on descriptor %d (host=%s, port=%s)\n",
					infd, hbuf, sbuf);
		}
#endif
		/* Make the incoming socket non-block
		 * and add it to list of fds to
		 * monitor*/
		if (make_socket_non_blocking(infd) == -1) {
			abort();
		}

		event.data.fd = infd;
		event.events = EPOLLIN | EPOLLET;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, infd, &event) == -1) {
			perror("epoll_ctl");
			abort();
		}
		in_len = sizeof(in_addr);
	}

	if (errno != EAGAIN && errno != EWOULDBLOCK)
		perror("accept");
	/* else
	 *
	 * We have processed all incomming connections
	 *
	 */
}

/**
 * Should be a tainted function when input == "secret"
 */
void process_more_tainted_data(char *str)
{
	printf("\033[0;31m%s: \033[0;32m%s\033[0m\n", __func__, str);

    int fd[2];
    fd[0] = open("/home/jay/Waterfall_Full/taint_analysis/tests/file.txt", O_RDWR);
    write(fd[0], str, strlen(str));     
	close(fd[0]);
}

void dynamically_unreachable(char *str)
{
	printf("Dynamically unreachable, but touches tainted value\n");
}

/**
 * This should be a tainted function if considering network data as taint src.
 */
void process_new_data(int fd)
{
	ssize_t count;
	char buf[16];

	while ((count = read(fd, buf, sizeof(buf) - 1))) {
		if (count == -1) {
			/* EAGAIN, read all data */
			if (errno == EAGAIN)
				return;
			perror("read");
			break;
		}

		/* Write buffer to stdout */
		buf[count-1] = '\0';
		printf("Buffer: %s\n", buf);
		//write(STDOUT_FILENO, buf, sizeof(buf)-1);

		/* Process more tainted data. */
		if (!strcmp(buf, "secret"))
			process_more_tainted_data(buf);
		else if (!strcmp(buf, "unreachable"))
			dynamically_unreachable(buf);
		else if (!strcmp(buf, "exit"))
			exit(1);
	}

	printf("Close connection on descriptor: %d\n", fd);
	close(fd);
}

int main()
{
    int pkey = pkey_alloc();
    if (pkey == -1) {
        perror("pkey_alloc()");
        return 1;
	}

	char *command;
	printf("Enter protection command: ");
	scanf("%s", command);

	if (strcmp(command,"y") == 0) {
		printf("Set protection\n");
		if (pkey_set(pkey, PKEY_DISABLE_ACCESS, 0) == -1) {
			perror("pkey_set()");
			return 1;
		}
	}
	else if (strcmp(command,"n") == 0)
	{
		printf("Disable protection\n");
		if (pkey_set(pkey, PKEY_ALL_ACCESS, 0) == -1) {
			perror("pkey_set()");
			return 1;
		}	
	}
	#if 1 
	if(pkey_mprotect(process_new_data, PAGESIZE, PROT_EXEC, pkey) == -1) {
		perror("pkey_mprotect()");
		return 1;
	}
	#endif
	#if 0
	if(pkey_mprotect(process_more_tainted_data, strlen(process_more_tainted_data) + 1, PROT_READ | PROT_WRITE, pkey) == -1) {
        perror("mprotect()");
        return 1;
    }
	#endif
	struct epoll_event event, *events;

	printf("sizeof epoll_event: %lu\n", sizeof(struct epoll_event));
	socket_create_bind_local();

	if (make_socket_non_blocking(socket_fd) == -1)
		exit(1);

        if (listen(socket_fd, 5) == -1) {
            perror("Listen");
            exit(1);
        }

	printf("\nTCPServer Waiting for client on port %d\n"
	       "Access the server with \"nc localhost %d\"\n", PORT, PORT);
        fflush(stdout);

	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1) {
		perror("epoll_create1");
		exit(1);
	}

	event.data.fd = socket_fd;
	event.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &event) == -1) {
		perror("epoll_ctl");
		exit(1);
	}

	events = calloc(MAXEVENTS, sizeof(event));
	printf("socket fd: %d, epoll fd: %d\n", socket_fd, epoll_fd);


	while(1) {
		int n, i;
		n = epoll_wait(epoll_fd, events, MAXEVENTS, -1);
		n = 1;
		for (i = 0; i < n; i++) {
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP ||
			    !(events[i].events & EPOLLIN)) {
				fprintf(stderr, "[%d] events: %x\n",
					n, events[i].events);
				/* An error on this fd or socket not ready */
				perror("epoll error");
				close(events[i].data.fd);
			} else if (events[i].data.fd == socket_fd) {
				/* New incoming connection */
				accept_and_add_new();
			} else {
				/* Data incoming on fd */
				process_new_data(events[i].data.fd);
			}
		}
	}

	free(events);
	close(socket_fd);
	return 0;
}
