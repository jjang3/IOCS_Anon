#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

int main() {
    FILE *filePointer = fopen("input.txt", "r");
    if (filePointer == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }
    
    int variable;
    char buffer[1024], stringInput[] = "123 456";
    int fd = fileno(stdin); // Example file descriptor, typically you'd use a real file or socket fd
    int sock = socket(AF_INET, SOCK_STREAM, 0); // Example socket, not connected
    
    // scanf - Reads from stdin; ensure stdin has data or redirect input from a file
    scanf("%d", &variable);

    // fscanf - Reads from a file stream
    fscanf(filePointer, "%s", buffer);

    // sscanf - Reads from a string
    sscanf(stringInput, "%d", &variable);

    // __isoc99_sscanf - Assuming it's available, usage is the same as sscanf
    __isoc99_sscanf(stringInput, "%d", &variable);

    // __isoc99_scanf - Reads from stdin; ensure stdin has data
    __isoc99_scanf("%d", &variable);

    // fgets - Reads a line from a file or stdin into a buffer
    fgets(buffer, sizeof(buffer), stdin);

    // gets - Unsafe, reads a line from stdin into a buffer (DO NOT USE)
    gets(buffer); // Deprecated and unsafe, included for completeness

    // read - Reads raw data from a file descriptor into a buffer
    read(fd, buffer, sizeof(buffer));

    // recv - Receives data from a socket into a buffer
    recv(sock, buffer, sizeof(buffer), 0);

    // recvfrom - Similar to recv, but also stores the address of the sender
    struct sockaddr_storage senderAddr;
    socklen_t addrLen = sizeof(senderAddr);
    recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&senderAddr, &addrLen);

    fclose(filePointer);
    close(sock);
    return 0;
}
