#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

void bar (char **input) {
    //printf("Input ptr: %p\n", *input);
    char *input_scanf = malloc(sizeof(char)*50);
    //printf("Input: ");
    scanf("%s", input_scanf);
    strcpy(*input, input_scanf);
    printf("scanf: %s\n", *input);
}

void foo(char **input) {
    bar (input);
}

int main()
{
    char *buf = malloc(sizeof(char)*50);
    foo(&buf);
    char *bar_buf = malloc(sizeof(char)*50);
    bar(&bar_buf);
    
    int fd[2];
    printf("Writing to a file\n");
    // assume foobar.txt is already created
    fd[0] = open("/home/jay/Waterfall_Full/taint_analysis/tests/file.txt", O_RDWR);
    write(fd[0], bar_buf, strlen(bar_buf));     

    //printf("Buf / Bar_buf Content: %s | %s\n", buf, bar_buf);
    //printf("Pointers: %p | %p\n", buf, bar_buf);
    free(buf);
    free(bar_buf);
}