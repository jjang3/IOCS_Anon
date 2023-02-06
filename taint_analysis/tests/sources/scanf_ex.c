#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void bar (char **input) {
    //printf("Input ptr: %p\n", *input);
    char *input_scanf = malloc(sizeof(char)*50);
    //printf("Input: ");
    scanf("%s", input_scanf);
    strcpy(*input, input_scanf);
    //printf("scanf: %s\n", *input);
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
    *bar_buf;
    //printf("Buf / Bar_buf Content: %s | %s\n", buf, bar_buf);
    //printf("Pointers: %p | %p\n", buf, bar_buf);
    free(buf);
    free(bar_buf);
}