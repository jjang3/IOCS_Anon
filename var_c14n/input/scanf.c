#include <stdio.h>

int main()
{
    printf("Hello World!\n");
    char filename[512];
    scanf("%s", &filename);
    printf("File name is: %s\n", filename);
    printf("filename addr: %p\n", filename);
}