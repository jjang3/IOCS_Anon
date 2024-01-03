#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
    off_t offset;              /* for support Range */
    char filename[512];
    size_t end;
} myStruct;


int main()
{
    printf("Hello World!\n");

    myStruct s1;
    
    // char *ptr_var = malloc(sizeof(char)*100);

    // char filename[512];
    // scanf("%s", &filename);
    s1.offset = 17;
    s1.offset = 71;
    int test = s1.offset - 65;
    s1.offset = test;
    for (int i = 0; i < s1.offset; i++)
    {
        printf("Test\n");
    }
    scanf("%s", &s1.filename);
    // char **double_ptr_var;
    // double_ptr_var = &ptr_var;
    printf("File name is: %s\n", s1.filename);
    printf("filename addr: %p %d\n", s1.filename, s1.offset);
}