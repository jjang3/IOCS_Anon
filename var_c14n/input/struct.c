#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>

typedef struct {
    char filename[512];
    off_t offset;              /* for support Range */
    size_t end;
} myStruct;

typedef struct {
    int test;
    size_t end;
} test;


int main()
{
    
    myStruct s1;
    *s1.filename = 'a';
    s1.offset = 17;
    s1.end = 71;

    int test_2;
    test_2 = 91;
    
    test test;
    test.test = 1;
    test.end = 1717;

    char *filename = malloc(sizeof(char)*8196);
    filename = "filename\n";

    char **filename_ptr = &filename;

    printf("Hello World %s %d %d %s %p %p\n", s1.filename, s1.offset, s1.end, filename, &filename, filename_ptr);
    return 0; 
}
