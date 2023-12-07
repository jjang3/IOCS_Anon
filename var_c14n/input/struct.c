#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    char filename[512];
    off_t offset;              /* for support Range */
    size_t end;
} myStruct;

typedef struct {
    int test;
} test;


int main()
{
    myStruct s1;
    *s1.filename = "Test";
    s1.offset = 17;
    s1.end = 71;

    printf("Hello World %s %d %d\n", s1.filename, s1.offset, s1.end);
    return 0; 
}
