#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char filename[512];
    // char filename2[512];
    // char filename3[512];
    off_t offset;              /* for support Range */
    size_t end;
} myStruct;

typedef struct {
    int test;

} test;

myStruct s3;

int main()
{
    
    myStruct s1;
    *s1.filename = 'a';
    s1.offset = 17;
    s1.end = 71;

    // printf("Hello World %s %d %d\n", s1.filename, s1.offset, s1.end);

    myStruct s2;
    memcpy(&s2, &s1, sizeof(myStruct));
    printf("Hello World %s %d %d\n", s2.filename, s2.offset, s2.end);
    return 0;
}