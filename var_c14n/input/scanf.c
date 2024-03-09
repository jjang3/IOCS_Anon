#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h> // For strlen

typedef struct {
    off_t offset;              /* for support Range */
    char filename[512];
    size_t end;
} myStruct;

// Function prototypes
void processFilename(const char *filename);
void printFilenameDetails(const char *filename);

int main() {
    printf("Hello World!\n");

    myStruct s1;
    s1.offset = 17;
    s1.offset = 71;
    int test = s1.offset - 65;
    s1.offset = test;
    uint8_t a = 100;  // 8-bit
    uint16_t b = 50;   // 16-bit correction
    uint16_t result;   // 16-bit correction

    // Addition of two values and then subtraction
    result = a + b;
    result = a - b;

    printf("Final result: %u\n", result);
    
    for (int i = 0; i < s1.offset; i++) {
        printf("Test\n");
    }
    
    scanf("%511s", s1.filename); // Securely read into filename
    processFilename(s1.filename); // Process the filename
    printFilenameDetails(s1.filename); // Print details about the filename
    
    printf("File name is: %s\n", s1.filename);
    printf("filename addr: %p %d\n", (void*)s1.filename, s1.offset);
    
    return 0;
}

void processFilename(const char *filename) {
    // Example: Check if filename has specific extension (dummy condition)
    if (strstr(filename, ".txt") != NULL) {
        printf("Filename has a .txt extension.\n");
    } else {
        printf("Filename does not have a .txt extension.\n");
    }
}

void printFilenameDetails(const char *filename) {
    // Print the length of the filename
    printf("Filename length: %lu\n", strlen(filename));
}
