#include <stdio.h>
#include <string.h>

#define MAX_FILENAME_LENGTH 256

typedef struct {
    char filename[MAX_FILENAME_LENGTH];
    unsigned long offset;
    unsigned long end;
} http_request;

// Function declarations
void foo(http_request *req);
void bar(http_request *req);

int main() {
    http_request req;
    // Initialize the http_request
    strcpy(req.filename, "initial.txt");
    req.offset = 0;
    req.end = 100; // Assume initial values for demonstration
    
    printf("Before foo: filename=%s, offset=%lu, end=%lu\n", req.filename, req.offset, req.end);
    
    // Pass the request to foo, which will modify it and pass it to bar
    foo(&req);
    
    // Final state of req after being processed by foo and bar
    printf("After bar: filename=%s, offset=%lu, end=%lu\n", req.filename, req.offset, req.end);
    
    return 0;
}

void foo(http_request *req) {
    // Modify and pass to bar
    strcpy(req->filename, "modifiedByFoo.txt");
    req->offset = 50; // Modify offset
    bar(req); // Pass the modified request to bar
}

void bar(http_request *req) {
    // Further modify the request
    strcpy(req->filename, "finalModifiedByBar.txt");
    req->end = 150; // Modify end
}
