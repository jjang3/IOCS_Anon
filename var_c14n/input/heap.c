#include <stdio.h>
#include <stdlib.h>

// Function to set the value of the data
void setData(int *data, int value) {
    *data = value;
}

// Function to get (and print) the value of the data
void printData(int *data) {
    printf("Data: %d\n", *data);
}

// Function to increment the value of the data
void incrementData(int *data) {
    (*data)++;
}

int main() {
    // Allocate memory on the heap for an integer
    int *data = (int *)malloc(sizeof(int));
    if (data == NULL) {
        printf("Memory allocation failed\n");
        return 1; // Return an error code
    }

    // Set the data to an initial value
    setData(data, 10);

    // Print the current value of the data
    printData(data);

    // Increment the data
    incrementData(data);

    // Print the incremented value of the data
    printData(data);

    // Free the allocated memory
    free(data);

    return 0;
}
