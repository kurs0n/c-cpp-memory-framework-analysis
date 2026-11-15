/*
 * Synthetic Testcase: CWE-416 Use After Free (UAF)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cwe416_bad(void) {
    char *ptr = (char *)malloc(32);
    if (!ptr) return;
    strcpy(ptr, "Initial memory chunk");
    printf("[*] Allocated memory at: %p\n", (void *)ptr);

    // Free the memory block
    free(ptr);
    printf("[*] Freed memory at: %p\n", (void *)ptr);

    // Accessing freed memory -> Use-After-Free violation
    printf("[*] Executing cwe416_bad() - Writing to freed pointer...\n");
    ptr[0] = 'X';
    printf("[*] Read from freed pointer: %c\n", ptr[0]);
}

void cwe416_good(void) {
    char *ptr = (char *)malloc(32);
    if (!ptr) return;
    strcpy(ptr, "Initial memory chunk");
    printf("[*] Executing cwe416_good() - Safe usage before free...\n");
    ptr[0] = 'X';
    printf("[*] Value: %c\n", ptr[0]);
    free(ptr);
    ptr = NULL; // Safe defensive nullification
}

int main(int argc, char *argv[]) {
#if defined(RUN_BAD)
    cwe416_bad();
#elif defined(RUN_GOOD)
    cwe416_good();
#else
    printf("Please compile with -DRUN_BAD or -DRUN_GOOD\n");
#endif
    return 0;
}
