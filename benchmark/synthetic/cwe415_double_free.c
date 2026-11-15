/*
 * Synthetic Testcase: CWE-415 Double Free
 */
#include <stdio.h>
#include <stdlib.h>

void cwe415_bad(void) {
    char *ptr = (char *)malloc(64);
    if (!ptr) return;
    printf("[*] Allocated memory at %p\n", (void *)ptr);

    printf("[*] First free call...\n");
    free(ptr);

    printf("[*] Executing cwe415_bad() - Second free call (Double Free)...\n");
    free(ptr);
}

void cwe415_good(void) {
    char *ptr = (char *)malloc(64);
    if (!ptr) return;
    printf("[*] Executing cwe415_good() - Single free call...\n");
    free(ptr);
    ptr = NULL;
}

int main(int argc, char *argv[]) {
#if defined(RUN_BAD)
    cwe415_bad();
#elif defined(RUN_GOOD)
    cwe415_good();
#else
    printf("Please compile with -DRUN_BAD or -DRUN_GOOD\n");
#endif
    return 0;
}
