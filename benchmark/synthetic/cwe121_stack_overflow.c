/*
 * Synthetic Testcase: CWE-121 Stack-based Buffer Overflow
 */
#include <stdio.h>
#include <string.h>

void cwe121_bad(void) {
    char stack_buffer[16];
    printf("[*] Executing cwe121_bad() - Overwriting stack buffer...\n");
    // Writing 32 bytes into 16-byte buffer -> Stack buffer overflow
    memset(stack_buffer, 'A', 32);
    // Prevent dead store elimination
    printf("[*] Buffer contents: %.16s\n", stack_buffer);
}

void cwe121_good(void) {
    char stack_buffer[16];
    printf("[*] Executing cwe121_good() - Safe stack buffer write...\n");
    memset(stack_buffer, 'A', 15);
    stack_buffer[15] = '\0';
    printf("[*] Buffer contents: %s\n", stack_buffer);
}

int main(int argc, char *argv[]) {
#if defined(RUN_BAD)
    cwe121_bad();
#elif defined(RUN_GOOD)
    cwe121_good();
#else
    printf("Please compile with -DRUN_BAD or -DRUN_GOOD\n");
#endif
    return 0;
}
