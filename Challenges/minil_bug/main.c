#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "vm.h"

void init()
{
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

int main(int argc, char *argv[]) {
    init();
    int code[128], nread = 0;
    puts("Input your code:");
    while (nread < sizeof(code)) {
        int ret = read(0, code+nread, sizeof(code)-nread);
        if (ret <= 0) break;
        nread += ret;
    }
    VM *vm = vm_create(code, nread/4, 0);
    vm_exec(vm, 0, true);
    vm_free(vm);
    return 0;
}

