// REQUIRES: system-linux
// RUN: gcc -o %t-gcc %s %S/Inputs/fibfunc.c
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-gcc -o %t-gcc-dis.ll
// RUN: clang -o %t-gcc-dis %t-gcc-dis.ll
// RUN: %t-gcc-dis 2>&1 | FileCheck %s -check-prefix=GCC
// GCC: Fibonacci of 21 17711

#include <stdio.h>

extern long fib(long n);

int main() {
  printf("Fibonacci of 21 %ld\n", fib(21));
  return 0;
}
