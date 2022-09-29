// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t.so %S/Inputs/fibfunc.c -shared -fPIC
// RUN: llvm-mctoll %mparams -d -I %S/test-inc.h %t.so
// RUN: clang -o %t1 %s %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s -check-prefix=CLANG
// CLANG: Fibonacci of 21 17711

#include <stdio.h>

extern long fib(long n);

int main() {
  printf("Fibonacci of 21 %ld\n", fib(21));
  return 0;
}
