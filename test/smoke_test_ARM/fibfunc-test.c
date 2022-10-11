// UNSUPPORTED: true
// Assertion failed: (CallFunc && "Failed to get called function!")
// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s -fno-inline
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: Fibonacci of 42 433494437

#include <stdio.h>

//extern long fib(long n);
long fib(long n) {
  if (n <= 1) {
    return 1;
  } else {
    return fib(n - 1) + fib(n - 2);
  }
}

int main() {
  printf("Fibonacci of 42 %ld\n", fib(42));
  return 0;
}
