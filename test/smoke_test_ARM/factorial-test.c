// UNSUPPORTED: true
// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Factorial of 10 3628800

#include <stdio.h>

//extern int factorial(int n);
int factorial(int n) {
  if (n == 0) {
    return 1;
  }
  return n * factorial(n - 1);
}

int main() {
  printf("Factorial of 10 %d\n", factorial(10));
  return 0;
}
