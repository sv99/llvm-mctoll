// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: test_1_func result 5

#include <stdio.h>

// extern long test_1_func(int a, long b);
long test_1_func(int a, long b) { return a + b; }

int main() {
  printf("test_1_func result %ld\n", test_1_func(2, 3));
  return 0;
}
