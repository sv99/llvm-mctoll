// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: test_2_func result 7

#include <stdio.h>

// extern long test_2_func(int a, long b);
long test_2_func(int a, long b) {
  int c = a + b;
  return a + c;
}

int main() {
  printf("test_2_func result %ld\n", test_2_func(2, 3));
  return 0;
}
