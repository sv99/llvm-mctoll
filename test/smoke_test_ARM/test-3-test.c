// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: test_3_func result 66

#include <stdio.h>

// extern int test_3_func(int a, int b);
int test_3_func(int a, int b) {
  int c = 0;
  c = b - a;
  return c;
}

int main() {
  printf("test_3_func result %d\n", test_3_func(234, 300));
  return 0;
}
