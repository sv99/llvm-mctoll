// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: Hello, World!
// CHECK: Hello again, World!
// CHECK: Sum = 6912
// CHECK: Sum of 1234 and 5678 = 6912

#include <stdio.h>

int main() {
  int a = 1234, b = 5678;
  printf("Hello, World!\n");
  printf("Hello again, World!\n");
  printf("Sum = %d\n", a + b);
  printf("Sum of %d and %d = %d\n", a, b, a + b);
}
