// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: 20  + 5 = 25
// CHECK-NEXT: 20  - 5 = 15
// CHECK-NEXT: 20  * 5 = 100

#include <stdio.h>

void __attribute__((noinline)) add(int op1, int op2) {
  printf("%d  + %d = %d\n", op1, op2, op1 + op2);
}

void __attribute__((noinline)) sub(int op1, int op2) {
  printf("%d  - %d = %d\n", op1, op2, op1 - op2);
}

void __attribute__((noinline)) mul(int op1, int op2) {
  printf("%d  * %d = %d\n", op1, op2, op1 * op2);
}

int main(int argc, char **argv) {
  add(20, 5);
  sub(20, 5);
  mul(20, 5);
  return 0;
}
