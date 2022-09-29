// UNSUPPORTED: true
// call func by pointer Not yet implemented!
// RUN: clang %c-target -o %t %s
// RUN: llvm-mctoll -d %m-target -I %S/test-inc.h %t
// RUN: clang %c-target -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: 20  + 5 = 25
// CHECK_NEXT: 20  - 5 = 15
// CHECK_NEXT: 20  * 5 = 100

#include <stdio.h>

void __attribute__((noinline)) add(int op1, int op2) {
  printf("%d  + %d = %d\n", op1, op2, op1 + op2);
}

//void __attribute__((noinline)) sub(int op1, int op2) {
//  printf("%d  - %d = %d\n", op1, op2, op1 - op2);
//}

//void __attribute__((noinline)) mul(int op1, int op2) {
//  printf("%d  * %d = %d\n", op1, op2, op1 * op2);
//}

void __attribute__((noinline)) binary_op(void (*f)(int, int), int a, int b) {
  (*f)(a, b);
}

int main(int argc, char **argv) {
  binary_op(&add, 20, 5);   
//  binary_op(&sub, 20, 5);
//  binary_op(&mul, 20, 5);
  return 0;
}
