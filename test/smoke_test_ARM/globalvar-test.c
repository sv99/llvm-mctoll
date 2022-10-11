// UNSUPPORTED: true
// run not exited
// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: GlobalVar Initial value = 42
// CHECK-NEXT: myglobal_func returns 72
// CHECK-NEXT: GlobalVar updated value = 52

#include <stdio.h>

//extern int myglob;
//extern int myglobal_func(int a, int b);
int myglob = 42;

int myglobal_func(int a, int b)
{
  myglob += a;
  return b + myglob;
}

int main() {
  printf("GlobalVar Initial value = %d\n", myglob);
  printf("myglobal_func returns %d\n", myglobal_func(10, 20));
  printf("GlobalVar updated value = %d\n", myglob);
  return 0;
}
