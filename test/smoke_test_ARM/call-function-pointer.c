//  clang -O0 -o %t %s -O2
// UNSUPPORTED: true
// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: Called function 1
// CHECK: Called function 2
// CHECK: Called function 3
// CHECK-EMPTY

#include <stdio.h>

void func(int i) { printf("Called function %d\n", i); }

int main() {
  void (*functions[3])(int);

  for (int i = 0; i < 3; ++i) {
    functions[i] = func;
  }

  for (int i = 0; i < 3; ++i) {
    functions[i](i + 1);
  }

  return 0;
}
