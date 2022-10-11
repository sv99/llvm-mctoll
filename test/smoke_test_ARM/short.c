// UNSUPPORTED: true
// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Short result: 5

#include <stdio.h>

short func(short a1, short a2) {
  short c1, c2;
  c1 = 2;
  c2 = a1 + a2;

  return c1 + c2;
}

int main() {
  printf("Short result: %d\n", func(1, 2));
  return 0;
}
