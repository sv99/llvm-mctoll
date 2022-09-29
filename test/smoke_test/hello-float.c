// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll %mparams -d -I %S/test-inc.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Hello float: 0.5
// CHECK: Mixed int, float: 1, 0.5

#include <stdio.h>

int main(int argc, char **argv) {
  printf("Hello float: %.1f\n", 0.5f);
  printf("Mixed int, float: %d, %.1f\n", 1, 0.5f);
  return 0;
}
