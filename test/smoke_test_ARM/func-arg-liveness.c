// UNSUPPORTED: true
// Assertion failed: (NPMap[Node] != nullptr && "Cannot find the corresponding node property!"), function getRealValue, file DAGRaisingInfo.cpp, line 25.
// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s -O2
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: Value 12
// CHECK: Value 4

/* Compiling this test with -O2 generates code with no prolog
   and use of first argument occurs in a basic block other than
   the first. This tests detection of argument register usage
   anywhere in the CFG
*/

#include <stdio.h>

void call_me(int i, int j) {
  int a;
  if (j == 0) {
    a = 4;
  } else {
    a = i + j;
  }
  printf("Value %d\n", a);
  return;
}

int main(int argc, char **argv) {
  call_me(10, 2);
  call_me(10, 0);
  return 0;
}
