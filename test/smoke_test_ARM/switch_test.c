// This test is disabled till work resumes on support for
// raising ARM binaries to catch-up with that for x64 binaries.
// Assertion failed: (NPMap[Node] != nullptr && "Cannot find the corresponding node property!"), function getRealValue, file DAGRaisingInfo.cpp, line 25.
// UNSUPPORTED: true
// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -c -o %t %S/Inputs/switch_func.c
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang -o %t1 %t-dis.ll %s
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Switch 1
// CHECK-NEXT: Return 15
// CHECK-NEXT: Switch 2
// CHECK-NEXT: Return 17
// CHECK-NEXT: Switch 3
// CHECK-NEXT: Return 18
// CHECK-NEXT: Switch 4
// CHECK-NEXT: Return 14
// CHECK-NEXT: Switch 5
// CHECK-NEXT: Return 16
// CHECK-NEXT: Switch 6
// CHECK-NEXT: Return 18
// CHECK-NEXT: Switch 7
// CHECK-NEXT: Return 22
// CHECK-NEXT: Switch 8
// CHECK-NEXT: Return 23
// CHECK-NEXT: Switch 9
// CHECK-NEXT: Return 22

#include <stdio.h>
#include <stdlib.h>

extern int switch_test(int);

int main(int argc, char** argv) {
  int n = 0;

  if (argc > 1) {
    n = atoi(argv[1]);
    printf("Return %d\n", switch_test(n));
  }
  else {
    for (int n = 1; n < 10; n++) {
      printf("Switch %d\n", n);
      printf("Return %d\n", switch_test(n));
    }
  }

  return 0;
}
