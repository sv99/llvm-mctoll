// UNSUPPORTED: true
// error: instruction expected to be numbered '%24'
// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: true or true = true
// CHECK-NEXT: true or false = true
// CHECK-NEXT: false or true = true
// CHECK-NEXT: false or false = false

#include <stdio.h>

typedef int bool;
#define true 1
#define false 0

//extern bool orvalues(bool r, bool y);
//typedef int bool;
bool orvalues(bool r, bool y) { return (y || r); }

int main() {
  printf("true or true = %s\n", (orvalues(true, true) ? "true" : "false"));
  printf("true or false = %s\n", (orvalues(true, false) ? "true" : "false"));
  printf("false or true = %s\n", (orvalues(false, true) ? "true" : "false"));
  printf("false or false = %s\n", (orvalues(false, false) ? "true" : "false"));
  return 0;
}
