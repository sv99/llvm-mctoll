// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s -O2
// RUN: llvm-mctoll %mparams -d -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// OSX Undefined symbols for architecture x86_64 "___assert_fail", run in the docker
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: argc == 1
// CHECK-EMPTY

#include <stdio.h>
#include <assert.h>

int main(int argc, char **argv) {
  assert(argc == 1);
  printf("argc == 1\n");
  return 0;
}
