// REQUIRES: system-linux || system-darwin
// XFAIL: x86_64
// RUN: clang %cparams -c %s -o %t
// RUN: llvm-mctoll %mparams -d -I %S/test-inc.h %t 2>&1 | FileCheck %s
// CHECK: Raising x64 relocatable (.o) x64 binaries not supported

#include <stdio.h>
int main(int argc, char **argv) {
  printf("Hello world!\n");
  return 0;
}
