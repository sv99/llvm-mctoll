// RUN: clang %c-target -o %t %s
// RUN: llvm-mctoll -d %m-target -I %S/test-inc.h %t
// RUN: clang %c-target -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: Hello world!

#include <stdio.h>
int main(int argc, char **argv) {
  printf("Hello world!\n");
  return 0;
}
