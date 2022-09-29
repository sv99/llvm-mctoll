// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll %mparams -d -I %S/test-inc.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 0x7fffffffffffffff
// CHECK: 0xffffffffffffffff
// CHECK-EMPTY

#include <stdio.h>
#include <limits.h>

void test(long int x) {
  printf("0x%lx\n", x);
}

int main() {
  test(LONG_MAX);
  test(ULONG_MAX);

  return 0;
}
