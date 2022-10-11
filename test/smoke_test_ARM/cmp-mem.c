// 61:7: error: void type only allowed for function results
// UNSUPPORTED: true
// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s -fno-inline
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
//  %t1 2>&1 | FileCheck %s
// CHECK: x > 0
// CHECK-EMPTY

#include <stdio.h>

typedef struct {
  int x;
} Data;

void test(Data *data) {
  if (data->x > 0) {
    printf("x > 0\n");
  } else {
    printf("x <= 0\n");
  }
}

int main() {
  Data data;
  data.x = 1 << 16;
  test(&data);
}
