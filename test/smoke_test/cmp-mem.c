// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s -O3 -fno-inline
// RUN: llvm-mctoll %mparams -d -I %S/test-inc.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
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
