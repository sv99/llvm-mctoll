// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -O3 -o %t %s
// RUN: llvm-mctoll %mparams -d -I %S/test-inc.h %t
// RUN: cat %t-dis.ll 2>&1 | FileCheck %s
// CHECK: %{{.*}} = call i32 (ptr, ...) @printf(ptr {{.*}}), double %{{.*}})

#include <stdio.h>

int main() {
  printf("%.1f\n", 0.0);
  return 0;
}
