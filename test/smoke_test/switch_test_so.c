// REQUIRES: system-linux
// RUN: clang -o %t.so %S/Inputs/switch_func.c -shared -fPIC
// RUN: llvm-mctoll -d -I %S/test-inc.h %t.so
// RUN: clang -o %t-so-dis %s %t-dis.ll
// RUN: %t-so-dis 2>&1 | FileCheck %s -check-prefix=DSO
// DSO: Switch 1
// DSO-NEXT: Return 15
// DSO-NEXT: Switch 2
// DSO-NEXT: Return 17
// DSO-NEXT: Switch 3
// DSO-NEXT: Return 18
// DSO-NEXT: Switch 4
// DSO-NEXT: Return 14
// DSO-NEXT: Switch 5
// DSO-NEXT: Return 16
// DSO-NEXT: Switch 6
// DSO-NEXT: Return 18
// DSO-NEXT: Switch 7
// DSO-NEXT: Return 22
// DSO-NEXT: Switch 8
// DSO-NEXT: Return 23
// DSO-NEXT: Switch 9
// DSO-NEXT: Return 22

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
