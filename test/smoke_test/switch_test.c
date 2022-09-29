// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s %S/Inputs/switch_func.c
// RUN: llvm-mctoll %mparams -d -I %S/test-inc.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s -check-prefix=EXEC
// EXEC: Switch 1
// EXEC-NEXT: Return 15
// EXEC-NEXT: Switch 2
// EXEC-NEXT: Return 17
// EXEC-NEXT: Switch 3
// EXEC-NEXT: Return 18
// EXEC-NEXT: Switch 4
// EXEC-NEXT: Return 14
// EXEC-NEXT: Switch 5
// EXEC-NEXT: Return 16
// EXEC-NEXT: Switch 6
// EXEC-NEXT: Return 18
// EXEC-NEXT: Switch 7
// EXEC-NEXT: Return 22
// EXEC-NEXT: Switch 8
// EXEC-NEXT: Return 23
// EXEC-NEXT: Switch 9
// EXEC-NEXT: Return 22

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
