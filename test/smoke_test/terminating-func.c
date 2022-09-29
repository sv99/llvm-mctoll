// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s -O2
// RUN: llvm-mctoll %mparams -d -I %S/test-inc.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: Hello from main!
// CHECK-NEXT: Bye!
// CHECK-EMPTY

#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
void exit_with_msg(const char *msg) {
  printf("%s\n", msg);
  exit(0);
}

__attribute__((noinline))
int exit_conditionally(int exit) {
  if (exit) {
    exit_with_msg("Bye!");
    return 0;
  } else {
    return printf("Not exiting");
  }
}

int main() {
  printf("Hello from main!\n");
  exit_conditionally(1);
  return 0;
}
