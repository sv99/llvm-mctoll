// UNSUPPORTED: true
// Assertion failed: (NPMap[Node] != nullptr && "Cannot find the corresponding node property!"), function getRealValue, file DAGRaisingInfo.cpp, line 25.
// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -o %t %s
// RUN: llvm-mctoll -d %mparams -I %S/test-inc.h %t
// RUN: clang %cparams -o %t1 %t-dis.ll
// RUN: %run-elf %t1 2>&1 | FileCheck %s
// CHECK: Lesser
// CHECK-NEXT: Equal
// CHECK-NEXT: Greater

#include <stdio.h>

//extern int libc_strcmp(const char *p1, const char *p2);
int libc_strcmp(const char *p1, const char *p2) {
  const unsigned char *s1 = (const unsigned char *)p1;
  const unsigned char *s2 = (const unsigned char *)p2;
  unsigned char c1, c2;

  do {
    c1 = (unsigned char)*s1++;
    c2 = (unsigned char)*s2++;
    if (c1 == '\0')
      return c1 - c2;
  } while (c1 == c2);

  return c1 - c2;
}

int main() {
  const char s1[] = "This is a string with label AOne";
  const char s2[] = "This is a string with label ATwo";

  int val = libc_strcmp(s1, s2);

  if (val > 0) {
    printf("Greater\n");
  } else if (val == 0) {
    printf("Equal\n");
  } else {
    printf("Lesser\n");
  }

  val = libc_strcmp(s2, s2);
  if (val > 0) {
    printf("Greater\n");
  } else if (val == 0) {
    printf("Equal\n");
  } else {
    printf("Lesser\n");
  }

  val = libc_strcmp(s2, s1);
  if (val > 0) {
    printf("Greater\n");
  } else if (val == 0) {
    printf("Equal\n");
  } else {
    printf("Lesser\n");
  }

  return 0;
}
