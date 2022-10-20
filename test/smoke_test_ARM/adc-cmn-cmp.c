// REQUIRES: system-linux || system-darwin
// RUN: clang %cparams -mfloat-abi=soft -c -o %t %S/Inputs/adc-cmn-cmp.s
// RUN: llvm-mctoll %mparams -d -I %S/test-inc.h %t
// RUN: clang -o %t1 %s %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: adc2: 2 + 3 = 5
// CHECK-NEXT: adc3: 2 + 3 = 5
// CHECK-NEXT: adc2_cmn: 2 + 3 = 6
// CHECK-NEXT: adc3_cmp: 2 + 3 = 6

#include <stdio.h>

extern int adc2(int op1, int op2);
extern int adc3(int op1, int op2);
extern int adc2_cmn(int op1, int op2);
extern int adc3_cmp(int op1, int op2);

int main() {
  printf("adc2: 2 + 3 = %d\n", adc2(2, 3));
  printf("adc3: 2 + 3 = %d\n", adc3(2, 3));
  printf("adc2_cmn: 2 + 3 = %d\n", adc2_cmn(2, 3));
  printf("adc3_cmp: 2 + 3 = %d\n", adc3_cmp(2, 3));
  return 0;
}