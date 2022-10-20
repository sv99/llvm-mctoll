// RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
// RUN: llvm-mctoll -d -debug  %t.o 2>&1 | FileCheck %s
// CHECK: CFG : After ARM MI Revising
// CHECK: BL 32,

int func1(int a, int b) {
  return a + b;
}

int func2(int c, int d) {
  return c - d;
}

int funcend() {
  return func2(5, 3);
}

