# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -debug %t.o 2>&1 | FileCheck %s

      .global test1
      .type test1, %function
test1:
      mov r0, #2
      mov r1, #3
      mov r2, r1
      mov r0, r2
      .size test1, .-test1

# CHECK: define i32 @test1() {
# CHECK: %4 = add i32 2, 0
# CHECK-NEXT: %5 = add i32 3, 0
# CHECK-NEXT: %6 = add i32 %5, 0
# CHECK-NEXT: %7 = add i32 %6, 0
