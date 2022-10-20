# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -debug %t.o 2>&1 | FileCheck %s

        .global adc2
        .type adc2, %function
adc2:
        # no CPSR Two Address mode
        mov r0, #2
        mov r1, #3
        adc r0, r1
        .size    adc2, .-adc2

# CHECK: define i32 @adc2() {
# CHECK: %4 = add i32 2, 0
# CHECK-NEXT: %5 = add i32 3, 0
# CHECK-NEXT: %6 = load i1, ptr %2, align 1
# CHECK-NEXT: %7 = zext i1 %6 to i32
# CHECK-NEXT: %8 = add i32 %4, %7
# CHECK-NEXT: %9 = add i32 %8, %5

       .global adc3
       .type adc3, %function
adc3:
        # no CPSR Three Address mode
        mov r1, #4
        mov r2, #5
        adc r0, r1, r2
        .size    adc3, .-adc3

# CHECK: define i32 @adc3() {
# CHECK: %4 = add i32 4, 0
# CHECK-NEXT: %5 = add i32 5, 0
# CHECK-NEXT: %6 = load i1, ptr %2, align 1
# CHECK-NEXT: %7 = zext i1 %6 to i32
# CHECK-NEXT: %8 = add i32 %4, %7
# CHECK-NEXT: %9 = add i32 %8, %5

        .global adc3imm
        .type adc3imm, %function
adc3imm:
        # no CPSR Three Address mode with const
        mov r1, #7
        adc r0, r1, #5
        .size    adc3imm, .-adc3imm

# CHECK: define i32 @adc3imm() {
# CHECK: %4 = add i32 7, 0
# CHECK-NEXT: %5 = load i1, ptr %2, align 1
# CHECK-NEXT: %6 = zext i1 %5 to i32
# CHECK-NEXT: %7 = add i32 %4, %6
# CHECK-NEXT: %8 = add i32 %7, 5