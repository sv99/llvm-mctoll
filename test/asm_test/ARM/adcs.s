# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -debug %t.o 2>&1 | FileCheck %s

        .global adcs2
        .type adcs2, %function
adcs2:
        # no CPSR Two Address mode
        mov r0, #2
        mov r1, #3
        adcs r0, r1
        .size    adcs2, .-adcs2

# CHECK: define i32 @adcs2() {
# CHECK: %4 = add i32 2, 0
# CHECK-NEXT: %5 = add i32 3, 0
# CHECK-NEXT: %6 = load i1, ptr %2, align 1
# CHECK-NEXT: %7 = zext i1 %6 to i32
# CHECK-NEXT: %8 = add i32 %4, %7
# CHECK-NEXT: %9 = add i32 %8, %5

       .global adcs3
       .type adcs3, %function
adcs3:
        # no CPSR Three Address mode
        mov r1, #4
        mov r2, #5
        adcs r0, r1, r2
        .size    adcs3, .-adcs3

# CHECK: define i32 @adcs3() {
# CHECK: %4 = add i32 4, 0
# CHECK-NEXT: %5 = add i32 5, 0
# CHECK-NEXT: %6 = load i1, ptr %2, align 1
# CHECK-NEXT: %7 = zext i1 %6 to i32
# CHECK-NEXT: %8 = add i32 %4, %7
# CHECK-NEXT: %9 = add i32 %8, %5

        .global adcs3imm
        .type adcs3imm, %function
adcs3imm:
        # no CPSR Three Address mode with const
        mov r1, #7
        adcs r0, r1, #5
        .size    adcs3imm, .-adcs3imm

# CHECK: i32 @adcs3imm() {
# CHECK: %4 = add i32 7, 0
# CHECK-NEXT: %5 = load i1, ptr %2, align 1
# CHECK-NEXT: %6 = zext i1 %5 to i32
# CHECK-NEXT: %7 = add i32 %4, %6
# CHECK-NEXT: %8 = add i32 %7, 5
# CHECK-NEXT: %9 = call { i32, i1 } @llvm.uadd.with.overflow.i32(i32 %7, i32 5)
# CHECK-NEXT: %10 = call { i32, i1 } @llvm.sadd.with.overflow.i32(i32 %7, i32 5)
# CHECK-NEXT: %11 = extractvalue { i32, i1 } %9, 0
# CHECK-NEXT: %12 = lshr i32 %11, 31
# CHECK-NEXT: %13 = trunc i32 %12 to i1
# CHECK-NEXT: store i1 %13, ptr %0, align 1
# CHECK-NEXT: %14 = icmp eq i32 %11, 0
# CHECK-NEXT: store i1 %14, ptr %1, align 1
# CHECK-NEXT: %15 = extractvalue { i32, i1 } %9, 1
# CHECK-NEXT: store i1 %15, ptr %2, align 1
# CHECK-NEXT: %16 = extractvalue { i32, i1 } %10, 1
# CHECK-NEXT: store i1 %16, ptr %3, align 1
