# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -debug %t.o 2>&1 | FileCheck %s

       .global cond_cs
       .type cond_cs, %function
cond_cs:
        # Three Address mode with CPSR
        cmp r0, #10
        adccs r0, #5
        .size   cond_cs, .-cond_cs

# CHECK: define i32 @cond_cs(i32 %arg.1) {
# CHECK: 15:
# CHECK-NEXT: %16 = load i1, ptr %2, align 1
# CHECK-NEXT: %17 = zext i1 %16 to i32
# CHECK-NEXT: %18 = add i32 %4, %17
# CHECK-NEXT: %19 = add i32 %18, 5
