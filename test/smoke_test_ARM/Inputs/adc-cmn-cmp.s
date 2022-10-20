
       .global adc2
       .type adc2, %function
adc2:
        # adc without carry
        adc r0, r1
        .size    adc2, .-adc2

       .global adc2_cmn
       .type adc2_cmn, %function
adc2_cmn:
        # set carry flag
        cmp r1, #10
        # adc with cary
        adc r0, r1
        .size    adc2_cmn, .-adc2_cmn

       .global adc3
       .type adc3, %function
adc3:
        # adc without carry
        adc r0, r0, r1
        .size    adc3, .-adc3

       .global adc3_cmp
       .type adc3_cmp, %function
adc3_cmp:
       # set carry flag
        # adc with cary
        mov r2, #1
        sub r2, #2
        cmn r1, r2
        adc r0, r1
        .size    adc3_cmp, .-adc3_cmp