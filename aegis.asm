
section .text
global update_state

update_state:
    ; Arguments:
    ; rdi - pointer to state (array of 8 u128 values)
    ; rsi - m0 (u128 value)
    ; rdx - m1 (u128 value)

    ; Save last state (state[7]) into r8
    movups xmm8, [rdi + 7*16]

    ; XOR state[4] with m1 and store in xmm9 (t[1])
    movups xmm9, [rdi + 4*16]
    pxor xmm9, xmmword [rdx]

    ; AESENC state[7], state[6] -> update state[7]
    movups xmm0, [rdi + 6*16]
    aesenc xmm8, xmm0
    movups [rdi + 7*16], xmm8

    ; AESENC state[6], state[5] -> update state[6]
    movups xmm1, [rdi + 5*16]
    aesenc xmm0, xmm1
    movups [rdi + 6*16], xmm0

    ; AESENC state[5], state[4] -> update state[5]
    movups xmm2, [rdi + 4*16]
    aesenc xmm1, xmm2
    movups [rdi + 5*16], xmm1

    ; AESENC state[4], t[1] -> update state[4]
    movups xmm3, [rdi + 3*16]
    aesenc xmm2, xmm9
    movups [rdi + 4*16], xmm2

    ; XOR state[0] with m0 and store in xmm10 (t[0])
    movups xmm10, [rdi]
    pxor xmm10, xmmword [rsi]

    ; AESENC state[3], state[2] -> update state[3]
    movups xmm4, [rdi + 2*16]
    aesenc xmm3, xmm4
    movups [rdi + 3*16], xmm3

    ; AESENC state[2], state[1] -> update state[2]
    movups xmm5, [rdi + 16]
    aesenc xmm4, xmm5
    movups [rdi + 2*16], xmm4

    ; AESENC state[1], state[0] -> update state[1]
    aesenc xmm5, xmm10
    movups [rdi + 16], xmm5

    ; AESENC state[0], last_state -> update state[0]
    aesenc xmm10, xmm8
    movups [rdi], xmm10

    ; Return
    ret
