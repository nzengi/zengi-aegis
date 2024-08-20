section .data
    ; Constants used in AES encryption (precomputed)
    c0: dq 0x150d080503020101, 0x00e99059372279e9
    c1: dq 0x20f12fc26d55183d, 0xdbdd28b573423111

section .text
    global update_state

; Update state function
; Input: rdi - pointer to state (array of 8 u128), rsi - m0, rdx - m1
update_state:
    ; Load last state (st[7]) into xmm8
    movaps xmm8, [rdi + 7*16]

    ; XOR st[4] with m1 and store result in xmm9
    movaps xmm9, [rdi + 4*16]
    pxor xmm9, [rdx]

    ; Perform AES rounds on state
    movaps xmm0, [rdi + 6*16]
    aesenc xmm8, xmm0
    movaps [rdi + 7*16], xmm8

    movaps xmm1, [rdi + 5*16]
    aesenc xmm0, xmm1
    movaps [rdi + 6*16], xmm0

    movaps xmm2, [rdi + 4*16]
    aesenc xmm1, xmm2
    movaps [rdi + 5*16], xmm1

    aesenc xmm2, xmm9
    movaps [rdi + 4*16], xmm2

    ; XOR st[0] with m0 and store result in xmm10
    movaps xmm10, [rdi]
    pxor xmm10, [rsi]

    movaps xmm3, [rdi + 3*16]
    aesenc xmm3, xmm10
    movaps [rdi + 3*16], xmm3

    movaps xmm4, [rdi + 2*16]
    aesenc xmm3, xmm4
    movaps [rdi + 2*16], xmm3

    movaps xmm5, [rdi + 16]
    aesenc xmm4, xmm5
    movaps [rdi + 16], xmm4

    aesenc xmm5, xmm8
    movaps [rdi], xmm5

    ret

; Absorb data into state
; Input: rdi - pointer to state, rsi - pointer to data (t[0], t[1])
absorb_data:
    ; Call update_state with the data inputs
    mov rdx, [rsi + 16]  ; m1
    call update_state
    ret

; Encrypt function
; Input: rdi - pointer to state, rsi - pointer to data (t[0], t[1])
; Output: xmm0 - encrypted block (out[0]), xmm1 - encrypted block (out[1])
encrypt_block:
    ; Load state into registers
    movaps xmm2, [rdi + 2*16]  ; st[2]
    movaps xmm3, [rdi + 3*16]  ; st[3]
    movaps xmm6, [rdi + 6*16]  ; st[6]
    movaps xmm7, [rdi + 7*16]  ; st[7]

    ; XOR and AND operations to create mask
    movaps xmm0, xmm2
    pand xmm0, xmm3            ; mask[0] = st[2] & st[3]

    movaps xmm1, xmm6
    pand xmm1, xmm7            ; mask[1] = st[6] & st[7]

    ; XOR st[6] with st[1] and st[2] with st[5]
    movaps xmm4, [rdi + 16]    ; st[1]
    pxor xmm6, xmm4            ; z[0] = st[6] ^ st[1]

    movaps xmm5, [rdi + 5*16]  ; st[5]
    pxor xmm2, xmm5            ; z[1] = st[2] ^ st[5]

    ; XOR masks with z[0] and z[1]
    pxor xmm6, xmm0            ; z[0] ^= mask[0]
    pxor xmm2, xmm1            ; z[1] ^= mask[1]

    ; XOR the result with the input data
    movaps xmm0, [rsi]         ; t[0]
    pxor xmm0, xmm6            ; out[0] = t[0] ^ z[0]

    movaps xmm1, [rsi + 16]    ; t[1]
    pxor xmm1, xmm2            ; out[1] = t[1] ^ z[1]

    ; Update state with the input data
    call update_state
    ret

; Decrypt function
; Input: rdi - pointer to state, rsi - pointer to ciphertext (t[0], t[1])
; Output: xmm0 - decrypted block (out[0]), xmm1 - decrypted block (out[1])
decrypt_block:
    ; Load state into registers
    movaps xmm2, [rdi + 2*16]  ; st[2]
    movaps xmm3, [rdi + 3*16]  ; st[3]
    movaps xmm6, [rdi + 6*16]  ; st[6]
    movaps xmm7, [rdi + 7*16]  ; st[7]

    ; XOR and AND operations to create mask
    movaps xmm0, xmm2
    pand xmm0, xmm3            ; mask[0] = st[2] & st[3]

    movaps xmm1, xmm6
    pand xmm1, xmm7            ; mask[1] = st[6] & st[7]

    ; XOR st[6] with st[1] and st[2] with st[5]
    movaps xmm4, [rdi + 16]    ; st[1]
    pxor xmm6, xmm4            ; z[0] = st[6] ^ st[1]

    movaps xmm5, [rdi + 5*16]  ; st[5]
    pxor xmm2, xmm5            ; z[1] = st[2] ^ st[5]

    ; XOR masks with z[0] and z[1]
    pxor xmm6, xmm0            ; z[0] ^= mask[0]
    pxor xmm2, xmm1            ; z[1] ^= mask[1]

    ; XOR the result with the ciphertext
    movaps xmm0, [rsi]         ; t[0]
    pxor xmm0, xmm6            ; out[0] = t[0] ^ z[0]

    movaps xmm1, [rsi + 16]    ; t[1]
    pxor xmm1, xmm2            ; out[1] = t[1] ^ z[1]

    ; Update state with the decrypted data
    call update_state
    ret

; Initialize state function
; Input: rdi - pointer to state, rsi - key pointer, rdx - nonce pointer
initialize_state:
    ; Load key and nonce
    movaps xmm0, [rsi]
    movaps xmm1, [rdx]

    ; XOR key with nonce
    pxor xmm0, xmm1
    movaps [rdi], xmm0          ; st[0] = key ^ nonce

    ; Load constant c1 and store in state[1] and state[3]
    movaps xmm2, [c1]
    movaps [rdi + 16], xmm2     ; st[1] = c1
    movaps [rdi + 3*16], xmm2   ; st[3] = c1

    ; Load constant c0 and store in state[2]
    movaps xmm3, [c0]
    movaps [rdi + 2*16], xmm3   ; st[2] = c0

    ; XOR key with c0 and store in state[5] and state[7]
    pxor xmm0, xmm3
    movaps [rdi + 5*16], xmm0   ; st[5] = key ^ c0
    movaps [rdi + 7*16], xmm0   ; st[7] = key ^ c0

    ; XOR key with c1 and store in state[6]
    pxor xmm0, xmm2
    movaps [rdi + 6*16], xmm0   ; st[6] = key ^ c1

    ; Perform 10 rounds of state update
    mov rsi, rdx                ; m0 = nonce
    mov rdx, rsi                ; m1 = key
    mov ecx, 10
update_loop:
    call update_state
    loop update_loop

    ret

; Finalize function
; Input: rdi - pointer to state, rsi - tag pointer, rdx - ad_len, rcx - msg_len
finalize_encryption:
    ; Reject weak keys
    call reject_weak_keys

    ; Prepare sizes for the finalization
    shl rdx, 3                  ; ad_len <<= 3
    shl rcx, 3                  ; msg_len <<= 3

    ; XOR sizes into state[2]
    movaps xmm0, [rdi + 2*16]
    pxor xmm0, [rdx]
    movaps [rdi + 2*16], xmm0

    ; Perform final rounds of updates
    mov ecx, 7
finalize_loop:
    call update_state
    loop finalize_loop

    ; Generate and store the tag (or verify if needed)
    ; Implementation left as per the original function logic

    ret

; Helper function to reject weak keys
; Input: rdi - pointer to state
reject_weak_keys:
    ; Compare state[0] with state[1]
    movaps xmm0, [rdi]
    movaps xmm1, [rdi + 16]
    pxor xmm0, xmm1

    ; Loop through the rest of the state to perform XOR
    mov ecx, 6
    lea rsi, [rdi + 2*16]
reject_loop:
    movaps xmm1, [rsi]
    pxor xmm0, xmm1
    add rsi, 16
    loop reject_loop

    ; Check if result is zero (weak key)
    pxor xmm1, xmm1
    pcmpeqq xmm0, xmm1
    pmovmskb rax, xmm0
    add rax, 1
    shr rax, 16
    neg rax

    ret
