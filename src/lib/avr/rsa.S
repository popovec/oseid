/*
    rsa.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2017 Peter Popovec, popovec.peter@gmail.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    montgomery modular arithmetics 
    assembler for atmega328 atmega128 etc.. 

*/


//Assembler code below is equivalent to C code in card_os/rsa.c

/////////////////////////////////////////////////////////////////////////////
#include "load_sp.h"


        .global rsa_mod
        .type   rsa_mod, @function
	.section .text.rsa_mod,"ax",@progbits
        .global mp_mod
        .type   mp_mod, @function

// rsa_mod (rsa_long_num * result, rsa_num * mod)
// warning, it is assumed, higest bit in modulus is 1

// clock cycles:
//  1024->512bits| 1536->768 | 2048->1024
// unrolled 8x
//    262593     |   575021  |  1008281
#define RESULT_PTR r14
#define HELPER_PTR r16
#define HELPER_PTR_H r17
#define LOOP r1
#define BYTES r19
#define BYTES_1 r5
#define INDEX r20
#define	TMP0	r22
#define TMP1	r23

#define COUNTER r24
#define COUNTER_H r25
#define TMP r28

#define M_TABLE r12
#define M_TABLEl r12
#define M_TABLEh r13
// normal unrol is 4x, if this is defined unrol is 8x (code size +34 bytes)
#define UNROL

mp_mod:
rsa_mod:
	push	r2
	push	r3
	push	r4
	push	r5
	push	r12
	push	r13

	push	r14
	push	r15
	push	r16
	push	r17
	push	r28
	push	r29
	movw	RESULT_PTR,r24

	in	r28,0x3d
	in	r29,0x3e

#define ALLOC (RSA_BYTES*2+(RSA_BYTES+1)*8)

	subi	r28,lo8(ALLOC)
	sbci	r29,hi8(ALLOC)
	LOAD_SP	r0, r28,r29
// get pointers of TMP, RESULT and HELPER
	adiw	r28,1		// Y point to TMP variable

// copy modulus to M_TABLE
        movw    r30,r28         // Z points to modulus table
        movw    M_TABLE,r30     // save modulus table start
        st      Z+,r1           // 1st value padded by one zero byte
// copy modulus
        movw    r26,r22         // initial modulus start

	lds	r24,mod_len
        mov     BYTES,r24
	mov	BYTES_1,BYTES
	inc	BYTES_1

        mov     LOOP,BYTES
rsa_mod_init_loop_0:
        ld      r0,X+
        st      Z+,r0
        dec     LOOP
        brne    rsa_mod_init_loop_0

        ldi     r25,7           // rotated 7 numbers
rsa_mod_init_loop_1:
// from number end ..
        movw    r26,r30
        add     r30,BYTES
        adc     r31,r1
        adiw    r30,1
        movw    HELPER_PTR,r30  // save number end
        mov     LOOP,BYTES_1

        clc
rsa_mod_init_loop_2:
        ld      r0,-X
        ror     r0
        st      -Z,r0
        dec     LOOP
        brne    rsa_mod_init_loop_2
        movw    r30,HELPER_PTR  // renew number end

        dec     r25
        brne    rsa_mod_init_loop_1

	movw	r30,r28
	mov	LOOP,BYTES
rsa_mod_init_loop_3:
	ldd	r0,Z+1
	st	Z+,r0
	dec	LOOP
	brne	rsa_mod_init_loop_3
	st	z+,r1

///////////////////////////////////////////////////
//  stack:  8x (RSA_BYTES+1)      2xRSA_BYTES
//          ^                     ^
//          M_TABLE               HELPER_PTR

// copy low bytes from RESULT to HELPER
	movw	r26,RESULT_PTR
	movw	r30,HELPER_PTR
	mov	LOOP,BYTES
1:
	ld	TMP0,X+
	st	Z+,TMP0
	dec	LOOP
	brne	1b

// init variables
	clr	INDEX

	mov	COUNTER_H,BYTES
	clr	COUNTER
//////////////////////////////////////////////
// subtract TMP from RESULT if RESULT > TMP
// (always subtract, but change result pointer if  subtract generates carry)
// check details in C version card_os/rsa.c
	movw	r12,r28
	mov	r4,BYTES
	lsr	r4
	lsr	r4
#ifdef UNROL
	lsr	r4
#endif
// 1st loop is diferent (one byte skipped)
// M_TABLE index
	ldi	r18,1
	mov	LOOP,r4
	rjmp	rsa_mod_subtract

rsa_mod_calculate:
// set pointers
	movw	r26,RESULT_PTR
	sbrc	INDEX,0
	movw	r26,HELPER_PTR

	movw	r30,RESULT_PTR
	sbrs	INDEX,0
	movw	r30,HELPER_PTR

// do not subtract zeros in operand (low part in modulus = zeros)
	add	r30,COUNTER_H
	adc	r31,LOOP	// ZERO
	add	r26,COUNTER_H
	adc	r27,LOOP	// ZERO

// calculate position in M_TABLE
	mul	BYTES_1,r18
	inc	r18
	andi	r18,7
	movw	r28,r0

	add	r28,r12
	adc	r29,r13

	mov	LOOP,r4

        ld      TMP0,X+
        ld      TMP1,Y+
        sbc     TMP0,TMP1
        st      Z+,TMP0
rsa_mod_subtract:
#ifdef UNROL
.rept	8
#else
.rept 	4
#endif
	ld	TMP0,X+
	ld	TMP1,Y+
	sbc	TMP0,TMP1
	st	Z+,TMP0
.endr
	dec	LOOP
	brne	rsa_mod_subtract

// based on carry use new result .. (if not carry, HELPER is new RESULT)
	sbci	INDEX,1
	sbiw	COUNTER,32	// COUNTER is BYTES*256, not BYTES*8 -> 256/8=32)
	brcc	rsa_mod_calculate

//rsa_mod_calculate_end:
// copy proper result to real result
	movw	r30,RESULT_PTR
	sbrc	INDEX,0
	movw	r30,HELPER_PTR
	movw	r26,RESULT_PTR

rsa_mod_final_copy:
	ld	r0,Z+
	st	X+,r0
	dec	BYTES
	brne	rsa_mod_final_copy

	in	r28,0x3d
	in	r29,0x3e
	subi	r28,lo8(-ALLOC)
	sbci	r29,hi8(-ALLOC)
	LOAD_SP	r0, r28,r29
	pop	r29
	pop	r28
	pop	r17
	pop	r16
	pop	r15
	pop	r14

	pop	r13
	pop	r12
	pop	r5
	pop	r4
	pop	r3
	pop	r2
	ret
#undef UNROL
#undef RESULT_PTR
#undef HELPER_PTR
#undef HELPER_PTR_H
#undef LOOP
#undef BYTES
#undef INDEX
#undef TMP0
#undef TMP1
#undef COUNTER
#undef COUNTER_H
#undef TMP
#undef ALLOC

	.global	rsa_inv_mod_N
	.type	rsa_inv_mod_N,@function
	.section .text.rsa_inv_mod_N,"ax",@progbits

//void rsa_inv_mod_N (rsa_num * n_, rsa_num * modulus);

#if RSA_BYTES > 256
#error This code is designed for RSA_BYTES <=256
#endif
// clock cycles (constant time)
//  512bits |  768  |  1024
//   188300 | 400684| 694988

#define ALLOC  8*RSA_BYTES+512
rsa_inv_mod_N:
	movw	r20,r24	// save result position
	push	r28
	push	r29

// create table (8 numbers) and two TMP variables (both 256 bytes long
// to allow simpel switching by add 1 to upper byte of pointer)
	in	r28,0x3d
	in	r29,0x3e
	subi	r28,lo8(ALLOC)
	sbci	r29,hi8(ALLOC)
	LOAD_SP	r0, r28,r29
	adiw	r28,1

// clear allocated space (TODO only TMP need to be cleared)
	movw	r30,r28
	ldi	r24,lo8(ALLOC)
	ldi	r25,hi8(ALLOC)
rsa_inv_mod_full_0:
	st	Z+,r1
	sbiw	r24,1
	brne	rsa_inv_mod_full_0

// create table with rotated modulus (8x)
// 1st copy modulus
	lds	r24,mod_len
	mov	r1,r24
	movw	r30,r28
	movw	r26,r22	// modulus position
rsa_inv_mod_full_1:
	ld	r0,X+
	st	Z+,r0
	dec	r1
	brne	rsa_inv_mod_full_1

// X is pointer to table start
	movw	r26,r30
	sub	r26,r24
	sbci	r27,0

// copy and rotate
	ldi	r25,7	// 7 more numbers
rsa_inv_mod_full_2:
	clc
	mov	r1,r24
rsa_inv_mod_full_3:
	ld	r0,X+
	rol	r0
	st	Z+,r0
	dec	r1
	brne	rsa_inv_mod_full_3
	dec	r25
	brne	rsa_inv_mod_full_2

	mov	r18,r24	// byte counter
	mov	r23,r24	// copy of byte counter
	mov	r22,r24

// Z is pointer to TMP variable
	movw	r24,r30
// Y is pointer to table (stack+1)
	movw	r26,r20
// X is pointer to result

// add modulus to TMP variable (modulus is prerotated in table)
// based on bits in TMP generate inversion/new add of modulus to TMP

// r0 is result byte, this byte is updated and if full stored into result memory
rsa_inv_mod_full_byte_loop:
	clr	r0
	ldi	r19,1	//MASK
rsa_inv_mod_full_loop:
	movw	r30,r24
	ld	r20,Z
	and	r20,r19	// and by mask
// update result byte
	or	r0,r20
// calculate offset for TMP variable add 0/1 to high byte of pointer
	ldi	r21,0xff
	add	r20,r21
	adc	r31,r1

//add modulus (rotated..) to tmp variable
//	clc		// not needed, "adc" above always clear carry
	mov	r1,r18
rsa_inv_mod_full_add_loop:
	ld	r20,Y+
	ld	r21,Z
	adc	r21,r20
	st	Z+,r21
	dec	r1
	brne	rsa_inv_mod_full_add_loop

	sub	r28,r18
	sbc	r29,r1

	add	r28,r23
	adc	r29,r1
// rotate mask
	lsl	r19
	brcc	rsa_inv_mod_full_loop
// update result byte
	com	r0
	st	X+,r0
	dec	r18	// reduce add length
	adiw	r24,1	// reduce TMP variale length
// reload table position
	in	r28,0x3d
	in	r29,0x3e
	adiw	r28,1
// next byte ..
	dec	r22
	brne	rsa_inv_mod_full_byte_loop

// return stack back (r28,r29 is already loaded from SP)
// but incremented by one
//	in	r28,0x3d
//	in	r29,0x3e
	subi	r28,lo8(-(ALLOC-1))
	sbci	r29,hi8(-(ALLOC-1))
	LOAD_SP	r0, r28,r29

	pop	r29
	pop	r28
	ret
#undef ALLOC

        .global monPro0
        .type   monPro0, @function
	.section .text.monPro0,"ax",@progbits

#define PTR_t	r12
#define PTR_n	r14
#define PTR_n0	r16

//monPro0 (rsa_num * a, rsa_long_num * t, rsa_long_num * tmp,rsa_num * n, n0_t n0)
monPro0:
	push	r12
	push	r13
	push	r14
	push	r15
	push 	r16
	push	r17

	push	r28
	push	r29

	movw	PTR_t,r22	//t
	movw	PTR_n,r18	//n
	movw	r28,r20		//tmp

// a = t_low * n0
// PTR_A = PTR_t * PTR_n0
// r24   =  r22  * r16
	movw	r20,PTR_n0
#undef PTR_n0
#define PTR_A	r16
// reuse r16,17 - call saved reg - as PTR_A
	movw	PTR_A,r24
	call	rsa_mul_mod
// tmp = a * n
	movw	r24,r28
	movw	r22,PTR_A
	movw	r20,PTR_n
	call	rsa_mul

// do adding .. help = help + t (do not store low part back)
	lds	r24,mod_len
	lsr	r24
	lsr	r24
	lsr	r24
	mov	r1,r24

	movw	r30,PTR_t	//t
	movw	r26,PTR_n	//n
//18,19,20,21,22,23

//      clc                     // CY is always cleared (mod_len is return  always even number)
monPro0_add_loop_a:
.rept 8
	ld	r0,Y+
	ld	r25,Z+
	adc	r0,r25
.endr
	dec	r1
	brne	monPro0_add_loop_a
// from low part only carry is relevant for us

//upper part 
	mov	r1,r24
	clr	r24	//carry switcher (do not clear carry flag!)
monPro0_add_loop_b:

.irp pos 12,13,14,15,16,17,18,19
	ld	r\pos,Y
	ldd	r0,Z+(\pos-12)
	adc	r\pos,r0
	st	Y+,r\pos	//sum back into help
.endr
	ror	r24	//save "add" carry, renew "sub" carry

.irp pos,12,13,14,15,16,17,18,19
	ld	r0,X+		//
	sbc	r\pos,r0
	st	Z+,r\pos
.endr
	rol	r24	//renew "add" carry, save "sub" carry
	dec	r1
	brne	monPro0_add_loop_b

// add and sub carry in bit 0 and CY, do XOR
	adc	r24,r1	// 00 ->0 10 -> 1 01 ->1 11 ->0
	com	r24
	andi	r24,1

	pop	r29
	pop	r28
	pop	r17
	pop	r16
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret

#undef PTR_A
#undef PTR_t
#undef PTR_n

	.global	bn_abs_sub
	.type	bn_abs_sub,@function
	.section .text.bn_asb_sub,"ax",@progbits

bn_abs_sub:
	movw	r18,r24
	call	bn_sub
	movw	r30,r18
	tst	r24
	brne	bn_neg_no_abi
	ret

	.global	bn_neg
	.type	bn_neg,@function
	.section .text.bn_neg,"ax",@progbits

bn_neg:
	movw	r30,r24
bn_neg_no_abi:
	lds	r25,mod_len
	lsr	r25
// warning, do not change r24, bn_abs_sub() does not save r24
// warning r18,r19,r20 prime_gcd() uses this regs  without saving
bn_neg_no_abi2:
	sub	r0,r0	// clear r0 and carry flag
bn_neg_loop:
	movw	r22,r0
	ldd	r21,Z+0
	sbc	r22,r21
	ldd	r21,Z+1
	sbc	r23,r21
	st	Z+,r22
	st	Z+,r23

	dec	r25
	brne	bn_neg_loop
	ret

	.global	bn_count_bits
	.type	bn_count_bits,@function
	.section .text.bn_count_bits,"ax",@progbits

bn_count_bits:
	movw	r30,r24
	lds	r24,mod_len
	clr	r25
	add	r30,r24
	adc	r31,r1
1:
	subi	r24,1
	brcs	2f		// loop end
	ld	r0,-Z
	tst	r0
	breq	1b
// ok not zero byte
	lsl	r24
	rol	r25
	lsl	r24
	rol	r25
	lsl	r24
	rol	r25
1:
	adiw	r24,1
	lsr	r0
	brne	1b
	ret
2:
	clr	r24
	ret


#if 1

	.global	prime_gcd
	.type	prime_gcd,@function
	.section .text.prime_gcd1,"ax",@progbits
#define Vl r12
#define Ul r14
#define TMP r18
#define TMPh r19
#include "../../card_os/constants.h"
prime_gcd:
	movw	r30,r24	// number position
	push	r12
	push	r13
	push	r14
	push	r15
	push	r28
	push	r29

	in	r28,0x3d
	in	r29,0x3e
// stack - 3x RSA_BYTES (but 4x is faster, smaller .. )
#if RSA_BYTES > 128
#error This code must be changed for RSA_BYTES > 128
#endif
#if 0
	subi	r28,lo8(RSA_BYTES*3)
	sbci	r29,hi8(RSA_BYTES*3)
	LOAD_SP	r0, r28,r29
#else
	subi	r29,2
	out	0x3e,r29
#endif
	adiw	r28,1
	movw	Vl,r28
// ZEROize
	ldi	r24,RSA_BYTES
	movw	r26,r28
1:
	st	X+,r1
	dec	r24
	brne	1b
// save end
	movw	Ul,r26
// V = tested number
	lds	r25,mod_len
1:
	ld	r24,Z+
	st	Y+,r24
	dec	r25
	brne	1b
// load constant
	movw	r24,Ul
	ldi	r22,N_GCD_PRIMES
	call	get_constant

// TMP variable pointer
	movw	TMP,Ul
	subi	TMP,lo8(-RSA_BYTES)
	sbci	TMPh,hi8(-RSA_BYTES)

prime_gcd_loop:
// if 'v' is even, rotate 'v' to get odd 'v'
1:	movw	r30,Vl
	ld	r24,Z
	ror	r24
	brcs	1f
	movw	r24,Vl
	ldi	r22,RSA_BYTES
	clr	r20
	call	bn_shift_R_v_c
	rjmp	1b

// subtract V=V-U
1:
	movw	r26,Ul
	movw	r28,TMP
	ldi	r25,RSA_BYTES
	sub	r20,r20
1:	ld	r0,Z+
	ld	r24,X+
	sbc	r0,r24
	or	r20,r0	// ZERO test
	st	Y+,r0
	dec	r25
	brne	1b

	brcc	1f
// minus

// TMP must be negated,
	movw	r30,TMP
	ldi	r25,(RSA_BYTES/2)
	call	bn_neg_no_abi2

// swap U,V
	movw	r24,Ul
	movw	Ul,Vl
	movw	Vl,r24
1:
//plus
	movw	r24,TMP
	movw	TMP,Vl
	movw	Vl,r24

	tst	r20	// ZERO ?
	brne	prime_gcd_loop

// test if U == 1 (negate bit 0, then check zero)
	movw	r30,Ul
	ld	r0,Z
	ldi	r24,1
	eor	r24,r0
	st	Z,r24
	movw	r24,Ul
// maximal GCD length is mod_len, there is no need to check RSA_BYTES
	call	bn_is_zero

#if 0
	in	r28,0x3d
	in	r29,0x3e
	subi	r28,lo8(-(RSA_BYTES*3))
	sbci	r29,hi8(-(RSA_BYTES*3))
	LOAD_SP	r0, r28,r29
#else
	in	r29,0x3e
	subi	r29,-2
	out	0x3e,r29
#endif
	pop	r29
	pop	r28
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret
#endif

#undef Vl
#undef Ul
#undef TMP
#undef TMPh

