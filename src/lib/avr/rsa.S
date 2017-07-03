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


// (uint8_t *result, uint8_t *t  uint8_t *n,  uint16_t n0)

//Assembler code below is equivalent to C code in card_os/rsa.c

/////////////////////////////////////////////////////////////////////////////
#include "load_sp.h"

#ifdef HAVE_MON_PRO0
        .global monPro0
        .type   monPro0, @function
#if USE_N0 == 8
#warning, not designet for RSA_BYTES != 64

#define SAVE_Z	r14
#define N_PTR	r16
#define LOOP_I	r18
#define LOOP_J	r19
#define ZERO	r25
#define N_0	r20
#define VAR_M	r21
#define ACC_L	r24
#define ACC_H	r25
monPro0:
	movw	r30,r22	//Z is used to address t
// save registers .. 
        push	r14
	push	r15
	push	r16
	push	r17

	push	r24
	push	r25		// save pointer to result..

	movw	N_PTR,r20	// save pointer to "n"
	mov	N_0,r18

	clr	ZERO		// temporary zero register
// load loop variable - maximum 256 loops 
	call	rsa_get_len
	mov	LOOP_I,r24
//========================================================================================
monPro0_loop_I:
	ld	VAR_M,Z		// load t[]
	movw	SAVE_Z,r30	// save Z (t)
	movw	r26,N_PTR	// renew "n" position to X
// calculate m 
	mul	VAR_M,N_0	//get m (n0 * t[i]) into r0
	mov	VAR_M,r0	//get m into VAR_M
//========================================================================================
.macro t_n_m
// multiple t*n  (t[i+j]=t[i+j] + n[j] * m + Carry
// first calculate (r0,r1) = n[j] * m
	ld	r22,X+		// load n[j]
	mul	r22,VAR_M	// n[j] * m
// r0,r1 = (r0,r1) + C
	add	r0,r24
	adc	r1,ZERO
// load t[i+j]
	ld	r22,Z
// r0,r1 = (r0,r1) + t[i+j]
	add	r0,r22
	adc	r1,ZERO
// return sum (r0) to t[i,j]
	st	Z+,r0
// save C (r1)
	mov	r24,r1
.endm
	call	rsa_get_len
	mov	LOOP_J,r24
	clr	r24		// clear initial Carry
monPro0_loop_J:
	t_n_m
	dec	LOOP_J
	brne	monPro0_loop_J
//========================================================================================
// update upper byte from multiplication .. 
	ld	r22,Z
	add	r22,r24
	st	Z+,r22

// propagate carry to upper bits of 't'

	mov     LOOP_J,LOOP_I
monPro0_loop_prop_carry:
	dec	LOOP_J
	breq	monPro0_end0
	ld	r22,Z
	adc	R22,ZERO
	st	Z+,r22
	rjmp	monPro0_loop_prop_carry
//========================================================================================
monPro0_end0:
	movw	r30,SAVE_Z 	// return Z to point on 't[i]' 
	ld	VAR_M,Z+	// increment Z, do not touch carry! (VAR_M is ignored)
	dec	LOOP_I		// decrement loop variable, do not touch carry! 
	breq	monPro0_end
	rjmp	monPro0_loop_I

monPro0_end:
// save carry bit in N_0
	clr	N_0
// save carry bit in r1
	adc	N_0,N_0
// 't' to 'n' comparation  (do subtract, get result from t or t-n)
// r30 point to 't' upper bits
// save pointer to Z 
	movw	SAVE_Z,r30
// N_PTR point to 'n'

// subtract
	movw	r26,N_PTR
	push	r28
	push	r29

	movw	r28,SAVE_Z
	movw	r30,SAVE_Z
	subi	r30,64
	sbci	r31,0

	clc
	ldi	LOOP_I,8
monPro0_subtract_loop:
.rept	8
	ld	ACC_L,Y+
	ld	ACC_H,X+
	sbc	ACC_L,ACC_H
	st	Z+,ACC_L
.endr 
	dec	LOOP_I
	brne	monPro0_subtract_loop

	pop	r29
	pop	r28

// result is in high/low part of t


// result is in high/low part of t

//  (regCARRY_L)  (CARRY flag)
// carry in T     carry in subtract  result  sub (create 0x40 by andi)
// calculation
//       0          0               T_low    64  0 - 0xc0 - 0 = 0x40
//       0          1               T_high   0   0 - 0xc0 - 1 = 0x3f
//       1          0               T low    64  1 - 0xc0 - 0 = 0x41
//       1          1               T low    64  1 - 0xc0 - 1 = 0x40

	sbci	N_0,0xC0
	andi	N_0,0x40

	pop	r31		// renew result position
	pop	r30
	movw	r26,SAVE_Z
	sub	r26,N_0	// if needed, address lower part
	sbci	r27,0

// copy correct value to result
	ldi	r24,8
monPro0_copy_loop:
.rept	8
	ld	r25,X+
	st	Z+,r25
.endr
	dec	r24
	brne	monPro0_copy_loop

// return restore call saved registers 
	clr	r1
	pop	r17
	pop	r16
	pop	r15
	pop	r14
	ret
#undef N_PTR
#undef SAVE_Z
#undef LOOP_I
#undef LOOP_J
#undef ZERO
#endif // 8 bit version

#if USE_N0 == 16
#warning, not designet for RSA_BYTES != 64

// 16 bit monPro0

//SAVE_Z  in call saved reg .. 
#define SAVE_Z_L r6  
#define SAVE_Z   r6
#define SAVE_Z_H r7

#define CARRY_L r8
#define CARRY	r8
#define CARRY_H r9

#define N0_L	r10
#define N0_H    r11


// SAVE_N_PTR in call saved reg ..
#define SAVE_N_PTR_L r12
#define SAVE_N_PTR	r12
#define SAVE_N_PTR_H r13


#define M_L	r14
#define M_H	r15

// r16 temp .. 
// r17 r16,17 TEMP
#define ZERO r18
#define ZERO_L r18
#define ZERO_H r19

#define ACC_L	r20
#define ACC_H	r21
#define LOOP_J	r22
#define LOOP_I	r23



#define N_PTR	r26
// N_PTR_H      r27
// REG Y is call save 
// unused	r28
// unused	r29
#define T_PTR	r30
// T_PTR_H      r31

// (uint8_t *result, uint8_t *t  uint8_t *n,  uint32_t n0)

monPro0:
  	push	r6
  	push	r7
  	push	r8
  	push	r9
  	push	r10
  	push	r11
  	push	r12
  	push	r13
  	push	r14
  	push	r15
  	push	r16
  	push	r17

	push	r24	// save result position
	push	r25

	movw	SAVE_N_PTR, r20
	movw	N0_L, r18
	movw	T_PTR,r22

	clr	ZERO_L
	clr	ZERO_H

//init loop variable
//  	ldi	LOOP_I, lo8(RSA_BYTES/2)
	call	rsa_get_len
	mov	LOOP_I,r24
	lsr	LOOP_I
monPro0_loop:
  	movw	SAVE_Z, T_PTR
// load t[]
  	ld	ACC_L, Z
  	ldd	ACC_H, Z+1
// multiply M (16 bit)  from t[] * N0 
  	mul	N0_L, ACC_L
  	movw	M_L, r0
  	mul	N0_L, ACC_H
  	add	M_H, r0
  	mul	N0_H, ACC_L
  	add	M_H, r0
// renew n pointer
	movw	N_PTR,SAVE_N_PTR
// clear initial CARRY
	movw	CARRY,ZERO
// init loop variable
//	ldi	LOOP_J,lo8(RSA_BYTES/2)
	call	rsa_get_len
	mov	LOOP_J,r24
	lsr	LOOP_J
monPro0_loop0:

.macro	t_n_m16
// summ t[], carry
	ld	ACC_L, Z
	ldd	ACC_H, Z+1	; 0x01
	add	ACC_L,CARRY_L
	adc	ACC_H,CARRY_H
	movw	CARRY,ZERO
	adc	CARRY_L,ZERO_L

//add low  part of n[] * M
	ld      r16, X+
	mul	r16, M_L
	add	ACC_L,r0
	adc	ACC_H,r1
	adc	CARRY_L,ZERO_L

// add 1st middle part of n[] * M
	mul	r16,M_H
	add	ACC_H,r0
	adc	CARRY_L,r1
	adc	CARRY_H,ZERO_H
// add 2nd middle part of n[] * M
	ld      r16, X+
	mul     r16, M_L
	add     ACC_H,r0
	adc     CARRY_L,r1
	adc     CARRY_H,ZERO_H
// add high part of n[] * M
	mul     r16, M_H
	add	CARRY_L,r0
	adc	CARRY_H,r1
// return result to t[]
  	st	Z+, ACC_L
  	st	Z+, ACC_H
.endm
	t_n_m16	
	dec 	LOOP_J
  	brne	monPro0_loop0
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	ld	ACC_L,Z
	add	ACC_L,CARRY_L
	st      Z+,ACC_L
	ld	ACC_L,Z
	adc	ACC_L,CARRY_H
	st      Z+,ACC_L

       	mov	LOOP_J, LOOP_I
monPro0_loop1:
	dec     LOOP_J
	breq	monPro0_carry_end
	ld      ACC_L, Z
	adc	ACC_L,ZERO_L
	st	Z+,ACC_L	
	ld      ACC_L, Z
	adc	ACC_L,ZERO_L
	st	Z+,ACC_L
	rjmp	monPro0_loop1	
monPro0_carry_end:
// generate  carry to CARRY_L 
	movw	CARRY_L,ZERO_L
	adc	CARRY_L,CARRY_L
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	movw	T_PTR,SAVE_Z
	adiw	T_PTR,2
   	dec	LOOP_I
	breq	monPro0_loop_end
  	rjmp	monPro0_loop
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
monPro0_loop_end:
	clr	r1		// gcc need r1=0	- safety only
// upper part of t[] is now addressed by T_PTR
 	movw	M_L,T_PTR

// subtract
	movw	r26,SAVE_N_PTR
	movw	ZERO_L,r28	// save r28,r29 

	movw	r28,M_L
	movw	r30,M_L
	subi	r30,64
	sbc	r31,r1

	clc
	ldi	LOOP_I,8
monPro0_subtract_loop:
.rept	8
	ld	ACC_L,Y+
	ld	ACC_H,X+
	sbc	ACC_L,ACC_H
	st	Z+,ACC_L
.endr 
	dec	LOOP_I
	brne	monPro0_subtract_loop
	movw	r28,ZERO_L	// renew r28,r29

// result is in high/low part of t

// based on rsa_get_len  64/96/128 need to be subtracted

//  (regCARRY_L)  (CARRY flag)
// carry in T     carry in subtract  result             subtract
// calculation
//       0          0               T_low    64/96/128	0 - 0 =  0
//       0          1               T_high   0          0 - 1 = FF
//       1          0               T low    64/96/128  1 - 0 =  1
//       1          1               T low    64/96/128  1 - 1 =  0

	mov	r25,CARRY_L
	sbci	r25,0		// 00/FF/01/00
	com	r25     	// FF/00/FE/FF
	call	rsa_get_len     // 40/60/80
	and	r25,r24

	pop	r31		// renew result position
	pop	r30
	movw	r26,M_L
	sub	r26,r24	// if needed, address lower part
	sbci	r27,0

// copy correct value to result
	ldi	r24,8
monPro0_copy_loop:
.rept	8
	ld	r25,X+
	st	Z+,r25
.endr
	dec	r24
	brne	monPro0_copy_loop

       	pop	r17
       	pop	r16
       	pop	r15
       	pop	r14
       	pop	r13
       	pop	r12
       	pop	r11
       	pop	r10
       	pop	r9
       	pop	r8
       	pop	r7
       	pop	r6
       	ret

#endif	// USE_N0 == 16 
#if USE_N0 == 32
//calclulated in outer loop from N0 and 't'
#define M_0   r2
#define M_1   r3
#define M_2   r4
#define M_3   r5
// cleared in outer loop
#define CARRY_0 r6
#define CARRY_1 r7
#define CARRY_2 r8
#define CARRY_3 r9
// calculated one per exponentation 
#define N_0   r10 
#define N_1   r11 
#define N_2   r12  
#define N_3   r13
// saved after function start 
#define SAVE_T_PTR r14
#define SAVE_T_PTR_L r14
#define SAVE_T_PTR_H r15
#define SAVE_N_PTR r16
#define SAVE_N_PTR_L r16
#define SAVE_N_PTR_H r17
//normal use (no initialization)
#define ACC_0   r18
#define ACC_1   r19
#define ACC_2   r20    
#define ACC_3   r21
// cleared at function start
#define ZERO_0  r22
#define ZERO_1  r23
//normal use
#define TMP_0 r24
// temp variable r25
#define TMP_1 ACC_0   
#define TMP_2 ACC_1
#define TMP_3 ACC_2 

#define LOOP_I	r26
#define LOOP_J	r27

// r28,29 as n pointer
#define N_PTR   r28
// r30,31 as T pointer
#define T_PTR   r30

// (uint8_t *result, uint8_t *t  uint8_t *n,  uint16_t n0)

monPro0:
	push	r2
	push	r3
	push	r4
	push	r5
  	push	r6
  	push	r7
  	push	r8
  	push	r9
  	push	r10
  	push	r11
  	push	r12
  	push	r13
  	push	r14
  	push	r15
  	push	r16
  	push	r17
	push	r28
	push	r29

	push	r24	// save return value position
	push	r25

	movw	T_PTR,r22
	movw	N_0, r16
	movw	N_2, r18
	movw	SAVE_N_PTR, r20

// prepare ZERO
	ldi	ZERO_0,0
	ldi	ZERO_1,0

// loop is 36112 ticks .. 
//init loop variable
	call	rsa_get_len
// divide by 4 (32 bits per step)
	lsr	r24
	lsr	r24
	mov	LOOP_I,r24
monPro0_loop:
	movw    SAVE_T_PTR, T_PTR
// calculate (t * n) mod (2^32) = m
	ldd	ACC_0,Z+0
	ldd	ACC_1,Z+1
	ldd	ACC_2,Z+2
	ldd	ACC_3,Z+3			;8 ticks

	mul	ACC_0,N_0		;0,0
	movw	M_0,r0
	mul	ACC_0,N_2		;0,2
	movw	M_2,r0

	mul	ACC_2,N_0		;2,0
	add	M_2,r0
	adc	M_3,r1
	mul	ACC_1,N_1		;1,1
	add	M_2,r0
	adc	M_3,r1

	mul	ACC_0,N_1		;0,1
	add	M_1,r0
	adc	M_2,r1
	adc	M_3,ZERO_0
	mul	ACC_1,N_0		;1,0
	add	M_1,r0
	adc	M_2,r1
	adc	M_3,ZERO_0

	mul	ACC_0,N_3		;0,3
	add	M_3,r0
	mul	ACC_3,N_0		;3,0
	add	M_3,r0
	mul	ACC_2,N_1		;2,1
	add	M_3,r0
	mul	ACC_1,N_2		;1,2
	add	M_3,r0				;36 ticks

// renew n pointer
        movw    N_PTR,SAVE_N_PTR

// clear carry
	movw	CARRY_0,ZERO_0
	movw	CARRY_2,ZERO_0

// inner loop
// init loop variable

	call	rsa_get_len
// divide by 4 (32 bits per step)
	lsr	r24
	lsr	r24
	mov	LOOP_J,r24
monPro0_loop0:
	ld	TMP_0,Y+
	mul	TMP_0,M_0
	movw	ACC_2,ZERO_0
	ld 	ACC_0,Z
	ldd	ACC_1,Z+1
	add	ACC_0,r0  
	adc	ACC_1,r1
	adc	ACC_2,ZERO_0
// no carry to ACC_3 because adding 16 bit+16 bit value only
	add	ACC_0,CARRY_0
	adc	ACC_1,CARRY_1
	adc	ACC_2,ZERO_0 
// maximal value in ACC_2 = 2 (0xffff+0xffff+0xfe01)=0x02FDFF
// final t[0]
	st	Z+, ACC_0

	mul	TMP_0,M_1
	add	ACC_1,r0 
	adc	ACC_2,r1 
	adc	ACC_3,ZERO_0

// no carry over ACC3 because 0x02FDFF+0xFE01=100FEFF
// reuse ACC_0 as TMP_1
	ld	TMP_1,Y+
	mul	TMP_1,M_0
	add	ACC_1,r0 
	adc	ACC_2,r1 
	adc	ACC_3,ZERO_0
// no carry over ACC_3 100FEFF + FE0100 = 1FEFFFF
// final t[1]
	st	Z+,ACC_1

// 1st partial product for position 2 
	mul	TMP_1,M_1
	add	ACC_2,r0 
	adc	ACC_3,r1 
// no carry over ACC_3 1FEFFFF + FE0100 = FFFFFFFF

// clear next bytes of result (new carry)
	movw	CARRY_0,ZERO_0
// add rest of previous carry
	add	ACC_2,CARRY_2
	adc 	ACC_3,CARRY_3
	adc	CARRY_0,ZERO_0
// add rest of 't'
// reuse ACC_1 as local TMP
	ld 	ACC_1, Z
	add 	ACC_2, ACC_1
	ldd	ACC_1, Z+1 
	adc	ACC_3, ACC_1
	adc	CARRY_0, ZERO_0
// 2nd partial product for position 2 
	mul	TMP_0, M_2
	add	ACC_2, r0 
	adc	ACC_3, r1 
	adc	CARRY_0, ZERO_0
// reuse ACC_1 as TMP_2 
	ld	TMP_2, Y+
// 3rd (last) partial product for position 2 
	mul	TMP_2, M_0
	add	ACC_2, r0
	adc	ACC_3, r1
	adc	CARRY_0, ZERO_0
// max value in CARRY0 is 4, because maximum 
// 3xFFFF+2xFE01
// final t[2]
	st	Z+, ACC_2
// reuse ACC_2 as TMP_3
	ld	TMP_3, Y+
//
	mul	TMP_2, M_1
	add	ACC_3, r0
	adc	CARRY_0, r1
	adc	CARRY_1, ZERO_0

	mul	TMP_1, M_2
	add	ACC_3, r0
	adc	CARRY_0, r1
	adc	CARRY_1, ZERO_0

	mul	TMP_0, M_3
	add	ACC_3, r0 
	adc	CARRY_0, r1
	adc	CARRY_1, ZERO_0

	mul	TMP_3, M_0
	add	ACC_3, r0 
	adc	CARRY_0, r1
	adc	CARRY_1, ZERO_0
// final t[3]
	st	Z+, ACC_3
// clear
	movw	CARRY_2, ZERO_0

	mul	TMP_3, M_1
	add	CARRY_0, r0
	adc	CARRY_1, r1
	adc	CARRY_2, ZERO_0

	mul	TMP_1, M_3
	add	CARRY_0, r0
	adc	CARRY_1, r1
	adc	CARRY_2, ZERO_0

	mul	TMP_2, M_2
	add	CARRY_0, r0
	adc	CARRY_1, r1
	adc	CARRY_2, ZERO_0

	mul	TMP_2, M_3
	add	CARRY_1, r0
	adc	CARRY_2, r1
	adc	CARRY_3, ZERO_0

// maximal value for CARRY 1 is 03, adding max 0xFE01
	mul	TMP_3, M_2
	add	CARRY_1, r0
	adc	CARRY_2, r1
	adc	CARRY_3, ZERO_0

	mul	TMP_3, M_3
	add	CARRY_2, r0
	adc	CARRY_3, r1

	dec 	LOOP_J
//  	brne	monPro0_loop0
	breq	monPro0_carry
	rjmp	monPro0_loop0
monPro0_carry:
;-----------------
// propagate carry (32 bits)
	ld	ACC_0,Z
	add	ACC_0,CARRY_0
	st      Z+,ACC_0
	ld	ACC_0,Z
	adc	ACC_0,CARRY_1
	st      Z+,ACC_0
	ld	ACC_0,Z
	adc	ACC_0,CARRY_2
	st      Z+,ACC_0
	ld	ACC_0,Z
	adc	ACC_0,CARRY_3
	st      Z+,ACC_0
// rest of carry
       	mov	LOOP_J, LOOP_I
monPro0_loop1:
	dec     LOOP_J
	breq	monPro0_carry_end
	ld	ACC_0,Z
	adc	ACC_0,ZERO_0
	st      Z+,ACC_0
	ld	ACC_0,Z
	adc	ACC_0,ZERO_0
	st      Z+,ACC_0
	ld	ACC_0,Z
	adc	ACC_0,ZERO_0
	st      Z+,ACC_0
	ld	ACC_0,Z
	adc	ACC_0,ZERO_0
	st      Z+,ACC_0
	rjmp	monPro0_loop1	

monPro0_carry_end:
// generate  carry to CARRY_L 
	movw	CARRY_0,ZERO_0
	adc	CARRY_0,CARRY_0
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	movw	T_PTR,SAVE_T_PTR
	adiw	T_PTR,4
   	dec	LOOP_I
	breq	monPro0_loop_end
  	rjmp	monPro0_loop
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
monPro0_loop_end:
	clr	r1		// gcc need r1=0	- safety only
// upper part of t[] is now addressed by T_PTR
 	movw	M_0,T_PTR

// subtract
	movw	r26,SAVE_N_PTR
	movw	r28,M_0
	movw	r30,M_0
	call	rsa_get_len
	sub	r30,r24
	sbci	r31,0

	clc
	call	rsa_get_len
	lsr	r24
	lsr	r24
	lsr	r24
monPro0_subtract_loop:
.rept	8
	ld	r25,Y+
	ld	r23,X+
	sbc	r25,r23
	st	Z+,r25
.endr 
	dec	r24
	brne	monPro0_subtract_loop

// result is in high/low part of t

//  (regCARRY_0)  (CARRY flag)
// carry in T     carry in subtract  result             subtract
// calculation
//       0          0               T_low    64/96/128	0 - 0 =  0
//       0          1               T_high   0          0 - 1 = FF
//       1          0               T low    64/96/128  1 - 0 =  1
//       1          1               T low    64/96/128  1 - 1 =  0

        mov     r25,CARRY_0
        sbci    r25,0           // 00/FF/01/00
        com     r25             // FF/00/FE/FF
        call    rsa_get_len     // 40/60/80
        and     r25,r24

	pop	r31		// renew result position
	pop	r30
	movw	r26,M_0
	sub	r26,r25	// if needed, address lower part
	sbci	r27,0

// copy correct value to result
	call	rsa_get_len
// unroll 8x
	lsr	r24
	lsr	r24
	lsr	r24
monPro0_copy_loop:
.rept	8
	ld	r25,X+
	st	Z+,r25
.endr
	dec	r24
	brne	monPro0_copy_loop

monPro0_ret:
	pop	r29
	pop	r28
       	pop	r17
       	pop	r16
       	pop	r15
       	pop	r14
       	pop	r13
       	pop	r12
       	pop	r11
       	pop	r10
       	pop	r9
       	pop	r8
       	pop	r7
       	pop	r6
	pop	r5
	pop	r4
	pop	r3
	pop	r2
       	ret

#undef M_0
#undef M_1
#undef M_2
#undef M_3
#undef CARRY_0
#undef CARRY_1
#undef CARRY_2
#undef CARRY_3
#undef N_0
#undef N_1
#undef N_2
#undef N_3
#undef SAVE_T_PTR
#undef SAVE_T_PTR_L
#undef SAVE_T_PTR_H
#undef SAVE_N_PTR
#undef SAVE_N_PTR_L
#undef SAVE_N_PTR_H
#undef ACC_0
#undef ACC_1
#undef ACC_2
#undef ACC_3
#undef ZERO_0
#undef ZERO_1
#undef TMP_0
#undef TMP_1
#undef TMP_2
#undef TMP_3
#undef LOOP_I
#undef LOOP_J
#undef N_PTR
#undef T_PTR


#endif	// USE_N0 == 32
#endif	// HAVE_MON_PRO0

#ifdef HAVE_RSA_MOD
        .global rsa_mod
        .type   rsa_mod, @function

// rsa_mod (rsa_long_num * result, rsa_num * mod)
// ~897000 ticks for reduction from 128 to 64

#define RESULT_PTR r14
#define HELPER_PTR r16
#define HELPER_PTR_H r17
#define LOOP r18
#define BYTES r19
#define INDEX r20
#define	TMP0	r22
#define TMP1	r23

#define COUNTER r24
#define COUNTER_H r25
#define TMP r28

rsa_mod:
	push	r2
	push	r3
	push	r4
	push	r5
	push	r6
	push	r7
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	push	r13

	push	r14
	push	r15
	push	r16
	push	r17
	push	r28
	push	r29
// allocate space for 2x long RSA_NUM on stack
	in	r28,0x3d
	in	r29,0x3e
	subi	r28,lo8(RSA_BYTES*4)
	sbci	r29,hi8(RSA_BYTES*4)
	LOAD_SP	r0, r28,r29
// get pointers of TMP, RESULT and HELPER
	adiw	TMP,1		// Y point to TMP variable
	movw	HELPER_PTR,TMP
	subi	HELPER_PTR,lo8(-RSA_BYTES*2)
	sbci	HELPER_PTR_H,hi8(-RSA_BYTES*2)
	movw	RESULT_PTR,r24

// init variables
	clr	INDEX

// init TMP to MOD rotated left by rsa_get_len() bytes
	movw	r30,TMP		// Z points to TMP
	movw	r26,r22		// X points to "mod"

	call	rsa_get_len
	mov	BYTES,r24
	mov	LOOP,BYTES
rsa_mod_init_loop1:
	st	Z+,r1
	dec	LOOP
	brne	rsa_mod_init_loop1

	mov	LOOP,BYTES
rsa_mod_init_loop2:
	ld	r0,X+
	st	Z+,r0
	dec	LOOP
	brne	rsa_mod_init_loop2

// rotate TMP to get "1" in higest bit, count rotated bits..
	mov	COUNTER,BYTES
	clr	COUNTER_H
	add	COUNTER,COUNTER
	adc	COUNTER_H,COUNTER_H
	add	COUNTER,COUNTER
	adc	COUNTER_H,COUNTER_H
	add	COUNTER,COUNTER
	adc	COUNTER_H,COUNTER_H

//////////////////////////////////////////////
// subtract TMP from RESULT if RESULT > TMP
// (always subtract, but change result pointer if  subtract generates carry)
// check details in C version card_os/rsa.c

// preload 8 bytes from Y to registers (cache)
.irp	pos,2,3,4,5,6,7,8,9,10,11,12,13
	ld	\pos,Y+
.endr

// recalculate BYTES - in next code loop unrolled 4x
	lsr	BYTES
rsa_mod_calculate:
// set pointers
	movw	r26,RESULT_PTR
	sbrc	INDEX,0
	movw	r26,HELPER_PTR

	movw	r30,RESULT_PTR
	sbrs	INDEX,0
	movw	r30,HELPER_PTR

	mov	LOOP,BYTES
	subi	LOOP,3	// 12 bytes in cache

// next loop is unrolled 4x,  to get 2x RSA_BYTES
	ld	TMP0,X+
	sub	TMP0,r2
	st	Z+,TMP0

.irp	pos,3,4,5,6,7,8,9,10,11,12,13
	ld	TMP0,X+
	sbc	TMP0,\pos
	st	Z+,TMP0
.endr
// Y is incremented, but in rsa_mod_rotate_r is moved back
// no need to save Y (r28,29)
rsa_mod_subtract:
	ld	TMP0,X+
	ld	TMP1,Y+
	sbc	TMP0,TMP1
	st	Z+,TMP0
	ld	TMP0,X+
	ld	TMP1,Y+
	sbc	TMP0,TMP1
	st	Z+,TMP0
	ld	TMP0,X+
	ld	TMP1,Y+
	sbc	TMP0,TMP1
	st	Z+,TMP0
	ld	TMP0,X+
	ld	TMP1,Y+
	sbc	TMP0,TMP1
	st	Z+,TMP0
	dec	LOOP
	brne	rsa_mod_subtract

// based on carry use new result .. (if not carry, HELPER is new RESULT)
	sbci	INDEX,1

	mov	LOOP,BYTES
	subi	LOOP,3
//	clc			//CARRY = 0 (LOOP is always > 3)
rsa_mod_rotate_r:
	ld	r0,-Y
	ror	r0
	st	Y,r0
	ld	r0,-Y
	ror	r0
	st	Y,r0
	ld	r0,-Y
	ror	r0
	st	Y,r0
	ld	r0,-Y
	ror	r0
	st	Y,r0
	dec	LOOP
	brne	rsa_mod_rotate_r
.irp    pos,13,12,11,10,9,8,7,6,5,4,3,2
	ror	\pos
.endr

	sbiw	COUNTER,1
	brmi	rsa_mod_calculate_end
	rjmp	rsa_mod_calculate

rsa_mod_calculate_end:
// copy proper result to real result
	movw	r30,RESULT_PTR
	sbrc	INDEX,0
	movw	r30,HELPER_PTR
	movw	r26,RESULT_PTR
	mov	LOOP,BYTES
rsa_mod_final_copy:
	ld	r0,Z+
	st	X+,r0
	ld	r0,Z+
	st	X+,r0
	dec	LOOP
	brne	rsa_mod_final_copy

	clr	r24
	clr	r25
rsa_mod_error:
	in	r28,0x3d
	in	r29,0x3e
	subi	r28,lo8(-RSA_BYTES*4)
	sbci	r29,hi8(-RSA_BYTES*4)
	LOAD_SP	r0, r28,r29
	pop	r29
	pop	r28
	pop	r17
	pop	r16
	pop	r15
	pop	r14

	pop	r13
	pop	r12
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	r7
	pop	r6
	pop	r5
	pop	r4
	pop	r3
	pop	r2

	ret
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

#endif

#ifdef HAVE_RSA_MOD_R
        .global rsa_mod_r
        .type   rsa_mod_r, @function
#define TMP0 r0
#define BYTES r1
#define ACTIVE0 r14
#define ACTIVE1 r16
#define LOOP r18
#define KL r19
#define CY    r20
#define TMP1 r21
#define MOD r22
#define MOD_ r23
#define COUNTER r24
#define COUNTER_L r24
#define COUNTER_H r25
#define X_PTR	r26
#define Y_PTR   r28
#define Z_PTR   r30

rsa_mod_r:
	push	r2
	push	r3
	push	r4
	push	r5
	push	r6
	push	r7
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	push	r13

	push	r14
	push	r15
	push	r16
	push	r17

	push	r28
	push	r29
// create TMP variable for rsa_num
	in	r28,0x3d
	in	r29,0x3e
	subi	r28,lo8(RSA_BYTES)
	sbci	r29,hi8(RSA_BYTES)
	LOAD_SP	r0 r28,r29

// create pointers for two posible results
	adiw	r28,1
	movw	ACTIVE1,r28
	movw	ACTIVE0,r24

// get number of bits ..
	call	rsa_get_len
// result is in r24 = COUNTER_L
// save copy 
	mov	BYTES,COUNTER_L
// 8x unrolled loops.. 
	lsr	BYTES
	lsr	BYTES
	lsr	BYTES

// calculate number of bites ..
	clr	COUNTER_H
	lsl	COUNTER_L
	rol	COUNTER_H
	lsl	COUNTER_L
	rol	COUNTER_H
	lsl	COUNTER_L
	rol	COUNTER_H

// select k/l
	clr	KL
// clear carry
	clr	CY
	movw	X_PTR,MOD
// preload X to register cache
.irp	pos,2,3,4,5,6,7,8,9,10,11,12,13
	ld	\pos,X+
.endr
	movw	MOD,X_PTR
rsa_mod_r_loop:
// subtract ACTIVE[k] = ACTIVE[l] - mod
	movw	X_PTR,MOD
// select k/l into Y,Z
	movw	Y_PTR,ACTIVE0
	movw	Z_PTR,ACTIVE0
	sbrs	KL,0
	movw	Y_PTR,ACTIVE1
	sbrc	KL,0
	movw	Z_PTR,ACTIVE1
	mov	LOOP,BYTES	// init loop counter
	subi	LOOP,2
// SUBTRACT
// 12 bytes from cache
	ld	TMP0,Z+
	sub	TMP0,r2
	st	Y+,TMP0
.irp	pos,3,4,5,6,7,8,9,10,11,12,13
	ld	TMP0,Z+
	sbc	TMP0,\pos
	st	Y+,TMP0
.endr
// 4 bytes from mem
.rept	4
	ld	TMP0,Z+
	ld	TMP1,X+
	sbc	TMP0,TMP1
	st	Y+,TMP0
.endr
// rest on loop
rsa_mod_r_sub:
.rept	8
	ld	TMP0,Z+
	ld	TMP1,X+
	sbc	TMP0,TMP1
	st	Y+,TMP0
.endr
	dec	LOOP
	brne	rsa_mod_r_sub

// save carry
	rol	CY
// test if c1 == c2
	inc	CY
	sbrs	CY,1
	com	KL	// swap k,l

	sbiw	COUNTER,1
	brmi	rsa_mod_r_end
// rotate result left
	movw 	Z_PTR,ACTIVE0
	sbrc	KL,0
	movw    Z_PTR,ACTIVE1

	mov	LOOP,BYTES
	clc
rsa_mod_r_rot:
.rept	8
	ld	TMP0,Z
	rol	TMP0
	st	Z+,TMP0
.endr
	dec	LOOP
	brne	rsa_mod_r_rot
// save carry
	rol	CY
	rjmp	rsa_mod_r_loop

rsa_mod_r_end:
// copy result back
	movw	Z_PTR,ACTIVE0
// select what is correct result
	movw	X_PTR,ACTIVE0
	sbrc	KL,0
	movw	X_PTR,ACTIVE1
rsa_mod_r_end_loop:
.rept	8
	ld	r0,X+
	st	Z+,r0
.endr
	dec	BYTES
	brne	rsa_mod_r_end_loop

// return stack back
	in	r28,0x3d
	in	r29,0x3e
	subi	r28,lo8(-RSA_BYTES)
	sbci	r29,hi8(-RSA_BYTES)
	LOAD_SP	r0, r28,r29
	pop	r29
	pop	r28
	pop	r17
	pop	r16
	pop	r15
	pop	r14

	pop	r13
	pop	r12
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	r7
	pop	r6
	pop	r5
	pop	r4
	pop	r3
	pop	r2
	ret
#undef LOOP
#undef TMP0
#undef TMP1
#undef TMP18
#undef KL
#undef ACTIVE0
#undef ACTIVE1
#undef CY
#undef BYTES
#undef MOD
#undef MOD_
#undef COUNTER
#undef COUNTER_L
#undef COUNTER_H
#undef X_PTR
#undef Y_PTR
#undef Z_PTR

#endif //HAVE_RSA_MOD_R

#ifdef HAVE_RSA_INV_MOD


//
// calculate modular inversion, no abi!
//
// calculate mod inverse for k^-1  mod n,  k is in form 2^w
// input "n" addressed by r22,r23
// result addressed by Z
#define BYTES8  r19
#define TMP	r20
#define COUNTER r21
#define N	r22
// r23 reserved for Nh
#define BITS	r24
#define BITS_H	r25

rsa_inv_mod:
//result addressed by Z (available space 2x RSA_BYTES)

// clear result (full available space)
	movw	r26,r30
	ldi	COUNTER,RSA_BYTES
rsa_inv_mod_c0:
	st	X+,r1
	dec	COUNTER
	brne	rsa_inv_mod_c0

	ldi	COUNTER,RSA_BYTES
rsa_inv_mod_c1:
	st	X+,r1
	dec	COUNTER
	brne	rsa_inv_mod_c1

// result set to 1
	ldi	r24,1
// initial r0
	mov	r0,r24
	st	Z,r24
// real rsa bits ..
	call	rsa_get_len
	mov	TMP,r24
	
// bytes to bits
	mov	BITS,TMP
	clr	BITS_H

	add	BITS,BITS
	adc	BITS_H,BITS_H
	add	BITS,BITS
	adc	BITS_H,BITS_H
	add	BITS,BITS
	adc	BITS_H,BITS_H

	mov	BYTES8,TMP
	lsr	BYTES8
	lsr	BYTES8
	lsr	BYTES8
	subi 	BYTES8,2	// 16 bytes are cached, dec counter

// prepare pointer to "zero" (in upper part of result - unused part)
	ldi	r26,lo8(RSA_BYTES)
	ldi	r27,hi8(RSA_BYTES)
	add	r26,r30
	adc	r27,r31
	movw	r28,r26

// cache 1st  bytes in reg
.irp	pos,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
	ld	\pos,Z+
.endr

rsa_inv_mod_loop_bits:
	movw	r26,r28
// based on bit 0 in r0 (n_) select zero/n to add to n_
	sbrc	r2,0
// renew X to point  n
	movw	r26,N
	mov	COUNTER,BYTES8

	ld	TMP,X+
	add	r2,TMP
.irp	pos,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
	ld	TMP,X+
	adc	\pos,TMP
.endr

rsa_inv_mod_loop_add:
.rept 8
	ld	TMP,X+
	ld	r0,Z
	adc	r0,TMP
	st	Z+,r0
.endr
	dec	COUNTER
	brne	rsa_inv_mod_loop_add
	
// rotate right (inclusice carry from previous add)
	mov	COUNTER,BYTES8
rsa_inv_mod_loop_ror:
.rept	8
	ld	r0,-Z
	ror	r0
	st	Z,r0
.endr
	dec	COUNTER
	brne	rsa_inv_mod_loop_ror

.irp	pos,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2
	ror	\pos
.endr
	sbiw	BITS,1
	breq	.+2
	rjmp	rsa_inv_mod_loop_bits

// restore cached bytes into RAM
	sbiw	r30,16
.irp	pos,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
	std	Z+\pos-2,\pos
.endr
	ret
#undef N
#undef TMP
#undef BYTES8
#undef BYTES
#undef BITS
#undef BITS_H
#undef COUNTER

#define LOOP r1
#define TMP0 r0
#define RESULT_END r10
#define RESULT_END_ r11
#define RESULT r12
#define RESULT_ r13
#define ACTIVE0 r14
#define ACTIVE1 r16
#define TMP1 r18
#define KL r19
#define CY    r20
#define BYTES r21
#define MOD r22
#define RESULT_BYTE r25
#define X_PTR	r26
#define Y_PTR   r28
#define Z_PTR   r30

// calculate r*r^(-1) - n*n' = 1
//
// precisely: n' = (r*r^(-1) - 1 )/n
// input r22,r23 =  n
//       r24,r25 =  position of result n'
// r is choised as nearest power of two (by RSA_BYTES  2^1024, 2^1536 or  2^2048)
	.global	rsa_inv_mod_full
	.type	rsa_inv_mod_full,@function

rsa_inv_mod_full:

// 8 bytes of modulus cache
	push	r2
	push	r3
	push	r4
	push	r5
	push	r6
	push	r7
	push	r8

	push	r9
	push	r10
	push	r11
	push	r12
	push	r13
	push	r14
	push	r15
	push	r16
	push	r17

	push	r28
	push	r29
// create TMP variable for rsa_num
	in	r28,0x3d
	in	r29,0x3e
	subi	r28,lo8(2*RSA_BYTES)
	sbci	r29,hi8(2*RSA_BYTES)
	LOAD_SP	r0, r28,r29

	movw	r30,r28	// result into variable on stack
	adiw	r30,1
// calculate inversion
// rsa_inv_mod (input in r22,r23)
// result is addessed by r30,31
	push	r24
	push	r25
	rcall	rsa_inv_mod
	pop	r25
	pop	r24

// two variables RESULT and RESULT_END is used to control cycle
// RESULT point to higger bits in result, and is decremented
// if "match" RESULT_END, this is loop end

	sbiw	r24,1
	movw	RESULT_END,r24
	movw	RESULT,r24
	call	rsa_get_len
	add	RESULT,r24
	adc	RESULT_,r1

// subtract 1, create copy
	in	r26,0x3d
	in	r27,0x3e
	adiw	r26,1			
	movw	r30,r26	// pointer to ALT
	subi	r30,lo8(-RSA_BYTES)
	sbci	r31,hi8(-RSA_BYTES)

// create pointers for two posible results
	movw	ACTIVE1,r30
	movw	ACTIVE0,r26

// here subtract 1
// get number of bites
	call	rsa_get_len
	dec	r24

	ld	r25,X
	subi	r25,1
	st	X+,r25
inv_sub_loop:
	ld	r25,X
	sbci	r25,0
	st	X+,r25
	dec	r24
	brne	inv_sub_loop

// get number of bits ..
	call	rsa_get_len
// result is in r24 = COUNTER_L
// save copy 
	mov	BYTES,r24
// 8x unrolled loops.. 
	lsr	BYTES
	lsr	BYTES
	lsr	BYTES

	clr	KL		// initial operand (ACTIVE0)
	ldi	RESULT_BYTE,1	// stop flag

// fill modulus cache in registers (8 bytes)
	movw	X_PTR,MOD
.irp	pos,2,3,4,5,6,7,8,9
	ld	\pos,X+
.endr
	movw	MOD,X_PTR
inv_loop:
/////////////////////////////////////////////////////
// rotate left
	movw 	Z_PTR,ACTIVE0
	sbrc	KL,0
	movw    Z_PTR,ACTIVE1

	mov	LOOP,BYTES
//simulate 2x RSA_NUM, in low part "ones" (subtract 1 in previous code)
	sec
inv_rot:
.rept	8
	ld	TMP0,Z
	rol	TMP0
	st	Z+,TMP0
.endr
	dec	LOOP
	brne	inv_rot
// save carry
	rol	CY
////////////////////////////////////////////////////
// subtract modulus
// subtract ACTIVE[k] = ACTIVE[l] - mod
	movw	X_PTR,MOD
// select k/l into Y,Z
	movw	Y_PTR,ACTIVE0
	movw	Z_PTR,ACTIVE0
	sbrs	KL,0
	movw	Y_PTR,ACTIVE1
	sbrc	KL,0
	movw	Z_PTR,ACTIVE1
	mov	LOOP,BYTES
	dec	LOOP

// subtract modulus, use cache in registers ..
	ld	TMP0,Z+
	sub	TMP0,r2
	st	Y+,TMP0
.irp	pos,3,4,5,6,7,8,9
	ld	TMP0,Z+
	sbc	TMP0,\pos
	st	Y+,TMP0
.endr
// subtract rest (from MEM)
inv_sub:
.rept	8
	ld	TMP0,Z+
	ld	TMP1,X+
	sbc	TMP0,TMP1
	st	Y+,TMP0
.endr
	dec	LOOP
	brne	inv_sub
// compare carry from rotation and subtract (in bit 0 in CY and C flag)
// test if c1 == c2
	sbci	CY,1	// bit 0 in CY:  for c1==c2 -> 1  c1!=c2 -> 0
	eor	KL,CY	// swap active0/active1 if needed (bit 0 in KL)
	ror	CY	// save result bite into RESULT_BYTE
	rol	RESULT_BYTE
	brcc	inv_mask_ok // test stop flag in RESULT_BYTE,

//stop flag found, 8 bits of RESULT_BYTE need to be saved in final result
	movw	r30,RESULT
	st	Z,RESULT_BYTE
	ldi	RESULT_BYTE,1	// renew stop flag
	sbiw	r30,1
	movw	RESULT,r30
// test loop end
	sub	r30,RESULT_END
	sbc	r31,RESULT_END_
//	or	r30,r31		// my habit from Z80 :-) not needed for AVR
	breq	inv_ok
inv_mask_ok:
	rjmp	inv_loop

inv_ok:
// return stack back
	in	r28,0x3d
	in	r29,0x3e
	subi	r28,lo8(-(2*RSA_BYTES))
	sbci	r29,hi8(-(2*RSA_BYTES))
	LOAD_SP	r0, r28,r29
	pop	r29
	pop	r28
	pop	r17
	pop	r16
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	r11
	pop	r10
	pop	r9

	pop	r8
	pop	r7
	pop	r6
	pop	r5
	pop	r4
	pop	r3
	pop	r2
	clr	r1
	ret
#undef LOOP
#undef TMP0
#undef TMP1
#undef RESULT_END
#undef RESULT_END_
#undef RESULT
#undef RESULT_
#undef ACTIVE0
#undef ACTIVE1
#undef RESULT_BYTE
#undef KL
#undef CY
#undef BYTES
#undef MOD
#undef X_PTR
#undef Y_PTR
#undef Z_PTR


#endif // HAVE_INV_MOD

#ifdef HAVE_MON_PRO0
#if USE_N0 == 0 

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
	call	rsa_get_len
	lsr	r24
	lsr	r24
	lsr	r24
	mov	r1,r24

	movw	r30,PTR_t	//t
	movw	r26,PTR_n	//n
//18,19,20,21,22,23

//      clc                     // CY is always cleared (rsa_get_len return  always even number)
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


#endif //USE_N0 == 0
#endif //HAVE_MON_PRO0
