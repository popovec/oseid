/*
    mp.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015,2016 Peter Popovec, popovec.peter@gmail.com

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

    Atmega assembler, base routines for aritmetics for EC and RSA

*/
#include "rsa.h"

#ifndef RSA_BYTES
#error undefined RSA_BYTES
#endif

#include <avr/io.h>

#ifdef HAVE_MP_ADD
        .global mp_add
        .type   mp_add, @function
#endif
#ifdef HAVE_MP_SUB
        .global mp_sub
        .type   mp_sub, @function
#endif
#ifdef HAVE_MP_SUB_2N
	.global mp_sub_2N
        .type   mp_sub_2N, @function
#endif
#ifdef HAVE_MP_CMP
        .global mp_cmpGE
        .type   mp_cmpGE, @function
#endif
#ifdef HAVE_MP_SHIFTR
        .global mp_shiftr
        .type   mp_shiftr, @function
#endif
#ifdef HAVE_MP_SHIFTR_C
        .global mp_shiftr_c
        .type   mp_shiftr_c, @function
#endif
#ifdef HAVE_MP_SHIFTL
        .global mp_shiftl
        .type   mp_shiftl, @function
#endif
#ifdef HAVE_MP_SHIFTR_2N
        .global mp_shiftr_2N
        .type   mp_shiftr_2N, @function
#endif
#ifdef HAVE_RSA_ADD
        .global rsa_add
        .type   rsa_add, @function
#endif
#ifdef HAVE_RSA_ADD_LONG
        .global rsa_add_long
        .type   rsa_add_long, @function
#endif
#ifdef HAVE_RSA_SUB
        .global rsa_sub
        .type   rsa_sub, @function
#endif
#ifdef HAVE_RSA_SUB_LONG
        .global rsa_sub_long
        .type   rsa_sub_long, @function
#endif
#ifdef HAVE_MP_ADDSUB_MOD
        .global sub_mod
        .type   sub_mod, @function
        .global add_mod
        .type   add_mod, @function
#endif
        .global rsa_shiftl
        .type   rsa_shiftl, @function


/////////////////////////////////////////////////////////////
#ifdef HAVE_MP_ADDSUB_MOD
#if  1
// big, fast, constant time
// add_mod (Result, Operand, Modulus), Result = (Result + Operand) mod Modulus
add_mod:
.irp    Reg,2,3,4,5,6,7,28,29
	push	r\Reg
.endr
	movw	r18,r24	// save result
	call	rsa_get_len
	lsr	r24
	lsr	r24
	mov	r25,r24
	lsr	r24

	movw	r30,r18	// result
	movw	r28,r22	// operand
	movw	r26,r20 // modulus

	sub	r22,r22		// clear initial carry
add_mod_loop1:
	ror	r22		// renew carry from R22:0
// do addition
.irp	Reg,0,1,2,3,4,5,6,7
	ld	r\Reg,Z	// result
	ld	r23,Y+	//     + operand
	adc	r\Reg,r23
	st	Z+,r\Reg
.endr
	rol	r22	// save carry from ADD into R22:0
// compare with modulus
.irp	Reg,0,1,2,3,4,5,6,7
	ld	r23,X+	// modulus
	cpc	r\Reg,r23
.endr
	dec	r24
	brne	add_mod_loop1

	ldi	r24,1
	sbci	r24,0	// invert carry from SUB

	or	r24,r22	// combine with carry from ADD

// renew result, modulus
	movw	r30,r18	// result
	movw	r26,r20	// modulus
	neg	r24	// 0 or 0xff
	subi	r25,2	// last 8 bytes already loaded in Reg0..7
// carry is cleared ..
// subtract modulus or 0
add_mod_loop2:
.rept	4
	ld	r22,X+  // modulus
	and	r22,r24 // 0 or modulus byte
	ld	r23,Z
	sbc	r23,r22
	st	Z+,r23
.endr
	dec	r25
	brne	add_mod_loop2
// cached bytes
.irp    Reg,0,1,2,3,4,5,6,7
	ld	r22,X+
	and	r22,r24 // 0 or modulus byte
	sbc	r\Reg,r22
	st	Z+,r\Reg
.endr

	clr	r1
.irp	Reg,29,28,7,6,5,4,3,2
	pop	r\Reg
.endr
	ret
#else
add_mod:
	movw	r18,r24	// save result position
	rcall	mp_add
// r24 0/1
	mov	r23,r24
// subtract modulus (do not change result, only check carry)
	call	rsa_get_len
	lsr	r24
	lsr	r24
	mov	r25,r24
	movw	r30,r18	// Z pointer to result
	movw	r26,r20	// X pointer to modulus
//	clc	// not needed ..
add_mod_loop1:
.rept 4
	ld	r22,Z+  // result
	ld	r0,X+	// modulus
	sbc	r22,r0
.endr
	dec	r24
	brne	add_mod_loop1
// 0 if carry, 1 if not carry
	ldi	r24,1
	sbc	r24,r1
// if add generates carry  or subtract generatres non carry, subtract
// modulus
	or	r24,r23
	movw	r30,r18	// result
	movw	r26,r20	// modulus
#if 1
	neg	r24	//0 or 0xff
	clc
add_mod_loop2:
.rept	4
	ld	r22,X+  // modulus
	and	r22,r24 // 0 or modulus byte
	ld	r23,Z
	sbc	r23,r22
	st	Z+,r23
.endr
	dec	r25
	brne	add_mod_loop2
	ret
#else
	push	r28
	push	r29
	mov	r28,r24 // 0 or 1
	clr	r29
	clr	r0
// y is pointer to r0/r1
	clc
add_mod_loop2:
.rept	4
	ld	r1,X+	// read modulus byte
	ld	r22,Y	// read modulus byte or 0
	ld	r23,Z   // result
	sbc	r23,r22
	st	Z+,r23
.endr
	dec	r25
	brne	add_mod_loop2
	clr	r1
	pop	r29
	pop	r28
	ret
#endif
#endif
// sub mod(r,a,modulus); r = (r-a) mod modulus
sub_mod:
	movw	r30,r24
	movw	r26,r22

	call	rsa_get_len
	lsr	r24
	lsr	r24
	mov	r25,r24
	movw	r18,r30
//	clc
sub_mod_loop1:
.rept	4
	ld	r22,Z
	ld	r23,X+
	sbc	r22,r23
	st	Z+,r22
.endr
	dec	r24
	brne	sub_mod_loop1
#if 1
// if carry, add modulus
// minimize the possibility of side channel attack: always add 0 or modulus
// byte (this is done by "and r22,r24" r24 is set to 0/0xff - by carry form
// previous subtraction
	sbc	r24,r24 // 0 /ff
	movw	r26,r20 // modulus
	movw	r30,r18 // result
	clc
sub_mod_loop2:
.rept	4
	ld	r22,X+  //modulus
	and	r22,r24 //0 or modulus byte
	ld	r23,Z   // result
	adc	r23,r22
	st	Z+,r23
.endr
	dec	r25
	brne	sub_mod_loop2
	ret
#else
	push	r28
	push	r29
// if carry, add modulus
// minimize the possibility of side channel attack: Y is pointer
// to r0/r1 registers, r0 is set 0, r1 is filled by modulus bytes
	clr	r0
	movw	r28,r0
	adc	r28,r28	//0/1 by carry

	movw	r26,r20	// modulus
	movw	r30,r18	// result
	clc
sub_mod_loop2:
.rept	4
	ld	r1,X+	// read modulus byte
	ld	r22,Y	// read modulus byte or 0
	ld	r23,Z	// result
	adc	r23,r22	// add 0 or modulus byte
	st	Z+,r23
.endr
	dec	r25
	brne	sub_mod_loop2
	clr	r1
	pop	r29
	pop	r28
	ret
#endif
#endif
// unroll only 8 bytes,  rest in loop
.macro MP_ADD_BYTE
	ld r23,X+
	ld r25,Z
	adc r23,r25
	st Z+,r23
.endm
#if defined(HAVE_MP_ADD)
mp_add:
#endif
#if defined (HAVE_RSA_ADD) || defined(HAVE_MP_ADD)
rsa_add:
	movw XL,r22
	movw ZL,r24
	call	rsa_get_len
	lsr	r24
	lsr	r24
	lsr	r24
	rjmp	mp_add0
#endif
#ifdef HAVE_RSA_ADD_LONG
rsa_add_long:
	movw XL,r22
	movw ZL,r24
	call	rsa_get_len
	lsr	r24
	lsr	r24
	rjmp	mp_add0
#endif

#if defined(HAVE_RSA_ADD) || defined(HAVE_RSA_ADD_LONG) || defined(HAVE_MP_ADD)
mp_add0:
//      clc			// CY is always cleared (rsa_get_len return always even number)
mp_add1:
	MP_ADD_BYTE
	MP_ADD_BYTE
	MP_ADD_BYTE
	MP_ADD_BYTE
	MP_ADD_BYTE
	MP_ADD_BYTE
	MP_ADD_BYTE
	MP_ADD_BYTE   
        dec r24
        brne mp_add1
        rol r24  
        ret
#endif
/////////////////////////////////////////////////////////////
#ifdef HAVE_MP_CMP
#ifdef EC_CONSTANT_TIME
mp_cmpGE:
	movw	ZL,r24
	movw	XL,r22
	call	rsa_get_len
	lsr	r24
	lsr	r24
//      clc			// CY is always cleared (rsa_get_len return always even number)
mp_cmpGE_loop:
.rept	4
	ld	r22,Z+
	ld	r23,X+
	sbc	r22,r23
.endr
	dec	r24
	brne	mp_cmpGE_loop
	ldi	r24,1
	sbc	r24,r1
	ret
#else
mp_cmpGE:
	movw	ZL,r24
	movw	XL,r22
	call	rsa_get_len
// move pointers to end of variables
	add	r30,r24
	adc	r31,r1
	add	r26,r24
	adc	r27,r1

	mov	r25,r24	// loop counter
	ldi	r24,1	// default return value Z GE X
	rjmp	mp_cmp_loop0

mp_cmp_loop:
	dec	r25
	breq	mp_cmp_end
mp_cmp_loop0:
	ld	r22,-Z
	ld	r23,-X
	cp	r22,r23
	breq	mp_cmp_loop
	brcc	mp_cmp_end
	clr	r24
mp_cmp_end:
	ret
#endif
#endif
/////////////////////////////////////////////////////////////
#ifdef HAVE_MP_SUB_2N
mp_sub_2N:
#endif
#if defined (HAVE_RSA_SUB_LONG) || defined (HAVE_MP_SUB_2N)
rsa_sub_long:
	push	YL
	push	YH
	movw	ZL,r24
	movw	XL,r22
	movw	YL,r20
	call	rsa_get_len
	lsr	r24
	lsr	r24
//      clc			// CY is always cleared (rsa_get_len return always even number)
	rjmp mp_sub1
#endif
#ifdef HAVE_MP_SUB
mp_sub:
#endif
#if defined (HAVE_RSA_SUB) || defined (HAVE_MP_SUB)
rsa_sub:
	push	YL
	push	YH
	movw	ZL,r24
	movw	XL,r22
	movw	YL,r20
	call	rsa_get_len
	lsr	r24
	lsr	r24
	lsr	r24
//      clc			// CY is always cleared (rsa_get_len return always even number)
#endif
#if defined(HAVE_RSA_SUB) || defined(HAVE_MP_SUB) || defined (HAVE_MP_SUB_2N) || defined (HAVE_RSA_SUB_LONG)
mp_sub1:
.rept	8
	ld	r22,X+
	ld	r23,Y+
	sbc	r22,r23
	st	Z+,r22
.endr
	dec	r24
	brne	mp_sub1
	rol	r24
	pop	YH
	pop	YL
	ret
#endif
/////////////////////////////////////////////////////////////
#ifdef HAVE_MP_SHIFTL
mp_shiftl:
#endif
#if defined(HAVE_RSA_SHIFTL) || defined(HAVE_MP_SHIFTL)
rsa_shiftl:
	movw	ZL,r24
	call	rsa_get_len
	lsr	r24
	lsr	r24
	lsr	r24
mp_shiftl0:
//      clc			// CY is always cleared (rsa_get_len return always even number)
mp_shiftl1:
.rept	8
	ld	r25,Z
	rol	r25
	st	Z+,r25
.endr
	dec	r24
	brne	mp_shiftl1
	rol	r24
	ret
#endif
#if defined(HAVE_RSA_SHIFTL5)
        .global rsa_shiftl5
        .type   rsa_shiftl5, @function

rsa_shiftl5:
	movw	ZL,r24
	call	rsa_get_len
	lsr	r24
	lsr	r24

	clr	r25

rsa_shiftl5_loop:
.rep	4
	ld	r22,Z
	mov	r23,r22

	swap	r23
	lsl	r23
	andi	r23,0xe0

	lsr	r22
	lsr	r22
	lsr	r22

	or	r23,r25
	st	Z+,r23
	mov	r25,r22
.endr
	dec	r24
	brne	rsa_shiftl5_loop
	ret
#endif
/////////////////////////////////////////////////////////////
// normal shift right, insert 0 to upper bit
#ifdef HAVE_MP_SHIFTR
mp_shiftr:
	ldi  r22,0
#endif
#if defined( HAVE_MP_SHIFTR_C) || defined(HAVE_MP_SHIFTR)
// shift right, insert 0/1 to upper bit based on r22 (arg 3)
// if r22 == 0 insert 0 otherwise 1
mp_shiftr_c:
        movw	ZL,r24
	call	rsa_get_len
	clr	r25
	add	r30,r24
	adc	r31,r25
// set carry flag if r22 != 0
	sub	r25,r22

mp_shiftr1:
        ld	r25,-Z
        ror	r25
        st	Z,r25 
        dec	r24   
        brne	mp_shiftr1
        rol	r24
        ret
#endif
#ifdef HAVE_MP_SHIFTR_C
mp_shiftr_2N:
#endif
#if defined (HAVE_RSA_SHIFTR_LONG) || defined (mp_shiftr_2N)
	.global	rsa_shiftr_long
	.type	rsa_shiftr_long,@function

rsa_shiftr_long:
	movw	ZL,r24
	call	rsa_get_len
	add	ZL,r24
	adc	ZH,r1
	add	ZL,r24
	adc	ZH,r1
	lsr	r24
	lsr	r24
//      clc			// CY is always cleared (rsa_get_len return always even number)
rsa_shiftr_long_loop:
.rept 8
        ld r25,-Z
        ror r25
        st Z,r25 
.endr
        dec r24  
        brne rsa_shiftr_long_loop
        rol r24
        ret
#endif
