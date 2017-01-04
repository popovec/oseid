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
        .global mp_cmp
        .type   mp_cmp, @function
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
        .global rsa_shiftl
        .type   rsa_shiftl, @function


/////////////////////////////////////////////////////////////
// unroll only 8 bytes,  rest in loop
.macro MP_ADD_BYTE
	ld r23,X+
	ld r25,Y+
	adc r23,r25
	st Z+,r23
.endm
#if defined(HAVE_MP_ADD)
mp_add:
#endif
#if defined (HAVE_RSA_ADD) || defined(HAVE_MP_ADD)
rsa_add:
	movw XL,r20
	movw ZL,r24
	call	rsa_get_len
	lsr	r24
	lsr	r24
	lsr	r24
	rjmp	mp_add0
#endif
#ifdef HAVE_RSA_ADD_LONG
rsa_add_long:
	movw XL,r20
	movw ZL,r24
	call	rsa_get_len
	lsr	r24
	lsr	r24
	rjmp	mp_add0
#endif

#if defined(HAVE_RSA_ADD) || defined(HAVE_RSA_ADD_LONG) || defined(HAVE_MP_ADD)
mp_add0:
        push YL  
        push YH   
        movw YL,r22 
        clc
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
        pop YH     
        pop YL  
        ret
#endif
/////////////////////////////////////////////////////////////
#ifdef HAVE_MP_CMP
mp_cmp:
	movw	ZL,r24
	movw	XL,r22
	call	rsa_get_len
	mov	r25,r24
	ldi	r24,0
	add	r30,r25
	adc	r31,r24
	add	r26,r25
	adc	r27,r24
	rjmp	mp_cmp_loop0

mp_cmp_loop:
	dec	r25
	breq	mp_cmp_end

mp_cmp_loop0:
	ld	r22,-Z
	ld	r23,-X

	cp	r22,r23
	breq	mp_cmp_loop

	ldi	r24,0xff
	brcs	.+2
	ldi	r24,1
mp_cmp_end:
	ret
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
	clc
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
	clc
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
	clc
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
	clc	
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
