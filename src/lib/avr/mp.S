/*
    mp.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2021 Peter Popovec, popovec.peter@gmail.com

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



/////////////////////////////////////////////////////////////
        .global mp_is_zero
        .type   mp_is_zero, @function
	.section .text.mp_is_zero,"ax",@progbits

mp_is_zero:
	movw	r30,r24
	lds	r24,mod_len
	clr	r25
mp_is_zero_loop:
	ld	r0,Z+
	or	r25,r0
	dec	r24
	brne	mp_is_zero_loop
// carry on non zero, non carry on zero
	cp	r24,r25
	sbc	r24,r24
	com	r24
	clr	r25
	ret
/////////////////////////////////////////////////////////////
        .global add_mod
        .type   add_mod, @function
        .global	bn_add_mod
        .type   bn_add_mod, @function

	.section .text.add_mod,"ax",@progbits
#if  1
// big, fast, constant time
// add_mod (Result, Operand, Modulus), Result = (Result + Operand) mod Modulus
add_mod:
bn_add_mod:
.irp    Reg,2,3,4,5,6,7,28,29
	push	r\Reg
.endr
	movw	r18,r24	// save result
	lds	r24,mod_len
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
	lds	r24,mod_len
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
        .global sub_mod
        .type   sub_mod, @function
        .global bn_sub_mod
        .type   bn_sub_mod, @function
	.section .text.sub_mod,"ax",@progbits

// sub mod(r,a,modulus); r = (r-a) mod modulus
sub_mod:
bn_sub_mod:
	movw	r30,r24
	movw	r26,r22

	lds	r24,mod_len
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


// unroll only 8 bytes,  rest in loop
.macro MP_ADD_BYTE
	ld r23,X+
	ld r25,Z
	adc r23,r25
	st Z+,r23
.endm

        .global mp_add_v
        .type   mp_add_v, @function
	.section .text.mp_add_v,"ax",@progbits

mp_add_v:
	movw	XL,r22
	movw	ZL,r24
	mov	r24,r20
	lsr	r24
	lsr	r24
	lsr	r24
	cp	r1,r18	// set carry if needed
//	clr	r1
	rjmp	mp_add1

        .global bn_add
        .type   bn_add, @function
	.section .text.mp_add,"ax",@progbits

        .global mp_add
        .type   mp_add, @function
	.section .text.mp_add,"ax",@progbits

        .global rsa_add
        .type   rsa_add, @function
	.section .text.rsa_add,"ax",@progbits
mp_add:
rsa_add:
bn_add:
	movw XL,r22
	movw ZL,r24
	lds	r24,mod_len
	lsr	r24
	lsr	r24
	lsr	r24
	rjmp	mp_add0

	.global mp_add1
	.type   mp_add1, @function
	.section .text.mp_add1,"ax",@progbits

mp_add0:
//      clc			// CY is always cleared (mod_len is always even number)
mp_add1:
	MP_ADD_BYTE
	MP_ADD_BYTE
	MP_ADD_BYTE
	MP_ADD_BYTE
	MP_ADD_BYTE
	MP_ADD_BYTE
	MP_ADD_BYTE
	MP_ADD_BYTE   
        dec	r24
        brne	mp_add1
        rol	r24
        ret

        .global rsa_add_long
        .type   rsa_add_long, @function
	.section .text.rsa_add_long,"ax",@progbits

rsa_add_long:
	movw XL,r22
	movw ZL,r24
	lds	r24,mod_len
	lsr	r24
	lsr	r24
	rjmp	mp_add0

/////////////////////////////////////////////////////////////
        .global mp_cmpGE
        .type   mp_cmpGE, @function
        .global rsa_cmpGE
        .type   rsa_cmpGE, @function
        .global bn_cmpGE
        .type   bn_cmpGE, @function
	 .section .text.mp_cmpGE,"ax",@progbits
#ifdef EC_CONSTANT_TIME
mp_cmpGE:
rsa_cmpGE:
bn_cmpGE:
	movw	ZL,r24
	movw	XL,r22
	lds	r24,mod_len
	lsr	r24
	lsr	r24
//      clc			// CY is always cleared (mod_len is always even number)
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
rsa_cmpGE:
mp_cmpGE:
bn_cmpGE:
	movw	ZL,r24
	movw	XL,r22
	lds	r24,mod_len
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
/////////////////////////////////////////////////////////////

        .global mp_sub
        .type   mp_sub, @function

        .global bn_sub
        .type   bn_sub, @function

        .global bn_sub_long
        .type   bn_sub_long, @function

        .global rsa_sub
        .type   rsa_sub, @function
	.section .text.rsa_sub,"ax",@progbits

        .global rsa_sub_long
        .type   rsa_sub_long, @function

	.global mp_sub_2N
        .type   mp_sub_2N, @function

// warning, do not change r18,19  or fix bn_abs_sub()
rsa_sub_long:
mp_sub_2N:
bn_sub_long:
	push	YL
	push	YH
	movw	ZL,r24
	movw	XL,r22
	movw	YL,r20
	lds	r24,mod_len
	lsr	r24
	lsr	r24
//      clc			// CY is always cleared (mod_len in always even number)
	rjmp mp_sub1
mp_sub:
rsa_sub:
bn_sub:
	push	YL
	push	YH
	movw	ZL,r24
	movw	XL,r22
	movw	YL,r20
	lds	r24,mod_len
	lsr	r24
	lsr	r24
	lsr	r24
//      clc			// CY is always cleared (mod_len is always even number)

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

/////////////////////////////////////////////////////////////

	.section .text.rsa_shiftl,"ax",@progbits
	.global bn_shift_L_v
	.type   bn_shift_L_v, @function

bn_shift_L_v:
	movw	Z,r24
	mov	r24,r22
	rjmp	1f

	.global	mp_shiftl4
	.type	mp_shiftl4, @function
mp_shiftl4:
	rcall	mp_shiftl2
	movw	r24,r22

	.global	mp_shiftl2
	.type	mp_shiftl2, @function
mp_shiftl2:
	movw	r22,r24
	rcall	mp_shiftl
	movw	r24,r22

        .global mp_shiftl
        .type   mp_shiftl, @function
        .global bn_shiftl
        .type   bn_shiftl, @function
        .global rsa_shiftl
        .type   rsa_shiftl, @function

mp_shiftl:
rsa_shiftl:
bn_shiftl:
	movw	ZL,r24
	lds	r24,mod_len
1:
	lsr	r24
	lsr	r24
	lsr	r24
mp_shiftl0:
//      clc			// CY is always cleared (mod_len is always even number)
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
/////////////////////////////////////////////////////////////
        .global bn_shift_R_signed
        .type   bn_shift_R_signed, @function
	.section .text.bn_shift_R_v_signed,"ax",@progbits

        .global bn_shift_R_v_signed
        .type   bn_shift_R_v_signed, @function
bn_shift_R_signed:
	lds	r22,mod_len
// signed shift
bn_shift_R_v_signed:
	movw	r30,r24
	add	r30,r22
	adc	r31,r1
	ld	r20,-Z
	adiw	r30,1
	andi	r20,0x80
	rjmp	bn_shift_R_0

        .global mp_shiftr_long
        .type   mp_shiftr_long, @function

	.global	rsa_shiftr_long
	.type	rsa_shiftr_long,@function

	.global	bn_shiftr_long
	.type	bn_shiftr_long,@function
	.section .text.bn_shiftr_long,"ax",@progbits

mp_shiftr_long:
rsa_shiftr_long:
bn_shiftr_long:
	movw	ZL,r24
	lds	r22,mod_len
	add	ZL,r22
	adc	ZH,r1
	add	ZL,r22
	adc	ZH,r1
	lsr	r22
	lsr	r22
//      clc			// CY is always cleared (mod_len is always even number)
	rjmp	bn_shift_R_generic


        .global mp_shiftr
        .type   mp_shiftr, @function

        .global rsa_shiftr
        .type	rsa_shiftr, @function

        .global bn_shiftr
        .type   bn_shiftr, @function
	.section .text.bn_shiftr,"ax",@progbits

// uint8_t __attribute__ ((weak)) bn_shiftr (void *r);
mp_shiftr:
rsa_shiftr:
bn_shiftr:
	clr	r22		// shift zero from right

        .global 	mp_shiftr_c
        .type		mp_shiftr_c, @function

        .global 	rsa_shiftr_c
        .type		rsa_shiftr_c, @function

        .global 	bn_shiftr_c
        .type		bn_shiftr_c, @function

// uint8_t __attribute__ ((weak)) bn_shiftr_c (void *r, uint8_t carry);
mp_shiftr_c:
rsa_shiftr_c:
bn_shiftr_c:
	mov	r20,r22		// 0 or not 0 to r20 (to be shifted from right)
	lds	r22,mod_len

// generic fcion - pointer, size, carry
// uint8_t __attribute__ ((weak)) bn_shift_R_v_c (void *r, uint8_t len, uint8_t carry);
        .global		bn_shift_R_v_c
        .type		bn_shift_R_v_c, @function

bn_shift_R_v_c:
	movw	r30,r24

bn_shift_R_:
	add	r30,r22
	adc	r31,r1
bn_shift_R_0:
	lsr	r22
	lsr	r22
	lsr	r22
// set carry flag if r20 != 0
	cp	r1,r20

bn_shift_R_generic:
.rept 8
        ld	r23,-Z
        ror	r23
        st	Z,r23
.endr
        dec	r22
        brne	bn_shift_R_generic
        rol	r22
        ret
