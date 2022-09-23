/*
    bn_inv_mod.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2021 Peter Popovec, popovec.peter@gmail.com

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

    modular multiplicative inversion

    This is optimized code (from ASM generated from C fcion)
*/

	.global bn_inv_mod	
	.type   bn_inv_mod, @function
	.section .text.bn_inv_mod,"ax",@progbits
// variables on stack
// 1,2 - modulus pointer
// 3,4 - bsize_V

// registers
//  r3,r2  rot
//  r5,r4  's'
//  r7,r6  bn_len
// r7 in loop used as sV sU
//  r9,r8  result
// r11,r10 'r'
// r13,r12 'u'
// r15,r14 'v'
// r17,r16 'V_off'

#include "load_sp.h"
// uint8_t __attribute__ ((weak)) bn_inv_mod (void * r, void * a, void * p);
bn_inv_mod:
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

	lds	r6, mod_len
// uint16_t bn_len
	clr	r7

// variables on stack..
	in	r28,0x3d
	in	r29,0x3e
	sbiw	r28,4

// 4 * bn_len
	movw	r26,r6
	add	r26,r26
	adc	r27,r27
	add	r26,r26
	adc	r27,r27
// alloca
	movw	r30,r28
	sub	r30,r26
	sbc	r31,r27
	LOAD_SP r0, r30,r31	
	adiw	r30,1

	movw	r12,r30		// 'u'
// clear 4 * bn_len ..
1:
	st	Z+,r1
	sbiw	r26,1
	brne	1b

// save modulus and resul pointer
	movw	r8, r24		// result
	std	Y+1,r20		// modulus
	std	Y+2,r21

 // one of A or M must be odd (or both)
	movw	r30,r22
	ld	r25,Z
	movw	r30,r20
	ld	r24,Z
	or	r24,r25
	sbrs	r24,0
	rjmp	no_inversion

// copy 'a' (r22,r23) into matrix
// pointer to 'u' in r13,12
	movw	r20,r6
	movw	r24,r12
	call	memcpy

// pointer to 'r' into r11,r10
	movw	r10,r12
	add	r10,r6
	adc	r11,r7
// pointer to 'v' r15,r14
	movw	r14,r10
	add	r14,r6
	adc	r15,r7
// copy 'm' to 'v'
	movw	r20,r6
	ldd	r22,Y+1		// 'm'
	ldd	r23,Y+2
	movw	r24,r14
	call	memcpy
// pointer to 's' into r5,r4
	movw	r4,r14
	add	r4,r6
	adc	r5,r7
// 'r' = 1
	ldi	r24,1
	movw	r30,r10
	st	Z,r24

// compare 'a' 'm' swap if needed
	movw	r22,r14
	movw	r24,r12
	call	bn_cmpGE
	and	r24,r24
	breq	1f
// swap
	movw	r24,r10
	movw	r10,r4
	movw	r4,r24

	movw	r24,r12
	movw	r12,r14
	movw	r14,r24
1:
///////////////////////////////////////////////////
	movw	r24,r14
 	call	bn_count_bits
	std	Y+3,r24		// bsize_V
	std	Y+4,r25
	sbiw	r24, 2
	brcs	1f

	clr	r7		// clear sV sU (bit 4,0)
	mov	r16,r1		// V_off
	mov	r17,r1
	rjmp	loop_start
1:
// result 0 or 1
	movw	r30,r8		// result
	st	Z+,r24		// bsize_V
	dec	r6
1:
	st	Z+,r1
	dec	r6
	brne	1b
	rjmp	bn_inv_mod_ok
	
///////////////////////////////////////////////////////////////////
// main loop
/////
// rot >=0 
rot_plus:
// uint16_t tmp = V_off - rot;
	sub	r16,r2
	sbc	r17,r3
//	  while (tmp--)
//	    {
//	      bn_shift_R_signed (s);
//	      bn_shiftr (v);
//	    }
2:
	cp	r16,r1
	cpc	r17,r1
	breq	2f
1:

	movw	r24,r4
 	call	bn_shift_R_signed
	movw	r24,r14
 	call	bn_shiftr
	ldi	r31,1
	sub	r16,r31
	sbc	r17,r1
	rjmp	2b
2:

update_matrix:
	movw	r24,r10		// 'r'
// compare sV sU
	mov	r18,r7		// sV sU
	swap	r18
	eor	r18,r7
	brne	1f

	movw	r20,r4		// 's'
	movw	r22, r10	// 'r'
	call	bn_sub		// 'r' = 'r' - 's'
	rjmp	2f
1:
	movw	r22, r4
 	call	bn_add		// 'r' = 'r' + 's' 
2:
	movw	r20, r14	// 'v'
	movw	r22, r12
	movw	r24, r12
 	call	bn_abs_sub

	eor	r7,r24		// sU ^= bn_abs_sub (u, u, v);
	movw	r16, r2

loop_start:
	movw	r24, r12

 	call	bn_count_bits
	movw	r22,r24
	movw	r2,r24		// rot = bsize_U - bsize_V
	ldd	r20,Y+3		// bsize_V
	ldd	r21, Y+4
	sub	r2,r20		//	       - bsize_V
	sbc	r3,r21
// test 'rot' sign
	brpl	rot_plus

// rot < 0
	sbiw	r24, 0		// bsize_U
	brne	1f
no_inversion:
	ldi	r24,1
	rjmp	bn_inv_mod_end
1:
	sbiw	r24, 1
	breq	inversion_found

	std	Y+3,r22		// bsize_V = bsize_U;
	std	Y+4,r23
//
//	  while (V_off--)
//	    {
//	      bn_shift_R_signed (s);
//	      bn_shiftr (v);
//	    }

1:
	subi	r16,1
	sbci	r17,0	// test 0-> -1
	brcs	1f
	movw	r24, r4		// 's'
 	call	bn_shift_R_signed
	movw	r24, r14	// 'v'
 	call	bn_shiftr
	rjmp	1b
1:
// rot = -rot;
	neg	r3
	neg	r2
	sbc	r3,r1
//	 V_off = rot;  	//// tmp = rot,
	movw	r16,r2

//	    while (rot--)	//// tmp--
//	      {
//		bn_shiftl (s);
//		bn_shiftl (v);
//	      }
//	  }
1:
	subi	r16,1
	sbci	r17,0
	brcs	1f
// here 'r' 'u' is used because swap  of 'u' 'v' is after this loop
	movw	r24, r10	// 'r'
 	call	bn_shiftl
	movw	r24,r12
 	call	bn_shiftl	// 'u'
	rjmp	1b

1:
	swap	r7		// swap 'sV' 'sU'

	movw	r24,r10
	movw	r10,r4
	movw	r4,r24

	movw	r24,r12
	movw	r12,r14
	movw	r14,r24
	rjmp	update_matrix
///////////////////////////////////////////////////////
inversion_found:
	movw	r24,r10		// 'r'
	sbrc	r7,0		// test sU
	call    bn_neg		// negate 'r' if needed
1:
	ldd	r22,Y+1		// modulus
	ldd	r23,Y+2

	movw	r30,r8		// result
	movw	r26,r10		// 'r'
1:
	ld	r24,X+
	st	Z+,r24
	dec	r6
	brne	1b
// last byte of result is in r24

	sbrs	r24,7		// test sign
	rjmp	1f

	movw	r24,r8		// result
 	call	bn_add
	rjmp	bn_inv_mod_ok
1:
	movw	r24,r10
 	call	bn_cmpGE	// compare modulus and result
	and	r24,r24
	breq	bn_inv_mod_end

// result = result - modulus
	ldd	r20,Y+1		// modulus
	ldd	r21,Y+2
	movw	r22,r8		// result
	movw	r24,r8		// result
	call	bn_sub
bn_inv_mod_ok:
	ldi	r24,0
bn_inv_mod_end:
	adiw	r28,4
	LOAD_SP r0,r28,r29

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
