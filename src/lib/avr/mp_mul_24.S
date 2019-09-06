/*
    mp_mul_24.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2019 Peter Popovec, popovec.peter@gmail.com

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

    Atmega assembler routines for (24 bits and derived) multiplications 

    This file depend on mp_mul_192.S
*/
/////////////////////////////////////////////////////////////
#include "load_sp.h"

	.global mp_mul_192
	.type	mp_mul_192, @function
	.global rsa_mul_192
	.type	rsa_mul_192, @function
	.section .text.rsa_mul_192,"ax",@progbits

mp_mul_192:
rsa_mul_192:
//save registers
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

	movw	r30,r24
	movw	r28,r22
	movw	r26,r20

	call	rsa_mul_192_no_abi

	clr	r1
// return registers
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

	.global mp_mul_384
	.type	mp_mul_384, @function
	.global rsa_mul_384
	.type	rsa_mul_384, @function
	.section .text.rsa_mul_384,"ax",@progbits
#define UNROLL 4

#ifndef UNROLL
#define UNROLL 1
#endif

#define OPERAND_B r10
#define RESULT    r12
#define OPERAND_A r14

mp_mul_384:
rsa_mul_384:
//save registers
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
	movw	r30,r24
	movw	r28,r22
	movw	r26,r20
	call	rsa_mul_384_no_abi
// return registers
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
	.global rsa_mul_384_no_abi
	.type	rsa_mul_384_no_abi, @function
	.section .text.rsa_mul_384_no_abi,"ax",@progbits

rsa_mul_384_no_abi:
	movw    r22,r28 // save A pointer copy
// create space on stack(48 bytes TMP variable, 3x pointer, 1x sign
	in	r28, 0x3d
	in	r29, 0x3e
	subi	r28, lo8(48+2+2+2+1)
	sbci	r29, hi8(48+2+2+2+1)
	LOAD_SP r0, r28,r29

// save  pointers to stack
	std	Y+1,r22	// A pointer
	std	Y+2,r23
	std	Y+3,r30	// Result
	std	Y+4,r31
	std	Y+5,r26	// B pointer
	std	Y+6,r27

// calculate a_low - a_high -> r
	movw	r28,r22		//A, A+24 is addressed by Y
	ldi	r25,3		//3*8 = 24 bytes
	sub	r24,r24		//initial carry(s)
rsa_mul_384_loop1a:
// load A into r0..r7, A+24 to r8..r15
.irp	pos,0,1,2,3,4,5,6,7
	ld	r\pos,Y+
.endr
.irp	pos,8,9,10,11,12,13,14,15
	ldd	r\pos,Y+8+\pos
.endr
// copy
	movw	r16,r0
	movw	r18,r2
	movw	r20,r4
	movw	r22,r6

	sbc	r0,r8
	sbc	r1,r9
	sbc	r2,r10
	sbc	r3,r11
	sbc	r4,r12
	sbc	r5,r13
	sbc	r6,r14
	sbc	r7,r15
.irp    pos,0,1,2,3,4,5,6,7
	st	Z+,r\pos
.endr
	ror	r24	//save carry/renew carry
	sbc	r8,r16
	sbc	r9,r17
	sbc	r10,r18
	sbc	r11,r19
	sbc	r12,r20
	sbc	r13,r21
	sbc	r14,r22
	sbc	r15,r23
.irp    pos,8,9,10,11,12,13,14,15
	std	Z+8+\pos,r\pos
.endr
	rol	r24	//renew carry

	dec	r25
	brne	rsa_mul_384_loop1a

	movw	r28,r26 // B pointer
	movw	r2,r30	// result + ../.. for b_low -b_high
	bst	r24,0	// save sign	
	bld	r25,4	// 0 or 24
        bld	r25,3

	sub	r30,r25
	sbci	r31,0
	movw	r26,r30		// first operand for multiply
// sign is saved in T flag, r26 position of first operand		

// calculate b_low - b_high -> r
	movw	r30,r2		// result + 48/60 for b_low -b_high
	adiw	r30,24
	ldi	r25,3		//3*8 = 24 bytes

	sub	r24,r24		//initial carry(s)
rsa_mul_384_loop1b:
// load B into r0..r7, B+24 to r8..r15
.irp	pos,0,1,2,3,4,5,6,7
	ld	r\pos,Y+
.endr
.irp	pos,8,9,10,11,12,13,14,15
	ldd	r\pos,Y+8+\pos
.endr
// copy
	movw	r16,r0
	movw	r18,r2
	movw	r20,r4
	movw	r22,r6

	sbc	r0,r8
	sbc	r1,r9
	sbc	r2,r10
	sbc	r3,r11
	sbc	r4,r12
	sbc	r5,r13
	sbc	r6,r14
	sbc	r7,r15
.irp    pos,0,1,2,3,4,5,6,7
	st	Z+,r\pos
.endr
	ror	r24	//save carry/renew carry
	sbc	r8,r16
	sbc	r9,r17
	sbc	r10,r18
	sbc	r11,r19
	sbc	r12,r20
	sbc	r13,r21
	sbc	r14,r22
	sbc	r15,r23
.irp    pos,8,9,10,11,12,13,14,15
	std	Z+8+\pos,r\pos
.endr
	rol	r24	//renew carry

	dec	r25
	brne	rsa_mul_384_loop1b

// get xor from sing of (a_low - a_high),(b_low - b_high)
	in	r28, 0x3d
	in	r29, 0x3e
	mov	r25,r24	// copy sign
	bld	r0,0	// previous sign
	eor 	r25,r0
	andi	r25,1
	std	Y+7,r25 // sign	

// select RESULT or RESULT + 24 for |b_low - b_high|
	bst	r24,0
	clr	r24
	bld	r24,4
	bld	r24,3
	sub	r30,r24
	sbci	r31,0
	movw	r28,r30	//second operand

// multiply |a_low - a_high| * |b_low - b_high| into TMP
	
	in	r30, 0x3d
	in	r31, 0x3e
	adiw	r30,8		// skip variables on stack to point 64 byt TMP
		
	call	rsa_mul_192_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	ldd	r26,Y+1	// OPERAND_B
	ldd	r27,Y+2
	ldd	r24,Y+5	// OPERAND_A
	ldd	r25,Y+6
	movw	r28,r24
// a_low * b_low to r
	call	rsa_mul_192_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
// a_high * b_high to r+48
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	subi	r30,-48
	sbci	r31,0xff
	ldd	r26,Y+1	// OPERAND_B
	ldd	r27,Y+2
	adiw	r26,24
	ldd	r24,Y+5	// OPERAND_A
	ldd	r25,Y+6
	movw	r28,r24
	adiw	r28,24

	call	rsa_mul_192_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	ldd	r24,Y+7	// sign
	movw	r26,r28
	adiw	r26,8		// skip variables on stack to point 48 byt TMP

// summarize L,H,M, sub/add M (based on sign.. in r24,r25)

// get sign from r24
// if signs are the same, set r25 to 0xff r24 to 1
// else                   set r25 to 0x00 r24 to 0


#define _CARRY r24
#define _ACC r23
#define _EOR r25

	ldi	_EOR,1
	eor	_CARRY,r25
// generate ff/0  from 1/0
	mov	_EOR,_CARRY
	neg	_EOR

// r24 is used as initial carry, r25 as eor value

	movw	r28,r30
	subi	r28,lo8(-48)
	sbci	r29,hi8(-48)
//       D          C           B          A          
//   95      72 71      48 47       24 23      0
//                      Y                      Z
//-------------------------------------------------
// cahce = r6..r22
// summarize B,C into C (bytes 48..71), sum into cache
	ldd	r0,Z+24
	ldd	r6,Y+0
	add	r6,r0
.irp	pos,1,2,3,4,5
	ldd	\pos,Z+\pos+24	//B
	ldd	\pos+6,Y+\pos	//C
	adc	\pos+6,\pos
.endr
	ror	_CARRY	//save carry
// from A+B+C subtract/add M store final result into B
.irp	pos,0,1,2,3,4,5
	ld	\pos,X+
	eor	\pos,_EOR
	adc	\pos,\pos+6
.endr
	ror	_CARRY	//save carry
// to B+C add part A
	ldd	_ACC,Z+0
	add	r0,_ACC
	std	Z+24,r0
.irp    pos,1,2,3,4,5
	ldd     _ACC,Z+\pos
	adc	\pos,_ACC
	std	Z+24+\pos,\pos
.endr	
	rol	_CARRY	//save carry
	rol	_CARRY	//renew carry
//-------------------------------------------------
.irp	pos,0,1,2,3,4,5
	ldd	\pos,Z+\pos+24+6
	ldd	\pos+6+6,Y+\pos+6
	adc	\pos+6+6,\pos
.endr
	ror	_CARRY	//save carry
// from A+B+C subtract/add M store final result into B 
.irp	pos,0,1,2,3,4,5
	ld	\pos,X+
	eor	\pos,_EOR
	adc	\pos,\pos+6+6
.endr
	ror	_CARRY	//save carry
// to B+C add part A
.irp    pos,0,1,2,3,4,5
	ldd     _ACC,Z+\pos+6
	adc	\pos,_ACC
	std	Z+24+\pos+6,\pos
.endr
	rol	_CARRY	//save carry
	rol	_CARRY	//renew carry
//-------------------------------------------------
.irp	pos,0,1,2,3,4
	ldd	\pos,Z+\pos+24+12
	ldd	\pos+6+12,Y+\pos+12
	adc	\pos+6+12,\pos
	std	Y+\pos+12,\pos+6+12
.endr
	ldd	r5,Z+5+24+12
	ldd	_ACC,Y+5+12
	adc	r5,_ACC
	std	Y+5+12,r5	// no cache . store to RAM

	ror	_CARRY	//save carry
// from A+B+C subtract/add M store final result into B
.irp	pos,0,1,2,3,4
	ld	\pos,X+
	eor	\pos,_EOR
	adc	\pos,\pos+6+12
.endr
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	r5,_ACC

	ror	_CARRY	//save carry
// to B+C add part A
.irp    pos,0,1,2,3,4,5
	ldd     _ACC,Z+\pos+12
	adc	r\pos,_ACC
	std	Z+24+\pos+12,r\pos
.endr
	rol	_CARRY	//save carry
	rol	_CARRY	//renew carry
//-------------------------------------------------
// summarize B,C into C
.irp	pos,0,1,2,3,4,5
	ldd	r\pos,Z+\pos+24+18
	ldd	_ACC,Y+18+\pos
	adc	r\pos,_ACC
	std	Y+18+\pos,r\pos
.endr
	ror	_CARRY	//save carry
	bst	_CARRY,7
// from A+B+C subtract M store final result into B 
.irp	pos,0,1,2,3,4,5
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	r\pos,_ACC
.endr
	ror	_CARRY	//save carry
// to B+C add part A
.irp	pos,0,1,2,3,4,5
	ldd     _ACC,Z+18+\pos
	adc	r\pos,_ACC
	std	Z+24+18+\pos,r\pos
.endr
	rol	_CARRY	//save borrow/carry,renew ABC
	rol	_CARRY
//////////////////////////////////////////////////////////////////
// A,B is in final state
//--------------------------------------------------
// continue in C part .. C+D bytes 48..53
// B+C from cache
.irp	pos,0,1,2,3,4,5
	ldd	\pos,Y+24+0+\pos	//D cache in r0..r5
	adc	\pos+6,\pos		//B+C +D
.endr
	ror	_CARRY	//save carry
// subtract/add rest of M
.irp	pos,0,1,2,3,4,5
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	\pos+6,_ACC
.endr
	ror	_CARRY	//save carry
	clr	_ACC
.irp	pos,0,1,2,3,4,5
	adc	\pos+6,_ACC
	std	Y+0+\pos,\pos+6
.endr
// continue in C part .. C+D bytes 54..59
// prop carry .. to B+C in cache
.irp	pos,0,1,2,3,4,5
	adc	\pos+6+6,_ACC
.endr
	rol	_CARRY
// subtract/add rest of M
.irp	pos,0,1,2,3,4,5
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	\pos+6+6,_ACC
.endr
	rol	_CARRY
// add D
.irp	pos,0,1,2,3,4,5
	ldd	\pos+6,Y+24+6+\pos	//D cache in r6..r11
	adc	\pos+6+6,\pos+6
	std	Y+6+\pos,\pos+6+6
.endr
// continue in C part .. C+D bytes 60..65
// B+C from cache
.irp	pos,0,1,2,3,4
	ldd	\pos+6+6,Y+24+12+\pos	// D cache in r12..16
	adc	\pos+6+12,\pos+6+6	// bc from cache
.endr
// not cached .. get from MEM
	ldd	r17,Y+24+12+5		// not cahed D17 !
	ldd	_ACC,Y+12+5		// bc from mem
	adc	r17,_ACC

	ror	_CARRY	//save carry
// subtract/add rest of M
.irp	pos,0,1,2,3,4
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	\pos+6+12,_ACC
.endr
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	r17,_ACC

	ror	_CARRY	//save carry
	clr	_ACC
.irp	pos,0,1,2,3,4
	adc	\pos+6+12,_ACC
	std	Y+12+\pos,\pos+6+12
.endr
	adc	r17,_ACC
	std	Y+12+5,r17
// continue in C part .. C+D bytes 66 ..71
// ACU in r18..r23
#undef _ACC
#define _ACC r17
// continue add carry from B+C
	clr	_ACC
.irp	pos,0,1,2,3,4,5
	ldd	\pos+18,Y+18+\pos	//B+C
	adc	\pos+18,_ACC
.endr
	rol	_CARRY
// subtract/add rest of M
.irp	pos,0,1,2,3,4,5
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	\pos+18,_ACC
.endr
	rol	_CARRY

.irp	pos,0,1,2,3,4,5
	ldd	\pos+17,Y+24+18+\pos	//D cache in r17..r22
	adc	\pos+18,\pos+17
	std	Y+18+\pos,\pos+18
.endr
//-------------------------------------------------
//summarize borow carry, propagate to D
#define _CARRY16L _EOR
#define _CARRY16H  r27
#undef _ACC
#define _ACC r23

	mov	_CARRY16H,_CARRY16L

// T,  CY, and from _CARRY bit 7 and bit 6  must be summarized..
// 1st T and CY
	bld	_ACC,0
	andi	_ACC,1

	adc	_CARRY16L,_ACC
	clr	_ACC
	adc	_CARRY16H,_ACC

// rotate bit 1,0 to CY and bit 0
	ror	_CARRY

	andi	_CARRY,1
	adc	_CARRY16L,_CARRY
	adc	_CARRY16H,_ACC

	add	r0,_CARRY16L
	std	Y+24,r0

.irp	pos,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
	adc	\pos,_CARRY16H
	std	Y+24+\pos,\pos
.endr
// not cached!
	ldd     _ACC,Y+24+17
	adc	_ACC,_CARRY16H
	std	Y+24+17,_ACC

.irp	pos,18,19,20,21,22,23
	adc	\pos-1,_CARRY16H
	std	Y+24+\pos,\pos-1
.endr
// return stack position
	in	r28, 0x3d
	in	r29, 0x3e
	subi	r28, lo8(-(48+2+2+2+1))
	sbci	r29, hi8(-(48+2+2+2+1))
	LOAD_SP r0, r28,r29
	ret

#undef _CARRY
#undef _ACC
#undef _EOR
#undef OPERAND_B
#undef RESULT
#undef OPERAND_A
#undef UNROLL
#undef L1
#undef L2
#undef L3
#undef L4
#undef L5
#undef L6
#undef L7


/////////////////////////////////////////////////////////////
	.global mp_mul_768
	.type	mp_mul_768, @function
        .global rsa_mul_768
        .type   rsa_mul_768, @function
	.section .text.rsa_mul_768,"ax",@progbits

#define UNROLL 4

#ifndef UNROLL
#define UNROLL 1
#endif

#define OPERAND_B r10
#define RESULT    r12
#define OPERAND_A r14
rsa_mul_768:
mp_mul_768:
//save registers
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
	push	r16	// sign of a_low - a_high
	push	r17	// sign of b_low - b_high
	push	r28
	push	r29
// create space on stack(96 bytes TMP variable, 3x pointer, 1x sign
	in	r28, 0x3d
	in	r29, 0x3e
	subi	r28, lo8(96+2+2+2+1)
	sbci	r29, hi8(96+2+2+2+1)
	LOAD_SP r0, r28,r29

// save operands position
	movw	RESULT, r24	// r
	movw	OPERAND_A, r22	// a
	movw	OPERAND_B, r20	// b

// calculate a_low - a_high -> r
	movw	r30,OPERAND_A	// a, a+48 to Z
	movw	r26,RESULT	// r to X

	ldi	r21,48/UNROLL	// loop counter
	sub	r16,r16		// initial carry, and clear r16
rsa_mul_768_loop1:
.rept	UNROLL
	ld	r24,Z+
	ldd	r25,Z+47
	sbc	r24,r25
	st	x+,r24
.endr
	dec	r21
	brne	rsa_mul_768_loop1

// negate if needed, sign based on carry
	sbc	r16,r16		//r16=0/0xff (from carry)

	movw	r26,RESULT	// r to X
	ldi	r21,48/UNROLL	// loop counter

	clc
rsa_mul_768_loop2:
.rept	UNROLL
	ld	r24,X
	eor	r24,r16		// xor 0xff
	sbc	r24,r16
	st	x+,r24
.endr
	dec	r21
	brne	rsa_mul_768_loop2

// calculate b_low - b_high -> r + 48
	movw	r30,OPERAND_B	// b, b+48 to Z
	movw	r26,RESULT	// r
	subi	r26,lo8(-48)
	sbci	r27,hi8(-48)	//r+48

	ldi	r21,48/UNROLL	// loop counter
	sub	r17,r17		// initial carry, and clear r17
rsa_mul_768_loop3:
.rept	UNROLL
	ld	r24,Z+
	ldd	r25,Z+47
	sbc	r24,r25
	st	x+,r24
.endr
	dec	r21
	brne	rsa_mul_768_loop3

// negate if needed, sign based on carry
	sbc	r17,r17		//r17=0/0xff (from carry)

	movw	r26,RESULT	// r to X
	subi	r26,lo8(-48)
	sbci	r27,hi8(-48)	//r+48
	ldi	r21,48/UNROLL	// loop counter

	clc
rsa_mul_768_loop4:
.rept	UNROLL
	ld	r24,X
	eor	r24,r17		// xor 0/0xff
	sbc	r24,r17		
	st	x+,r24
.endr
	dec	r21
	brne	rsa_mul_768_loop4

// create "sign" xor into R16

	eor	r16,r17
// save sign, pointers to stack, rsa_mul_512_no_abi uses _all_ registers
	std	Y+1,r10	// B pointer
	std	Y+2,r11
	std	Y+3,r12	// Result
	std	Y+4,r13
	std	Y+5,r14	// A pointer
	std	Y+6,r15
	std	Y+7,r16	// sign

// multiply |a_low - a_high| * |b_low - b_high| into TMP
	movw	r30,r28		// STACK,
	adiw	r30,8		// skip variables on stack to point 96 byt TMP

	movw	r28,RESULT
	movw	r26,RESULT
	subi	r26,lo8(-48)
	sbci	r27,hi8(-48)	//r+48

	call	rsa_mul_384_no_abi
// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	ldd	r24,Y+1	// OPERAND_B
	ldd	r25,Y+2
	ldd	r26,Y+5	// OPERAND_A
	ldd	r27,Y+6
	movw	r28,r24
// a_low * b_low to r
	call	rsa_mul_384_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
// a_high * b_high to r+96
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	subi	r30,lo8(-96)
	sbci	r31,hi8(-96)
	ldd	r24,Y+1	// OPERAND_B
	ldd	r25,Y+2
	subi	r24,lo8(-48)
	sbci	r25,hi8(-48)	//B+48
	ldd	r26,Y+5	// OPERAND_A
	ldd	r27,Y+6
	subi	r26,lo8(-48)
	sbci	r27,hi8(-48)	//B+48
	movw	r28,r24
	call	rsa_mul_384_no_abi
// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
#define _CARRY r25
#define _ACC r24
#define _COUNT r23
#define _EOR r22
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	ldd	_EOR,Y+7	// sign
	movw	r26,r28
	adiw	r26,8		// skip variables on stack to point 128 byt TMP

// get sign from r16
// if signs are the same, set _EOR to 0xff
// else                   set _EOR to 0x00

	com	_EOR

// _CARRY is used as initial carry, _EOR as eor value

// 8 byt ACU in r0..r7
/*
     255...192 191...128 127...64 63...0
                      Y              Z
middle part is addressed by X
*/
	movw	r28,r30
	subi	r28,lo8(-96)
	sbci	r29,hi8(-96)

//	ldi	_COUNT,6
	mov	_COUNT,r30
	subi	_COUNT,(-48)
// set initial carry for add/sub
	sub	_CARRY,_CARRY
	bst	_EOR,0
	bld	_CARRY,6

rsa_mul_768_xloop1:
// first read A to move Z pointer to reach B part
.irp	pos,0,1,2,3,4,5,6,7
	ld	\pos+8,Z+
.endr
// summarize B+C, store to MEM at position C
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Z+48-8+\pos	//load B
	ldd	_ACC,Y+\pos		//load C
	adc	\pos,_ACC		//sum
.endr
.irp    pos,0,1,2,3,4,5,6,7
	st	Y+,\pos			//store BC into RAM
.endr
	rol	_CARRY		// save B+C carry
// add A
.irp	pos,0,1,2,3,4,5,6,7
	adc	\pos,\pos+8	//sum
.endr
	rol	_CARRY
//subtract/add M
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+		//load M
	eor	_ACC,_EOR
	adc	\pos,_ACC	//subtract
	std	Z+48-8+\pos,\pos	//save final B
.endr
	ror	_CARRY
	ror	_CARRY

//	dec	_COUNT
//	breq	rsa_mul_768_xloop1_end
	cpse	_COUNT,r30
	rjmp	rsa_mul_768_xloop1
//rsa_mul_768_xloop1_end:

// A,B part	 ok, add D
// prevent carry, correct Z to point C
	ror	_CARRY
	bst	_CARRY,7	//save B+C carry
	subi	r30,lo8(-48)
	sbci	r31,hi8(-48)
/*
     255...192 191...128 127...64 63...0
             Y        Z
middle part is addressed by X
*/
//	ldi	_COUNT,6
	mov	_COUNT,r30
	subi	_COUNT,(-48)
	rol	_CARRY
rsa_mul_768_xloop2:
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Z+\pos	//B+C in RAM
	ld	\pos+8,Y+		//D
	adc	\pos,\pos+8
.endr
	rol	_CARRY
// propagate carry
	clr	_ACC
.irp	pos,0,1,2,3,4,5,6,7
	adc	\pos,_ACC
.endr
	rol	_CARRY
//subtract M
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+		//M
	eor	_ACC,_EOR
	adc	\pos,_ACC
	st	Z+,\pos		// save final C
.endr
	ror	_CARRY
	ror	_CARRY

//	dec	_COUNT
//	breq	rsa_mul_768_xloop2_end
	cpse	_COUNT,r30
	rjmp	rsa_mul_768_xloop2
//rsa_mul_768_xloop2_end:

/*
     255...192 191...128 127...64 63...0
             Z
*/
// propagate carry to D
//(rest of carry in _CARRY bit 7,6 and C bit)
// 0 or 0xffff (_EOR,r23)
	clr	r1
	mov	r23,_EOR

	clr	_ACC
	bld	_ACC,0
	adc	_EOR,_ACC
	adc	r23,r1

	rol	_CARRY
	rol	_CARRY
	andi	_CARRY,1
	adc	_EOR,_CARRY
	adc	r23,r1


	ld	_ACC,Z
	add	_ACC,_EOR
	st	Z+,_ACC
.rept	47-8
	ld	_ACC,Z
	adc	_ACC,r23
	st	Z+,_ACC
.endr
//cached
.irp	pos,0,1,2,3,4,5,6,7
	adc	\pos+8,r23
	st	Z+,\pos+8
.endr
// return stack position (X is used to point variable on stack, correct X to get old SP)
	sbiw 	r26,1
	LOAD_SP r0, r26,r27
// return registers
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
#undef OPERAND_B
#undef RESULT
#undef OPERAND_A
#undef UNROLL
#undef L1
#undef L2
#undef L3
#undef L4
#undef L5
#undef L6
#undef L7



#ifdef HAVE_RSA_MUL_192_MOD
// multiplication 48x48 bites, A1,A0 is destroyed!
//                RESULT                                             B                  A
.macro MUL_48 RS11 RS10 RS9 RS8 RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0  B5 B4 B3 B2 B1 B0   A5 A4 A3 A2 A1 A0
//            25   24   23   22  21  20  19 18
// clear upper part of result
	clr	\RS6
	clr	\RS7
	movw	\RS8,\RS6

// line by line multiplication,
//A0
	mul	\A0,\B2
	movw	\RS2,r0
	mul	\A0,\B0
	movw	\RS0,r0
	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\RS9
	mul	\A0,\B4
	movw	\RS4,r0
	mul	\A0,\B3
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\RS9
	mul	\A0,\B5
	add	\RS5,r0
	adc	\RS6,r1
//A1
// use RS10,11 for carry catching
	mul	\A1,\B2
	movw	\RS10,r0
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\RS10
	adc	\RS11,\RS9
	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS11,\RS9
	mul	\A1,\B4
	add	\RS4,\RS11
	adc	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\RS9
	mul	\A1,\B3
	movw	\RS10,r0
	mul	\A1,\B5
	add	\RS4,\RS10
	adc	\RS5,\RS11
	adc	\RS6,r0
	adc	\RS7,r1
//A2
	mul	\A2,\B2
	movw	\RS10,r0
	mul	\A2,\B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\RS10
	adc	\RS11,\RS9
	mul	\A2,\B1
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS11,\RS9
	mul	\A2,\B4
	add	\RS5,\RS11
	adc	\RS6,r0
	adc	\RS7,r1
// zero to upper registers of result, RS8 is needed now
	movw	\RS10,\RS8
// A0,A1 is reused for carry ..
	adc	\RS8,\RS9
	mul	\A2,\B3
	movw	\A0,r0
	mul	\A2,\B5
	add	\RS5,\A0
	adc	\RS6,\A1
	adc	\RS7,r0
	adc	\RS8,r1
//A3
	mul	\A3,\B2
	movw	\A0,r0
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\A0
	adc	\A1,\RS11
	mul	\A3,\B1
	add	\RS4,r0
	adc	\RS5,r1
	adc	\A1,\RS11
	mul	\A3,\B4
	add	\RS6,\A1
	adc	\RS7,r0
	adc	\RS8,r1
	adc	\RS9,\RS11
	mul	\A3,\B3
	movw	\A0,r0
	mul	\A3,\B5
	add	\RS6,\A0
	adc	\RS7,\A1
	adc	\RS8,r0
	adc	\RS9,r1

//A4
	mul	\A4,\B2
	movw	\A0,r0
	mul	\A4,\B0
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\A0
	adc	\A1,\RS11
	mul	\A4,\B1
	add	\RS5,r0
	adc	\RS6,r1
	adc	\A1,\RS11
	mul	\A4,\B4
	add	\RS7,\A1
	adc	\RS8,r0
	adc	\RS9,r1
	adc	\RS10,\RS11
	mul	\A4,\B3
	movw	 \A0,r0
	mul	\A4,\B5
	add	\RS7,\A0
	adc	\RS8,\A1
	adc	\RS9,r0
	adc	\RS10,r1
//A5
	mul	\A5,\B2
	movw	 \A0,r0
	mul	\A5,\B0
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\A0
	adc	\A1,\RS11
	mul	\A5,\B1
	add	\RS6,r0
	adc	\RS7,r1
	adc	\A1,\RS11
	mul	\A5,\B4
	add	\RS8,\A1
	adc	\RS9,r0
	adc	\RS10,r1
	adc	\RS11,\RS11
	mul	\A5,\B3
	movw	\A0,r0
	mul	\A5,\B5
	add	\RS8,\A0
	adc	\RS9,\A1
	adc	\RS10,r0
	adc	\RS11,r1
.endm

.macro MUL_48_ADD   RS11 RS10 RS9 RS8 RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0     B5 B4 B3 B2 B1 B0   A5 A4 A3 A2 A1 A0      ZERO1 ZERO0
// clear upper part of result first (some of result registers are used as carry cacther 1st)
	movw	\RS6,\ZERO0
	movw	\RS8,\ZERO0
	movw	\RS10,\ZERO0

// first low part from operands A0..5 B0 .. 5 (to add in low part of result)
// use RS8, RS9 as carry catcher
	mul	\B0,\A0
	add	\RS0,r0
	adc	\RS1,r1
	adc	\RS2,\ZERO1
	adc	\RS8,\ZERO1

	mul	\B0,\A1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS8,\ZERO1

	mul	\B1,\A0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\RS8
	adc	\RS9,\ZERO1

	mul	\B0,\A2
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS9,\ZERO1

	mul	\B1,\A1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS9,\ZERO1

// release old carry catcher RS8,RS9,use new in RS6,RS7
	mul	\B2,\A0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\RS9
	adc	\RS7,\ZERO1

// clear old carry catcher (RS8,RS9)
	movw	\RS8,\ZERO0

	mul	\B0,\A3
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS7,\ZERO1

	mul	\B1,\A2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS7,\ZERO1

	mul	\B2,\A1
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS7,\ZERO1

	mul	\B3,\A0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\RS7
	adc	\RS6,\ZERO1

	mul	\B0,\A4
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO1

	mul	\B1,\A3
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO1

	mul	\B2,\A2
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO1

	mul	\B3,\A1
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO1

	mul	\B4,\A0
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO1

// Result in RS7 - clear first, was used as carry catcher
	clr	\RS7
	mul	\B0,\A5
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO1

	mul	\B1,\A4
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO1

	mul	\B2,\A3
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO1

	mul	\B3,\A2
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO1

	mul	\B4,\A1
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO1

	mul	\B5,\A0
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO1
////////////// LOW part (with add to result) end

	mul	\B5,\A1
	add	\RS6,r0
	adc	\RS7,r1
	adc	\RS8,\ZERO1

	mul	\B4,\A2
	add	\RS6,r0
	adc	\RS7,r1
	adc	\RS8,\ZERO1

	mul	\B3,\A3
	add	\RS6,r0
	adc	\RS7,r1
	adc	\RS8,\ZERO1

	mul	\B2,\A4
	add	\RS6,r0
	adc	\RS7,r1
	adc	\RS8,\ZERO1

	mul	\B1,\A5
	add	\RS6,r0
	adc	\RS7,r1
	adc	\RS8,\ZERO1


	mul	\B5,\A2
	add	\RS7,r0
	adc	\RS8,r1
	adc	\RS9,\ZERO1

	mul	\B4,\A3
	add	\RS7,r0
	adc	\RS8,r1
	adc	\RS9,\ZERO1

	mul	\B3,\A4
	add	\RS7,r0
	adc	\RS8,r1
	adc	\RS9,\ZERO1

	mul	\B2,\A5
	add	\RS7,r0
	adc	\RS8,r1
	adc	\RS9,\ZERO1


	mul	\B5,\A3
	add	\RS8,r0
	adc	\RS9,r1
	adc	\RS10,\ZERO1

	mul	\B4,\A4
	add	\RS8,r0
	adc	\RS9,r1
	adc	\RS10,\ZERO1

	mul	\B3,\A5
	add	\RS8,r0
	adc	\RS9,r1
	adc	\RS10,\ZERO1


	mul	\B5,\A4
	add	\RS9,r0
	adc	\RS10,r1
	adc	\RS11,\ZERO1

	mul	\B4,\A5
	add	\RS9,r0
	adc	\RS10,r1
	adc	\RS11,\ZERO1


	mul	\B5,\A5
	add	\RS10,r0
	adc	\RS11,r1
.endm

.macro ABS_48  RS5 RS4 RS3 RS2 RS1 RS0   SIGN
	eor	\RS0,\SIGN
	eor	\RS1,\SIGN
	eor	\RS2,\SIGN
	eor	\RS3,\SIGN
	eor	\RS4,\SIGN
	eor	\RS5,\SIGN
	sub	\RS0,\SIGN
	sbc	\RS1,\SIGN
	sbc	\RS2,\SIGN
	sbc	\RS3,\SIGN
	sbc	\RS4,\SIGN
	sbc	\RS5,\SIGN
.endm

// zero here     vvvvvvv
.macro MUL_48_X  RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0  B5 B4 B3 B2 B1 B0    A5 A4 A3 A2 A1 A0
// not enough registers, calculate RS0,RS1 into free register pairs
	movw	\RS4,\RS6 //ZERO
#if 0
	movw	\RS2,\RS6 //ZERO
	mul	\B0,\A0
	movw	\RS0,r0

	mul	\B0,\A1
	add	\RS1,r0
	adc	\RS2,r1

	mul	\B1,\A0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\RS7 //ZERO
///

	mul	\B0,\A2
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\RS7 //ZERO
#else
	mul	\B0,\A0
	movw	\RS0,r0
	mul	\B0,\A2
	movw	\RS2,r0

	mul	\B0,\A1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\RS7	//ZERO
	adc	\RS4,\RS7	//ZERO

	mul	\B1,\A0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\RS7	//ZERO
	adc	\RS4,\RS7	//ZERO

#endif

	mul	\B1,\A1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\RS7 //ZERO
	mul	\B2,\A0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\RS7 //ZERO

	mul	\B0,\A3
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\RS7 //ZERO
	mul	\B1,\A2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\RS7 //ZERO
	mul	\B2,\A1
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\RS7 //ZERO
	mul	\B3,\A0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\RS7 //ZERO

	mul	\B0,\A4
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\RS7 //ZERO		//first use or \RS6
	mul	\B1,\A3
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\RS7 //ZERO
	mul	\B2,\A2
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\RS7 //ZERO
	mul	\B3,\A1
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\RS7 //ZERO
	mul	\B4,\A0
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\RS7 //ZERO

	mul	\B0,\A5		//last \B0

// Reuse B0 as zero
	clr	\B0
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\B0 //ZERO
	mul	\B1,\A4
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\B0 //ZERO
	mul	\B2,\A3
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\B0 //ZERO
	mul	\B3,\A2
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\B0 //ZERO
	mul	\B4,\A1
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\B0 //ZERO
	mul	\B5,\A0		//last A0,reuse A0 into result RS8
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\B0 //ZERO
// A0 is reused from here  as RS8
	clr	\A0
	mul	\B1,\A5
	add	\RS6,r0
	adc	\RS7,r1
	adc	\A0,\B0 //ZERO
	mul	\B2,\A4
	add	\RS6,r0
	adc	\RS7,r1
	adc	\A0,\B0 //ZERO
	mul	\B3,\A3
	add	\RS6,r0
	adc	\RS7,r1
	adc	\A0,\B0 //ZERO
	mul	\B4,\A2
	add	\RS6,r0
	adc	\RS7,r1
	adc	\A0,\B0 //ZERO
	mul	\B5,\A1
	add	\RS6,r0
	adc	\RS7,r1
	adc	\A0,\B0 //ZERO
// A1 is reused from here  as RS9
	clr	\A1
	mul	\B2,\A5
	add	\RS7,r0
	adc	\A0,r1
	adc	\A1,\B0 //ZERO
	mul	\B3,\A4
	add	\RS7,r0
	adc	\A0,r1
	adc	\A1,\B0 //ZERO
	mul	\B4,\A3
	add	\RS7,r0
	adc	\A0,r1
	adc	\A1,\B0 //ZERO
	mul	\B5,\A2
	add	\RS7,r0
	adc	\A0,r1
	adc	\A1,\B0 //ZERO
 // A2 is reused from here  as RS10
	clr	\A2
	mul	\B3,\A5
	add	\A0,r0
	adc	\A1,r1
	adc	\A2,\B0 //ZERO
	mul	\B4,\A4
	add	\A0,r0
	adc	\A1,r1
	adc	\A2,\B0 //ZERO
	mul	\B5,\A3
	add	\A0,r0
	adc	\A1,r1
	adc	\A2,\B0 //ZERO
// A3 is reused from here  as RS11
	clr	\A3
	mul	\B4,\A5
	add	\A1,r0
	adc	\A2,r1
	adc	\A3,\B0 //ZERO
	mul	\B5,\A4
	add	\A1,r0
	adc	\A2,r1
	adc	\A3,\B0 //ZERO

	mul	\B5,\A5
	add	\A2,r0
	adc	\A3,r1

.endm

// multiply 12 bytes pointed by X and 6 bytes pointed by Y, add resul to
// RZ11.. RZ0, (truncated, low part only)  Karatsuba is slower (tested)
.macro RSA_MUL_96_MOD_ADD   RZ11 RZ10 RZ9 RZ8 RZ7 RZ6 RZ5 RZ4 RZ3 RZ2 RZ1 RZ0	\
			  TR11 ZERO TMP_X T_B6 T_B4 T_B2 T_B1 T_B0 TR9 TR8 TMP_Y4 TMP_Y2 TMP1 TMP0
	clr	\ZERO

	ld	\TMP_X,X+	// load A0
	ldd	\T_B0,Y+0
	ldd	\T_B1,Y+1
	ldd	\T_B2,Y+2
	ldd	\T_B4,Y+4
	ldd	\T_B6,Y+6
//pair!
	ldd	\TR8,Y+8
	ldd	\TR9,Y+10

	mul	\T_B2,\TMP_X	//B2 A0
	movw	\TMP0,r0

	mul	\T_B0,\TMP_X	//B0 A0
	add	\RZ0,r0
	adc	\RZ1,r1
	adc	\RZ2,\TMP0
	adc	\TMP1,\ZERO

	mul	\T_B1,\TMP_X     //B1 A0
	add	\RZ1,r0
	adc	\RZ2,r1
	adc	\TMP1,\ZERO

	mul	\T_B6,\TMP_X	//B6 A0
	movw	\TMP_Y2,r0

	mul	\T_B4,\TMP_X    //B4 A0
	add	\RZ3,\TMP1
	adc	\RZ4,r0
	adc	\RZ5,r1
	adc	\RZ6,\TMP_Y2
	adc	\TMP_Y4,\ZERO

	ldd	r0,Y+5		// not cached
	mul	r0,\TMP_X    	//B5 A0
	add	\RZ5,r0
	adc	\RZ6,r1
	adc	\TMP_Y4,\ZERO

	mul	\TR8,\TMP_X     // B8 A0
	movw	\TMP0,r0

	mul	\TR9,\TMP_X	 // B10 A1

	add	\RZ7,\TMP_Y4
	adc	\RZ8,\TMP0
	adc	\RZ9,\TMP1
	adc	\RZ10,r0
	adc	\RZ11,r1
	ldd	r0,Y+11
	mul	r0,\TMP_X	//B11,A0
	add	\RZ11,r0

// A0: missing 3,7,9
// cache:
//       A0:TMP_X
//       B0:T_B0  B1:T_B1  B2:T_B2  B4:T_B4  B6:T_B6  B8:TR8  B10:TR9
/////////////////////////////////////////////////////////////////////
	ld	\TR11,X+	//load A1

	mul	\T_B2,\TR11	//B2,A1
	movw	\TMP0,r0

	mul	\T_B0,\TR11	//B0,A1
	add	\RZ1,r0
	adc	\RZ2,r1
	adc	\RZ3,\TMP0
	adc	\TMP1,\ZERO

	mul	\T_B1,\TR11	//B1,A1
	add	\RZ2,r0
	adc	\RZ3,r1
	adc	\TMP1,\ZERO

	mul	\T_B6,\TR11    //B6 A1
	movw	\TMP_Y2,r0

	mul	\T_B4,\TR11	//B4 A1
	add	\RZ4,\TMP1
	adc	\RZ5,r0
	adc	\RZ6,r1
	adc	\RZ7,\TMP_Y2
	adc	\TMP_Y4,\ZERO

	mul	\TR8,\TR11	//B8,A1
	add	\RZ8,\TMP_Y4
	adc	\RZ9,r0
	adc	\RZ10,r1
	adc	\RZ11,\ZERO

	mul	\TR9,\TR11	//B10,A1
	add	\RZ11,r0

// A0: missing 3,7,9
// A1: missing 3,5,7,9
// cache:
//       A0:TMP_X A1:TR11
//       B0:T_B0  B1:T_B1  B2:T_B2  B4:T_B4  B6:T_B6  B8:TR8
////////////////////////////////////////////////////////////
	ld	\TR9,X+		//load A2

	mul	\T_B2,\TR9	//B2,A2
	movw	\TMP0,r0

	mul	\T_B0,\TR9	//B0,A2
	add	\RZ2,r0
	adc	\RZ3,r1
	adc	\RZ4,\TMP0
	adc	\TMP1,\ZERO   //ZERO

	mul	\T_B1,\TR9	//B1,A2
	add	\RZ3,r0
	adc	\RZ4,r1
	adc	\TMP1,\ZERO   //ZERO

	mul	\T_B6,\TR9	//B6,A2
	movw	\TMP_Y2,r0

	mul	\T_B4,\TR9	//B4,A2
	add	\RZ5,\TMP1
	adc	\RZ6,r0
	adc	\RZ7,r1
	adc	\RZ8,\TMP_Y2
	adc	\TMP_Y4,\ZERO   //ZERO

	mul	\TR8,\TR9	//B8,A2
	add	\RZ9,\TMP_Y4
	adc	\RZ10,r0
	adc	\RZ11,r1
// A0: missing 3,7,9
// A1: missing 3,5,7,9
// A2: missing 3,5,7,9
// cache:
//       A0:TMP_X A1:TR11 TR9:A2
//       B0:T_B0  B1:T_B1  B2:T_B2  B4:T_B4  B6:T_B6  B8:TR8
////////////////////////////////////////////////////////////
	ldd	\TMP_Y2,Y+3
	mul	\TMP_Y2,\TR9		//B3,A2
	movw	\TMP0,r0

	mul	\TMP_Y2,\TMP_X		//B3 A0
	add	\RZ3,r0
	adc	\RZ4,r1
	adc	\RZ5,\TMP0
	adc	\TMP1,\ZERO

	mul	\TMP_Y2,\TR11		//B3 A1
	add	\RZ4,r0
	adc	\RZ5,r1
	adc	\TMP1,\ZERO

	mov	\TMP_Y4,\TMP1
	ldd	r0,Y+9		// no cache
	mul	r0,\TMP_X 		//B9,A0
	movw	\TMP0,r0

	ldd	r0,Y+7		// no cache
	mul	r0,\TMP_X		//B7 A0
	add	\RZ6,\TMP_Y4
	adc	\RZ7,r0
	adc	\RZ8,r1
	adc	\RZ9,\TMP0
	adc	\RZ10,\TMP1
	adc	\RZ11,\ZERO

// A0  ok
// A1 missing 5,7,9
// A2 missing 5,7,9
// TMP_X:A0, TR11:A1, TR9:A2
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 T_B6:B6 TR8:B8
/////////////////////////////////////////////////
	ldd	\TMP_Y4,Y+5
	ldd	\TMP_X,Y+7
	mul	\TMP_X,\TR11	//B7 A1
	movw	\TMP0,r0

	mul	\TMP_Y4,\TR11	//B5 A1
	add	\RZ6,r0
	adc	\RZ7,r1
	adc	\RZ8,\TMP0
	adc	\TMP1,\ZERO

	mul	\TMP_Y4,\TR9	//B5 A2
	add	\RZ7,r0
	adc	\RZ8,r1
	adc	\TMP1,\ZERO

	ldd	\TMP0,Y+9
	mul	\TMP0,\TR11	//B9,A1
	add	\RZ9,\TMP1
	adc	\RZ10,r0
	adc	\RZ11,r1

	mul	\TMP0,\TR9	//B9,A2
	add	\RZ11,r0

	ld	\TR11,X+	//load A3
	mul	\TR8,\TR11	//B8,A3
	add	\RZ11,r0
///
//A0,A1 B11,B10,B9,B8   OK
//A2 missing B7
// TR9:A2, TR11:A3
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 TMP_Y4:B5  T_B6:B6 TMP_X:B7
// free TMP0,TMP1, TR8

//////////////////////////////////////////////////
	mul	\T_B2,\TR11	//B2 A3
	movw	\TMP0,r0

	mul	\T_B0,\TR11	//B0 A3
	add	\RZ3,r0
	adc	\RZ4,r1
	adc	\RZ5,\TMP0
	adc	\TMP1,\ZERO

	mul	\T_B1,\TR11     //B1 A3
	add	\RZ4,r0
	adc	\RZ5,r1
	adc	\TMP1,\ZERO

	mul	\TMP_X,\TR9	//B7,A2
// free TR9,TR8
	movw	\TR8,r0

	mul	\T_B4,\TR11     //B4 A3
	add	\RZ6,\TMP1
	adc	\RZ7,r0
	adc	\RZ8,r1
	adc	\RZ9,\TR8
	adc	\TR9,\ZERO   //ZERO

	ld	\TR8,X+		// load A4
	mul	\TMP_X,\TR8	// B7,A4
	add	\RZ10,\TR9
	adc	\RZ11,r0

//A0,A1,A2 B11,B10,B9,B8   OK
//A3 missing 3,5,6,7 A4: 0,1,2,3,4,5,6
//
// TR11:A3 TR8:A4
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 TMP_Y4:B5  T_B6:B6 TMP_X:B7
// free TMP0,TMP1, TR9
	mul	\TMP_Y2,\TR11	//B3,A3
	movw	\TMP0,r0

	mul	\T_B0,\TR8	//B0,A4
	add	\RZ4,r0
	adc	\RZ5,r1
	adc	\RZ6,\TMP0
	adc	\TMP1,\ZERO

	mul	\T_B1,\TR8	//B1,A4
	add	\RZ5,r0
	adc	\RZ6,r1
	adc	\TMP1,\ZERO

	mov	\TR9,\TMP1
	mul	\TMP_X,\TR11	//B7,A3
	movw	\TMP0,r0

	mul	\TMP_Y4,\TR11	//B5,A3
	add	\RZ7,\TR9
	adc	\RZ8,r0
	adc	\RZ9,r1
	adc	\RZ10,\TMP0
	adc	\RZ11,\TMP1

//A0,A1,A2 B11,B10,B9,B8,B7   OK
//A3 missing 6  A4: 2,3,4,5,6
//
// TR11:A3 TR8:A4
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 TMP_Y4:B5  T_B6:B6
// free TMP0,TMP1, TR9, TMP_X
	ld	\TMP_X,X+	//load A5

	mul	\T_B2,\TMP_X	//B2,A5
	movw	\TMP0,r0

	mul	\T_B0,\TMP_X	//B0 A5
	add	\RZ5,r0
	adc	\RZ6,r1
	adc	\RZ7,\TMP0
	adc	\TMP1,\ZERO

	mul	\T_B1,\TMP_X	//B1 A5
	add	\RZ6,r0
	adc	\RZ7,r1
	adc	\TMP1,\ZERO

	mul	\T_B6,\TMP_X	//B6,A5
	mov	\TR9,r0

	mul	\T_B6,\TR11	//B6,A3
	add	\RZ8,\TMP1
	adc	\RZ9,r0
	adc	\RZ10,r1
	adc	\RZ11,\TR9

//A0,A1,A2,A3 B11,B10,B9,B8,B7   OK
//missing:   A4: 2,3,4,5,6   A5: 3,4,5
//
// TR8:A4 TMP_X:A5
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 TMP_Y4:B5 T_B6:B6
// free TMP0,TMP1,TR9
	mul	\T_B4,\TR8	//B4 A4
	movw	\TMP0,r0

	mul	\T_B2,\TR8	//B2 A4
	add	\RZ6,r0
	adc	\RZ7,r1
	adc	\RZ8,\TMP0
	adc	\TMP1,\ZERO

	mul	\TMP_Y2,\TR8	//B3 A4
	add	\RZ7,r0
	adc	\RZ8,r1
	adc	\TMP1,\ZERO

	mul	\T_B6,\TR8	//B6 A4
	add	\RZ9,\TMP1
	adc	\RZ10,r0
	adc	\RZ11,r1
//A0,A1,A2,A3 B11,B10,B9,B8,B7,B6   OK
//missing:   A4: 5   A5: 3,4,5
//
// TR8:A4 TMP_X:A5
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 TMP_Y4:B5
// free TMP0,TMP1,TR9
	ld	\T_B6,X+	// load A6

	mul	\TMP_Y2,\TMP_X	//B3 A5
	movw	\TMP0,r0

	mul	\T_B0,\T_B6	//B0 A6
	add	\RZ6,r0
	adc	\RZ7,r1
	adc	\RZ8,\TMP0
	adc	\TMP1,\ZERO

	mul	\T_B1,\T_B6	//B1 A6
	add	\RZ7,r0
	adc	\RZ8,r1
	adc	\TMP1,\ZERO

	mul	\TMP_Y4,\TMP_X	//B5 A5
	add	\RZ9,\TMP1
	adc	\RZ10,r0
	adc	\RZ11,r1
//A0,A1,A2,A3 B11,B10,B9,B8,B7,B6   OK
//missing:   A4: 5   A5: 4   A6: 2,3,4,5
//
// TR8:A4 TMP_X:A5 T_B6:A6
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 TMP_Y4:B5
// free TMP0,TMP1,TR9
	ld	\TR9,X+	//load A7

	mul	\TMP_Y4,\TR8	//B5,A4
	movw	\TMP0,r0
	mul	\T_B0,\TR9	//B0 A7
	add	\RZ7,r0
	adc	\RZ8,r1
	adc	\RZ9,\TMP0
	adc	\TMP1,\ZERO

	mul	\T_B2,\T_B6	//B2 A6
	add	\RZ8,r0
	adc	\RZ9,r1
	adc	\TMP1,\ZERO

	mul	\TMP_Y4,\T_B6		//B5,A6
	add	\RZ10,\TMP1
	adc	\RZ11,r0
//A0,A1,A2,A3,A4 B11,B10,B9,B8,B7,B6   OK
//missing:    A5: 4   A6: 3,4 A7: 1,2,3,4
//
// TMP_X:A5 T_B6:A6 TR9:A7
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 TMP_Y4:B5
// free TMP0,TMP1
	mul	\T_B4,\T_B6	//B4,A6
	movw	\TMP0,r0

	mul	\T_B1,\TR9	//B1,A7
	add	\RZ8,r0
	adc	\RZ9,r1
	adc	\RZ10,\TMP0
	adc	\RZ11,\TMP1
//A0,A1,A2,A3,A4 B11,B10,B9,B8,B7,B6   OK
//missing:    A5: 4   A6: 3  A7: 2,3,4
//
// TMP_X:A5 T_B6:A6 TR9:A7
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 TMP_Y4:B5
// free TMP0,TMP1
	mul	\T_B4,\TR9	//B4,A7
	mov	\TMP0,r0
	mul	\T_B4,\TMP_X	//B4 A5
	add	\RZ9,r0
	adc	\RZ10,r1
	adc	\RZ11,\TMP0
//A0,A1,A2,A3,A4,A5  B11,B10,B9,B8,B7,B6   OK
//missing:     A6: 3  A7: 2,3
//
// T_B6:A6 TR9:A7
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 TMP_Y4:B5
// free TMP0,TMP1
	ld	\TR8,X+		//A8
	mul	\TMP_Y2,\TR9	//B3 A7
	movw	\TMP0,r0
	mul	\T_B0,\TR8	//B0 A8
	add	\RZ8,r0
	adc	\RZ9,r1
	adc	\RZ10,\TMP0
	adc	\RZ11,\TMP1
//A0,A1,A2,A3,A4,A5  B11,B10,B9,B8,B7,B6   OK
//missing:     A6: 3  A7: 2  A8: 1,2,3
//
// T_B6:A6 TR9:A7 TR8:A8
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 TMP_Y4:B5
// free TMP0,TMP1
	mul	\TMP_Y2,\TR8	//B3,A8
	mov	\TMP0,r0
	mul	\TMP_Y2,\T_B6 	//B3,A6
	add	\RZ9,r0
	adc	\RZ10,r1
	adc	\RZ11,\TMP0
//A0,A1,A2,A3,A4,A5  B11,B10,B9,B8,B7,B6   OK
//missing:      A7: 2  A8: 1,2
//
// TR8:A4 TMP_X:A5 T_B6:A6 TR9:A7 TR8:A8
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 TMP_Y4:B5
// free TMP0,TMP1
	ld	\TR11,X+
	mul	\T_B2,\TR11	//B2,A9
	mov	\TMP0,r0
	mul	\T_B2,\TR9	//B2,A7
	add	\RZ9,r0
	adc	\RZ10,r1
	adc	\RZ11,\TMP0
//A0,A1,A2,A3,A4,A5  B11,B10,B9,B8,B7,B6   OK
//missing:      A8: 1,2  A9: 0 1
//
// TR8:A4 TMP_X:A5 T_B6:A6 TR9:A7 TR8:A8  TR11:A9
// T_B0:B0  T_B1:B1  T_B2:B2 TMP_Y2:B3 T_B4:B4 TMP_Y4:B5
// free TMP0,TMP1
	mul	\T_B1,\TR8	//B1,A8
	add	\RZ9,r0
	adc	\RZ10,r1
	adc	\RZ11,\ZERO

	mul	\T_B2,\TR8	//B2,A8
	add	\RZ10,r0
	adc	\RZ11,r1

	mul	\T_B0,\TR11	//B0,A9
	add	\RZ9,r0
	adc	\RZ10,r1
	adc	\RZ11,\ZERO

	mul	\T_B1,\TR11	//B1,A9
	add	\RZ10,r0
	adc	\RZ11,r1

	ld	\TR11,X+
	mul	\T_B0,\TR11
	add	\RZ10,r0
	adc	\RZ11,r1

	mul	\T_B1,\TR11
	add	\RZ11,r0

	ld	\TR11,X+
	mul	\T_B0,\TR11
	add	\RZ11,r0
.endm


	.global	rsa_mul_192_mod
	.type	rsa_mul_192_mod, @function
	.section .text.rsa_mul_192_mod,"ax",@progbits

rsa_mul_192_mod:
//save registers
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

	movw	r30,r24
	movw	r26,r20
	movw	r28,r22
	call	rsa_mul_192_mod_no_abi

	clr	r1
// return registers
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

	.global	rsa_mul_192_mod_no_abi
	.type	rsa_mul_192_mod_no_abi, @function
	.section .text.rsa_mul_192_mod_no_abi,"ax",@progbits

// clock cycles are not updated here! (about 18 clock cycles and about 10
// bytes need to be added here, actual clock cycles - from old code old code
// store result at stack not Z)

// 1632 inclusive ret  2468 bytes
// 1629 inclusive ret  2456 bytes (RAM_LE32)
rsa_mul_192_mod_no_abi:
// rsa_mul_192_mod_no_abi stores result to Z

#define S_OFF 0
#define S0_OFF 0
#define S1_OFF 0
#define S2_OFF 0


// karatsuba, calculate L
	ld	r2,X+
	ld	r3,X+
	ld	r4,X+
	ld	r5,X+
	ld	r6,X+
	ld	r7,X+
	ldd	r8,Y+0
	ldd	r9,Y+1
	ldd	r10,Y+2
	ldd	r11,Y+3
	ldd	r12,Y+4
	ldd	r13,Y+5

// warning, operands in r3,2 are destroyed

	MUL_48 r25 r24 r23 r22 r21 r20 r19 r18 r17 r16 r15 r14     r13 r12 r11 r10 r9 r8    r7 r6 r5 4 r3 r2

	std	Z+0+S1_OFF,r14
	std	Z+1+S1_OFF,r15
	std	Z+2+S1_OFF,r16
	std	Z+3+S1_OFF,r17
	std	Z+4+S1_OFF,r18
	std	Z+5+S1_OFF,r19

// upper part A11..A6  B11..B6
	ld	r14,X+
	ld	r15,X+
	ld	r16,X+
	ld	r17,X+
	ld	r18,X+
	ld	r19,X+

	push	r26
	push	r27
	push	r28
	push	r29

	push	r30
	push	r31
	ldd	r8,Y+6
	ldd	r9,Y+7
	ldd	r10,Y+8
	ldd	r11,Y+9
	ldd	r12,Y+10
	ldd	r13,Y+11

// calculate H (combine high part of L with low part of H
// L[11..6] + H in [r5 r4 r3 r2 r7 r6  r25 r24 r23 r22 r21 r20] = [13 12 11 10 9 8 ] * [ 19 18 17 16 15 14]

// local ZERO, in r30,r31
	clr	r30
	clr	r31
// clear upper part of result, (some registers are reused as carry catcher and then recleared)
//------------------
	MUL_48_ADD  r5 r4 r3 r2 r7 r6 r25 r24 r23 r22 r21 r20    r13 r12 r11 r10 r9 r8  r19 r18 r17 r16 r15 r14 r31 r30
//--------------
// L[11..6] + H in [r5 r4 r3 r2 r6 r7   r25 r24 r23 r22 r21 r20]
// X in [ 19 18 17 16 15 14]
// Y in [13 12 11 10 9 8 ]

////////////////////////////////////////////////////////////////////////////
// A11..A6 - A5..A0
	sbiw	r26,12
	ld	r0,X+
	sub	r14,r0
	ld	r0,X+
	sbc	r15,r0
	ld	r0,X+
	sbc	r16,r0
	ld	r0,X+
	sbc	r17,r0
	ld	r0,X+
	sbc	r18,r0
	ld	r0,X+
	sbc	r19,r0
// save carry (for sign)
	sbc	r0,r0
// B11..B6 - B5..B0
	ldd	r1,Y+0
	sub	r8,r1
	ldd	r1,Y+1
	sbc	r9,r1
	ldd	r1,Y+2
	sbc	r10,r1
	ldd	r1,Y+3
	sbc	r11,r1
	ldd	r1,Y+4
	sbc	r12,r1
	ldd	r1,Y+5
	sbc	r13,r1
// save carry (for sign)
	sbc	r1,r1

//                                      sign
	ABS_48 r19 r18 r17 r16 r15 r14  r0
	ABS_48 r13 r12 r11 r10 r9 r8    r1

// sign is needed to decide subtraction/adition
		eor	r0,r1
// use T to save sign
	bst	r0,0


///////////////////////////////////////////////////////////////////////////////
// middle part
///////////////////////////////////////////////////////////////////////////////

// M = [r13 r12 r11 r10 r9 r8]  * [r19 r18 r17 r16 r15 r14]
// M to [r11 r10 r9 r8 r13 r12 r29 r28 r27 r26 r7 r6 ]

// must be saved r7 r6 r5 r4 r3 r2 = Hight part of result (H part)
// must be saved r25,24,23,22,21,20 = low part of result


// not enough register, save some ..
	push	r6
	push	r7

// zero here     vvvvvvv
// high part of result in r11,10,9,8,  r31,30 must be cleared before expand this macro
//                0   0       result                    operand B                 operand A
	MUL_48_X r31 r30  r29 r28 r27 r26 r7 r6     r19 r18 r17 r16 r15 r14   r13 r12 r11 r10 r9 r8

	movw	r0,r30

// restore back
	pop	r13
	pop	r12
	pop	r31
	pop	r30

	ldd	r14,Z+0+S2_OFF
	ldd	r15,Z+1+S2_OFF
	ldd	r16,Z+2+S2_OFF
	ldd	r17,Z+3+S2_OFF
	ldd	r18,Z+4+S2_OFF
	ldd	r19,Z+5+S2_OFF
	add	r14,r20
	adc	r15,r21
	adc	r16,r22
	adc	r17,r23
	adc	r18,r24
	adc	r19,r25
	adc	r20,r12
	adc	r21,r13
	adc	r22,r2
	adc	r23,r3
	adc	r24,r4
	adc	r25,r5
// select add/sub by sign bit
#ifdef RAM_LE32
	rol	r31
#endif
	brts	rsa_mul_192_mod_no_abi_add
#ifndef RAM_LE32
// carry into T
	rol	r5
	bst	r5,0
	ror	r5
#endif
	sub	r14,r6
	sbc	r15,r7
	sbc	r16,r26
	sbc	r17,r27
	sbc	r18,r28
	sbc	r19,r29
	sbc	r20,r0
	sbc	r21,r1
	sbc	r22,r8
	sbc	r23,r9
	sbc	r24,r10
	sbc	r25,r11

	sbc	r6,r6
	sbc	r7,r7
	rjmp	rsa_mul_192_mod_no_abi_final

rsa_mul_192_mod_no_abi_add:
#ifndef RAM_LE32
// carry into T
	rol	r5
	bst	r5,0
	ror	r5
#endif
	add	r14,r6
	adc	r15,r7
	adc	r16,r26
	adc	r17,r27
	adc	r18,r28
	adc	r19,r29
	adc	r20,r0
	adc	r21,r1
	adc	r22,r8
	adc	r23,r9
	adc	r24,r10
	adc	r25,r11

	clr	r6
	clr	r7
	adc	r6,r6

rsa_mul_192_mod_no_abi_final:
#ifndef RAM_LE32
// get carry back from T
	bld	r8,0
	asr	r8
// propagate carry
#else
	lsr	r31
#endif
	adc	r12,r6
	adc	r13,r7
	adc	r2,r7
	adc	r3,r7
	adc	r4,r7
	adc	r5,r7

	std	Z+6+S2_OFF,r14
	std	Z+7+S2_OFF,r15
	std	Z+8+S2_OFF,r16
	std	Z+9+S2_OFF,r17
	std	Z+10+S2_OFF,r18
	std	Z+11+S2_OFF,r19
// add to upper part (rsa_mul_96_mod)
// renew operands pointers
	pop	r29
	pop	r28
	pop	r27
	pop	r26
//  sbiw r26,12
	push	r30
	push	r31
	// result of multipllication is added to output registers
        // operands fom  X, Y pointers                                   temp  variables               free regs 

	RSA_MUL_96_MOD_ADD  r5 r4 r3 r2 r13 r12 r25 r24 r23 r22 r21 r20  r19 r18 r17 r16 r30 r31   r15,r14,r11,r10,r9 r8 r7 r6
	sbiw	r26,24
	adiw	r28,12
	RSA_MUL_96_MOD_ADD  r5 r4 r3 r2 r13 r12 r25 r24 r23 r22 r21 r20  r19 r18 r17 r16 r30 r31   r15,r14,r11,r10,r9 r8 r7 r6
	pop	r31
	pop	r30
	std Z+12+S_OFF,r20
	std Z+13+S_OFF,r21
	std Z+14+S_OFF,r22
	std Z+15+S_OFF,r23
	std Z+16+S_OFF,r24
	std Z+17+S_OFF,r25
	std Z+18+S_OFF,r12
	std Z+19+S_OFF,r13
	std Z+20+S_OFF,r2
	std Z+21+S_OFF,r3
	std Z+22+S_OFF,r4
	std Z+23+S_OFF,r5
#undef S_OFF
#undef S0_OFF
#undef S1_OFF
#undef S2_OFF
	ret

#endif

// input in r22,r23 r26,27  result r30,31
	.global	rsa_mul_384_mod
	.type	rsa_mul_384_mod, @function
	.section .text.rsa_mul_384_mod,"ax",@progbits

rsa_mul_384_mod:
//save registers
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

	movw	r30,r24
	movw	r26,r20

	call	rsa_mul_384_mod_no_abi

	clr	r1
// return registers
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

	.global	rsa_mul_384_mod_no_abi
	.type	rsa_mul_384_mod_no_abi, @function
	.section .text.rsa_mul_384_mod_no_abi,"ax",@progbits

rsa_mul_384_mod_no_abi:
// create space on stack - 48 bytes TMP variable, 3x pointer
// (there is enough to create 24 byte variable, but if HAVE_RSA_MUL_192_MOD
// is not defined, full and slower rsa_mul_192_no_abi is used as woraround
// (rsa_mul_192_mod_no_abi waste about 2.5kB of flash..)
	in	r28, 0x3d
	in	r29, 0x3e
	subi	r28, lo8(48+2+2+2)
	sbci	r29, hi8(48+2+2+2)
	LOAD_SP r0, r28,r29

// save  pointers to stack
	std	Y+1,r22	// A pointer
	std	Y+2,r23
	std	Y+3,r30	// Result
	std	Y+4,r31
	std	Y+5,r26	// B pointer
	std	Y+6,r27

	movw	r28,r22
	call	rsa_mul_192_no_abi
// load values back 
	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r28,Z+1	// OPERAND_B
	ldd	r29,Z+2
	adiw	r28,24	// upper part
	ldd	r26,Z+5	// OPERAND_A
	ldd	r27,Z+6	

	adiw	r30,7
	call 	rsa_mul_192_mod_no_abi

// load values back 
	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r28,Z+3	// result
	ldd	r29,Z+4
	adiw	r28,24	// upper part
	adiw	r30,7

	ldi	r24,3
	clc
rsa_mul_384_mod_loop1:
.rept	8
	ld	r0,Y
	ld	r25,Z+
	adc	r25,r0
	st	Y+,r25
.endr
	dec	r24
	brne	rsa_mul_384_mod_loop1

// load values back 
	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r28,Z+1	// OPERAND_B
	ldd	r29,Z+2
	ldd	r26,Z+5	// OPERAND_A
	ldd	r27,Z+6	
	adiw	r26,24	//upper part
	
	adiw	r30,7
	call 	rsa_mul_192_mod_no_abi
	
// load values back 
	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r28,Z+3	// result
	ldd	r29,Z+4
	adiw	r28,24	// upper part
	adiw	r30,7

	ldi	r24,3
	clc
rsa_mul_384_mod_loop2:
.rept	8
	ld	r0,Y
	ld	r25,Z+
	adc	r25,r0
	st	Y+,r25
.endr
	dec	r24
	brne	rsa_mul_384_mod_loop2
// return stack position (Z is used to point variable on stack, correct Z to get old SP)
	adiw 	r30,23
	LOAD_SP r0, r30,r31
	ret
