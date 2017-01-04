/*
    mp_mul_32.S

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

    Atmega assembler routines for (32 bits and derived) multiplications 

    This file depend on mp_mul_128.S and mp_mul_256.S files.

    depends:
    rsa_mul_256_no_abi:  256 bit multiplication 
                         r30:31 result
                         r28:29 operand B
                         r26:27 operand A


    public functions:  
    rsa_mul_256:  256 bit multiplication (C ABI)
    mp_mul:       256 bit multiplication (C ABI)
                  (same as rsa_mul_256, only different name)
    rsa_mul_512:  512 bit multiplication (C ABI)

    local functions:

    rsa_mul_512_no_abi:  512 bit multiplication 
                         r30:31 result
                         r22:23 operand B
                         r26:27 operand A

multiplication with modulus (mod 128, 256 .. ):
    depends:
    rsa_mul_128_no_abi:  128 bit multiplication 
                         r30:31 result
                         r28:29 operand B
                         r26:27 operand A
    public functions:
    rsa_mul_512_mod:    512 bit multiplication (C ABI)    
                        result is only 512 bit long (low bites)


*/

/////////////////////////////////////////////////////////////
#include "load_sp.h"

#if defined(HAVE_RSA_MUL_256_NO_ABI)

#if defined(HAVE_RSA_MUL_256)
  .global rsa_mul_256   
  .type rsa_mul_256, @function
rsa_mul_256:
#endif

#if defined(HAVE_RSA_MUL_256)
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

	call rsa_mul_256_no_abi

  	clr	 r1
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
#endif // defined(HAVE_RSA_MUL_256)

#if defined (HAVE_RSA_MUL_512) || defined (HAVE_RSA_MUL_1024)

rsa_mul_512_no_abi:
// create space on stack(64 bytes TMP variable, 3x pointer, 1x sign
	in	r28, 0x3d
	in	r29, 0x3e
	subi	r28, lo8(64+2+2+2+1)
	sbci	r29, hi8(64+2+2+2+1)
	LOAD_SP	r0, r28,r29

// save  pointers to stack
	std	Y+1,r22	// A pointer
	std	Y+2,r23
	std	Y+3,r30	// Result
	std	Y+4,r31
	std	Y+5,r26	// B pointer
	std	Y+6,r27

// calculate a_low - a_high -> r
	movw	r28,r22		//A, A+32 is addressed by Y
	ldi	r25,4		//4*8 = 32 bytes
	sub	r24,r24		//initial carry(s)
rsa_mul_512_loop1a:
// load A into r0..r7, A+32 to r8..r15
.irp	pos,0,1,2,3,4,5,6,7
	ld	r\pos,Y+
.endr
.irp	pos,8,9,10,11,12,13,14,15
	ldd	r\pos,Y+16+\pos
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
	std	Z+16+\pos,r\pos
.endr
	rol	r24	//renew carry

	dec	r25
	brne	rsa_mul_512_loop1a

	movw	r28,r26 // B pointer
	movw	r2,r30	// result + 64/96 for b_low -b_high
	bst	r24,0	// save sign	
	bld	r25,5	// 0 or 32

	sub	r30,r25
	sbci	r31,0
	movw	r26,r30		// first operand for multiply
// sign is saved in T flag, r26 position of first operand		

// calculate b_low - b_high -> r
	movw	r30,r2		// result + 64/96 for b_low -b_high
	adiw	r30,32
	ldi	r25,4		//4*8 = 32 bytes
	sub	r24,r24		//initial carry(s)

rsa_mul_512_loop1b:
// load A into r0..r7, A+32 to r8..r15
.irp	pos,0,1,2,3,4,5,6,7
	ld	r\pos,Y+
.endr
.irp	pos,8,9,10,11,12,13,14,15
	ldd	r\pos,Y+16+\pos
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
	std	Z+16+\pos,r\pos
.endr
	rol	r24	//renew carry

	dec	r25
	brne	rsa_mul_512_loop1b

// get xor from sing of (a_low - a_high),(b_low - b_high)
	in	r28, 0x3d
	in	r29, 0x3e

	mov	r25,r24	// copy sign
	bld	r0,0	// previous sign
	eor 	r25,r0
	andi	r25,1
	std	Y+7,r25 // sign	

// select RESULT or RESULT + 32 for |b_low - b_high|
	bst	r24,0
	clr	r24
	bld	r24,5
	sub	r30,r24
	sbci	r31,0
	movw	r28,r30	//second opeand
// multiply |a_low - a_high| * |b_low - b_high| into TMP
	
	in	r30, 0x3d
	in	r31, 0x3e
	adiw	r30,8		// skip variables on stack to point 64 byt TMP
		
	call	rsa_mul_256_no_abi

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
	call	rsa_mul_256_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
// a_high * b_high to r+64
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	subi	r30,-64
	sbci	r31,0xff
	ldd	r26,Y+1	// OPERAND_B
	ldd	r27,Y+2
	adiw	r26,32
	ldd	r24,Y+5	// OPERAND_A
	ldd	r25,Y+6
	movw	r28,r24
	adiw	r28,32

	call	rsa_mul_256_no_abi

// load values back 
#define _CARRY r24
#define _ACC   r23
#define _EOR   r25

	in	r28, 0x3d
	in	r29, 0x3e
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	ldd	_CARRY,Y+7	// sign
	movw	r26,r28
	adiw	r26,8		// skip variables on stack to point 64 byt TMP

// summarize L,H,M, sub/add M (based on sign ..)
// get sign from _CARRY
// if signs are the same, set _EOR to 0xff _CARRY to 1
// else                   set _EOR to 0x00 _CARRY to 0

	ldi	_EOR,1
	eor	_CARRY,_EOR
// generate ff/0  from 1/0
	mov	_EOR,_CARRY
	neg	_EOR
// r24 is used as initial carry, r25 as eor value

	movw	r28,r30
	subi	r28,lo8(-64)
	sbci	r29,hi8(-64)
//       D          C           B          A          
//  127      96 95      64 63       32 31      0
//                      Y                      Z
//-------------------------------------------------
// summarize B,C into cache (r8..r15)
// bytes 39..32
	ldd	r0,Z+0+32+0
	ldd	r8,Y+0
	add	r8,r0
.irp	pos,1,2,3,4,5,6,7
	ldd	\pos,Z+\pos+32+0
	ldd	\pos+8,Y+\pos
	adc	\pos+8,\pos
.endr
	ror	_CARRY	//save carry BC load carry M
// from B+C subtract/add M
.irp	pos,0,1,2,3,4,5,6,7
	ld	\pos,X+
	eor	\pos,_EOR
	adc	\pos,\pos+8
.endr
	ror	_CARRY	//save carry M, load ABC
// to B+C -M  add part A, save tesult in RAM
.irp    pos,0,1,2,3,4,5,6,7
	ldd     _ACC,Z+\pos
	adc	r\pos,_ACC
	std	Z+32+\pos,r\pos
.endr
	rol	_CARRY	//save carry ABC,load M
	rol	_CARRY	//save carry M, load BC
//continue B,C into cache r16..r22
// bytes 47..40
// no enough register for cache ..(r23 is reserved)
.irp	pos,0,1,2,3,4,5,6
	ldd	\pos,Z+\pos+32+8
	ldd	\pos+16,Y+\pos+8
	adc	\pos+16,\pos
.endr
// no enough registers - store to ram
	ldd	r7,Z+32+7+8
	ldd	_ACC,Y+7+8
	adc	r7,_ACC
	std	Y+7+8,r7

	ror	_CARRY	//save carry BC load carry M
// from B+C subtract/add M
.irp	pos,0,1,2,3,4,5,6
	ld	\pos,X+
	eor	\pos,_EOR
	adc	\pos,\pos+16
.endr
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	r7,_ACC

	ror	_CARRY	//save carry M, load ABC
// to B+C -M  add part A, save tesult in RAM
.irp    pos,0,1,2,3,4,5,6,7
	ldd     _ACC,Z+\pos+8
	adc	\pos,_ACC
	std	Z+32+\pos+8,\pos
.endr
// bytes 55..48
	rol	_CARRY	//save carry ABC,load M
	rol	_CARRY	//save carry M, load BC

.irp	pos,0,1,2,3,4,5,6,7
	ldd	r\pos,Z+\pos+32+16
	ldd	_ACC,Y+\pos+16
	adc	r\pos,_ACC
	std	Y+\pos+16,r\pos
.endr
	ror	_CARRY	//save carry BC load carry M
// from B+C subtract/add M
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	r\pos,_ACC
.endr
	ror	_CARRY	//save carry M, load ABC
// to B+C -M  add part A, save tesult in RAM
.irp    pos,0,1,2,3,4,5,6,7
	ldd     _ACC,Z+\pos+16
	adc	r\pos,_ACC
	std	Z+32+\pos+16,r\pos
.endr
	rol	_CARRY	//save carry ABC,load M
	rol	_CARRY	//save carry M, load BC
// bytes 63..56
.irp	pos,0,1,2,3,4,5,6,7
	ldd	r\pos,Z+\pos+32+24
	ldd	_ACC,Y+\pos+24
	adc	r\pos,_ACC
	std	Y+\pos+24,r\pos
.endr
	ror	_CARRY	//save carry BC load carry M
// from B+C subtract/add M
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	r\pos,_ACC
.endr
	ror	_CARRY	//save carry M, load ABC
// to B+C -M  add part A, save tesult in RAM
.irp    pos,0,1,2,3,4,5,6,7
	ldd     _ACC,Z+\pos+24
	adc	r\pos,_ACC
	std	Z+32+\pos+24,r\pos
.endr
	rol	_CARRY	//save carry ABC,load M
	bst	_CARRY,7
	rol	_CARRY	//save carry M, load BC
//-------------------------------------------------
// A,B is in final state
// T = carry from B+C  (this carry is propagated to D too)
// 1st bytes of B+C are cached in r8..r22
//--------------------------------------------------
// continue in C part .. C+D
// bytes 79..64
// add D, reuse cached bytes from B+C in registers
.irp	pos,0,1,2,3,4,5,6,7
	ldd	_ACC,Y+32+\pos	//D0..D7
	adc	\pos+8,_ACC
.endr
	ror	_CARRY	//save carry BC, load M
// B+C -M
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	\pos+8,_ACC
.endr
	ror	_CARRY	//save carry M, load ABC
	clr	_ACC
.irp	pos,0,1,2,3,4,5,6,7
	adc	\pos+8,_ACC
	std	Y+\pos,\pos+8
.endr
/////////////////////
// B+C in r16..r22, load last byte B+C into r0
	ldd	r0,Y+15
//continue - acc carry
.irp	pos,0,1,2,3,4,5,6
	adc	\pos+16,_ACC
.endr
	adc	r0,_ACC
	rol	_CARRY
//subtract M
.irp	pos,0,1,2,3,4,5,6
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	\pos+16,_ACC
.endr
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	r0,_ACC
	rol	_CARRY
// add D
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos+8,Y+32+8+\pos      //D8..D15
.endr
.irp	pos,0,1,2,3,4,5,6
	adc	\pos+16,\pos+8
	std	Y+\pos+8,\pos+16
.endr
	adc	r0,r15
	std	Y+15,r0
/////////////////////////
// bytes 95..80
.irp	pos,0,1,2,3,4,5,6
	ldd	\pos+16,Y+32+16+\pos	// preload D22..D16
	ldd	\pos,Y+16+\pos	// preload B+C from RAM
	adc	\pos,\pos+16	// add D
.endr
// add not cached D (D23)
	ldd	_ACC,Y+32+16+7	//D23
	ldd	r7,Y+16+7	//B+C from RAM
	adc	r7,_ACC
	ror	_CARRY	//save carry BC, load M

// B+C -M
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	\pos,_ACC
.endr
	ror	_CARRY	//save carry M load ABC
	clr	_ACC
.irp	pos,0,1,2,3,4,5,6,7
	adc	\pos,_ACC
	std	Y+16+\pos,\pos
.endr
/////////////////////////
// bytes 127..96
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Y+16+8+\pos	// preload B+C from RAM
.endr
// add carry
	clr	_ACC
.irp	pos,0,1,2,3,4,5,6,7
	adc	r\pos,_ACC
.endr
	rol	_CARRY	// save ABC, load M
// B+C -M
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	r\pos,_ACC
.endr
	rol	_CARRY	// save M load BC
// res of D is preloaded into r27,r0..r6
	ldd	r27,Y+32+16+8+0	//D24
	adc	r0,r27
	std	Y+16+8+0,r0

.irp	pos,1,2,3,4,5,6,7
	ldd	\pos-1,Y+32+16+8+\pos	//D31..D25
	adc	\pos,\pos-1
	std	Y+16+8+\pos,\pos
.endr

// _CARRY = x x x x   x x ABC M
// C bit in flags reg = BC carry
// T bit in flags reg = BC carry from 1st add
//-------------------------------------------------
//summarize borow carry, propagate to D
#define _CARRY16L _EOR
#define _CARRY16H  r7
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

// propagate carry to D (1st part of D in RAM)
	ldd	_ACC,Y+32
	add	_ACC,_CARRY16L
	std	Y+32,_ACC
// not cached
.irp	pos,1,2,3,4,5,6,7
	ldd	_ACC,Y+32+\pos
	adc	_ACC,_CARRY16H
	std	Y+32+\pos,_ACC
.endr
// cached
.irp	pos,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22
	adc	\pos,_CARRY16H
	std	Y+32+\pos,\pos
.endr

// not cached
	ldd	_ACC,Y+32+23
	adc	_ACC,_CARRY16H
	std	Y+32+23,_ACC

// cached
	adc	r7,_CARRY16H
	std	Y+32+24,r27
// cached
.irp	pos,25,26,27,28,29,30,31
	adc	\pos-25,_CARRY16H
	std	Y+32+\pos,\pos-25
.endr
// return stack position
	in	r28, 0x3d
	in	r29, 0x3e
	subi	r28, lo8(-(64+2+2+2+1))
	sbci	r29, hi8(-(64+2+2+2+1))
	LOAD_SP r0, r28,r29
	ret
#undef _ACC
#undef _CARRY
#undef _EOR
#undef _CARRY16H
#undef _CARRY16L

#undef OPERAND_B
#undef RESULT
#undef OPERAND_A
#undef L1
#undef L2
#undef L3
#undef L4
#undef L5
#undef L6
#undef L7
#endif // defined (HAVE_RSA_MUL_512) || defined (HAVE_RSA_MUL_1024)

#ifdef HAVE_RSA_MUL_512
        .global rsa_mul_512
        .type   rsa_mul_512, @function
// 16363 ticks,
// stack 18 for regs, 71 for variables, 58 in rsa_256_no_aby = 147

#define OPERAND_B r10
#define RESULT    r12
#define OPERAND_A r14
rsa_mul_512:
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
	movw	r30,r24
	movw	r26,r20
	call	rsa_mul_512_no_abi
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

#endif //HAVE_RSA_MUL_512


#if defined (HAVE_RSA_MUL_1024 )
        .global rsa_mul_1024
        .type   rsa_mul_1024, @function
// stack 282 

#define UNROLL 4

#ifndef UNROLL
#define UNROLL 1
#endif

#define OPERAND_B r10
#define RESULT    r12
#define OPERAND_A r14
rsa_mul_1024:
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
// create space on stack(64 bytes TMP variable, 3x pointer, 1x sign
	in	r28, 0x3d
	in	r29, 0x3e
	subi	r28, 128+2+2+2+1
	sbc	r29, r1
	LOAD_SP r0, r28,r29

// save operands position
	movw	RESULT, r24	// r
	movw	OPERAND_A, r22	// a
	movw	OPERAND_B, r20	// b

// calculate a_low - a_high -> r
	movw	r30,OPERAND_A	// a, a+64 to Z
	movw	r26,RESULT	// r to X

	ldi	r21,64/UNROLL	// loop counter
	sub	r16,r16		// initial carry, and clear r16
rsa_mul_1024_loop1:
.rept	UNROLL
	ld	r24,Z+
	ldd	r25,Z+63
	sbc	r24,r25
	st	x+,r24
.endr
	dec	r21
	brne	rsa_mul_1024_loop1

// negate if needed, sign based on carry
	adc	r16,r1		//r16=0 or 1 by carry

	movw	r26,RESULT	// r to X
	ldi	r21,64/UNROLL	// loop counter

	mov	r25,r16		//duplicate
	neg	r25		//create 0 or 0xff into r25, carry is set if r25 !=0

rsa_mul_1024_loop2:
.rept	UNROLL
	ld	r24,X
	eor	r24,r25		// xor 0xff
	adc	r24,r1		// add carry
	st	x+,r24
.endr
	dec	r21
	brne	rsa_mul_1024_loop2

// calculate b_low - b_high -> r + 64
	movw	r30,OPERAND_B	// b, b+64 to Z
	movw	r26,RESULT	// r
	subi	r26,lo8(-64)
	sbci	r27,hi8(-64)	//r+64

	ldi	r21,64/UNROLL	// loop counter
	sub	r17,r17		// initial carry, and clear r17
rsa_mul_1024_loop3:
.rept	UNROLL
	ld	r24,Z+
	ldd	r25,Z+63
	sbc	r24,r25
	st	x+,r24
.endr
	dec	r21
	brne	rsa_mul_1024_loop3

// negate if needed, sign based on carry
	adc	r17,r1		//r17=0 or 1 by carry

	movw	r26,RESULT	// r to X
	subi	r26,lo8(-64)
	sbci	r27,hi8(-64)	//r+64
	ldi	r21,64/UNROLL	// loop counter

	mov	r25,r17		//duplicate
	neg	r25		//create 0 or 0xff into r25, carry is set if r25 !=0

rsa_mul_1024_loop4:
.rept	UNROLL
	ld	r24,X
	eor	r24,r25		// xor 0xff
	adc	r24,r1		// add carry
	st	x+,r24
.endr
	dec	r21
	brne	rsa_mul_1024_loop4

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
	adiw	r30,8		// skip variables on stack to point 128 byt TMP

	movw	r22,RESULT
	movw	r26,RESULT
	subi	r26,lo8(-64)
	sbci	r27,hi8(-64)	//r+64

	call	rsa_mul_512_no_abi
// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	ldd	r22,Y+1	// OPERAND_B
	ldd	r23,Y+2
	ldd	r26,Y+5	// OPERAND_A
	ldd	r27,Y+6

// a_low * b_low to r
	call	rsa_mul_512_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
// a_high * b_high to r+128
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	subi	r30,lo8(-128)
	sbci	r31,hi8(-128)
	ldd	r22,Y+1	// OPERAND_B
	ldd	r23,Y+2
	subi	r22,lo8(-64)
	sbci	r23,hi8(-64)	//B+64
	ldd	r26,Y+5	// OPERAND_A
	ldd	r27,Y+6
	subi	r26,lo8(-64)
	sbci	r27,hi8(-64)	//B+64
	call	rsa_mul_512_no_abi

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

	neg	_EOR
	com	_EOR

// _CARRY is used as initial carry, _EOR as eor value

// 8 byt ACU in r0..r7
/*
     255...192 191...128 127...64 63...0
                      Y              Z
middle part is addressed by X
*/
	movw	r28,r30
	subi	r28,lo8(-128)
	sbci	r29,hi8(-128)

	ldi	_COUNT,8
// set initial carry for add/sub
	sub	_CARRY,_CARRY
	bst	_EOR,0
	bld	_CARRY,6

rsa_mul_1024_xloop1:
// first read A to move Z pointer to reach B part
.irp	pos,0,1,2,3,4,5,6,7
	ld	\pos+8,Z+
.endr
// summarize B+C, store to MEM at position C
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Z+64-8+\pos	//load B
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
	std	Z+64-8+\pos,\pos	//save final B
.endr
	ror	_CARRY
	ror	_CARRY

	dec	_COUNT
	breq	rsa_mul_1024_xloop1_end
	rjmp	rsa_mul_1024_xloop1
rsa_mul_1024_xloop1_end:

// A,B part	 ok, add D
// prevent carry, correct Z to point C
	ror	_CARRY
	bst	_CARRY,7	//save B+C carry
	subi	r30,lo8(-64)
	sbci	r31,hi8(-64)
	rol	_CARRY
/*
     255...192 191...128 127...64 63...0
             Y        Z
middle part is addressed by X
*/
	ldi	_COUNT,8
rsa_mul_1024_xloop2:
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

	dec	_COUNT
	breq	rsa_mul_1024_xloop2_end
	rjmp	rsa_mul_1024_xloop2
rsa_mul_1024_xloop2_end:

/*
     255...192 191...128 127...64 63...0
             Z
*/
// propagate carry to D
//(rest of carry in _CARRY bit 7,6 and C bit)
// 0 or 0xffff (_EOR,r27)
	clr	r1
	mov	r17,_EOR

	clr	_ACC
	bld	_ACC,0
	adc	_EOR,_ACC
	adc	r17,r1

	rol	_CARRY
	rol	_CARRY
	andi	_CARRY,1
	adc	_EOR,_CARRY
	adc	r17,r1

	ld	_ACC,Z
	add	_ACC,_EOR
	st	Z+,_ACC

.rept	63-8
	ld	_ACC,Z
	adc	_ACC,r17
	st	Z+,_ACC
.endr
//cached
.irp	pos,0,1,2,3,4,5,6,7
	adc	\pos+8,r17
	st	Z+,\pos+8
.endr
// return stack position
	sbiw	r26,1
	LOAD_SP	r0, r26,r27
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
#endif // HAVE_RSA_MUL_1024

#endif // HAVE_RSA_MUL_256_NO_ABI

#ifdef HAVE_RSA_MUL_128_NO_ABI
/////////////////////////////////////////////////////////////
.macro MUL_32_MOD_ADD  RS3 RS2 RS1 RS0  B3 B2 B1 B0   A3 A2 A1 A0 ZERO

	mul	\A0,\B0	// 0 0
	add	\RS0,r0
	adc	\RS1,r1
	adc	\RS2,\ZERO
	adc	\RS3,\ZERO

	mul	\A0,\B1	 // 0 1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\ZERO

	mul	\A1,\B0	 //1 0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\ZERO

	mul	\A1,\B1	 //1 1
	add	\RS2,r0
	adc	\RS3,r1

	mul	\A2,\B0	 //2 0
	add	\RS2,r0
	adc	\RS3,r1

	mul	\A0,\B2	// 0 2
	add	\RS2,r0
	adc	\RS3,r1

	mul	\A0,\B3	// 0 3
	add	\RS3,r0

	mul	\A1,\B2	// 1 2
	add	\RS3,r0

	mul	\A2,\B1	// 2 1
	add	\RS3,r0

	mul	\A3,\B0	// 3 0
	add	\RS3,r0
.endm
/////////////////////////////////////////////////////////////
.macro MUL_32_MOD_ADDx  RS3 RS2 RS1 RS0  B3 B2 B1 B0   A3 A2 A1 A0 ZERO  CC1 CC0

	mul	\A2,\B0
	movw	\CC0,r0

	mul	\A0,\B0	// 0 0
	add	\RS0,r0
	adc	\RS1,r1
	adc	\RS2,\CC0
	adc	\RS3,\CC1

	mul	\A0,\B1	 // 0 1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\ZERO

	mul	\A1,\B0	 //1 0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\ZERO

	mul	\A1,\B1	 //1 1
	add	\RS2,r0
	adc	\RS3,r1

	mul	\A0,\B2	// 0 2
	add	\RS2,r0
	adc	\RS3,r1

	mul	\A0,\B3	// 0 3
	add	\RS3,r0

	mul	\A1,\B2	// 1 2
	add	\RS3,r0

	mul	\A2,\B1	// 2 1
	add	\RS3,r0

	mul	\A3,\B0	// 3 0
	add	\RS3,r0
.endm


//clear ZERO  before call
.macro MUL_32_mod	RS3 RS2 RS1 RS0   A3 A2 A1 A0   B3 B2 B1 B0  ZERO

	mul	\A0,\B0
	movw	\RS0,r0

	mul	\A0,\B2
	movw	\RS2,r0

	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\ZERO

	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\ZERO

	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1

	mul	\A2,\B0
	add	\RS2,r0
	adc	\RS3,r1

	mul	\A0,\B3
	add	\RS3,r0
 
	mul	\A1,\B2
	add	\RS3,r0

	mul	\A2,\B1
	add	\RS3,r0

	mul	\A3,\B0
	add	\RS3,r0

.endm

//clear RS7,RS6, ZERO  before call!
.macro MUL_32	RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0   A3 A2 A1 A0   B3 B2 B1 B0  ZERO CC1 CC0
	mul	\A0, \B2
	movw	\RS2,r0

	mul	\A0,\B0
	movw	\RS0,r0

	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\ZERO

	mul	\A1,\B3
	movw	\RS4,r0

	mul	\A0,\B3
	movw	\CC0,r0

	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\CC0
	adc	\CC1,\ZERO

	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\CC1,\ZERO

	mul	\A2,\B3
	add	\RS4,\CC1
	adc	\RS5,r0
	adc	\RS6,r1

	mul	\A2,\B2
	movw	\CC0,r0

	mul	\A2,\B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\CC0
	adc	\CC1,\ZERO

	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\CC1,\ZERO

	mul	\A3,\B3
	add	\RS5,\CC1
	adc	\RS6,r0
	adc	\RS7,r1

	mul	\A3,\B1
	movw	\CC0,r0

	mul	\A2,\B1
	add	\RS3,r0
	adc	\CC0,r1
	adc	\CC1,\ZERO

	mul	\A3,\B0
	add	\RS3,r0
	adc	\CC0,r1
	adc	\CC1,\ZERO

	mul	\A3,\B2
	add	\RS4,\CC0
	adc	r0,\CC1
	adc	r1,\ZERO
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO
.endm

//RS7, RS6 is added to result!
.macro MUL_32x	RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0   A3 A2 A1 A0   B3 B2 B1 B0  ZERO CC1 CC0
	mul	\A0,\B2
	movw	\RS2,r0

	mul	\A0,\B0
	movw	\RS0,r0

	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\ZERO

	mul	\A1,\B3
	movw	\RS4,r0

	mul	\A0,\B3
	movw	\CC0,r0

	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\CC0
	adc	\CC1,\ZERO

	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\CC1,\ZERO

	mul	\A2,\B3
	add	\RS4,\CC1
	adc	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO

	mul	\A2,\B2
	movw	\CC0,r0

	mul	\A2,\B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\CC0
	adc	\CC1,\ZERO

	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\CC1,\ZERO

	mul	\A3,\B3
	add	\RS5,\CC1
	adc	\RS6,r0
	adc	\RS7,r1

	mul	\A3,\B1
	movw	\CC0,r0

	mul	\A2,\B1
	add	\RS3,r0
	adc	\CC0,r1
	adc	\CC1,\ZERO

	mul	\A3,\B0
	add	\RS3,r0
	adc	\CC0,r1
	adc	\CC1,\ZERO

	mul	\A3,\B2
	add	\RS4,\CC0
	adc	r0,\CC1
	adc	r1,\ZERO
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO
.endm
.macro	ADD32	RZ3 RZ2 RZ1 RZ0  A3 A2 A1 A0
	add	\RZ0,\A0
	adc	\RZ1,\A1
	adc	\RZ2,\A2
	adc	\RZ3,\A3
.endm
.macro	SUB32	RZ3 RZ2 RZ1 RZ0  A3 A2 A1 A0
	sub	\RZ0,\A0
	sbc	\RZ1,\A1
	sbc	\RZ2,\A2
	sbc	\RZ3,\A3
.endm
.macro ABS32	RZ3 RZ2 RZ1 RZ0  SIGN ZERO
	eor	\RZ0,\SIGN
	eor	\RZ1,\SIGN
	eor	\RZ2,\SIGN
	eor	\RZ3,\SIGN
	neg	\SIGN
	add	\RZ0,\SIGN
	adc	\RZ1,\ZERO
	adc	\RZ2,\ZERO
	adc	\RZ3,\ZERO
.endm
.macro	ADD64	RZ7 RZ6 RZ5 RZ4 RZ3 RZ2 RZ1 RZ0  A7 A6 A5 A4 A3 A2 A1 A0
	add	\RZ0,\A0
	adc	\RZ1,\A1
	adc	\RZ2,\A2
	adc	\RZ3,\A3
	adc	\RZ4,\A4
	adc	\RZ5,\A5
	adc	\RZ6,\A6
	adc	\RZ7,\A7
.endm
.macro	ADC64	RZ7 RZ6 RZ5 RZ4 RZ3 RZ2 RZ1 RZ0  A7 A6 A5 A4 A3 A2 A1 A0
	adc	\RZ0,\A0
	adc	\RZ1,\A1
	adc	\RZ2,\A2
	adc	\RZ3,\A3
	adc	\RZ4,\A4
	adc	\RZ5,\A5
	adc	\RZ6,\A6
	adc	\RZ7,\A7
.endm
.macro SUB64	RZ7 RZ6 RZ5 RZ4 RZ3 RZ2 RZ1 RZ0  A7 A6 A5 A4 A3 A2 A1 A0
	sub	\RZ0,\A0
	sbc	\RZ1,\A1
	sbc	\RZ2,\A2
	sbc	\RZ3,\A3
	sbc	\RZ4,\A4
	sbc	\RZ5,\A5
	sbc	\RZ6,\A6
	sbc	\RZ7,\A7
.endm
// add to  memory (Z+offset)  target = source + register set
.macro MEM_ADD64 T  S  RG7 RG6 RG5 RG4 RG3 RG2 RG1 RG0 TMP
	ldd	\TMP,Z+\S+0
	add	\TMP,\RG0
	std	Z+\T+0,\TMP
	ldd	\TMP,Z+\S+1
	adc	\TMP,\RG1
	std	Z+\T+1,\TMP
	ldd	\TMP,Z+\S+2
	adc	\TMP,\RG2
	std	Z+\T+2,\TMP
	ldd	\TMP,Z+\S+3
	adc	\TMP,\RG3
	std	Z+\T+3,\TMP
	ldd	\TMP,Z+\S+4
	adc	\TMP,\RG4
	std	Z+\T+4,\TMP
	ldd	\TMP,Z+\S+5
	adc	\TMP,\RG5
	std	Z+\T+5,\TMP
	ldd	\TMP,Z+\S+6
	adc	\TMP,\RG6
	std	Z+\T+6,\TMP
	ldd	\TMP,Z+\S+7
	adc	\TMP,\RG7
	std	Z+\T+7,\TMP
.endm

#ifdef HAVE_RSA_MUL_128_MOD
rsa_mul_128_mod_no_abi:
// result is constructed into  part:
// D  B+C  A (all parts 32 bites)

// do not use reg 26,27,30,31 here ..
#define  RES_A0		r24
#define  RES_A1		r25
#define  RES_A2		r12
#define  RES_A3		r13

#define  RES_BC0	r14
#define  RES_BC1	r15
#define  RES_BC2	r16
#define  RES_BC3	r17

#define  RES_D0		r10
#define  RES_D1		r11
#define  RES_D2		r18
#define  RES_D3		r19

// MUL_32 need zero in upper two bytes of result
	clr	RES_BC2
	clr	RES_BC3
#define LL_ZERO  RES_D2

	movw	LL_ZERO,RES_BC2

	push	r26
	push	r27
// TODO maybe push r28,r29 (and pop) waste 8 ticks, but
// pair of registers can be used to speed up multiplications
// and save more ticks

	ld	r2,X+
	ld	r3,X+
	ld	r4,X+
	ld	r5,X+
	ldd	r6,Y+0
	ldd	r7,Y+1
	ldd	r8,Y+2
	ldd	r9,Y+3
// calculate A,B from low parts of operands
	MUL_32  RES_BC3 RES_BC2 RES_BC1 RES_BC0  RES_A3 RES_A2 RES_A1 RES_A0   r5,r4,r3,r2   r9,r8,r7,r6 LL_ZERO,RES_D1,RES_D0
// load zero for mult. result...
	movw	RES_D0,LL_ZERO

// calculate differences high - low
#define L_ZERO  r20
#define L2_ZERO r21

#define A0 L_ZERO
#define A1 L2_ZERO
#define A2 r22
#define A3 r23
	ld	A0,X+
	ld	A1,X+
	ld	A2,X+
	ld	A3,X+
#define B0 r30
#define B1 r31 
#define B2 r26
#define B3 r27
	ldd	B0,Y+4
	ldd	B1,Y+5
	ldd	B2,Y+6
	ldd	B3,Y+7
// differences hi-lo, save final sign into T
	SUB32	r5 r4 r3 r2  A3 A2 A1 A0
	sbc	r0,r0
	ABS32	r5 r4 r3 r2  r0,LL_ZERO

	SUB32	r9 r8 r7 r6  B3 B2 B1 B0
	sbc	r1,r1
	ABS32	r9 r8 r7 r6  r1,LL_ZERO

	eor	r0,r1
	bst	r0,0
// prevent r9 r8 r7 r6 r5 r4 r3 r2 !!!
//                        D                                   B+C                         A
// final result   RES_D3 RES_D2 RES_D1 RES_D0  RES_BC3 RES_BC2 RES_BC1  RES_BC0 RES_A3 RES_A2 RES_A1 RES_A0
// calculate D,B+C from high parts of operand
	mul	A0, B0
	add	RES_BC0, r0
	adc	RES_BC1, r1
	adc	RES_BC2, LL_ZERO
	adc	RES_D3, LL_ZERO  	// reuse RES_D3 as Carry catcher

	mul	A0, B1
	add	RES_BC1, r0
	adc	RES_BC2, r1
	adc	RES_D3, LL_ZERO

	mul	A1, B0
	add	RES_BC1, r0
	adc	RES_BC2, r1
	adc	RES_BC3, RES_D3
	adc	RES_D0, LL_ZERO

	mul	A0, B2
	add	RES_BC2, r0 
	adc	RES_BC3, r1
	adc	RES_D0, LL_ZERO

	mul	A1, B1
	add	RES_BC2, r0
	adc	RES_BC3, r1
	adc	RES_D0, LL_ZERO

	mul	A2, B0
	add	RES_BC2, r0
	adc	RES_BC3, R1
	adc	RES_D0, LL_ZERO

	mul	A0, B3
	add	RES_BC3, r0
	adc	RES_D0, R1
	adc	RES_D1, LL_ZERO

	mul	A1, B2
	add	RES_BC3, r0
	adc	RES_D0, R1
	adc	RES_D1, LL_ZERO

	mul	A2, B1
	add	RES_BC3, r0
	adc	RES_D0, R1
	adc	RES_D1, LL_ZERO

	mul	A3, B0
	add	RES_BC3, r0
	adc	RES_D0, R1
	adc	RES_D1, LL_ZERO

	mul	A1, B3
	add	RES_D0, r0
	adc	RES_D1, r1
	adc	RES_D2, RES_D2

#undef LL_ZERO
// move to L_ZERO (LL_ZERO is in result bytes .. D3,D2)
	clr	L_ZERO

	mul	A2, B2
	add	RES_D0, r0
	adc	RES_D1, r1
	adc	RES_D2, L_ZERO

	mul	A3, B1
	add	RES_D0, r0
	adc	RES_D1, r1
	adc	RES_D2, L_ZERO

	clr	RES_D3
	mul	A2, B3
	add	RES_D1, r0
	adc	RES_D2, r1
	adc	RES_D3, L_ZERO

	mul	A3, B2
	add	RES_D1, r0
	adc	RES_D2, r1
	adc	RES_D3, L_ZERO

	mul	A3, B3
	add	RES_D2, r0
	adc	RES_D3, r1

// new register pair with zero ..
	mov	L2_ZERO,L_ZERO

#undef A0
#undef A1
#undef A2
#undef A3
#undef B0
#undef B1
#undef B2
#undef B3

// middle part (prevent result D, BC, A)
//          result(15..12)               sum (11..8 + 7..4)              result (3..0)
//       RES_D3 RES_D2 RES_D1 RES_D0  RES_BC3 RES_BC2 RES_BC1 RES_BC0  RES_A3 RES_A2 RES_A1 RES_A0


// multiply  r9,r8,r7,r6  by  r5,r4,r3,r2
// result in  RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0


#define A0 r2
#define A1 r3
#define A2 r4
#define A3 r5

#define B0 r6
#define B1 r7
#define B2 r8
#define B3 r9

#define RS0	r22
#define RS1	r23
#define RS2	r30
#define RS3	r31
#define RS4	r26
#define RS5	r27

#define RS6	A0
#define RS7	A1

	movw	RS2,L_ZERO	// zeros for result
	movw	RS4,L_ZERO

	mul	A0, B0
	movw	RS0, r0

	mul	A0, B1
	add	RS1, r0
	adc	RS2, r1

	mul	A1, B0
	add	RS1, r0
	adc	RS2, r1
	adc	RS3, L_ZERO

	mul	A0, B2
	add	RS2, r0
	adc	RS3, r1
	adc	RS4, L_ZERO

	mul	A1, B1
	add	RS2, r0
	adc	RS3, r1
	adc	RS4, L_ZERO

	mul	A2, B0
	add	RS2, r0
	adc	RS3, r1
	adc	RS4, L_ZERO

	mul	A0, B3
	add	RS3, r0
	adc	RS4, r1
	adc	RS5, L_ZERO

	mul	A1, B2
	add	RS3, r0
	adc	RS4, r1
	adc	RS5, L_ZERO

	mul	A2, B1
	add	RS3, r0
	adc	RS4, r1
	adc	RS5, L_ZERO

	mul	A3, B0
	add	RS3, r0
	adc	RS4, r1
	adc	RS5, L_ZERO

	mul	A1, B3
// A1 is not needed anymore, A1 is reused as RS7, do clear RS6,RS7
	movw	RS6,L_ZERO

	add	RS4, r0
	adc	RS5, r1
	adc	RS6, L_ZERO

	mul	A2, B2
	add	RS4, r0
	adc	RS5, r1
	adc	RS6, L_ZERO

	mul	A3, B1
	add	RS4, r0
	adc	RS5, r1
	adc	RS6, L_ZERO

	mul	A2, B3
	add	RS5, r0
	adc	RS6, r1
	adc	RS7, L_ZERO

	mul	A3, B2
	add	RS5, r0
	adc	RS6, r1
	adc	RS7, L_ZERO

	mul	A3, B3
	add	RS6, r0
	adc	RS7, r1

// combine
//          result(15..12)               sum (11..8 + 7..4)              result (3..0)
//       RES_D3 RES_D2 RES_D1 RES_D0  RES_BC3 RES_BC2 RES_BC1 RES_BC0  RES_A3 RES_A2 RES_A1 RES_A0
// middle part       RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0

// save A - result bytes 3..0
#define RES_B0 r6
#define RES_B1 r7
#define RES_B2 r8
#define RES_B3 r9

	movw	RES_B0,RES_A0
	movw	RES_B2,RES_A2

	ADD64  RES_BC3 RES_BC2 RES_BC1 RES_BC0  RES_B3 RES_B2 RES_B1 RES_B0     RES_D3 RES_D2 RES_D1 RES_D0  RES_BC3 RES_BC2 RES_BC1 RES_BC0
	// save carry
	adc	L2_ZERO,L2_ZERO

	// sign from (BH-BL)*(AH-AL)
	brtc	sub_M_L_mod

	ADD64  RES_BC3 RES_BC2 RES_BC1 RES_BC0  RES_B3 RES_B2 RES_B1 RES_B0   RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0
	// prepare 0,1, 2 for carry propagation
	adc	L2_ZERO,L_ZERO
	rjmp	final_L_mod

sub_M_L_mod:
	SUB64  RES_BC3 RES_BC2 RES_BC1 RES_BC0  RES_B3 RES_B2 RES_B1 RES_B0   RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0
	// prepare -1, 0, 1  for carry propagation
	sbci	L2_ZERO,0
	sbc	L_ZERO,L_ZERO

final_L_mod:

#undef RS0
#undef RS1
#undef RS2
#undef RS3
#undef RS4
#undef RS5
#undef RS6
#undef RS7
	pop	r27
	pop	r26

	in	r30, 0x3d
	in	r31, 0x3e

#if __AVR_3_BYTE_PC__ == 1
//xmega
#define S_OFF 16+9+4
#elif __AVR_2_BYTE_PC__ == 1
//atmega
#define S_OFF 16+9+2
#else
#error unknown PC size
#endif
	// add 64 bit value in registers to variables in memory 
	//        target =  source +  registers                                                 tmp
	MEM_ADD64 S_OFF     S_OFF   RES_B3 RES_B2 RES_B1 RES_B0 RES_A3 RES_A2 RES_A1 RES_A0     r2
// save carry
#define CARRY_SAVE  r13
	rol	CARRY_SAVE
// RESULT:
#define RS0 RES_BC0
#define RS1 RES_BC1
#define RS2 RES_BC2
#define RS3 RES_BC3
#define RS4 RES_D0
#define RS5 RES_D1
#define RS6 RES_D2
#define RS7 RES_D3

#define ZERO r12

#define TMP_0 r20
#define TMP_1 r21
#define TMP_2 r22
#define TMP_3 r23
#define TMP_4 r24
#define TMP_5 r25

// propagate carry to end 
	ADD32   RES_D3 RES_D2 RES_D1 RES_D0   L_ZERO L_ZERO L_ZERO L2_ZERO

#undef L_ZERO
#undef L2_ZERO

	ld	r2, X+
	ld	r3, X+
	ld	r4, X+
	ld	r5, X+
	ldd	r6, Y+8
	ldd	r7, Y+9
	ldd	r8, Y+10
	ldd	r9, Y+11

  	clr	ZERO
	MUL_32x  RS7,RS6,TMP_5,TMP_4,TMP_3,TMP_2,TMP_1,TMP_0   r5,r4,r3,r2   r9,r8,r7,r6   ZERO,r31,r30
// renew carry 
	ror	CARRY_SAVE

	ADC64	RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   ZERO,ZERO,TMP_5,TMP_4,TMP_3,TMP_2,TMP_1,TMP_0

	ldd	TMP_0,Y+12
	ldd	TMP_1,Y+13
	ldd	TMP_2,Y+14
	ldd	TMP_3,Y+15

	MUL_32_MOD_ADDx RS7 RS6 RS5 RS4   r5,r4,r3,r2   TMP_3,TMP_2,TMP_1,TMP_0   ZERO  r31,r30

	ld	r2,X+
	ld	r3,X+
	ld	r4,X+
	ld	r5,X+

	MUL_32_MOD_ADDx RS7 RS6 RS5 RS4   r5,r4,r3,r2   r9,r8,r7,r6   ZERO  r31 r30

	ld	r2,X+
	ld	r3,X+
	ld	r4,X+
	ld	r5,X+
	ldd	r6,Y+0
	ldd	r7,Y+1
	ldd	r8,Y+2
	ldd	r9,Y+3

	MUL_32x  RS7,RS6,TMP_5,TMP_4,TMP_3,TMP_2,TMP_1,TMP_0   r5,r4,r3,r2   r9,r8,r7,r6  ZERO,r31,r30

	ADD64    RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   ZERO,ZERO,TMP_5,TMP_4,TMP_3,TMP_2,TMP_1,TMP_0

	ldd	TMP_0,Y+4
	ldd	TMP_1,Y+5
	ldd	TMP_2,Y+6
	ldd	TMP_3,Y+7

	MUL_32_MOD_ADDx RS7 RS6 RS5 RS4  r5,r4,r3,r2   TMP_3,TMP_2,TMP_1,TMP_0   ZERO  r31 r30

	ld	r2,X+
	ld	r3,X+
	ld	r4,X+
	ld	r5,X+

	MUL_32_MOD_ADDx RS7 RS6 RS5 RS4   r5,r4,r3,r2   r9,r8,r7,r6   ZERO  r31 r30

	in	r30, 0x3d
	in	r31, 0x3e

	// add 64 bit value in registers to variables in memory (addressed by Z)
	//        target =  source +  registers                          tmp
	MEM_ADD64 S_OFF+8   S_OFF+8   RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0     r2
	ret
#undef S_OFF
// warning, result is in stack, use SP to get result position  
rsa_mul_256_mod_no_abi:
// save pointers to stack
	push	r27
	push	r26
	push	r29
	push	r28
// get result position	
	in	r30, 0x3d
	in	r31, 0x3e
#if __AVR_3_BYTE_PC__ == 1
//xmega
	adiw	r30,9+4+1
#elif __AVR_2_BYTE_PC__ == 1
//atmega
	adiw    r30,9+4
#else
#error unknown PC size
#endif
	rcall	rsa_mul_128_no_abi
// load pointers
	pop	r28
	pop	r29
	pop	r26
	pop	r27
	adiw	r28,16	// upper part
	rcall    rsa_mul_128_mod_no_abi

	sbiw	r28,16 // lower part, X is incremented in rsa_mul_128_mod_no_abi

// do not replace this by jmp/rjmp, SP is used to point result 
	rcall    rsa_mul_128_mod_no_abi
	ret

#undef RS0
#undef RS1
#undef RS2
#undef RS3
#undef RS4
#undef RS5
#undef RS6
#undef RS7
#undef ZERO
#undef TMPTMP
#undef TMP_0
#undef TMP_1
#undef TMP_2
#undef TMP_3
#undef TMP_4
#undef TMP_5

#endif
#ifdef HAVE_RSA_MUL_512_MOD
#ifndef HAVE_RSA_MUL_128_MOD
#error rsa_mul_512_mod depend on HAVE_RSA_MUL_128_MOD
#endif
        .global rsa_mul_512_mod
        .type   rsa_mul_512_mod, @function

rsa_mul_512_mod:
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
	
// create space on stack - 64 bytes TMP variable, 3x pointer
	in	r28, 0x3d
	in	r29, 0x3e
//	subi	r28, lo8(32+2+2+2)
//	sbci	r29, hi8(32+2+2+2)
	sbiw	r28,(32+2+2+2)
	LOAD_SP r0, r28,r29

// save  pointers to stack
	std	Y+1,r22	// A pointer
	std	Y+2,r23
	std	Y+3,r30	// Result
	std	Y+4,r31
	std	Y+5,r26	// B pointer
	std	Y+6,r27

	movw	r28,r22
	call	rsa_mul_256_no_abi
// load values back 
	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r28,Z+1	// OPERAND_B
	ldd	r29,Z+2
	adiw	r28,32	// upper part
	ldd	r26,Z+5	// OPERAND_A
	ldd	r27,Z+6	

	rcall 	rsa_mul_256_mod_no_abi
	
// load values back 
	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r28,Z+3	// result
	ldd	r29,Z+4
	adiw	r28,32	// upper part
	adiw	r30,7

	ldi	r24,4
	clc
rsa_mul_512_mod_loop1:
.rept	8
	ld	r0,Y
	ld	r25,Z+
	adc	r25,r0
	st	Y+,r25
.endr
	dec	r24
	brne	rsa_mul_512_mod_loop1

// load values back 
	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r28,Z+1	// OPERAND_B
	ldd	r29,Z+2
	ldd	r26,Z+5	// OPERAND_A
	ldd	r27,Z+6	
	adiw	r26,32	//upper part

	rcall 	rsa_mul_256_mod_no_abi
	
// load values back 
	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r28,Z+3	// result
	ldd	r29,Z+4
	adiw	r28,32	// upper part
	adiw	r30,7

	ldi	r24,4
	sub	r1,r1	// clear carry and r1
rsa_mul_512_mod_loop2:
.rept	8
	ld	r0,Y
	ld	r25,Z+
	adc	r25,r0
	st	Y+,r25
.endr
	dec	r24
	brne	rsa_mul_512_mod_loop2
// return stack position
	sbiw	r30,1
	LOAD_SP	r0, r30,r31
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
// r1 is already cleared
	ret
	
#endif  //HAVE_RSA_MUL_512_MOD
#endif //HAVE_RSA_MUL_128_NO_ABI
