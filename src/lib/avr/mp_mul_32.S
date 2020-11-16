/*
    mp_mul_32.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2020 Peter Popovec, popovec.peter@gmail.com

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

    This file depend on mp_mul_256.S files.

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
                         r28:29 result
                         r22:23 operand B
                         r26:27 operand A

multiplication with modulus (mod 128, 256 .. ):
    public functions:
    rsa_mul_512_mod:    512 bit multiplication (C ABI)    
                        result is only 512 bit long (low bites)


*/

/////////////////////////////////////////////////////////////
#include "load_sp.h"

  .global mp_mul_256   
  .type mp_mul_256, @function

  .global rsa_mul_256   
  .type rsa_mul_256, @function
  .section .text.rsa_mul_256,"ax",@progbits

mp_mul_256:
rsa_mul_256:
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

  .global rsa_mul_512_no_abi
  .type rsa_mul_512_no_abi, @function
  .section .text.rsa_mul_512_no_abi,"ax",@progbits

rsa_mul_512_no_abi:
// create space on stack(64 bytes TMP variable, 3x pointer, 1x sign
	in	r30, 0x3d
	in	r31, 0x3e
	subi	r30, lo8(64+2+2+2+1)
	sbci	r31, hi8(64+2+2+2+1)
	LOAD_SP	r0, r30,r31

// save  pointers to stack
	std	Z+1,r22	// A pointer
	std	Z+2,r23
	std	Z+3,r28	// Result
	std	Z+4,r29
	std	Z+5,r26	// B pointer
	std	Z+6,r27

// calculate a_low - a_high -> r
	movw	r30,r22		//A, A+32 is addressed by Y
	ldi	r25,4		//4*8 = 32 bytes
	sub	r24,r24		//initial carry(s)

rsa_mul_512_loop1a:
// load A into r0..r7, A+32 to r8..r15
.irp	pos,0,1,2,3,4,5,6,7
	ld	r\pos,Z+
.endr
.irp	pos,8,9,10,11,12,13,14,15
	ldd	r\pos,Z+16+\pos
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
	st	Y+,r\pos
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
	std	Y+16+\pos,r\pos
.endr
	rol	r24	//renew carry

	dec	r25
	brne	rsa_mul_512_loop1a

	movw	r30,r26 // B pointer

// calculate position of 1st operand  |ah - al|
	movw	r26,r28	// first operand for multiply
	bst	r24,0	// save sign	
	bld	r25,5	// 0 or 32
	sub	r26,r25
	sbci	r27,0

// sign is saved in T flag, r26 position of first operand		

// calculate b_low - b_high -> r
	adiw	r28,32
	ldi	r25,4		//4*8 = 32 bytes
	sub	r24,r24		//initial carry(s)

rsa_mul_512_loop1b:
// load A into r0..r7, A+32 to r8..r15
.irp	pos,0,1,2,3,4,5,6,7
	ld	r\pos,Z+
.endr
.irp	pos,8,9,10,11,12,13,14,15
	ldd	r\pos,Z+16+\pos
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
	st	Y+,r\pos
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
	std	Y+16+\pos,r\pos
.endr
	rol	r24	//renew carry

	dec	r25
	brne	rsa_mul_512_loop1b

// get xor from sing of (a_low - a_high),(b_low - b_high)
	in	r30, 0x3d
	in	r31, 0x3e

	bld	r24,1	// load previous sign from T
	bst	r24,0	// save new sign into T
	dec	r24	// do xor old/new sign (in bit 1, but 0 = sign different, 1 same)
	ror	r24
	andi	r24,1	// into bit 0
	std	Z+7,r24 // save sign

// select RESULT or RESULT + 32 for |b_low - b_high|
	bld	r25,5	// get saved sing from T
	sub	r28,r25
	sbci	r29,0

// multiply |a_low - a_high| * |b_low - b_high| into TMP
	
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

	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r28,Z+3	// Result
	ldd	r29,Z+4
	ldd	_CARRY,Z+7	// sign
	movw	r26,r30
	adiw	r26,8		// skip variables on stack to point 64 byt TMP

// summarize L,H,M, sub/add M (based on sign ..)
// get sign from _CARRY (already negated => 1 same signs)
// if signs are the same, set _EOR to 0xff _CARRY to 1
// else                   set _EOR to 0x00 _CARRY to 0

// generate ff/0  from 1/0
	mov	_EOR,_CARRY
	neg	_EOR
// r24 is used as initial carry, r25 as eor value

	movw	r30,r28
	subi	r30,lo8(-64)
	sbci	r31,hi8(-64)
//       D          C           B          A          
//  127      96 95      64 63       32 31      0
//                      Z                      Y
//-------------------------------------------------
// summarize B,C into cache (r8..r15)
// bytes 39..32
	ldd	r0,Y+0+32+0
	ldd	r8,Z+0
	add	r8,r0
.irp	pos,1,2,3,4,5,6,7
	ldd	\pos,Y+\pos+32+0
	ldd	\pos+8,Z+\pos
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
	ldd     _ACC,Y+\pos
	adc	r\pos,_ACC
	std	Y+32+\pos,r\pos
.endr
	rol	_CARRY	//save carry ABC,load M
	rol	_CARRY	//save carry M, load BC
//continue B,C into cache r16..r22
// bytes 47..40
// no enough register for cache ..(r23 is reserved)
.irp	pos,0,1,2,3,4,5,6
	ldd	\pos,Y+\pos+32+8
	ldd	\pos+16,Z+\pos+8
	adc	\pos+16,\pos
.endr
// no enough registers - store to ram
	ldd	r7,Y+32+7+8
	ldd	_ACC,Z+7+8
	adc	r7,_ACC
	std	Z+7+8,r7

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
	ldd     _ACC,Y+\pos+8
	adc	\pos,_ACC
	std	Y+32+\pos+8,\pos
.endr
// bytes 55..48
	rol	_CARRY	//save carry ABC,load M
	rol	_CARRY	//save carry M, load BC

.irp	pos,0,1,2,3,4,5,6,7
	ldd	r\pos,Y+\pos+32+16
	ldd	_ACC,Z+\pos+16
	adc	r\pos,_ACC
	std	Z+\pos+16,r\pos
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
	ldd     _ACC,Y+\pos+16
	adc	r\pos,_ACC
	std	Y+32+\pos+16,r\pos
.endr
	rol	_CARRY	//save carry ABC,load M
	rol	_CARRY	//save carry M, load BC
// bytes 63..56
.irp	pos,0,1,2,3,4,5,6,7
	ldd	r\pos,Y+\pos+32+24
	ldd	_ACC,Z+\pos+24
	adc	r\pos,_ACC
	std	Z+\pos+24,r\pos
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
	ldd     _ACC,Y+\pos+24
	adc	r\pos,_ACC
	std	Y+32+\pos+24,r\pos
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
	ldd	_ACC,Z+32+\pos	//D0..D7
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
	std	Z+\pos,\pos+8
.endr
/////////////////////
// B+C in r16..r22, load last byte B+C into r0
	ldd	r0,Z+15
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
	ldd	\pos+8,Z+32+8+\pos      //D8..D15
.endr
.irp	pos,0,1,2,3,4,5,6
	adc	\pos+16,\pos+8
	std	Z+\pos+8,\pos+16
.endr
	adc	r0,r15
	std	Z+15,r0
/////////////////////////
// bytes 95..80
.irp	pos,0,1,2,3,4,5,6
	ldd	\pos+16,Z+32+16+\pos	// preload D22..D16
	ldd	\pos,Z+16+\pos	// preload B+C from RAM
	adc	\pos,\pos+16	// add D
.endr
// add not cached D (D23)
	ldd	_ACC,Z+32+16+7	//D23
	ldd	r7,Z+16+7	//B+C from RAM
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
	std	Z+16+\pos,\pos
.endr
/////////////////////////
// bytes 127..96
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Z+16+8+\pos	// preload B+C from RAM
.endr
// add carry
	clr	_ACC
.irp	pos,0,1,2,3,4,5,6,7
	adc	r\pos,_ACC
.endr
	rol	_CARRY	// save ABC, load M
// B+C -M
.irp	pos,0,1,2,3,4,5,6
	ld	_ACC,X+
	eor	_ACC,_EOR
	adc	r\pos,_ACC
.endr
//	movw	r28,r26
	ld	_ACC,X
	eor	_ACC,_EOR
	adc	r7,_ACC

	rol	_CARRY	// save M load BC
// res of D is preloaded into r29,r0..r6
	ldd	r29,Z+32+16+8+0	//D24
	adc	r0,r29
	std	Z+16+8+0,r0

.irp	pos,1,2,3,4,5,6,7
	ldd	\pos-1,Z+32+16+8+\pos	//D31..D25
	adc	\pos,\pos-1
	std	Z+16+8+\pos,\pos
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

// rotate bit 1,0 to C and bit 0
	ror	_CARRY
	andi	_CARRY,1
	adc	_CARRY16L,_CARRY
	adc	_CARRY16H,_ACC

// propagate carry to D (1st part of D in RAM)
	ldd	_ACC,Z+32
	add	_ACC,_CARRY16L
	std	Z+32,_ACC
// not cached
.irp	pos,1,2,3,4,5,6,7
	ldd	_ACC,Z+32+\pos
	adc	_ACC,_CARRY16H
	std	Z+32+\pos,_ACC
.endr
// cached
.irp	pos,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22
	adc	\pos,_CARRY16H
	std	Z+32+\pos,\pos
.endr

// not cached
	ldd	_ACC,Z+32+23
	adc	_ACC,_CARRY16H
	std	Z+32+23,_ACC

// cached
	adc	r7,_CARRY16H
	std	Z+32+24,r29
// cached
.irp	pos,25,26,27,28,29,30,31
	adc	\pos-25,_CARRY16H
	std	Z+32+\pos,\pos-25
.endr
// return stack position
	LOAD_SP r0, r26,r27
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

        .global rsa_mul_512
        .type   rsa_mul_512, @function
	.section .text.rsa_mul_512,"ax",@progbits

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
	movw	r28,r24
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



        .global rsa_mul_1024
        .type   rsa_mul_1024, @function
	.section .text.rsa_mul_1024,"ax",@progbits

// stack 282 

#define UNROLL 4

#ifndef UNROLL
#define UNROLL 1
#endif

#define RESULT    r12
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

// set this to 1, code is then about 84 bytes longer, and about 428 clock
// cycles faster.  This is used only in RSA 2048, (558x for 4 bit window,
// blinded, Belcore protection). Because only 238824 clock cycles can be
// saved, this is not enabled by default.
#if 0
// create space on stack (128 bytes TMP variable, 3x pointer, 1x sign
	in	r30, 0x3d
	in	r31, 0x3e
	subi	r30, 128+2+2+2+1
	sbci	r31, 0
	LOAD_SP r0, r30,r31
// save pointers to stack
	std	Z+1,r20	// B pointer
	std	Z+2,r21
	std	Z+3,r24	// Result
	std	Z+4,r25
	std	Z+5,r22	// A pointer
	std	Z+6,r23

	movw	r26,r20	// save B
// calculate a_low - a_high -> r
	movw	r28,r24		// result
	movw	r30,r22		// operand B
	ldi	r25,8		//8*8 = 64 bytes
	sub	r24,r24		//initial carry(s)

rsa_mul_1024_loop1a:

.irp	pos,0,1,2,3,4,5,6,7
	ld	r\pos,Z+
.endr

.irp	pos,8,9,10,11,12,13,14,15
	ldd	r\pos,Z+48+\pos
.endr
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
	st	Y+,r\pos
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
	std	Y+48+\pos,r\pos
.endr
	rol	r24	//renew carry
	dec	r25
	brne	rsa_mul_1024_loop1a

	movw	r30,r26	// B pointer
	movw	r26,r28
	bst	r24,0	// sign
	bld	r25,6	// 0 or 64
	sub	r26,r25
	sbci	r27,0

	subi	r28,lo8(-64)
	sbci	r29,hi8(-64)

	ldi	r25,8
	sub	r24,r24

rsa_mul_1024_loop1b:
.irp	pos,0,1,2,3,4,5,6,7
	ld	r\pos,Z+
.endr
.irp	pos,8,9,10,11,12,13,14,15
	ldd	r\pos,Z+48+\pos
.endr
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
	st	Y+,r\pos
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
	std	Y+48+\pos,r\pos
.endr
	rol	r24	//renew carry

	dec	r25
	brne	rsa_mul_1024_loop1b

	movw	r22,r28
	in	r28, 0x3d
	in	r29, 0x3e
	bld	r24,1	// load previous sign from T
	bst	r24,0	// save new sign into T
	inc	r24	// do xor
	ror	r24
	andi	r24,1
	neg	r24	// 0x00  or 0xff
	std	Y+7,r24

	bld	r25,6
	sub	r22,r25
	sbci	r23,0

// r28 result, r26,r22 operands
	adiw	r28,8	// skip variables on stack to point TMP variable (128 bytes)
#else
// create space on stack (128 bytes TMP variable, 3x pointer, 1x sign
	in	r28, 0x3d
	in	r29, 0x3e
	subi	r28, 128+2+2+2+1
	sbci	r29, 0
	LOAD_SP r0, r28,r29
// save pointers to stack
	std	Y+1,r20	// B pointer
	std	Y+2,r21
	std	Y+3,r24	// Result
	std	Y+4,r25
	std	Y+5,r22	// A pointer
	std	Y+6,r23

// save operands position
	movw	RESULT, r24	// r
// calculate a_low - a_high -> r
	movw	r30,r22 	// a, a+64 to Z
	movw	r26,r24		// r to X

	ldi	r24,64/UNROLL	// loop counter
	sub	r16,r16		// initial carry, and clear r16
rsa_mul_1024_loop1:
.rept	UNROLL
	ld	r0,Z+
	ldd	r25,Z+63
	sbc	r0,r25
	st	x+,r0
.endr
	dec	r24
	brne	rsa_mul_1024_loop1
	movw	r10,r26		// save r+64 position
// negate if needed, sign based on carry
	sbc	r16,r16		//r16=0 or 0xff

	movw	r26,RESULT	// r to X
	ldi	r24,64/UNROLL	// loop counter

	clc
rsa_mul_1024_loop2:
.rept	UNROLL
	ld	r0,X
	eor	r0,r16		// xor 0xff
	sbc	r0,r16		// add 0/1 (subtract -1)
	st	x+,r0
.endr
	dec	r24
	brne	rsa_mul_1024_loop2

// calculate b_low - b_high -> r + 64
	movw	r30,r20		// b, b+64 to Z
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
	sbc	r17,r17		//r17=0 or 0xff by carry

	movw	r26,r10		// r+64
	ldi	r21,64/UNROLL	// loop counter

	clc
rsa_mul_1024_loop4:
.rept	UNROLL
	ld	r24,X
	eor	r24,r17		// xor 0xff
	sbc	r24,r17		// add 0/1 (subtract -1)
	st	x+,r24
.endr
	dec	r21
	brne	rsa_mul_1024_loop4

// create "sign" xor into r16

	eor	r16,r17
// save sign, to stack, rsa_mul_512_no_abi uses _all_ registers
	std	Y+7,r16	// sign

// multiply |a_low - a_high| * |b_low - b_high| into TMP
	adiw	r28,8		// skip variables on stack to point 128 byt TMP

	movw	r22,RESULT
	movw	r26,RESULT
	subi	r26,lo8(-64)
	sbci	r27,hi8(-64)	//r+64
#endif
	call	rsa_mul_512_no_abi
// load values back 

	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r28,Z+3	// Result
	ldd	r29,Z+4
	ldd	r22,Z+1	// OPERAND_B
	ldd	r23,Z+2
	ldd	r26,Z+5	// OPERAND_A
	ldd	r27,Z+6

// a_low * b_low to r
	call	rsa_mul_512_no_abi

// load values back 
	in	r30, 0x3d
	in	r31, 0x3e
// a_high * b_high to r+128
	ldd	r28,Z+3	// Result
	ldd	r29,Z+4
	subi	r28,lo8(-128)
	sbci	r29,hi8(-128)
	ldd	r22,Z+1	// OPERAND_B
	ldd	r23,Z+2
	subi	r22,lo8(-64)
	sbci	r23,hi8(-64)	//B+64
	ldd	r26,Z+5	// OPERAND_A
	ldd	r27,Z+6
	subi	r26,lo8(-64)
	sbci	r27,hi8(-64)	//A+64
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

	mov	_COUNT,r30
	subi	_COUNT,(-64)
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

	cpse	_COUNT,r30
	rjmp	rsa_mul_1024_xloop1
//rsa_mul_1024_xloop1_end:

// A,B part	 ok, add D
// prevent carry, correct Z to point C
	ror	_CARRY		// save B+C carry
	bst	_CARRY,7	// save B+C carry into T
	subi	r30,lo8(-64)
	sbci	r31,hi8(-64)
/*
     255...192 191...128 127...64 63...0
             Y        Z
middle part is addressed by X
*/
	mov	_COUNT,r30
	subi	_COUNT,(-64)

	rol	_CARRY		// renew B+C carry
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

	cpse	_COUNT,r30
	rjmp	rsa_mul_1024_xloop2
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
	bld	_ACC,0	// renev B+C carry from T
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
#undef RESULT
#undef UNROLL
#undef L1
#undef L2
#undef L3
#undef L4
#undef L5
#undef L6
#undef L7

