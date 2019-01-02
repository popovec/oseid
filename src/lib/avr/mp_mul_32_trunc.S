/*
    mp_mul_32_trunc.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2018 Peter Popovec, popovec.peter@gmail.com

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

    truncated multiplications
*/

/////////////////////////////////////////////////////////////
#include "load_sp.h"

/////////////////////////////////////////////////////////////
.macro  LOAD32_FROM_X  REG3 REG2 REG1 REG0
        ld      \REG0,X+
        ld      \REG1,X+
        ld      \REG2,X+
        ld      \REG3,X+
.endm
.macro  LOAD32_FROM_Y  REG3 REG2 REG1 REG0    M
        ldd     \REG0,Y+0+\M
        ldd     \REG1,Y+1+\M
        ldd     \REG2,Y+2+\M
        ldd     \REG3,Y+3+\M
.endm

.macro  LOAD64_FROM_Y  REG7 REG6 REG5 REG4 REG3 REG2 REG1 REG0    M
        ldd     \REG0,Y+0+\M
        ldd     \REG1,Y+1+\M
        ldd     \REG2,Y+2+\M
        ldd     \REG3,Y+3+\M
        ldd     \REG4,Y+4+\M
        ldd     \REG5,Y+5+\M
        ldd     \REG6,Y+6+\M
        ldd     \REG7,Y+7+\M
.endm

.macro  LOAD32_FROM_Z  REG3 REG2 REG1 REG0    M
        ldd     \REG0,Z+0+\M
        ldd     \REG1,Z+1+\M
        ldd     \REG2,Z+2+\M
        ldd     \REG3,Z+3+\M
.endm
.macro  STORE32_TO_Z  REG3 REG2 REG1 REG0    M
        std     Z+0+\M,\REG0
        std     Z+1+\M,\REG1
        std     Z+2+\M,\REG2
        std     Z+3+\M,\REG3
.endm

.macro  LOAD64_FROM_Z  REG7 REG6 REG5 REG4 REG3 REG2 REG1 REG0    M
        ldd     \REG0,Z+0+\M
        ldd     \REG1,Z+1+\M
        ldd     \REG2,Z+2+\M
        ldd     \REG3,Z+3+\M
        ldd     \REG4,Z+4+\M
        ldd     \REG5,Z+5+\M
        ldd     \REG6,Z+6+\M
        ldd     \REG7,Z+7+\M
.endm
.macro  STORE64_TO_Z  REG7 REG6 REG5 REG4 REG3 REG2 REG1 REG0    M
        std     Z+0+\M,\REG0
        std     Z+1+\M,\REG1
        std     Z+2+\M,\REG2
        std     Z+3+\M,\REG3
        std     Z+4+\M,\REG4
        std     Z+5+\M,\REG5
        std     Z+6+\M,\REG6
        std     Z+7+\M,\REG7
.endm

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

//clear RS7,RS6, ZERO  before call! (73 ticks)
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
.macro	ADC32	RZ3 RZ2 RZ1 RZ0  A3 A2 A1 A0
	adc	\RZ0,\A0
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
.macro ABS32	RZ3 RZ2 RZ1 RZ0  SIGN
	eor	\RZ0,\SIGN
	eor	\RZ1,\SIGN
	eor	\RZ2,\SIGN
	eor	\RZ3,\SIGN
	sub	\RZ0,\SIGN
	sbc	\RZ1,\SIGN
	sbc	\RZ2,\SIGN
	sbc	\RZ3,\SIGN
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

        .global rsa_mul_128_mod_no_abi
        .type   rsa_mul_128_mod_no_abi, @function
	.section .text.rsa_mul_128_mod_no_abi,"ax",@progbits

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
	LOAD32_FROM_X	r5,r4,r3,r2
	LOAD32_FROM_Y	r9,r8,r7,r6	0

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
	LOAD32_FROM_X	A3,A2,A1,A0

#define B0 r30
#define B1 r31 
#define B2 r26
#define B3 r27
	LOAD32_FROM_Y	B3,B2,B1,B0	4
// differences hi-lo, save final sign into T
	SUB32	r5 r4 r3 r2  A3 A2 A1 A0
	sbc	r0,r0
	ABS32	r5 r4 r3 r2  r0

	SUB32	r9 r8 r7 r6  B3 B2 B1 B0
	sbc	r1,r1
	ABS32	r9 r8 r7 r6  r1

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
	adc	RES_BC3, r1
	adc	RES_D0, LL_ZERO

	mul	A0, B3
	add	RES_BC3, r0
	adc	RES_D0, r1
	adc	RES_D1, LL_ZERO

	mul	A1, B2
	add	RES_BC3, r0
	adc	RES_D0, r1
	adc	RES_D1, LL_ZERO

	mul	A2, B1
	add	RES_BC3, r0
	adc	RES_D0, r1
	adc	RES_D1, LL_ZERO

	mul	A3, B0
	add	RES_BC3, r0
	adc	RES_D0, r1
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
	LOAD32_FROM_X	r5,r4,r3,r2
	LOAD32_FROM_Y	r9,r8,r7,r6	8

  	clr	ZERO
	MUL_32x  RS7,RS6,TMP_5,TMP_4,TMP_3,TMP_2,TMP_1,TMP_0   r5,r4,r3,r2   r9,r8,r7,r6   ZERO,r31,r30
// renew carry 
	ror	CARRY_SAVE

	ADC64	RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   ZERO,ZERO,TMP_5,TMP_4,TMP_3,TMP_2,TMP_1,TMP_0

	LOAD32_FROM_Y	TMP_3,TMP_2,TMP_1,TMP_0	12

	MUL_32_MOD_ADDx RS7 RS6 RS5 RS4   r5,r4,r3,r2   TMP_3,TMP_2,TMP_1,TMP_0   ZERO  r31,r30

	LOAD32_FROM_X	r5,r4,r3,r2

	MUL_32_MOD_ADDx RS7 RS6 RS5 RS4   r5,r4,r3,r2   r9,r8,r7,r6   ZERO  r31 r30

	LOAD32_FROM_X	r5,r4,r3,r2
	LOAD32_FROM_Y	r9,r8,r7,r6	0

	MUL_32x  RS7,RS6,TMP_5,TMP_4,TMP_3,TMP_2,TMP_1,TMP_0   r5,r4,r3,r2   r9,r8,r7,r6  ZERO,r31,r30

	ADD64    RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   ZERO,ZERO,TMP_5,TMP_4,TMP_3,TMP_2,TMP_1,TMP_0

	LOAD32_FROM_Y	TMP_3,TMP_2,TMP_1,TMP_0 4

	MUL_32_MOD_ADDx RS7 RS6 RS5 RS4  r5,r4,r3,r2   TMP_3,TMP_2,TMP_1,TMP_0   ZERO  r31 r30

	LOAD32_FROM_X	r5,r4,r3,r2

	MUL_32_MOD_ADDx RS7 RS6 RS5 RS4   r5,r4,r3,r2   r9,r8,r7,r6   ZERO  r31 r30

	in	r30, 0x3d
	in	r31, 0x3e

	// add 64 bit value in registers to variables in memory (addressed by Z)
	//        target =  source +  registers                          tmp
	MEM_ADD64 S_OFF+8   S_OFF+8   RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0     r2
	ret
#undef S_OFF



// multiply only 1st 4 bytes of result, precalculate bytes 4,5
// ZERO, RS2,RS3,RS4 and RS5 must be cleared before .. (47)
.macro MUL_32_8  RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0 A3,A2,A1,A0 ZERO
	mul	\A0,\B0
	movw	\RS0,r0

	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\ZERO

	mul	\A0,\B2
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\ZERO
	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\ZERO
	mul	\A2,\B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\ZERO

	mul	\A0,\B3
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO

	mul	\A2,\B1
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
.endm
// (29)
.macro  MUL_32_8cont RS7,RS6,RS5,RS4   B3,B2,B1,B0 A3,A2,A1,A0  ZERO
	mul	\A1,\B3
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO

	mul	\A2,\B2
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO
	mul	\A3,\B1
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO

	mul	\A2,\B3
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO
	mul	\A3,\B2
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO

	mul	\A3,\B3
	add	\RS6,r0
	adc	\RS7,r1

.endm
//(30)
.macro  MUL_32_8contA RS5,RS4   B3,B2,B1,B0 A3,A2,A1,A0  ZERO2
	mul	\A1,\B3
	movw	\A0,\ZERO2
	add	\RS4,r0
	adc	\RS5,r1
	adc	\A0,\ZERO2

	mul	\A2,\B2
	add	\RS4,r0
	adc	\RS5,r1
	adc	\A0,\ZERO2
	mul	\A3,\B1
	add	\RS4,r0
	adc	\RS5,r1
	adc	\A0,\ZERO2

	mul	\A2,\B3
	add	\RS5,r0
	adc	\A0,r1
	adc	\A1,\ZERO2
	mul	\A3,\B2
	add	\RS5,r0
	adc	\A0,r1
	adc	\A1,\ZERO2

	mul	\A3,\B3
	add	\A0,r0
	adc	\A1,r1
.endm

// mutiply without use of CC registers (79 ticks)
.macro	MUL32_ncc	RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0 B3,B2,B1,B0  A3,A2,A1,A0  ZERO
	mul	\A0,\B0
	movw	\RS0,r0

	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\ZERO

	mul	\A0,\B2
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\ZERO
	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\ZERO
	mul	\A2,\B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\ZERO

	mul	\A0,\B3
	clr	\A0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
	mul	\A2,\B1
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO

	mul	\A1,\B3
	clr	\A1
	add	\RS4,r0
	adc	\RS5,r1
	adc	\A1,\ZERO
	mul	\A2,\B2
	add	\RS4,r0
	adc	\RS5,r1
	adc	\A1,\ZERO
	mul	\A3,\B1
	add	\RS4,r0
	adc	\RS5,r1
	adc	\A1,\ZERO

	mul	\A2,\B3
	clr	\A2
	add	\RS5,r0
	adc	\A1,r1
	adc	\RS7,\ZERO
	mul	\A3,\B2
	add	\RS5,r0
	adc	\A1,r1
	adc	\A2,\ZERO

	mul	\A3,\B3
	add	\A1,r0
	adc	\A2,r1
.endm

.macro ABS64  RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0 SIGN
	eor	\RS0,\SIGN
	eor	\RS1,\SIGN
	eor	\RS2,\SIGN
	eor	\RS3,\SIGN
	eor	\RS4,\SIGN
	eor	\RS5,\SIGN
	eor	\RS6,\SIGN
	eor	\RS7,\SIGN
	sub	\RS0,\SIGN
	sbc	\RS1,\SIGN
	sbc	\RS2,\SIGN
	sbc	\RS3,\SIGN
	sbc	\RS4,\SIGN
	sbc	\RS5,\SIGN
	sbc	\RS6,\SIGN
	sbc	\RS7,\SIGN
.endm


.macro SBC64	RZ7 RZ6 RZ5 RZ4 RZ3 RZ2 RZ1 RZ0  A7 A6 A5 A4 A3 A2 A1 A0
	sbc	\RZ0,\A0
	sbc	\RZ1,\A1
	sbc	\RZ2,\A2
	sbc	\RZ3,\A3
	sbc	\RZ4,\A4
	sbc	\RZ5,\A5
	sbc	\RZ6,\A6
	sbc	\RZ7,\A7
.endm
//(49)
.macro  MUL32_ADD_n  RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0   A1,A0  ZERO
	mul	\A0,\B0
	add	\RS0,r0
	adc	\RS1,r1
	adc	\RS2,\ZERO
	adc	\RS7,\ZERO

	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS7,\ZERO
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\RS7
	adc	\RS4,\ZERO

	ld	\RS7,X+

	mul	\A0,\B2
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\ZERO
	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\ZERO

	mul	\RS7,\B0	//A2,B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\ZERO

	mul	\A0,\B3
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
	mul	\RS7,\B1	//A2,B1
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
.endm
//(34)
.macro  MUL32_ADD_cont_n  RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0   A1,A3  ZERO
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO

	mul	\A1,\B3
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO
	mul	\RS7,\B2	//A2,B2
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO
	mul	\A3,\B1		//A3,B1
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO

	mul	\RS7,\B3
	clr	\RS7
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO
	mul	\A3,\B2
	add	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO

	mul	\A3,\B3
	add	\RS6,r0
	adc	\RS7,r1
.endm
.macro MUL32_ADD_xx  RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0   A1,A0  ZERO
	mul	\A0,\B0
	add	\RS0,r0
	adc	\RS1,r1
	adc	\RS2,\ZERO
	adc	\RS7,\ZERO

	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS7,\ZERO
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\RS7
	adc	\RS4,\ZERO

	ld	\RS7,X+
	mul	\A0,\B2
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\ZERO
	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\ZERO
	mul	\RS7,\B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\ZERO

	mul	\A0,\B3
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
	mul	\RS7,\B1
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
.endm
//  RS6 must be cleared before call
//  A3 = RS7
//  A1 is cleared at end
.macro  MUL32_ADD_cont_BB RS6,RS5,RS4,RS3   B3,B2,B1,B0  A3 A2 A1
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\RS6

	mul	\A1,\B3
	clr	\A1
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\A1
	mul	\A2,\B2
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\A1
	mul	\A3,\B1
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\A1

	mul	\A2,\B3
	clr	\A2
	add	\RS5,r0
	adc	\RS6,r1
	adc	\A2,\A1
	mul	\A3,\B2
	add	\RS5,r0
	adc	\RS6,r1
	adc	\A2,\A1

	mul	\A3,\B3
	add	\RS6,r0
	adc	\A2,r1
.endm

        .global rsa_mul_256_mod_no_abi
        .type   rsa_mul_256_mod_no_abi, @function
	.section .text.rsa_mul_256_mod_no_abi,"ax",@progbits

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
#define R_OFF 9+4+1
#elif __AVR_2_BYTE_PC__ == 1
//atmega
#define R_OFF 9+4
#else
#error unknown PC size
#endif
//// from this line to line 1770 .. is multiplication  128*128 bits  this
//// can be optimized because stack pointer point to result, Z reg is free
///////////////////////////////////////////////////  rsa_mul_128_no_abi START
  ; init zero registers

	clr	r20
	clr	r21
	movw	r16,r20	//ZERO

  ;--- level 2: compute L ---
	LOAD32_FROM_X	r5,r4,r3,r2
	LOAD32_FROM_Y	r9,r8,r7,r6	0

//              result                             A                B    zero CC1 CC0
	MUL_32  r17,r16,r15,r14,r13,r12,r11,r10  r5,r4,r3,r2  r9,r8,r7,r6 r21 r19,r18

	STORE32_TO_Z	r13,r12,r11,r10	R_OFF+0
  
  ;--- load a4..a7 and b4..b7 ---
	movw	r10,r20	// ZERO
	movw    r12,r20	// ZERO

  LD r18, X+
  LD r19, X+
  ; rest is loaded later
	LOAD32_FROM_Y	r25,r24,r23,r22	4
  ;--- level 2: compute H + (l3,l4,l5) ---
// upper bytes of operand A are readed from X+!
	MUL32_ADD_n 	r13,r12,r11,r10,r17,r16,r15,r14  r25,r24,r23,r22  r19,r18   r21

;--- subtract a0-a4 ---
  SUB r2, r18
  SBC r3, r19
  SBC r4, r13
  ; load a7 to r18
  LD r18, X+
  SBC r5, r18
	sbc	r0,r0	// carry to r0 (0x00/0xff)

  ;--- subtract b0-b4 ---
	SUB32	r9,r8,r7,r6	r25,r24,r23,r22
	sbc	r1,r1	// carry to r1 (0x00/0xff)

        ABS32   r5,r4,r3,r2  r0
        ABS32   r9,r8,r7,r6  r1
	eor	r0,r1
	bst	r0,0

	MUL32_ADD_cont_n  r13,r12,r11,r10,r17,r16,r15,r14  r25,r24,r23,r22  r19,r18   r21
  ;--- continue ---

  ;--- level 2: compute M ---
// r4,r3,r19,r18,r25,r24,r23,r22    r9,r8,r7,r6    r5,r4,r3,r2
        movw    r24,r20	// ZERO
        movw    r18,r20	// ZERO

// multiply only 1st 4 bytes of result, precalculate bytes 4,5
        MUL_32_8   /* r3 r2 */r19,r18,r25,r24,r23,r22   r9,r8,r7,r6  r5,r4,r3,r2 r20
// continue,  r20,r21 is zero!
        MUL_32_8contA /*r3,r2, */ r19,r18     r9,r8,r7,r6  r5,r4,r3,r2  r20

// middle part in
// r3,r2,r19,r18,r25,r24,r23,r22

  ;--- add l4+h0 to l0 and h4 ---
	LOAD32_FROM_Z	r1,r0,r7,r6	R_OFF+0

	movw	r4,r20	// ZERO

	ADD64	r17,r16,r15,r14,r1,r0,r7,r6  r13,r12,r11,r10,r17,r16,r15,r14
	adc	r5,r5	// carry/borrow to r4,r5
  
	brtc	sub_M_L
add_M_L: 
	ADD64   r17,r16,r15,r14,r1,r0,r7,r6     r3,r2,r19,r18,r25,r24,r23,r22
	adc	r5,r4	// carry/borrow to r4,r5
	RJMP final_L
sub_M_L:
	SUB64   r17,r16,r15,r14,r1,r0,r7,r6     r3,r2,r19,r18,r25,r24,r23,r22
	sbc	r5,r4	// carry/borrow to r4,r5
	sbc	r4,r4

final_L:
	STORE32_TO_Z    r1,r0,r7,r6 R_OFF+4

  ;--- propagate carry to end ---
	ADD32	r13,r12,r11,r10  r4,r4,r4,r5

  ; h8...h15 stored in 22,23,24,25,18,21,19,20

  ;------ level 1: compute H ------

  ; init zero registers
	movw	r22,r20	// ZERO
	movw	r24,r20	// ZERO
  ;--- level 2: compute L ---
	LOAD32_FROM_X	r5,r4,r3,r2
	LOAD32_FROM_Y   r9,r8,r7,r6     8

	MUL_32_8 /*r,r*/ r23,r22,r25,r24,r19,r18   r9,r8,r7,r6  r5,r4,r3,r2 r20
  ; now add h0+l8 and h0+l12
	ADD64	r25,r24,r19,r18, r17,r16,r15,r14   r13,r12,r11,r10, r25,r24,r19,r18

	STORE32_TO_Z	r17,r16,r15,r14	R_OFF+16

// preload operand b4..b7
	LOAD32_FROM_Y	r13,r12,r31,r30	12
#ifdef RAM_LE32
  ; store carry in bit 15 of RAM pointer
  ROL r29
#else
  ; store carry on stack
  SBC r0, r0
  PUSH r0
#endif
	movw	r16,r20	// ZERO
  ; continue
	MUL_32_8cont r17,r16,r23,r22   r9,r8,r7,r6  r5,r4,r3,r2  r21
/////////////////////////////////////////////////////////////////////////////////////////////////////

  ;--- load a4..a5  a6..a7 load later in macro..
	movw	r14,r20	// ZERO
  LD r10, X+
  LD r11, X+
  ;--- level 2: compute H + (l3,l4,l5) ---

	MUL32_ADD_xx r20,r11,r15,r14,r17,r16,r23,r22  r13,r12,r31,r30    r11,r10  r21
  ;--- subtract a0-a4 ---
  SUB r2, r10
  SBC r3, r11
// r20 is loaded in MUL32_ADD_xx
  SBC r4, r20
  ; load a7 to r18

  LD r10, X+
  SBC r5, r10
	sbc	r0,r0	// carry to r0 (0x00/0xff)
  ;--- subtract b0-b4 ---
	SUB32	r9,r8,r7,r6  r13,r12,r31,r30  
  ; 0xff if carry and 0x00 if no carry
	sbc	r1,r1	// carry to r1 (0x00/0xff)

	ABS32   r5,r4,r3,r2  r0
	ABS32   r9,r8,r7,r6  r1
	eor	r0,r1
	bst	r0, 0

  ;--- continue ---
// clear RS6 before MUL32_ADD_cont_BB!
//                   RS7   RS6 ....... RS3         B          A3   A2  A1
  MUL32_ADD_cont_BB /*A2*/ r21,r15,r14,r17   r13,r12,r31,r30  r10 r20 r11
// A1 = r11 is zero
  ;--- level 2: compute M ---
	clr	r10
	movw	r12,r10	// ZERO
	MUL32_ncc	r4,r3,r2,r10,r13,r12,r31,r30  r9,r8,r7,r6  r5,r4,r3,r2  r11
  ;--- add l4+h0 to l0 and h4 ---
	ADD64   r17,r16,r23,r22,r25,r24,r19,r18  r20,r21,r15,r14,r17,r16,r23,r22
 	adc	r11, r11	// carry to r11

  ;--- propagate carry ---  
// load carry ..
#ifdef RAM_LE32
  LSR r29
#else
  POP r0
  LSR r0
#endif
  CLR r0
	ADC32	r17,r16,r23,r22   r0 r0 r0 r0	  
  ; update carry in r11
  ADC r11, r0

  ;--- process sign bit ---  
  BRTc sub_M_H

	ADD64	r17,r16,r23,r22,r25,r24,r19,r18 r4,r3,r2,r10,r13,r12,r31,r30
  ADC r11, r0
  RJMP final_H
sub_M_H:
  ; subtract M
	SUB64	r17,r16,r23,r22,r25,r24,r19,r18 r4,r3,r2,r10,r13,r12,r31,r30
  SBC r11, r0
  SBC r0, r0

final_H:
	in	r30, 0x3d
	in	r31, 0x3e
	STORE64_TO_Z	r17,r16,r23,r22,r25,r24,r19,r18  R_OFF+20

  ;--- propagate carry to end ---
	ADD32	r20,r21,r15,r14   r0 r0 r0 r11
	STORE32_TO_Z	r20,r21,r15,r14	R_OFF+28  

////////////////////////////////////////////////////////////////////////////////////////////////
  ;------ level 1: subtract a0-a7 ------
  	sbiw	r26,16

	LOAD32_FROM_X	r5,r4,r3,r2
	LOAD32_FROM_X	r21,r20,r30,r18
	LOAD32_FROM_X	r13,r12,r11,r10
	LOAD32_FROM_X	r17,r16,r15,r14

	SUB64 r21,r20,r30,r18,r5,r4,r3,r2  r17,r16,r15,r14,r13,r12,r11,r10
	sbc	 r0,r0	// carry to r0 (0x00/0xff)

	LOAD64_FROM_Y	r19,r24,r23,r22,r9,r8,r7,r6	0
	LOAD64_FROM_Y	r17,r16,r15,r14,r13,r12,r11,r10	8

	SUB64	r19,r24,r23,r22,r9,r8,r7,r6  r17,r16,r15,r14,r13,r12,r11,r10
	sbc r1,r1	// carry to r1 (0x00/0xff)
    
  ;------ level 1: absolute values ------
	ABS64   r21,r20,r30,r18,r5,r4,r3,r2  r0
	ABS64   r19,r24,r23,r22,r9,r8,r7,r6  r1
	eor	r0,r1
#ifdef RAM_LE32
	lsr	r0
	rol	r31
#else
	push	r0
#endif
	clr 	r27
	clr	r26
  ;------ level 1: compute M ------
	movw	r16, r26	//ZERO
//             result                             A                B    zero    CC1 CC0
	MUL_32  r17,r16,r15,r14,r13,r12,r11,r10  r5,r4,r3,r2  r9,r8,r7,r6  r26  r29,r28

	SUB32	r5,r4,r3,r2  r21,r20,r30,r18
	sbc	r0,r0	// carry to r0 (0x00/0xff)
  
	SUB32	r9,r8,r7,r6   r19,r24,r23,r22
	sbc	r1,r1	// carry to r1 (0x00/0xff)

	ABS32   r5,r4,r3,r2  r0
	ABS32   r9,r8,r7,r6  r1
	eor	r0,r1
	bst	r0,0
//    result                             B               A
// r19 r18 r27 r26 r17,r16,r15,r14    r19,r24,r23,r22  r21,r20,r30,r18
  ;--- level 2: compute H + (l3,l4,l5) ---
  CLR r25		// 1

  MUL r18, r24 ;a0*b2
  MOVW r28, r0
  MUL r18, r22 ;a0*b0
  ADD r14, r0
  ADC r15, r1
  ADC r16, r28
  ADC r29, r26
  MUL r18, r23 ;a0*b1
  ADD r15, r0
  ADC r16, r1
  ADC r29, r26
  MUL r30, r19 ;a1*b3
  ADD r17, r29
  ADC r26, r0
  ADC r27, r1			//19

  MUL r18, r19 ;a0*b3
  MOVW r28, r0
  MUL r30, r22 ;a1*b0
  ADD r15, r0
  ADC r16, r1
  ADC r17, r28
  CLR r18
  ADC r29, r18	// ZERO
  MUL r30, r23 ;a1*b1
  ADD r16, r0
  ADC r17, r1
  ADC r29, r18	// ZERO
  MUL r20, r19 ;a2*b3
  ADD r26, r29
  ADC r27, r0
  ADC r18, r1			//20

  MUL r20, r24 ;a2*b2
  MOVW r28, r0
  MUL r20, r22 ;a2*b0
  ADD r16, r0
  ADC r17, r1
  ADC r26, r28
  ADC r29, r25	// ZERO
  MUL r30, r24 ;a1*b2
  ADD r17, r0
  ADC r26, r1
  ADC r29, r25		// ZERO
  MUL r21, r19 ;a3*b3
  ADD r27, r29
  ADC r18, r0
  CLR r19
  ADC r19, r1			//20
  
  MUL r21, r23 ;a3*b1
  MOVW r28,r0
  MUL r20, r23 ;a2*b1
  ADD r17, r0
  ADC r28, r1
  ADC r29, r25		// ZERO
  MUL r21, r22 ;a3*b0
  ADD r17, r0
  ADC r28, r1
  ADC r29, r25
  MUL r21, r24 ;a3*b2
  ADD r26, r28
  ADC r0, r29
  ADC r1, r25
  ADD r27, r0
  ADC r18, r1
  ADC r19, r25			//21

  ;--- level 2: compute M ---
//  do not touch    r19 r18 r27 r26       r17,r16,r15,r14,r13,r12,r11,r10
//  free r28,r29
//  result                                   operands
//  r9,r25,r30,r24,r23,r22,r21,r20    r9 r8 r7 r6    r5 r4 r3 r2
// (77)
  MUL r2, r8 ;a0*b2
  MOVW r22, r0
  MUL r2, r6 ;a0*b0
  MOVW r20, r0
  MUL r2, r7 ;a0*b1
  ADD r21, r0
  ADC r22, r1
  ADC r23, r25
  MUL r3, r9 ;a1*b3
  MOV r24, r0
  MOV r30, r1

  MUL r2, r9 ;a0*b3
	clr	r2	// ZERO
  MOVW r28, r0
  MUL r3, r6 ;a1*b0
  ADD r21, r0
  ADC r22, r1
  ADC r23, r28
  ADC r29, r2		// ZERO		
  MUL r3, r7 ;a1*b1
  ADD r22, r0
  ADC r23, r1
  ADC r29, r2		// ZERO
  MUL r4, r9 ;a2*b3
  ADD r24, r29
  ADC r30, r0
  ADC r25, r1

  MUL r4, r8 ;a2*b2
  MOVW r28, r0
  MUL r4, r6 ;a2*b0
  ADD r22, r0
  ADC r23, r1
  ADC r24, r28
  ADC r29, r2		// ZERO
  MUL r3, r8 ;a1*b2
  ADD r23, r0
  ADC r24, r1
  ADC r29, r2		// ZERO
  MUL r5, r9 ;a3*b3
  ADD r30, r29
  ADC r25, r0
  CLR r9
  ADC r9, r1

  MUL r5, r7 ;a3*b1
  MOVW r28, r0
  MUL r4, r7 ;a2*b1
  ADD r23, r0
  ADC r28, r1
  ADC r29, r2		// ZERO
  MUL r5, r6 ;a3*b0
  ADD r23, r0
  ADC r28, r1
  ADC r29, r2		// ZERO
  MUL r5, r8 ;a3*b2
  ADD r24, r28
  ADC r0, r29
  ADC r1, r2		// ZERO
  ADD r0, r30
  ADC r25, r1
  ADC r9, r2		// ZERO
// r2 = ZERO
  ;--- add l4+h0 to l0 and h4 ---
  MOVW r4, r10
  MOVW r6, r12
	ADD64	r17,r16,r15,r14,r13,r12,r11,r10      r19,r18,r27,r26,r17,r16,r15,r14

  ; store carry in r3 (r2=0)
  	clr	r3
	movw	r28,r2	// copy ZERO, clear r28,r29
  	adc 	r3, r3
  
  ;--- process sign bit ---
	brtc	sub_M_M

	ADD64	r17,r16,r15,r14,r13,r12,r11,r10  r9,r25,r0,r24,r23,r22,r21,r20
	adc	r3,r2
	rjmp	final_M
sub_M_M:
  ;subtract M
	SUB64	r17,r16,r15,r14,r13,r12,r11,r10  r9,r25,r0,r24,r23,r22,r21,r20
	sbc r3, r2
	sbc r2, r2
final_M:
  ;--- propagate carry to end ---
	ADD32	r19,r18,r27,r26  r2,r2,r2,r3
  
  ;------ level 1: combine L, H, and M ------

  ;--- process sign bit ---
#ifdef RAM_LE32
	lsr	r31
#else
	pop	r1
	lsr	r1    // test bit0
#endif
	in      r30, 0x3d
	LOAD64_FROM_Z	r9,r8,r25,r24,r23,r22,r21,r20	R_OFF+0

  	ldd	r2, Z+R_OFF+16
	ldd	r3, Z+R_OFF+17
	ldd	r1, Z+R_OFF+18
	
	brcc sub_M

add_M: 
	ADD64   r9,r8,r25,r24,r23,r22,r21,r20 r13,r12,r11,r10,r7,r6,r5,r4
	rol	r0	// carry to r0
	
	LOAD32_FROM_Z	r10,r7,r6,r5	R_OFF+19
	ldd		r11, 		Z+R_OFF+23

	ADD64	r9,r8,r25,r24,r23,r22,r21,r20	r11,r10,r7,r6,r5,r1,r3,r2
	ror	r0	// carry to r0 bit 7, renew old carry

	ADC64	r11,r10,r7,r6,r5,r1,r3,r2   r19,r18,r27,r26,r17,r16,r15,r14
 	adc	r28, r28 // (r29 is cleared above)
  	rjmp	final

sub_M:
  ;subtract M
	SUB64	r9,r8,r25,r24,r23,r22,r21,r20  r13,r12,r11,r10,r7,r6,r5,r4
	rol	r0	//borrow to r0

	LOAD32_FROM_Z	r10,r7,r6,r5	R_OFF+19
	ldd		r11, 		Z+R_OFF+23

	ADD64	r9,r8,r25,r24,r23,r22,r21,r20	r11,r10,r7,r6,r5,r1,r3,r2
	ror	r0	// carry to r0, bit 7, renew borrow

	SBC64   r11,r10,r7,r6,r5,r1,r3,r2  r19,r18,r27,r26,r17,r16,r15,r14
	sbc	r28,r28
 	sbc	r29,r29
  
final:
	STORE64_TO_Z	r9,r8,r25,r24,r23,r22,r21,r20	R_OFF+8

	LOAD64_FROM_Z	r13,r12,r21,r20,r9,r8,r27,r26	R_OFF+24
  	rol	r0
	ADC64		r11,r10,r7,r6,r5,r1,r3,r2	r13,r12,r21,r20,r9,r8,r27,r26
	STORE64_TO_Z	r11,r10,r7,r6,r5,r1,r3,r2	R_OFF+16

  ;--- propagate carry to end ---
	ADC64		r13,r12,r21,r20,r9,r8,r27,r26 	r29,r29,r29,r29,r29,r29,r29,r28

	STORE64_TO_Z	r13,r12,r21,r20,r9,r8,r27,r26	R_OFF+24
#undef R_OFF
///////////////////////////////////////////////////////   rsa_mul_128_no_abi STOP
// load pointers
	pop	r28
	pop	r29
	pop	r26
	pop	r27
	adiw	r28,16	// upper part
	rcall    rsa_mul_128_mod_no_abi

	sbiw	r28,16 // lower part, X is incremented in rsa_mul_128_mod_no_abi

// do not replace this by jmp/rjmp, SP is used as pointer to result ( but this
// fail if -mrelax and -Wl,--relax is used for compiler/linker, use this
// with -Wl,--no-call-ret-replacement, or uncomment "nop" instruction in
// next code)
	rcall    rsa_mul_128_mod_no_abi
//	nop
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

        .global rsa_mul_512_mod_no_abi
        .type   rsa_mul_512_mod_no_abi, @function
	.section .text.rsa_mul_512_mod_no_abi,"ax",@progbits

rsa_mul_512_mod_no_abi:

// create space on stack - 64 bytes TMP variable, 3x pointer
	in	r28, 0x3d
	in	r29, 0x3e
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

//	clc			// r31:r30 + 7 is always below 64kB - carry is cleared
	ldi	r24,4
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
	ret


        .global rsa_mul_512_mod
        .type   rsa_mul_512_mod, @function
	.section .text.rsa_mul_512_mod,"ax",@progbits

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
	rcall	rsa_mul_512_mod_no_abi

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


        .global rsa_mul_1024_mod
        .type   rsa_mul_1024_mod, @function
	.section .text.rsa_mul_1024_mod,"ax",@progbits


rsa_mul_1024_mod:
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

	movw	r28,r24
	movw	r26,r20
	
// create space on stack - 64 bytes TMP variable, 3x pointer
	in	r30, 0x3d
	in	r31, 0x3e
	subi	r30,lo8(64+2+2+2)
	sbci	r31,hi8(64+2+2+2)
	LOAD_SP r0, r30,r31

// save  pointers to stack
	std	Z+1,r22	// A pointer
	std	Z+2,r23
	std	Z+3,r28	// Result
	std	Z+4,r29
	std	Z+5,r26	// B pointer
	std	Z+6,r27

	call	rsa_mul_512_no_abi		//

// load values back
	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r22,Z+1	// OPERAND_A
	ldd	r23,Z+2
	ldd	r26,Z+5	// OPERAND_B
	ldd	r27,Z+6

	rcall	rsa_mul_helper_1024
// load values back 
	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r22,Z+5	// OPERAND_B
	ldd	r23,Z+6
	ldd	r26,Z+1	// OPERAND_A
	ldd	r27,Z+2

	rcall	rsa_mul_helper_1024

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

#if __AVR_3_BYTE_PC__ == 1
//xmega
#define S_OFF 3
#elif __AVR_2_BYTE_PC__ == 1
//atmega
#define S_OFF 2
#else
#error unknown PC size
#endif


rsa_mul_helper_1024:
	subi	r22,lo8(-64)	// upper part
	sbci	r23,hi8(-64)
	adiw	r30,7	// temp result

	rcall 	rsa_mul_512_mod_no_abi

// load values back
	in	r30, 0x3d
	in	r31, 0x3e
	ldi	r24,64		// count

rsa_mul_helper:
	ldd	r28,Z+3+S_OFF	// result
	ldd	r29,Z+4+S_OFF
// move pointer to upper part of number
	add	r28,r24
	adc	r29,r1
// calculate end position of number into r24
	add	r24,r28
// tmp number (to be add)
	adiw	r30,7+S_OFF
	sub	r1,r1
rsa_mul_helper_loop:
.rept	16
	ld	r0,Y
	ld	r25,Z+
	adc	r25,r0
	st	Y+,r25
.endr
	cpse	r24,r28
	rjmp	rsa_mul_helper_loop

	ret
#undef S_OFF
