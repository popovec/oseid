/*
    mp_mul_32_trunc.S

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

//clear RS7,RS6, ZERO  before call!
.macro MUL_32	RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0   A3 A2 A1 A0   B3 B2 B1 B0  ZERO CC1 CC0
//73
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
// RS6 is initial ZERO,  CC1,A0 = 16 bit register, at end A1 is new zero
.macro	MUL32_MP	/*B3*/ RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0  A3,A2,A1,A0  CC1
// 76
	mul	\A0,\B2
	movw	\RS2,r0
	mul	\A0,\B0
	movw	\RS0,r0
	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\RS6	// ZERO
	mul	\A1,\B3
	movw	\RS4,r0

	mul	\A0,\B3
// A0,CC1 free, use CC1,A0 as CC
	movw	\A0,r0
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\A0
	adc	\CC1,\RS6	// CC1 + ZERO
	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\CC1,\RS6	// CC1 + ZERO
	mul	\A2,\B3
	add	\RS4,\CC1	// RS4 + CC1
	adc	\RS5,r0
	adc	\RS6,r1

	mul	\A2,\B2
	movw	\A0,r0		// CC1,0
	mul	\A2,\B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\A0	// CC0
	clr	\A0
	adc	\CC1,\A0		// CC1 + ZERO
	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\CC1,\A0		// CC1 + ZERO

	mul	\A3,\B3
	add	\RS5,\CC1	// CC1
	adc	\RS6,r0
	clr	\B3
	adc	\B3,r1

	mul	\A3,\B1
	movw	\A0,r0		// CC1,0
	mul	\A2,\B1
	add	\RS3,r0
	adc	\RS4,r1
	clr	\A1
	adc	\CC1,\A1	// CC1 + ZERO

	mul	\A3,\B0
	add	\RS3,r0
	adc	\A0,r1
	adc	\CC1,\A1	// ZERO
	mul	\A3,\B2
	add	\RS4,\A0
	adc	r0,\CC1
	adc	r1,\A1		// ZERO
	add	\RS5,r0		// RS5
	adc	\RS6,r1
	adc	\B3,\A1	// ZERO
.endm


// RS6 is initial ZERO,  CC1,A0 = 16 bit register
// RS5,4 - pair RS3,2 pair, RS1,0 pair
.macro	MUL32_MPxx	/*A1*/ RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0  A3,A2,A1,A0  CC1
// 76
	mul	\A0,\B2
	movw	\RS2,r0
	mul	\A0,\B0
	movw	\RS0,r0
	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\RS6	// ZERO
	mul	\A1,\B3
	movw	\RS4,r0

	mul	\A0,\B3
// A0,CC1 free, use CC1,A0 as CC
	movw	\A0,r0
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\A0
	adc	\CC1,\RS6	// CC1 + ZERO
	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\CC1,\RS6	// CC1 + ZERO
	mul	\A2,\B3
	add	\RS4,\CC1	// RS4 + CC1
	adc	\RS5,r0
	adc	\RS6,r1

	mul	\A2,\B2
	movw	\A0,r0		// CC1,0
	mul	\A2,\B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\A0	// CC0
	clr	\A0
	adc	\CC1,\A0		// CC1 + ZERO
	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\CC1,\A0		// CC1 + ZERO

	mul	\A3,\B3
	add	\RS5,\CC1	// CC1
	adc	\RS6,r0
	clr	\A1
	adc	\A1,r1

	mul	\A3,\B1
	movw	\A0,r0		// CC1,0
	mul	\A2,\B1
	add	\RS3,r0
	adc	\RS4,r1
	clr	\B3
	adc	\CC1,\B3	// CC1 + ZERO

	mul	\A3,\B0
	add	\RS3,r0
	adc	\A0,r1
	adc	\CC1,\B3	// ZERO
	mul	\A3,\B2
	add	\RS4,\A0
	adc	r0,\CC1
	adc	r1,\B3		// ZERO
	add	\RS5,r0		// RS5
	adc	\RS6,r1
	adc	\A1,\B3	// ZERO
.endm
// add multiplication result to RS7..RS0 and add bit 1 from CC to result.. 
.macro	MUL32_FULL_ADC	RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0  B3,B2,B1,B0 A3,A2,A1,A0 ZERO TMP3 TMP2 TMP1 TMP0
//82
	rol	\TMP2
	mul	\A0,\B2
	movw	\TMP0,r0

	mul	\A0,\B0
	ror	\TMP2
	adc	\RS0,r0
	adc	\RS1,r1
	adc	\RS2,\TMP0
	adc	\TMP1,\ZERO
// FF 01FE01
	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\TMP1,\ZERO
// FF FFFF01
	mul	\A3,\B3
	movw	\TMP2,r0

	mul	\A1,\B3
	add	\RS3,\TMP1
	adc	\RS4,r0
	adc	\RS5,r1	
	adc	\RS6,\TMP2
	adc	\RS7,\TMP3
// no carry
	mul	\A0,\B3
	movw	\TMP0,r0
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\TMP0
	adc	\TMP1,\ZERO

	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\TMP1,\ZERO

	mul	\A2,\B3
	add	\RS4,\TMP1
	adc	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO
// no carry
	mul	\A3,\B1
	movw	\TMP0,r0

	mul	\A2,\B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\TMP0
	adc	\TMP1,\ZERO
	
	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\TMP1,\ZERO
//TMP1 need to be added..
	mul	\A3,\B2
	movw	\TMP2,r0

	mul	\A2,\B1
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\TMP2
	adc	\TMP3,\ZERO
//TMP3 need to be added..
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\TMP1
	adc	\RS6,\TMP3
	adc	\RS7,\ZERO

	mul	\A2,\B2
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO
	adc	\RS7,\ZERO
.endm
// add multiplication result to RS7..RS0 
.macro	MUL32_FULL_ADD RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0  B3,B2,B1,B0 A3,A2,A1,A0 ZERO TMP3 TMP2 TMP1 TMP0
//80
	mul	\A0,\B2
	movw	\TMP0,r0

	mul	\A0,\B0
	add	\RS0,r0
	adc	\RS1,r1
	adc	\RS2,\TMP0
	adc	\TMP1,\ZERO
// FF 01FE00
	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\TMP1,\ZERO
// FF FFFF00
	mul	\A3,\B3
	movw	\TMP2,r0

	mul	\A1,\B3
	add	\RS3,\TMP1
	adc	\RS4,r0
	adc	\RS5,r1	
	adc	\RS6,\TMP2
	adc	\RS7,\TMP3
// no carry
	mul	\A0,\B3
	movw	\TMP0,r0
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\TMP0
	adc	\TMP1,\ZERO

	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\TMP1,\ZERO

	mul	\A2,\B3
	add	\RS4,\TMP1
	adc	\RS5,r0
	adc	\RS6,r1
	adc	\RS7,\ZERO
//no carry
	mul	\A3,\B1
	movw	\TMP0,r0

	mul	\A2,\B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\TMP0
	adc	\TMP1,\ZERO
	
	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\TMP1,\ZERO
//TMP1 need to be added..
	mul	\A3,\B2
	movw	\TMP2,r0

	mul	\A2,\B1
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\TMP2
	adc	\TMP3,\ZERO
//TMP3 need to be added..
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\TMP1
	adc	\RS6,\TMP3
	adc	\RS7,\ZERO

	mul	\A2,\B2
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\ZERO
	adc	\RS7,\ZERO
.endm


        .global rsa_mul_128_mod_no_abi
        .type   rsa_mul_128_mod_no_abi, @function
	.section .text.rsa_mul_128_mod_no_abi,"ax",@progbits
//  798 cycles  inclusive ret, r17,r18 must be cleared before call!
rsa_mul_128_mod_no_abi:
#if __AVR_3_BYTE_PC__ == 1
//xmega
#define S_OFF 16+9+4
#elif __AVR_2_BYTE_PC__ == 1
//atmega
#define S_OFF 16+9+2
#else
#error unknown PC size
#endif

// MUL_32 need zero in upper two bytes of result
	movw	r16,r18

	push	r26
	push	r27

	LOAD32_FROM_X	r5,r4,r21,r2
	LOAD32_FROM_Y	r9,r8,r7,r6	0

// calculate A,B from low parts of operands
//              result                              A                B       zero  CC1 CC0
	MUL_32	r19,r18,r15,r14,r13,r12,r25,r24  r5,r4,r21,r2   r9,r8,r7,r6    r16  r11,r10
// load zero for mult. result...
	movw	r10,r16

// calculate differences high - low
	LOAD32_FROM_X	r23,r22,r3,r20
	LOAD32_FROM_Y	r27,r26,r31,r30	4
// differences hi-lo, save final sign into T
	SUB32	r5,r4,r21,r2  r23,r22 r3,r20
	sbc	r0,r0
	ABS32	r5 r4 r21 r2  r0

	SUB32	r9,r8,r7,r6  r27,r26,r31,r30
	sbc	r1,r1
	ABS32	r9,r8,r7,r6  r1

	eor	r0,r1
	bst	r0,0
// prevent r9 r8 r7 r6 r5 r4 r21 r2 !!!
// mul add r23,r22,r3,r20  r27,r26,r31,r30

//                        D            B+C                         A
// final result   r17 r16 r11 r10  r19 r18 r15 r14    r13 r12 r25 r24
// calculate D,B+C from high parts of operand
	mul	r20, r30	// B0 A0
	add	r14, r0
	adc	r15, r1
	adc	r18, r16	// ZERO
	adc	r17, r16  	// ZERO	// reuse r17 as Carry catcher

	mul	r20, r31	// B0 A1
	add	r15, r0
	adc	r18, r1
	adc	r17, r16	// ZERO

	mul	r3, r30		// B1 A0
	add	r15, r0
	adc	r18, r1
	adc	r19, r17
	adc	r10, r16	// ZERO

	mul	r20, r26
	add	r18, r0
	adc	r19, r1
	adc	r10, r16	// ZERO

	mul	r3, r31
	add	r18, r0
	adc	r19, r1
	adc	r10, r16	// ZERO

	mul	r22, r30
	add	r18, r0
	adc	r19, r1
	adc	r10, r16	// ZERO

	mul	r20, r27
	add	r19, r0
	adc	r10, r1
	adc	r11, r16	// ZERO

	mul	r3, r26
	add	r19, r0
	adc	r10, r1
	adc	r11, r16	// ZERO

	mul	r22, r31
	add	r19, r0
	adc	r10, r1
	adc	r11, r16	// ZERO

	mul	r23, r30
	add	r19, r0
	adc	r10, r1
	adc	r11, r16	// ZERO

	mul	r3, r27
	add	r10, r0
	adc	r11, r1
	adc	r16, r16

	clr	r20

	mul	r22, r26
	add	r10, r0
	adc	r11, r1
	adc	r16, r20	// ZERO

	mul	r23, r31
	add	r10, r0
	adc	r11, r1
	adc	r16, r20	// ZERO

	clr	r17
	mul	r22, r27
	add	r11, r0
	adc	r16, r1
	adc	r17, r20	// ZERO

	mul	r23, r26
	add	r11, r0
	adc	r16, r1
	adc	r17, r20	// ZERO

	mul	r23, r27
	add	r16, r0
	adc	r17, r1

// middle part (prevent result D, BC, A)
//        result(15..12) sum (11..8 + 7..4)  result (3..0)
//       r17 r16 r11 r10  r19 r18 r15 r14  r13 r12 r25 r24
//
// middle part operands - multiply  r9,r8,r7,r6  by  r5,r4,r21,r2
// r20 zero
	MUL32_MP	/*r9*/r20,r27,r26,r31,r30,r23,r22  r9,r8,r7,r6  r5,r4,r21,r2 r3
// r21 = zero

	// B+C copy
	movw	r6,r18
	movw	r2,r14

	// sign from (BH-BL)*(AH-AL)
	brts	add_M_L_mod

sub_M_L_mod:
	SUB64  r7,r6,r3,r2,r19,r18,r15,r14   r9,r20,r27,r26,r31,r30,r23,r22
	// prepare -1, 0, 1  for carry propagation
	sbci	r21,0
	rjmp	final_L_mod
add_M_L_mod:
	ADD64  r7,r6,r3,r2,r19,r18,r15,r14    r9,r20,r27,r26,r31,r30,r23,r22
	// prepare 0,1, 2 for carry propagation
	clr	r20
	adc	r21,r20
final_L_mod:
	sbc	r20,r20
        
	ADD64	r7,r6,r3,r2,r19,r18,r15,r14, r17,r16,r11,r10, r13,r12,r25,r24
// propagate carry to end 
	ADC32	r17,r16,r11,r10, r20,r20,r20,r21

	pop	r27
	pop	r26

	in	r30, 0x3d
	in	r31, 0x3e
	// add 64 bit value in registers to variables in memory 
	//        target =  source +  registers                    tmp
	MEM_ADD64 S_OFF     S_OFF   r19,r18,r15,r14,r13,r12,r25,r24     r0

#define ZERO r18
// r19 free
	clr	ZERO	
	LOAD32_FROM_X	r5,r4,r15,r14
	LOAD32_FROM_Y	r9,r8,r13,r12	8
	MUL32_FULL_ADC  r17,r16,r11,r10,r7,r6,r3,r2  r5,r4,r15,r14   r9,r8,r13,r12  ZERO r23,r22,r21,r20

	LOAD32_FROM_Y	r23,r22,r21,r20	12
	MUL_32_MOD_ADDx r17 r16 r11,r10  r5,r4,r15,r14   r23,r22,r21,r20   ZERO  r25,r24

	LOAD32_FROM_X	r5,r4,r15,r14
	MUL_32_MOD_ADDx r17 r16 r11,r10   r5,r4,r15,r14   r9,r8,r13,r12   ZERO  r25 r24

	LOAD32_FROM_X	r5,r4,r15,r14
	LOAD32_FROM_Y	r9,r8,r13,r12	0
	MUL32_FULL_ADD	r17,r16,r11,r10,r7,r6,r3,r2  r5,r4,r15,r14   r9,r8,r13,r12  ZERO r23,r22,r21,r20

	LOAD32_FROM_Y	r23,r22,r21,r20 4
	MUL_32_MOD_ADDx r17 r16 r11,r10  r5,r4,r15,r14   r23,r22,r21,r20   ZERO  r25 r24

	LOAD32_FROM_X	r5,r4,r15,r14
	MUL_32_MOD_ADDx r17 r16 r11,r10   r5,r4,r15,r14   r9,r8,r13,r12   ZERO  r25 r24

	// add 64 bit value in registers to variables in memory (addressed by Z)
	//        target =  source +  registers                          tmp
	MEM_ADD64 S_OFF+8   S_OFF+8   r17 r16 r11,r10,r7,r6,r3,r2     r14
	ret
#undef S_OFF


// multiply only 1st 4 bytes of result, precalculate bytes 4,5
// ZERO, RS2,RS3,RS4 and RS5 must be cleared before .. (47)
.macro MUL_32_8  RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0 A3,A2,A1,A0 ZERO
	movw	\RS2,\ZERO
	movw	\RS4,\ZERO
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
	movw	\RS6,\ZERO
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


.macro  MUL32_ADD_n  RS7,/*RS6*/RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0   A1,A0  ZERO
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

.macro  MUL32_ADD_cont_n  /*A2*/RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0  A3,A2,A1  ZERO
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO

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
	clr	\A2
	add	\RS5,r0
	adc	\RS6,r1
	adc	\A2,\ZERO
	mul	\A3,\B2
	add	\RS5,r0
	adc	\RS6,r1
	adc	\A2,\ZERO

	mul	\A3,\B3
	add	\RS6,r0
	adc	\A2,r1
.endm

//(49)
.macro  MUL32_ADD_nXX  RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0   A1,A0  ZERO
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
.macro  MUL32_ADD_cont_nXX  RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0   A1,A3  ZERO
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
//// from this line to line 1740 .. is multiplication  128*128 bits  this
//// can be optimized because stack pointer point to result, Z reg is free
/// 1306 clock cycles inclusive ret
//     + 2x rcall  + 2x 798 rsa_mul_128_mod_no_abi = 2908 inclusive ret
///////////////////////////////////////////////////  rsa_mul_128_no_abi START
	clr	r24
	clr	r25
	movw	r16,r24	// ZERO
	movw	r10,r24	// ZERO
	movw    r12,r24	// ZERO
// >>>>>  bytes [3..0]
	LOAD32_FROM_X	r5,r4,r25,r2
	LOAD32_FROM_Y	r9,r8,r7,r6	0
//              result                              A                B    zero  CC1 CC0
	MUL_32  r17,r16,r15,r14,r19,r18,r21,r20  r5,r4,r25,r2  r9,r8,r7,r6 r24  r23,r22
	STORE32_TO_Z	r19,r18,r21,r20	R_OFF+0
// >>>>>  bytes [7..4]
	ld	r22,X+
	ld	r23,X+
	LOAD32_FROM_Y	r21,r20,r19,r18	4

// upper bytes of operand A (A6) are readed from X+!            B           A1  A0  ZERO
	MUL32_ADD_n     r13/*r12*/r11,r10,r17,r16,r15,r14  r21,r20,r19,r18 r23,r22  r24
// abs differences H-L
	sub	r2,r22
	sbc	r25,r23
	sbc	r4,r13
	ld	r22,X+
	sbc	r5,r22
	sbc	r0,r0		// sign to r0 (0x00/0xff)

	SUB32	r9,r8,r7,r6	r21,r20,r19,r18
	sbc	r1,r1		// sign to r1 (0x00/0xff)

        ABS32   r5,r4,r25,r2	r0
        ABS32   r9,r8,r7,r6	r1
	eor	r0,r1
	bst	r0,0		// combined sign to T
//                                                                 B           A3  A2  A1 ZERO
	MUL32_ADD_cont_n  /*r13*/r12,r11,r10,r17,r16,r15,r14 r21,r20,r19,r18  r22,r13,r23  r24

// >>>>>  midle part [7..4]  [3..0]
//r24 = zero
        MUL32_MPxx      /*r25*/r24,r23,r22,r21,r20,r19,r18   r9,r8,r7,r6  r5,r4,r25,r2 r3
//r9 zero
        clr     r8
// >>>>>  combine [7..0]  (middle part in r25,r24,r23,r22,r21,r20,r19,r18)
	LOAD32_FROM_Z	r3,r2,r7,r6	R_OFF+0

	movw	r0,r8	// ZERO
	ADD64	r17,r16,r15,r14,r3,r2,r7,r6	r13,r12,r11,r10,r17,r16,r15,r14
	adc	r1,r1	// carry
// add/subtract middle part
	brtc	sub_M_L
add_M_L: 
	ADD64   r17,r16,r15,r14,r3,r2,r7,r6     r25,r24,r23,r22,r21,r20,r19,r18
	adc	r1,r0	// carry
	rjmp	final_L
sub_M_L:
	SUB64   r17,r16,r15,r14,r3,r2,r7,r6     r25,r24,r23,r22,r21,r20,r19,r18
	sbc	r1,r0	// carry
	sbc	r0,r0
final_L:
	STORE32_TO_Z    r3,r2,r7,r6 R_OFF+4
// propagate carry to end
	ADD32	r13,r12,r11,r10		r0,r0,r0,r1

// =====  result in r13,r12,r11,r10    r17,r16,r15,r14,     mem:Z[7..0]
// free r21..r25,  r9..r2,  r1,r0 (ZERO in r9,r8)
/////////////////////////////////////////////////////////////////////////////
// bytes [15..0]        bytes [15..8]
/////////////////////////////////////////////////////////////////////////////

// >>>>>  bytes [11..8]
	LOAD32_FROM_X	r5,r4,r3,r2
	LOAD32_FROM_Y   r25,r24,r7,r6   8

	MUL_32_8 /*r,r*/ r19,r18,r21,r20,r23,r22	r25,r24,r7,r6  r5,r4,r3,r2 r8
; now add h0+l8 and h0+l12
	ADD64	r21,r20,r23,r22,r17,r16,r15,r14		r13,r12,r11,r10,r21,r20,r23,r22
	STORE32_TO_Z		r17,r16,r15,r14		R_OFF+16
// >>>>>  bytes [15..12]
	LOAD32_FROM_Y	r13,r12,r31,r30	12
#ifdef RAM_LE32
	rol	r29
#else
	sbc	r0,r0
	push	r0
#endif
//
//
//
	MUL_32_8cont r17,r16,r19,r18	r25,r24,r7,r6  r5,r4,r3,r2  r8

	movw	r14,r8	// ZERO
	ld	r10,X+
	ld	r11,X+
	MUL32_ADD_xx	r8,r11,    r15,r14,r17,r16,r19,r18  r13,r12,r31,r30  r11,r10 r9
// abs differences H-L
	sub	r2,r10
	sbc	r3,r11
	sbc	r4,r8		// r8 is loaded in MUL32_ADD_xx from X+
	ld	r10,X+
	sbc	r5,r10
	sbc	r0,r0		// sign to r0 (0x00/0xff)


	SUB32	r25,r24,r7,r6	r13,r12,r31,r30
	sbc	r1,r1		// sign to r1 (0x00/0xff)

	ABS32   r5,r4,r3,r2	r0
	ABS32   r25,r24,r7,r6	r1
	eor	r0,r1
	bst	r0,0		// combined sign to T
// ZERO in RS6 (r9)
//                   RS7   RS6 ....... RS3         B          A3   A2  A1
  MUL32_ADD_cont_BB /*A2*/ r9,r15,r14,r17   r13,r12,r31,r30  r10 r8 r11
// A1 = r11 is zero
  ;--- level 2: compute M ---
	clr	r10
	movw	r12,r10	// ZERO
//                      result                           B              A          ZERO
	MUL32_ncc	r4,r3,r2,r10,r13,r12,r31,r30  r25,r24,r7,r6  r5,r4,r3,r2  r11
  ;--- add l4+h0 to l0 and h4 ---
//
//
//
//
//
//
//
	ADD64   r17,r16,r19,r18,r21,r20,r23,r22  r8,r9,r15,r14,r17,r16,r19,r18
 	adc	r11, r11	// carry to r11
  ;--- propagate carry ---  
#ifdef RAM_LE32
	lsr	r29
#else
	pop	r0
	lsr	r0
#endif
	clr	r0
	ADC32	r17,r16,r19,r18   r0 r0 r0 r0
	adc	r11,r0
// add/subtract middle part
	brtc	sub_M_H

	ADD64	r17,r16,r19,r18,r21,r20,r23,r22 r4,r3,r2,r10,r13,r12,r31,r30
	adc	r11,r0
	rjmp	final_H
sub_M_H:
	SUB64	r17,r16,r19,r18,r21,r20,r23,r22 r4,r3,r2,r10,r13,r12,r31,r30
	sbc	r11,r0
	sbc	r0,r0
final_H:
	in	r30, 0x3d
	in	r31, 0x3e
	STORE64_TO_Z	r17,r16,r19,r18,r21,r20,r23,r22  R_OFF+20
	ADD32		r8,r9,r15,r14   r0 r0 r0 r11
	STORE32_TO_Z	r8,r9,r15,r14	R_OFF+28
////////////////////////////////////////////////////////////////////////////////////////////////
  ;------ level 1: subtract a0-a7 ------
  	sbiw	r26,16
	LOAD32_FROM_X	r5,r24,r30,r2
	LOAD32_FROM_X	r21,r20,r3,r18
	LOAD32_FROM_X	r13,r12,r11,r10
	LOAD32_FROM_X	r17,r16,r15,r14

	SUB64 r21,r20,r3,r18,r5,r24,r30,r2  r17,r16,r15,r14,r13,r12,r11,r10
	sbc	 r0,r0	// carry to r0 (0x00/0xff)

	LOAD64_FROM_Y	r19,r4,r23,r22,r9,r8,r7,r6	0
	LOAD64_FROM_Y	r17,r16,r15,r14,r13,r12,r11,r10	8

	SUB64	r19,r4,r23,r22,r9,r8,r7,r6  r17,r16,r15,r14,r13,r12,r11,r10
	sbc r1,r1	// carry to r1 (0x00/0xff)
    
  ;------ level 1: absolute values ------
	ABS64   r21,r20,r3,r18,r5,r24,r30,r2  r0
	ABS64   r19,r4,r23,r22,r9,r8,r7,r6  r1
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
	MUL_32  r17,r16,r15,r14,r13,r12,r11,r10  r5,r24,r30,r2  r9,r8,r7,r6  r26  r29,r28

	SUB32	r5,r24,r30,r2  r21,r20,r3,r18
	sbc	r0,r0	// carry to r0 (0x00/0xff)
  
	SUB32	r9,r8,r7,r6   r19,r4,r23,r22
	sbc	r1,r1	// carry to r1 (0x00/0xff)

	ABS32   r5,r24,r30,r2  r0
	ABS32   r9,r8,r7,r6  r1
	eor	r0,r1
	bst	r0,0
//    result                             B               A
// r19 r18 r27 r26 r17,r16,r15,r14    r19,r4,r23,r22  r21,r20,r3,r18
// free r29,r28  r25
// do not touch                    13,12,11,10        r9 r8 r7 r6    r5 r24 r30 r2
//
  ;--- level 2: compute H + (l3,l4,l5) ---
  CLR r25		// 1

  MUL r18, r4 ;a0*b2
  MOVW r28, r0
  MUL r18, r22 ;a0*b0
  ADD r14, r0
  ADC r15, r1
  ADC r16, r28
  ADC r29, r26	// ZERO
  MUL r18, r23 ;a0*b1
  ADD r15, r0
  ADC r16, r1
  ADC r29, r26	// ZERO
  MUL r3, r19 ;a1*b3
  ADD r17, r29
// r26,r27 = ZERO
  ADC r26, r0
  ADC r27, r1			//19

  MUL r18, r19 ;a0*b3
// r18 free,reuse below
  MOVW r28, r0
  MUL r3, r22 ;a1*b0
  ADD r15, r0
  ADC r16, r1
  ADC r17, r28
  ADC r29, r25	// ZERO
  MUL r3, r23 ;a1*b1
  ADD r16, r0
  ADC r17, r1
  ADC r29, r25	// ZERO
  MUL r20, r19 ;a2*b3
  ADD r26, r29
  ADC r27, r0
	clr	r18
  ADC r18, r1			//20

  MUL r20, r4 ;a2*b2
  MOVW r28, r0
  MUL r20, r22 ;a2*b0
  ADD r16, r0
  ADC r17, r1
  ADC r26, r28
  ADC r29, r25	// ZERO
  MUL r3, r4 ;a1*b2
// r3 free
  ADD r17, r0
  ADC r26, r1
  ADC r29, r25		// ZERO
  MUL r21, r19 ;a3*b3
// r19 free, reuse below
  ADD r27, r29
  ADC r18, r0
  CLR r19
  ADC r19, r1			//20
  
  MUL r21, r23 ;a3*b1
  MOVW r28,r0
  MUL r20, r23 ;a2*b1
// r23,r20 free
  ADD r17, r0
  ADC r28, r1
  ADC r29, r25	// ZERO
  MUL r21, r22 ;a3*b0
// r22 free
  ADD r17, r0
  ADC r28, r1
  ADC r29, r25	// ZERO
  MUL r21, r4 ;a3*b2
// r21,r4 free
  ADD r26, r28
  ADC r0, r29
  ADC r1, r25	// ZERO
  ADD r27, r0
  ADC r18, r1
  ADC r19, r25	// ZERO			//21

  ;--- level 2: compute M ---
//  do not touch    r19 r18 r27 r26       r17,r16,r15,r14,r13,r12,r11,r10
//  free r28,r29,r4
//  result                                   operands             free
//  r9,r25,r29,r28,r23,r22,r21,r20    r9 r8 r7 r6    r5 r24 r30 r2  (r3)
// r25 zero
//	/*r9*/ r25,r29,r28,r23,r22,r21,r20   r9 r8 r7 r6  r5 r24 r30 r2  r3
	clr	r4

	mul	r2, r8
	movw	r22, r0
	mul	r2, r6
	movw	r20, r0	// r20 final
	mul	r2, r7
	add	r21, r0
	adc	r22, r1
	adc	r23, r4	// ZERO
	mul	r30, r9
	movw	r28, r0
	mul	r2, r9
	movw	r2, r0
	mul	r30, r6
	add	r21, r0	// r21 final
	adc	r22, r1
	adc	r23, r2
	adc	r3, r4	// ZERO
	mul	r30, r7
	add	r22, r0
	adc	r23, r1
	adc	r3, r4	// ZERO
	mul	r24, r9
	add	r28, r3
	adc	r29, r0
	adc	r25, r1

	mul	r24, r8
	movw	r2, r0
	mul	r24, r6
	add	r22, r0	//r22 final
	adc	r23, r1
	adc	r28, r2
	adc	r3, r4	// ZERO

	mul	r30, r8
	add	r23, r0
	adc	r28, r1
	adc	r3, r4	// ZERO
	mul	r5, r9
// r9 free
	add	r29, r3
	adc	r25, r0

	clr	r9
	adc	r9, r1

	mul	r5, r7
	movw	r2, r0
	mul	r24, r7
//r24, r7 free
	add	r23, r0
	adc	r28, r1
	adc	r3, r4	// ZERO
	mul	r5, r6
// r6 free
	add	r23, r0	// r23 final
	adc	r2, r1
	adc	r3, r4	// ZERO

	mul	r5, r8
	add	r28, r2
	adc	r0, r3
	adc	r1, r4	// ZERO
	add	r29, r0
	adc	r25, r1
	adc	r9, r4	// ZERO
// r4 zero

	clr	r5
	movw	r0,r4	// copy ZERO, clear r0,r1
// copy B+C
	movw	r2,r14
	movw	r6,r16
  ;--- process sign bit ---
	brtc	sub_M_M

	ADD64	r17,r16,r15,r14,r7,r6,r3,r2	r9,r25,r29,r28,r23,r22,r21,r20
	adc	r5,r4
	rjmp	final_M
sub_M_M:
  ;subtract M
	SUB64	r17,r16,r15,r14,r7,r6,r3,r2	r9,r25,r29,r28,r23,r22,r21,r20
	sbc r5, r4
	sbc r4, r4
final_M:
//                [B+C]-M                            D             A
	ADD64	r17,r16,r15,r14,r7,r6,r3,r2	r19,r18,r27,r26,r13,r12,r11,r10
	ADC32	r19,r18,r27,r26			r4,r4,r4,r5

#ifdef RAM_LE32
	lsr	r31
#else
	pop	r29
	lsr	r29    // test bit0
#endif
	in      r30, 0x3d
	LOAD64_FROM_Z	r9,r8,r25,r24,r23,r22,r21,r20	R_OFF+0

	ldd	r4, Z+R_OFF+16
	ldd	r5, Z+R_OFF+17
	ldd	r29, Z+R_OFF+18
	
	brcc sub_M

add_M: 
	ADD64	r9,r8,r25,r24,r23,r22,r21,r20   r7,r6,r3,r2,r13,r12,r11,r10
	rol	r28	// carry to r28
	
	LOAD32_FROM_Z	r10,r7,r6,r3	R_OFF+19
	ldd		r11, 		Z+R_OFF+23

	ADD64	r9,r8,r25,r24,r23,r22,r21,r20	r11,r10,r7,r6,r3,r29,r5,r4
	ror	r28	// carry to r28 bit 7, renew old carry

	ADC64	r11,r10,r7,r6,r3,r29,r5,r4   r19,r18,r27,r26,r17,r16,r15,r14
	movw	r18,r0	// clear regs for rsa_mul_128_mod_no_abi
	adc	r0, r0	// (r1 is cleared above)
  	rjmp	final

sub_M:
	SUB64	r9,r8,r25,r24,r23,r22,r21,r20	r7,r6,r3,r2,r13,r12,r11,r10
	rol	r28	//borrow to r28

	LOAD32_FROM_Z	r10,r7,r6,r3	R_OFF+19
	ldd		r11, 		Z+R_OFF+23

	ADD64	r9,r8,r25,r24,r23,r22,r21,r20	r11,r10,r7,r6,r3,r29,r5,r4
	ror	r28	// carry to r28, bit 7, renew borrow

	SBC64   r11,r10,r7,r6,r3,r29,r5,r4  r19,r18,r27,r26,r17,r16,r15,r14
	movw	r18,r0	// clear regs for rsa_mul_128_mod_no_abi
	sbc	r0,r0
	sbc	r1,r1
  
final:
	STORE64_TO_Z	r9,r8,r25,r24,r23,r22,r21,r20	R_OFF+8

	LOAD64_FROM_Z	r13,r12,r21,r20,r9,r8,r27,r26	R_OFF+24
	rol	r28
	ADC64		r11,r10,r7,r6,r3,r29,r5,r4	r13,r12,r21,r20,r9,r8,r27,r26
	STORE64_TO_Z	r11,r10,r7,r6,r3,r29,r5,r4	R_OFF+16

  ;--- propagate carry to end ---
	ADC64		r13,r12,r21,r20,r9,r8,r27,r26 	r1,r1,r1,r1,r1,r1,r1,r0

	STORE64_TO_Z	r13,r12,r21,r20,r9,r8,r27,r26	R_OFF+24
#undef R_OFF
///////////////////////////////////////////////////////   rsa_mul_128_no_abi STOP
// load pointers
	pop	r28
	pop	r29
	pop	r26
	pop	r27
	adiw	r28,16	// upper part
// clear r19,r18 before call ! (already cleared above)
//	clr	r18
//	clr	r19
	rcall	rsa_mul_128_mod_no_abi

	sbiw	r28,16 // lower part, X is incremented in rsa_mul_128_mod_no_abi

// do not replace this by jmp/rjmp, SP is used as pointer to result ( but this
// fail if -mrelax and -Wl,--relax is used for compiler/linker, use this
// with -Wl,--no-call-ret-replacement, or uncomment "nop" instruction in
// next code)
// clear r19,r18 before call ! (r18 cleared from revious rsa_mul_128_mod_no_abi)
	clr	r19
	rcall	rsa_mul_128_mod_no_abi
//	nop
	ret

        .global rsa_mul_256_mod
        .type   rsa_mul_256_mod, @function
	.section .text.rsa_mul_256_mod,"ax",@progbits

rsa_mul_256_mod:
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

// create space on stack - 64 bytes TMP variable, 3x pointer
	in	r28, 0x3d
	in	r29, 0x3e
	sbiw	r28,(32+6)	// rsa_mul_256_mod_no_abi result in stack!
	LOAD_SP r0, r28,r29

// save  pointers to stack
	std	Y+3,r24	// Result
	std	Y+4,r25

	movw	r28,r22
	movw	r26,r20
	call	rsa_mul_256_mod_no_abi	// result to stack
//copy result from stack to real position
// load values back
	in	r30, 0x3d
	in	r31, 0x3e
	ldd	r28,Z+3	// result
	ldd	r29,Z+4
	adiw	r30,7
	ldi	r24,32
1:
	ld	r25,Z+
	st	Y+,r25
	dec	r24
	brne	1b

	clr	r1
// return registers
	sbiw	r30,1
	LOAD_SP r0, r30,r31
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
