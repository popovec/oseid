/*
    mp_square.S

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

this file provides AVR (atmega/xmega) functions for:

    256 bit squaring
    512 bit squaring
   1024 bit squaring

    192 bit squaring
    384 bit squaring
    768 bit squaring

Functions are interupt safe, reentrant, runs in constant time. 192 and
256 bit versions are without branches/one loops.  Functions that are marked
NO_ABI does not conform C ABI. Below information about no_abi function
calls.

WARNING, do not overlap input and output to functions!

To compile functions, select what must be compiled by defining:

HAVE_RSA_SQUARE_192_NO_ABI
HAVE_RSA_SQUARE_256_NO_ABI
HAVE_RSA_SQUARE_384_NO_ABI
HAVE_RSA_SQUARE_512_NO_ABI
HAVE_RSA_SQUARE_768_NO_ABI
HAVE_RSA_SQUARE_1024_NO_ABI

HAVE_RSA_SQUARE_192
HAVE_RSA_SQUARE_256
HAVE_RSA_SQUARE_384
HAVE_RSA_SQUARE_512
HAVE_RSA_SQUARE_768
HAVE_RSA_SQUARE_1024


(for example, it is enough to select HAVE_RSA_SQUARE_768, all function needed
to complette this call are selected automaticaly)


NO_ABI function arguments:
--------------------------
rsa_square_192_no_abi  - input is addressed by r28,r29 result by r30,r31
rsa_square_256_no_abi  - input is addressed by r28,r29 result by r30,r31
rsa_square_384_no_abi  - input is addressed by r22,r23 result by r30,r31
rsa_square_512_no_abi  - input is addressed by r22,r23 result by r30,r31
rsa_square_768_no_abi  - input is addressed by r22,r23 result by r24,r25
rsa_square_1024_no_abi - input is addressed by r22,r23 result by r24,r25

------------------------------------------------------------------
                ABI functions ticks inclusive prolog/epilog
function name   ticks (without call/ret, inclusive CLI/SEI if SP is changed)
------------------------------------------------------------------
rsa_square_192_no_abi    1839     (uses 10 bytes on stack)
rsa_square_256_no_abi    3081     (uses 32 bytes on stack)

(in next calculations number 7 is from rcall and ret clock cycles)

rsa_square_384_no_abi   (7+rsa_square_192_no_abi)*3 +  994 =  6532
rsa_square_512_no_abi   (7+rsa_square_256_no_abi)*3 + 1344 = 10608
rsa_square_192
rsa_square_256
rsa_square_384
rsa_square_512
rsa_square_768          (7+rsa_square_384_no_abi)*3 + 2175 = 21792
rsa_square_1024         (7+rsa_square_512_no_abi)*3 + 2889 = 34713

////////////////////////////////////////////////////////////////////////////////////////////////
Level  48 bits: squaring 0-5 to 0-11 bytes classical square (karatsuba is slower)
Level  96 bits: squaring to 0-24 by karatsuba
Level 192 bits: squaring to 0-48 by karatsuba

Level  64 bits: squaring 0-7 to 0-15 bytes classical square (karatsuba is slower)
Level 128 bits: squaring to 0-31 by karatsuba
Level 256 bits: squaring to 0-63 by karatsuba

All levels above uses stack as temp space for midle part of karatsuba algo.


convention (only for 256 bit squaring, not in rest code):
register names, asm instruction  lowercase
macros, #define, etc.  uppercase
r0,r1 temp registers (to hold carry/borrow/memory variable etc) 
r28,29 is used in first part of code to address operand, in second part to
address variables on stack
ZERO zero register hold zero (not r1!)
TMP temp register
do not use direct register names, use aliases to get code readable, only
r0,r1,r28,r29 are used direct without aliases.
*/

#include "load_sp.h"

/*
// if you get this file without load_sp.h, next macros must be defined:
// atmega:
.macro  LOAD_SP tmp   RL RH
        in      \tmp,0x3f
        cli
        out     0x3d, \RL
        out     0x3f, \tmp
        out     0x3e, \RH
.endm
.macro  LOAD_SP_SREG   tmp   RL RH
        cli
        out     0x3d, \RL
        out     0x3f, \tmp
        out     0x3e, \RH
.endm

// xmega
.macro  LOAD_SP tmp   RL RH
        out     0x3d, \RL
        out     0x3e, \RH
.endm
.macro  LOAD_SP_SREG   tmp   RL RH
        out     0x3d, \RL
	out     0x3f, \tmp
        out     0x3e, \RH
.endm
*/

// macro definitions

.macro	STORE32_TO_MEM	 M  REG3 REG2 REG1 REG0
	std	Z+0+\M, \REG0
	std	Z+1+\M, \REG1
	std	Z+2+\M, \REG2
	std	Z+3+\M, \REG3
.endm

.macro	STORE_TO_Y_MEM	 M  REG3 REG2 REG1 REG0
	std	Y+0+\M, \REG0
	std	Y+1+\M, \REG1
	std	Y+2+\M, \REG2
	std	Y+3+\M, \REG3
.endm

.macro	LOAD_FROM_MEM  REG3 REG2 REG1 REG0    M3 M2 M1 M0
	ldd	\REG0,Z+\M0
	ldd	\REG1,Z+\M1
	ldd	\REG2,Z+\M2
	ldd	\REG3,Z+\M3
.endm
.macro	LOAD_FROM_MEM_  REG3 REG2 REG1 REG0    M
	ldd	\REG0,Z+0+\M
	ldd	\REG1,Z+1+\M
	ldd	\REG2,Z+2+\M
	ldd	\REG3,Z+3+\M
.endm
.macro 	LOAD32_FROM_Y_MEM	A3 A2 A1 A0  M
	ldd	\A0,Y+\M+0
	ldd	\A1,Y+\M+1
	ldd	\A2,Y+\M+2
	ldd	\A3,Y+\M+3
.endm

.macro 	COPY64__ T7 T6 T5 T4 T3 T2 T1 T0  A7 A6 A5 A4 A3 A2 A1 A0
	movw	\T0,\A0
	movw	\T2,\A2
	movw	\T4,\A4
	movw	\T6,\A6
.endm

// REG = REG + MEM
.macro ADD64_MEM T7 T6 T5 T4 T3 T2 T1 T0   M TMP
	ldd	\TMP,Z+\M+0
	add	\T0,\TMP
	ldd	\TMP,Z+\M+1
	adc	\T1,\TMP
	ldd	\TMP,Z+\M+2
	adc	\T2,\TMP
	ldd	\TMP,Z+\M+3
	adc	\T3,\TMP
	ldd	\TMP,Z+\M+4
	adc	\T4,\TMP
	ldd	\TMP,Z+\M+5
	adc	\T5,\TMP
	ldd	\TMP,Z+\M+6
	adc	\T6,\TMP
	ldd	\TMP,Z+\M+7
	adc	\T7,\TMP
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
// add to  memory (Z+offset)  target = source + register set
.macro MEM_ADC64 T  S  RG7 RG6 RG5 RG4 RG3 RG2 RG1 RG0 TMP
	ldd	\TMP,Z+\S+0
	adc	\TMP,\RG0
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
.macro	PUSH32	  A3 A2 A1 A0
	push	\A3
	push	\A2
	push	\A1
	push	\A0
.endm
.macro	POP32	  A3 A2 A1 A0
	pop	\A0
	pop	\A1
	pop	\A2
	pop	\A3
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
.macro	ABS_SUB64	RZ7 RZ6 RZ5 RZ4 RZ3 RZ2 RZ1 RZ0	A7 A6 A5 A4 A3 A2 A1 A0       TMP
	sub	\RZ0,\A0
	sbc	\RZ1,\A1
	sbc	\RZ2,\A2
	sbc	\RZ3,\A3
	sbc	\RZ4,\A4
	sbc	\RZ5,\A5
	sbc	\RZ6,\A6
	sbc	\RZ7,\A7
	
	sbc	\TMP,\TMP
	eor	\RZ0,\TMP
	eor	\RZ1,\TMP
	eor	\RZ2,\TMP
	eor	\RZ3,\TMP
	eor	\RZ4,\TMP
	eor	\RZ5,\TMP
	eor	\RZ6,\TMP
	eor 	\RZ7,\TMP
	sub	\RZ0,\TMP
	sbc	\RZ1,\TMP
	sbc	\RZ2,\TMP
	sbc	\RZ3,\TMP
	sbc	\RZ4,\TMP
	sbc	\RZ5,\TMP
	sbc	\RZ6,\TMP
	sbc	\RZ7,\TMP
.endm

//A0..A7 must be saved, ACC3..0 is stored to RAM (at position M0)
.macro SQUARE_ADD_64x	M0 ACC_15 ACC_14 ACC_13 ACC_12 ACC_11 ACC_10 ACC_9 ACC_8 ACC_7 ACC_6 ACC_5 ACC_4 ACC_3 ACC_2 ACC_1 ACC_0  A7 A6 A5 A4 A3 A2 A1 A0  TMP2 TMP
// max value in ACC_7..0  FFFFFFFFFFFFFFFE
// add squared A3,A2,A1,A0 ..
	mul	\A3,\A3
	movw	\TMP,r0
	mul	\A2,\A2
	movw	\ACC_14,r0
	mul	\A1,\A1
	movw	\ACC_12,r0
	mul	\A0,\A0
	add	\ACC_0,r0
	adc	\ACC_1,r1
	adc	\ACC_2,\ACC_12
	adc	\ACC_3,\ACC_13
	adc	\ACC_4,\ACC_14
	adc	\ACC_5,\ACC_15
	adc	\ACC_6,\TMP
	adc	\ACC_7,\TMP2
// 1FE01FE01FE01FDFF = FFFFFFFFFFFFFFFE +FE01FE01FE01FE01
//load bit 0
	bst	\ACC_1,0
//divide (inclusive carry)
	ror	\ACC_7
	ror	\ACC_6
	ror	\ACC_5
	ror	\ACC_4
	ror	\ACC_3
	ror	\ACC_2
	ror	\ACC_1
// FF00 FF00 FF00 FEFF
	clr	\ACC_14

// sum of all squared parts = 00FF00FF00FF00FE00FF00FF00FF0100
// low part is already at max                 FF00FF00FF00FEFF
//
//
// final sum is max           00FF00FF00FF00FEFFFFFFFFFFFFFFFF
// xx 00 xx xx xxxxxxxx FF00FF00FF00FEFF
	mul	\A1,\A7
	movw	\ACC_8,r0

	mul	\A3,\A7
	movw	\ACC_10,r0
// xx = tmp registers
// xx 00 xx xx FE01FE01 FF00FF00FF00FEFF
//                        FE01FE01FE0100  A0:1,3,5
//                              FE010000  A0:2
//                   FE 0100000000000000  A0:7
//                      FE01000000000000 A0:6
	mul	\A0,\A7
	movw	\ACC_12,r0

	mul	\A0,\A3
	movw	\TMP,r0

	mul	\A0,\A1
	add	\ACC_1,r0
	adc	\ACC_2,r1
	adc	\ACC_3,\TMP
	adc	\TMP2,\ACC_14	//carry here or

	mul	\A0,\A2
	add	\ACC_2,r0
	adc	\ACC_3,r1
	adc	\TMP2,\ACC_14	//carry here, not both

	mul	\A0,\A5
	add	\ACC_4,\TMP2
	adc	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\ACC_12
	adc	\ACC_13,\ACC_14

	mul	\A0,\A6
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\ACC_13,\ACC_14

// xx 00 FF xx FE01FE01 FF0000FFFEFFFFFF
//                        FE01FE01000000 A1:2,4
//                          FE0100000000 A1:3
//                          FE0100000000 A0:4
//                   FF 0000000000000000 (ACC_13/to be addded to ACC_8)
	mul	\A1,\A4
	movw	\TMP,r0

	mul	\A1,\A2
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\TMP
	adc	\TMP2,\ACC_14	//carry here or

	mul	\A1,\A3
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\TMP2,\ACC_14	//carry here, not both

	mul	\A0,\A4
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\ACC_6,\TMP2

	adc	\ACC_7,\ACC_14
	adc	\ACC_8,\ACC_13
	adc	\ACC_9,\ACC_14

// xx 00 xx xx FE01FF00 FFFFFEFFFFFFFFFF
//                   FE 01FE010000000000 A3:2,4
//                      FE01000000000000 A2:4
//               FE0100 0000000000000000 A4:5
	mul	\A3,\A4
	movw	\TMP,r0

	mul	\A2,\A3
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\TMP
	adc	\TMP2,\ACC_14

	mul	\A2,\A4
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\TMP2,\ACC_14

	mul	\A4,\A5
	add	\ACC_8,\TMP2
	adc	\ACC_9,r0
	adc	\ACC_10,r1
	adc	\ACC_11,\ACC_14

//
// xx 00 xx xx FF0000FF FFFEFFFFFFFFFFFF
//               FE0100 0000000000000000 A2:7
	mul	\A2,\A7
	add	\ACC_9,r0
	adc	\ACC_10,r1
	adc	\ACC_11,\ACC_14
// xx 00 xx xx FFFE01FF FFFEFFFFFFFFFFFF
// OK ..
//                 FE01 0000000000000000 A2:6
//                      FE01000000000000 A1:5
//                   FE 0100000000000000 A1,6
	mul	\A4,\A7
	movw	\TMP,r0

	mul	\A2,\A6
	movw	\ACC_12,r0

	mul	\A1,\A5
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\ACC_8,\ACC_12
	adc	\ACC_13,\ACC_14

	mul	\A1,\A6
	add	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_13,\ACC_14

// xx 00 FF xx FFFE01FF FEFFFFFFFFFFFFFF
//       ^^ to ACC_9
//
//             FE010000 0000000000000000 A4:6
//                 FF00 0000000000000000 (ACC_13/to be added to ACC_9)
	mul	\A4,\A6
	add	\ACC_9,\ACC_13
	adc	\ACC_10,r0
	adc	\ACC_11,r1
	adc	\TMP2,\ACC_14
// xx 00 xx xx  FE0000FF FEFFFFFFFFFFFFFF
//            0100000000 0000000000000000 carry to TMP2 (above)
//          FE0100000000 0000000000000000 A5:7
//            FE01000000 0000000000000000 A4:7 (from TMP)
	mul	\A5,\A7
	movw	\ACC_12,r0

	add	\ACC_11,\TMP
	adc	\ACC_12,\TMP2
	adc	\ACC_13,\ACC_14

// xx 00 FF 00 FF0000FF FEFFFFFFFFFFFFFF
// +             FE0100 0000000000000000 A3,6
// +                 FE 0100000000000000 A2,5
// +               FE01 0000000000000000 A3,5
// +         FE01000000 0000000000000000 A5,6
	mul	\A3,\A6
	movw	\TMP,r0

	mul	\A2,\A5
	add	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\TMP
	adc	\TMP2,\ACC_14

	mul	\A3,\A5
	add	\ACC_8,r0
	adc	\ACC_9,r1
	adc	\TMP2,\ACC_14

	mul	\A5,\A6
	add	\ACC_10,\TMP2
	adc	\ACC_11,r0
	adc	\ACC_12,r1
	adc	\ACC_13,\ACC_14
//  xx 00FFFF00FF00FEFFFFFFFFFFFFFFFF
// +   FE0100000000000000000000000000   A6,7
	mul	\A6,\A7
	add	\ACC_13,r0
//	clr	\ACC_14
	adc	\ACC_14,r1
	clr	\ACC_15			// 108+28

// maximum resul:  FF00FF00FF00FEFFFFFFFFFFFFFFFF
// (FFFFFFFFFFFFFFFF*FFFFFFFFFFFFFFFF + FFFFFFFFFFFFFFFE - FE01FE01FE01FE010000000000000000)/2

// double result
	add	\ACC_1,\ACC_1
	adc	\ACC_2,\ACC_2
	adc	\ACC_3,\ACC_3
	adc	\ACC_4,\ACC_4
	adc	\ACC_5,\ACC_5
	adc	\ACC_6,\ACC_6
	adc	\ACC_7,\ACC_7
	adc	\ACC_8,\ACC_8
	adc	\ACC_9,\ACC_9
	adc	\ACC_10,\ACC_10
	adc	\ACC_11,\ACC_11
	adc	\ACC_12,\ACC_12
	adc	\ACC_13,\ACC_13
	adc	\ACC_14,\ACC_14
	adc	\ACC_15,\ACC_15
	bld	\ACC_1,0

// final ACC_0..ACC_7
	std	Z+0+\M0,\ACC_0
	std	Z+1+\M0,\ACC_1
	std	Z+2+\M0,\ACC_2
	std	Z+3+\M0,\ACC_3

	mul	\A7,\A7
	movw	\TMP,r0

	mul	\A6,\A6
	movw	\ACC_2,r0

	mul	\A5,\A5
	movw	\ACC_0,r0

	mul	\A4,\A4
	add	\ACC_8,r0
	adc	\ACC_9,r1
	adc	\ACC_10,\ACC_0
	adc	\ACC_11,\ACC_1
	adc	\ACC_12,\ACC_2
	adc	\ACC_13,\ACC_3
	adc	\ACC_14,\TMP
	adc	\ACC_15,\TMP2

.endm

//A0..A7 can be destroyed
.macro SQUARE_ADD_64x2	ACC_15 ACC_14 ACC_13 ACC_12 ACC_11 ACC_10 ACC_9 ACC_8 ACC_7 ACC_6 ACC_5 ACC_4 ACC_3 ACC_2 ACC_1 ACC_0  A7 A6 A5 A4 A3 A2 A1 A0  TMP2 TMP XTMP16h XTMP16l
// max value in ACC_7..0  FFFFFFFFFFFFFFFE
// add squared A3,A2,A1,A0 ..
	mul	\A3,\A3
	movw	\TMP,r0
	mul	\A2,\A2
	movw	\ACC_14,r0
	mul	\A1,\A1
	movw	\ACC_12,r0
	mul	\A0,\A0
	add	\ACC_0,r0
	adc	\ACC_1,r1
	adc	\ACC_2,\ACC_12
	adc	\ACC_3,\ACC_13
	adc	\ACC_4,\ACC_14
	adc	\ACC_5,\ACC_15
	adc	\ACC_6,\TMP
	adc	\ACC_7,\TMP2
// 1FE01FE01FE01FDFF = FFFFFFFFFFFFFFFE +FE01FE01FE01FE01
//load bit 0
	bst	\ACC_1,0
//divide (inclusive carry)
	ror	\ACC_7
	ror	\ACC_6
	ror	\ACC_5
	ror	\ACC_4
	ror	\ACC_3
	ror	\ACC_2
	ror	\ACC_1
// FF00 FF00 FF00 FEFF
	clr	\ACC_14

// sum of all squared parts = 00FF00FF00FF00FE00FF00FF00FF0100
// low part is already at max                 FF00FF00FF00FEFF
//
//
// final sum is max           00FF00FF00FF00FEFFFFFFFFFFFFFFFF
// xx 00 xx xx xxxxxxxx FF00FF00FF00FEFF
	mul	\A1,\A7
	movw	\ACC_8,r0

	mul	\A3,\A7
	movw	\ACC_10,r0
// xx = tmp registers
// xx 00 xx xx FE01FE01 FF00FF00FF00FEFF
//                        FE01FE01FE0100  A0:1,3,5
//                              FE010000  A0:2
//                   FE 0100000000000000  A0:7
//                      FE01000000000000 A0:6
	mul	\A0,\A7
	movw	\ACC_12,r0

	mul	\A0,\A3
	movw	\TMP,r0

	mul	\A0,\A1
	add	\ACC_1,r0
	adc	\ACC_2,r1
	adc	\ACC_3,\TMP
	adc	\TMP2,\ACC_14	//carry here or

	mul	\A0,\A2
	add	\ACC_2,r0
	adc	\ACC_3,r1
	adc	\TMP2,\ACC_14	//carry here, not both

	mul	\A0,\A5
	add	\ACC_4,\TMP2
	adc	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\ACC_12
	adc	\ACC_13,\ACC_14

	mul	\A0,\A6
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\ACC_13,\ACC_14

// xx 00 FF xx FE01FE01 FF0000FFFEFFFFFF
//                        FE01FE01000000 A1:2,4
//                          FE0100000000 A1:3
//                          FE0100000000 A0:4
//                   FF 0000000000000000 (ACC_13/to be addded to ACC_8)
	mul	\A1,\A4
	movw	\TMP,r0

	mul	\A1,\A2
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\TMP
	adc	\TMP2,\ACC_14	//carry here or

	mul	\A1,\A3
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\TMP2,\ACC_14	//carry here, not both

	mul	\A0,\A4
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\ACC_6,\TMP2

	adc	\ACC_7,\ACC_14
	adc	\ACC_8,\ACC_13
	adc	\ACC_9,\ACC_14

// xx 00 xx xx FE01FF00 FFFFFEFFFFFFFFFF
//                   FE 01FE010000000000 A3:2,4
//                      FE01000000000000 A2:4
//               FE0100 0000000000000000 A4:5
	mul	\A3,\A4
	movw	\TMP,r0

	mul	\A2,\A3
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\TMP
	adc	\TMP2,\ACC_14

	mul	\A2,\A4
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\TMP2,\ACC_14

	mul	\A4,\A5
	add	\ACC_8,\TMP2
	adc	\ACC_9,r0
	adc	\ACC_10,r1
	adc	\ACC_11,\ACC_14

//
// xx 00 xx xx FF0000FF FFFEFFFFFFFFFFFF
//               FE0100 0000000000000000 A2:7
	mul	\A2,\A7
	add	\ACC_9,r0
	adc	\ACC_10,r1
	adc	\ACC_11,\ACC_14
// xx 00 xx xx FFFE01FF FFFEFFFFFFFFFFFF
// OK ..
//                 FE01 0000000000000000 A2:6
//                      FE01000000000000 A1:5
//                   FE 0100000000000000 A1,6
	mul	\A4,\A7
	movw	\TMP,r0

	mul	\A2,\A6
	movw	\ACC_12,r0

	mul	\A1,\A5
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\ACC_8,\ACC_12
	adc	\ACC_13,\ACC_14

	mul	\A1,\A6
	add	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_13,\ACC_14

// xx 00 FF xx FFFE01FF FEFFFFFFFFFFFFFF
//       ^^ to ACC_9
//
//             FE010000 0000000000000000 A4:6
//                 FF00 0000000000000000 (ACC_13/to be added to ACC_9)
	mul	\A4,\A6
	add	\ACC_9,\ACC_13
	adc	\ACC_10,r0
	adc	\ACC_11,r1
	adc	\TMP2,\ACC_14
// xx 00 xx xx  FE0000FF FEFFFFFFFFFFFFFF
//            0100000000 0000000000000000 carry to TMP2 (above)
//          FE0100000000 0000000000000000 A5:7
//            FE01000000 0000000000000000 A4:7 (from TMP)
	mul	\A5,\A7
	movw	\ACC_12,r0

	add	\ACC_11,\TMP
	adc	\ACC_12,\TMP2
	adc	\ACC_13,\ACC_14

// xx 00 FF 00 FF0000FF FEFFFFFFFFFFFFFF
// +             FE0100 0000000000000000 A3,6
// +                 FE 0100000000000000 A2,5
// +               FE01 0000000000000000 A3,5
// +         FE01000000 0000000000000000 A5,6
	mul	\A3,\A6
	movw	\TMP,r0

	mul	\A2,\A5
	add	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\TMP
	adc	\TMP2,\ACC_14

	mul	\A3,\A5
	add	\ACC_8,r0
	adc	\ACC_9,r1
	adc	\TMP2,\ACC_14

	mul	\A5,\A6
	add	\ACC_10,\TMP2
	adc	\ACC_11,r0
	adc	\ACC_12,r1
	adc	\ACC_13,\ACC_14
//  xx 00FFFF00FF00FEFFFFFFFFFFFFFFFF
// +   FE0100000000000000000000000000   A6,7
	mul	\A6,\A7
	add	\ACC_13,r0
//	clr	\ACC_14
	adc	\ACC_14,r1
	clr	\ACC_15			// 108+28

// maximum resul:  FF00FF00FF00FEFFFFFFFFFFFFFFFF
// (FFFFFFFFFFFFFFFF*FFFFFFFFFFFFFFFF + FFFFFFFFFFFFFFFE - FE01FE01FE01FE010000000000000000)/2

// double result
	add	\ACC_1,\ACC_1
	adc	\ACC_2,\ACC_2
	adc	\ACC_3,\ACC_3
	adc	\ACC_4,\ACC_4
	adc	\ACC_5,\ACC_5
	adc	\ACC_6,\ACC_6
	adc	\ACC_7,\ACC_7
	adc	\ACC_8,\ACC_8
	adc	\ACC_9,\ACC_9
	adc	\ACC_10,\ACC_10
	adc	\ACC_11,\ACC_11
	adc	\ACC_12,\ACC_12
	adc	\ACC_13,\ACC_13
	adc	\ACC_14,\ACC_14
	adc	\ACC_15,\ACC_15
	bld	\ACC_1,0


	mul	\A7,\A7
	movw	\TMP,r0

	mul	\A6,\A6
	movw	\A2,r0

	mul	\A5,\A5
	movw	\A0,r0

	mul	\A4,\A4
	add	\ACC_8,r0
	adc	\ACC_9,r1
	adc	\ACC_10,\A0
	adc	\ACC_11,\A1
	adc	\ACC_12,\A2
	adc	\ACC_13,\A3
	adc	\ACC_14,\TMP
	adc	\ACC_15,\TMP2
.endm


// 0
// 1 0s1
// 2 0X2
// 3 0o3 1s2
// 4 0X4 1o3
// 5 0v5 1o4 2s3
// 6 0X6 1v5 2*4
// 7 0v7 1/6 2_5 3o4
// 8 1X7 2/6 3_5
// 9 2v7 3/6 4_5
//10 3X7 4.6
//11 4/7 5_6
//12 5X7
//13 6.7
//14
//1
//A0..A5 is destroyed
.macro SQUARE_64	ACC_15 ACC_14 ACC_13 ACC_12 ACC_11 ACC_10 ACC_9 ACC_8 ACC_7 ACC_6 ACC_5 ACC_4 ACC_3 ACC_2 ACC_1 ACC_0  A7 A6 A5 A4 A3 A2 A1 A0 TMP2 TMP
	clr	\ACC_15
	mul	\A0,\A2
	movw	\ACC_2,r0

	mul	\A0,\A1
	mov	\ACC_1,r0
	add	\ACC_2,r1
	adc	\ACC_3,\ACC_15

	mul	\A0,\A4
	movw	\ACC_4,r0

	mul	\A0,\A6
	movw	\ACC_6,r0

	mul	\A1,\A7
	movw	\ACC_8,r0

	mul	\A3,\A7
	movw	\ACC_10,r0

	mul	\A5,\A7
	movw	\ACC_12,r0

	mul	\A1,\A2
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\ACC_15

	mul	\A2,\A3
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\ACC_15

//FE01 FE01 FE01 FEFF FFFF FFFF 0100
////////////////////////////
	mul	\A1,\A4
	movw	\TMP,r0

	mul	\A0,\A3
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\TMP
	adc	\TMP2,\ACC_15

	mul	\A1,\A3
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\TMP2,\ACC_15

	mul	\A3,\A4
	add	\ACC_6,\TMP2
	adc	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\ACC_15
//FE01 FE01 FF00 00FE FFFF 00FF 0100
///////////////////////////////
	mul	\A0,\A7
	movw	\TMP,r0

	mul	\A0,\A5
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\TMP
	adc	\TMP2,\ACC_15

	mul	\A1,\A5
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\TMP2,\ACC_15

	mul	\A2,\A7
	add	\ACC_8,\TMP2
	adc	\ACC_9,r0
	adc	\ACC_10,r1
	adc	\ACC_11,\ACC_15
//FE01 FF00 00FF 00FE 00FF 00FF 0100
////////////////////////////////
	mul	\A4,\A5
	movw	\TMP,r0

	mul	\A2,\A5
	add	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\TMP
	adc	\TMP2,\ACC_15

	mul	\A3,\A5
	add	\ACC_8,r0
	adc	\ACC_9,r1
	adc	\TMP2,\ACC_15

	mul	\A5,\A6
	add	\ACC_10,\TMP2
	adc	\ACC_11,r0
	adc	\ACC_12,r1
	adc	\ACC_13,\ACC_15
//FF00 00FF 00FE 01FE 00FF 00FF 0100
////////////////////////////////
	mul	\A3,\A6
	movw	\TMP,r0

	mul	\A1,\A6
	add	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\TMP
	adc	\TMP2,\ACC_15

	mul	\A2,\A6
	add	\ACC_8,r0
	adc	\ACC_9,r1
	adc	\TMP2,\ACC_15

	mul	\A4,\A7
	add	\ACC_10,\TMP2
	adc	\ACC_11,r0
	adc	\ACC_12,r1
	adc	\ACC_13,\ACC_15
//FFFE 02FE 00FD 02FE 00FF 00FF 0100
////////////////////////////////
	mul	\A4,\A6
	movw	\TMP,r0

	mul	\A2,\A4
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\ACC_8,\ACC_15
	adc	\ACC_9,\ACC_15
	adc	\ACC_10,\TMP
	adc	\ACC_11,\TMP2
	adc	\ACC_12,\ACC_15
	adc	\ACC_13,\ACC_15
//FFFF 00FF 00FE 00FF 00FF 00FF 0100
////////////////////////////////
	mul	\A6,\A7
	add	\ACC_13,r0
	clr	\ACC_14
	adc	\ACC_14,r1

// maximal result 00FF00FF 00FF00FE 00FF00FF 00FF0100
// there is no carry to ACC_15

// double result
	add	\ACC_1,\ACC_1
	adc	\ACC_2,\ACC_2
	adc	\ACC_3,\ACC_3
	adc	\ACC_4,\ACC_4
	adc	\ACC_5,\ACC_5
	adc	\ACC_6,\ACC_6
	adc	\ACC_7,\ACC_7
	adc	\ACC_8,\ACC_8
	adc	\ACC_9,\ACC_9
	adc	\ACC_10,\ACC_10
	adc	\ACC_11,\ACC_11
	adc	\ACC_12,\ACC_12
	adc	\ACC_13,\ACC_13
	adc	\ACC_14,\ACC_14
	adc	\ACC_15,\ACC_15

	mul	\A1,\A1
	movw	\TMP,r0

	mul	\A0,\A0
	movw	\A0,r0

	mul	\A2,\A2
	mov	\ACC_0,\A0
	add	\ACC_1,\A1
	adc	\ACC_2,\TMP
	adc	\ACC_3,\TMP2
	adc	\ACC_4,r0
	adc	\ACC_5,r1
	rol	\ACC_15		//save carry

	mul	\A4,\A4
	movw	\A0,r0

	mul	\A3,\A3
	movw	\TMP,r0

	mul	\A5,\A5
	movw	\A2,r0

	mul	\A6,\A6
	movw	\A4,r0

	mul	\A7,\A7

	lsr	\ACC_15		//renew carry
	adc	\ACC_6,\TMP
	adc	\ACC_7,\TMP2
	adc	\ACC_8,\A0
	adc	\ACC_9,\A1
	adc	\ACC_10,\A2
	adc	\ACC_11,\A3
	adc	\ACC_12,\A4
	adc	\ACC_13,\A5
	adc	\ACC_14,r0
	adc	\ACC_15,r1
.endm
// same as SQUARE_64, but ACC_0 is not used, result byte 0 is stored to Z+ M0
.macro SQUARE_64_M	ACC_15 ACC_14 ACC_13 ACC_12 ACC_11 ACC_10 ACC_9 ACC_8 ACC_7 ACC_6 ACC_5 ACC_4 ACC_3 ACC_2 ACC_1 ACC_0 M0 A7 A6 A5 A4 A3 A2 A1 A0 TMP2 TMP
	clr	\ACC_15
	mul	\A0,\A2
	movw	\ACC_2,r0

	mul	\A0,\A1
	mov	\ACC_1,r0
	add	\ACC_2,r1
	adc	\ACC_3,\ACC_15

	mul	\A0,\A4
	movw	\ACC_4,r0

	mul	\A0,\A6
	movw	\ACC_6,r0

	mul	\A1,\A7
	movw	\ACC_8,r0

	mul	\A3,\A7
	movw	\ACC_10,r0

	mul	\A5,\A7
	movw	\ACC_12,r0

	mul	\A1,\A2
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\ACC_15

	mul	\A2,\A3
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\ACC_15

//FE01 FE01 FE01 FEFF FFFF FFFF 0100
////////////////////////////
	mul	\A1,\A4
	movw	\TMP,r0

	mul	\A0,\A3
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\TMP
	adc	\TMP2,\ACC_15

	mul	\A1,\A3
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\TMP2,\ACC_15

	mul	\A3,\A4
	add	\ACC_6,\TMP2
	adc	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\ACC_15
//FE01 FE01 FF00 00FE FFFF 00FF 0100
///////////////////////////////
	mul	\A0,\A7
	movw	\TMP,r0

	mul	\A0,\A5
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\TMP
	adc	\TMP2,\ACC_15

	mul	\A1,\A5
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\TMP2,\ACC_15

	mul	\A2,\A7
	add	\ACC_8,\TMP2
	adc	\ACC_9,r0
	adc	\ACC_10,r1
	adc	\ACC_11,\ACC_15
//FE01 FF00 00FF 00FE 00FF 00FF 0100
////////////////////////////////
	mul	\A4,\A5
	movw	\TMP,r0

	mul	\A2,\A5
	add	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\TMP
	adc	\TMP2,\ACC_15

	mul	\A3,\A5
	add	\ACC_8,r0
	adc	\ACC_9,r1
	adc	\TMP2,\ACC_15

	mul	\A5,\A6
	add	\ACC_10,\TMP2
	adc	\ACC_11,r0
	adc	\ACC_12,r1
	adc	\ACC_13,\ACC_15
//FF00 00FF 00FE 01FE 00FF 00FF 0100
////////////////////////////////
	mul	\A3,\A6
	movw	\TMP,r0

	mul	\A1,\A6
	add	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\TMP
	adc	\TMP2,\ACC_15

	mul	\A2,\A6
	add	\ACC_8,r0
	adc	\ACC_9,r1
	adc	\TMP2,\ACC_15

	mul	\A4,\A7
	add	\ACC_10,\TMP2
	adc	\ACC_11,r0
	adc	\ACC_12,r1
	adc	\ACC_13,\ACC_15
//FFFE 02FE 00FD 02FE 00FF 00FF 0100
////////////////////////////////
	mul	\A4,\A6
	movw	\TMP,r0

	mul	\A2,\A4
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\ACC_8,\ACC_15
	adc	\ACC_9,\ACC_15
	adc	\ACC_10,\TMP
	adc	\ACC_11,\TMP2
	adc	\ACC_12,\ACC_15
	adc	\ACC_13,\ACC_15
//FFFF 00FF 00FE 00FF 00FF 00FF 0100
////////////////////////////////
	mul	\A6,\A7
	add	\ACC_13,r0
	clr	\ACC_14
	adc	\ACC_14,r1

// maximal result 00FF00FF 00FF00FE 00FF00FF 00FF0100
// there is no carry to ACC_15

// double result
	add	\ACC_1,\ACC_1
	adc	\ACC_2,\ACC_2
	adc	\ACC_3,\ACC_3
	adc	\ACC_4,\ACC_4
	adc	\ACC_5,\ACC_5
	adc	\ACC_6,\ACC_6
	adc	\ACC_7,\ACC_7
	adc	\ACC_8,\ACC_8
	adc	\ACC_9,\ACC_9
	adc	\ACC_10,\ACC_10
	adc	\ACC_11,\ACC_11
	adc	\ACC_12,\ACC_12
	adc	\ACC_13,\ACC_13
	adc	\ACC_14,\ACC_14
	adc	\ACC_15,\ACC_15

	mul	\A1,\A1
	movw	\TMP,r0

	mul	\A0,\A0
	std	Z+\M0,r0
	mov	\A1,r1

	mul	\A2,\A2
	add	\ACC_1,\A1
	adc	\ACC_2,\TMP
	adc	\ACC_3,\TMP2
	std     Z+1+\M0,\ACC_1
	std     Z+2+\M0,\ACC_2
	std     Z+3+\M0,\ACC_3
	adc	\ACC_4,r0
	adc	\ACC_5,r1
	rol	\ACC_15		//save carry

	mul	\A4,\A4
	movw	\A0,r0

	mul	\A3,\A3
	movw	\TMP,r0

	mul	\A5,\A5
	movw	\A2,r0

	mul	\A6,\A6
	movw	\A4,r0

	mul	\A7,\A7

	lsr	\ACC_15		//renew carry
	adc	\ACC_6,\TMP
	adc	\ACC_7,\TMP2
	adc	\ACC_8,\A0
	adc	\ACC_9,\A1
	adc	\ACC_10,\A2
	adc	\ACC_11,\A3
	adc	\ACC_12,\A4
	adc	\ACC_13,\A5
	adc	\ACC_14,r0
	adc	\ACC_15,r1
.endm

.macro	REG_SUB_MEM128  A15 A14 A13 A12 A11 A10 A9 A8 A7 A6 A5 A4 A3 A2 A1 A0 M TMP
	ldd	\TMP,Y+\M+0
	sub	\A0,\TMP
	ldd	\TMP,Y+\M+1
	sbc	\A1,\TMP
	ldd	\TMP,Y+\M+2
	sbc	\A2,\TMP
	ldd	\TMP,Y+\M+3
	sbc	\A3,\TMP
	ldd	\TMP,Y+\M+4
	sbc	\A4,\TMP
	ldd	\TMP,Y+\M+5
	sbc	\A5,\TMP
	ldd	\TMP,Y+\M+6
	sbc	\A6,\TMP
	ldd	\TMP,Y+\M+7
	sbc	\A7,\TMP
	ldd	\TMP,Y+\M+8
	sbc	\A8,\TMP
	ldd	\TMP,Y+\M+9
	sbc	\A9,\TMP
	ldd	\TMP,Y+\M+10
	sbc	\A10,\TMP
	ldd	\TMP,Y+\M+11
	sbc	\A11,\TMP
	ldd	\TMP,Y+\M+12
	sbc	\A12,\TMP
	ldd	\TMP,Y+\M+13
	sbc	\A13,\TMP
	ldd	\TMP,Y+\M+14
	sbc	\A14,\TMP
	ldd	\TMP,Y+\M+15
	sbc	\A15,\TMP
.endm
.macro	EOR128	A15 A14 A13 A12 A11 A10 A9 A8 A7 A6 A5 A4 A3 A2 A1 A0  VAL
	eor	\A0,\VAL
	eor	\A1,\VAL
	eor	\A2,\VAL
	eor	\A3,\VAL
	eor	\A4,\VAL
	eor	\A5,\VAL
	eor	\A6,\VAL
	eor	\A7,\VAL
	eor	\A8,\VAL
	eor	\A9,\VAL
	eor	\A10,\VAL
	eor	\A11,\VAL
	eor	\A12,\VAL
	eor	\A13,\VAL
	eor	\A14,\VAL
	eor	\A15,\VAL
.endm
// result = MEM - operand  
.macro	REG_MEM_SUB_REG128	T15 T14 T13 T12 T11 T10 T9 T8 T7 T6 T5 T4 T3 T2 T1 T0	\
			M \
			S15 S14 S13 S12 S11 S10 S9 S8 S7 S6 S5 S4 S3 S2 S1 S0	\

	ldd	\T0,Z+0+\M
	sub	\T0,\S0
	ldd	\T1,Z+1+\M
	sbc	\T1,\S1
	ldd	\T2,Z+2+\M
	sbc	\T2,\S2
	ldd	\T3,Z+3+\M
	sbc	\T3,\S3
	ldd	\T4,Z+4+\M
	sbc	\T4,\S4
	ldd	\T5,Z+5+\M
	sbc	\T5,\S5
	ldd	\T6,Z+6+\M
	sbc	\T6,\S6
	ldd	\T7,Z+7+\M
	sbc	\T7,\S7
	ldd	\T8,Z+8+\M
	sbc	\T8,\S8
	ldd	\T9,Z+9+\M
	sbc	\T9,\S9
	ldd	\T10,Z+10+\M
	sbc	\T10,\S10
	ldd	\T11,Z+11+\M
	sbc	\T11,\S11
	ldd	\T12,Z+12+\M
	sbc	\T12,\S12
	ldd	\T13,Z+13+\M
	sbc	\T13,\S13
	ldd	\T14,Z+14+\M
	sbc	\T14,\S14
	ldd	\T15,Z+15+\M
	sbc	\T15,\S15

.endm
// result = MEM - operand  
.macro	REG_MEM_SBC_REG128	T15 T14 T13 T12 T11 T10 T9 T8 T7 T6 T5 T4 T3 T2 T1 T0	\
			M \
			S15 S14 S13 S12 S11 S10 S9 S8 S7 S6 S5 S4 S3 S2 S1 S0	\

	ldd	\T0,Z+0+\M
	sbc	\T0,\S0
	ldd	\T1,Z+1+\M
	sbc	\T1,\S1
	ldd	\T2,Z+2+\M
	sbc	\T2,\S2
	ldd	\T3,Z+3+\M
	sbc	\T3,\S3
	ldd	\T4,Z+4+\M
	sbc	\T4,\S4
	ldd	\T5,Z+5+\M
	sbc	\T5,\S5
	ldd	\T6,Z+6+\M
	sbc	\T6,\S6
	ldd	\T7,Z+7+\M
	sbc	\T7,\S7
	ldd	\T8,Z+8+\M
	sbc	\T8,\S8
	ldd	\T9,Z+9+\M
	sbc	\T9,\S9
	ldd	\T10,Z+10+\M
	sbc	\T10,\S10
	ldd	\T11,Z+11+\M
	sbc	\T11,\S11
	ldd	\T12,Z+12+\M
	sbc	\T12,\S12
	ldd	\T13,Z+13+\M
	sbc	\T13,\S13
	ldd	\T14,Z+14+\M
	sbc	\T14,\S14
	ldd	\T15,Z+15+\M
	sbc	\T15,\S15

.endm

// 0
// 1 0.1
// 2 0_2
// 3 0.3 1/2
// 4 0_4 1/3
// 5 0.5 1/4 2x3
// 6 1_5 2x4
// 7 2/5 3x4
// 8 3_5
// 9 4x5
//10
//11
// ACC5..ACC0 is saved to stack
.macro SQUARE_48_sp	ACC_11 ACC_10 ACC_9 ACC_8 ACC_7 ACC_6 ACC_5 ACC_4 ACC_3 ACC_2 ACC_1 ACC_0  A5 A4 A3 A2 A1 A0
	clr	\ACC_0
// ------------------ _
	mul	\A0,\A2
	movw	\ACC_2,r0

	mul	\A0,\A4
	movw	\ACC_4,r0

	mul	\A1,\A5
	movw	\ACC_6,r0

	mul	\A3,\A5
	movw	\ACC_8,r0

//------------------ .
	mul	\A0,\A1
	mov	\ACC_1,r0
	add	\ACC_2,r1
	adc	\ACC_3,\ACC_0

	mul	\A0,\A3
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\ACC_0

	mul	\A0,\A5
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\ACC_0

//----------------- /
	mul	\A1,\A4
	movw	\ACC_10,r0

	mul	\A1,\A2
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\ACC_10
	adc	\ACC_11,\ACC_0

	mul	\A1,\A3
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\ACC_11,\ACC_0

	mul	\A2,\A5
	add	\ACC_6,\ACC_11
	adc	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\ACC_0

//----------------- x
	mul	\A3,\A4
	movw	\ACC_10,r0

	mul	\A2,\A3
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\ACC_10
	adc	\ACC_11,\ACC_0

	mul	\A2,\A4
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\ACC_11,\ACC_0

	mul	\A4,\A5
	add	\ACC_8,\ACC_11
	adc	\ACC_9,r0
        clr	\ACC_10
	adc	\ACC_10,r1

	clr	\ACC_11

// maximal result is 00FF00 FF00FE 00FF00 FF0100, there is no carry to ACC_11

// double result
	add	\ACC_1,\ACC_1
	adc	\ACC_2,\ACC_2
	adc	\ACC_3,\ACC_3
	adc	\ACC_4,\ACC_4
	adc	\ACC_5,\ACC_5
	adc	\ACC_6,\ACC_6
	adc	\ACC_7,\ACC_7
	adc	\ACC_8,\ACC_8
	adc	\ACC_9,\ACC_9
	adc	\ACC_10,\ACC_10
	adc	\ACC_11,\ACC_11
// this is old code, result is in ACC_11.. ACC_0
#if 0
	mul	\A0,\A0
	mov	\ACC_0,r0
	add	\ACC_1,r1

	rol	\ACC_11		//save carry
	mul	\A1,\A1
	ror	\ACC_11		//renew carry
	adc	\ACC_2,r0
	adc	\ACC_3,r1

	rol	\ACC_11
	mul	\A2,\A2
	ror	\ACC_11		//renew carry
	adc	\ACC_4,r0
	adc	\ACC_5,r1

	rol	\ACC_11
	mul	\A3,\A3
	ror	\ACC_11		//renew carry
	adc	\ACC_6,r0
	adc	\ACC_7,r1

	rol	\ACC_11
	mul	\A4,\A4
	ror	\ACC_11		//renew carry
	adc	\ACC_8,r0
	adc	\ACC_9,r1

	rol	\ACC_11
	mul	\A5,\A5
	lsr	\ACC_11		//renew carry
	adc	\ACC_10,r0
	adc	\ACC_11,r1
#else
// new code result in ACCC_11.. ACC_6 .. then 6 bytes in stack
	mul	\A0,\A0
	push	r0
	add	\ACC_1,r1
	push	\ACC_1
	rol	\ACC_11		//save carry

	mul	\A2,\A2
	movw	\ACC_0,r0	// save to stack ..

	mul	\A1,\A1
	ror	\ACC_11		//renew carry
	adc	\ACC_2,r0
	adc	\ACC_3,r1
	adc	\ACC_4,\ACC_0
	adc	\ACC_5,\ACC_1

	push	\ACC_2
	push	\ACC_3
	push	\ACC_4
	push	\ACC_5
	rol	\ACC_11		//save carry

	mul	\A5,\A5
	movw	\ACC_2,r0

	mul	\A4,\A4
	movw	\ACC_0,r0

	mul	\A3,\A3
	lsr	\ACC_11		//renew carry
	adc	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\ACC_8,\ACC_0
	adc	\ACC_9,\ACC_1
	adc	\ACC_10,\ACC_2
	adc	\ACC_11,\ACC_3

#endif
.endm

// 0
// 1 0.1
// 2 0_2
// 3 0.3 1/2
// 4 0_4 1/3
// 5 0.5 1/4 2x3
// 6 1_5 2x4
// 7 2/5 3x4
// 8 3_5
// 9 4x5
//10
//11
//A0..A5 no needed anymore
.macro SQUARE_48c	ACC_11 ACC_10 ACC_9 ACC_8 ACC_7 ACC_6 ACC_5 ACC_4 ACC_3 ACC_2 ACC_1 ACC_0  A5 A4 A3 A2 A1 A0
	clr	\ACC_0
// ------------------ _
	mul	\A0,\A2
	movw	\ACC_2,r0

	mul	\A0,\A4
	movw	\ACC_4,r0

	mul	\A1,\A5
	movw	\ACC_6,r0

	mul	\A3,\A5
	movw	\ACC_8,r0

//------------------ .
	mul	\A0,\A1
	mov	\ACC_1,r0
	add	\ACC_2,r1
	adc	\ACC_3,\ACC_0

	mul	\A0,\A3
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\ACC_0

	mul	\A0,\A5
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\ACC_0

//----------------- /
	mul	\A1,\A4
	movw	\ACC_10,r0

	mul	\A1,\A2
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\ACC_10
	adc	\ACC_11,\ACC_0

	mul	\A1,\A3
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\ACC_11,\ACC_0

	mul	\A2,\A5
	add	\ACC_6,\ACC_11
	adc	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\ACC_0

//----------------- x
	mul	\A3,\A4
	movw	\ACC_10,r0

	mul	\A2,\A3
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\ACC_10
	adc	\ACC_11,\ACC_0

	mul	\A2,\A4
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\ACC_11,\ACC_0

	mul	\A4,\A5
	add	\ACC_8,\ACC_11
	adc	\ACC_9,r0
        clr	\ACC_10
	adc	\ACC_10,r1

	clr	\ACC_11

// maximal result is 00FF00 FF00FE 00FF00 FF0100, there is no carry to ACC_11

// double result
	add	\ACC_1,\ACC_1
	adc	\ACC_2,\ACC_2
	adc	\ACC_3,\ACC_3
	adc	\ACC_4,\ACC_4
	adc	\ACC_5,\ACC_5
	adc	\ACC_6,\ACC_6
	adc	\ACC_7,\ACC_7
	adc	\ACC_8,\ACC_8
	adc	\ACC_9,\ACC_9
	adc	\ACC_10,\ACC_10
	adc	\ACC_11,\ACC_11

	mul	\A0,\A0
	mov	\ACC_0,r0
	add	\ACC_1,r1

	rol	\ACC_11		//save carry
	mul	\A1,\A1
	ror	\ACC_11		//renew carry
	adc	\ACC_2,r0
	adc	\ACC_3,r1

	rol	\ACC_11
	mul	\A3,\A3
	movw	\A0,r0

	mul	\A2,\A2
	ror	\ACC_11		//renew carry
	adc	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\ACC_6,\A0
	adc	\ACC_7,\A1

	rol	\ACC_11

	mul	\A5,\A5
	movw	\A0,r0

	mul	\A4,\A4
	lsr	\ACC_11		//renew carry
	adc	\ACC_8,r0
	adc	\ACC_9,r1
	adc	\ACC_10,\A0
	adc	\ACC_11,\A1
.endm

// M0 is memory position (Z+M0) where result byte 0 is stored
.macro SQUARE_48_z	ACC_11 ACC_10 ACC_9 ACC_8 ACC_7 ACC_6 ACC_5 ACC_4 ACC_3 ACC_2 ACC_1  M0   A5 A4 A3 A2 A1 A0   TMP5 TMP4 TMP3 TMP2 TMP1 TMP0
	clr	\ACC_11
// ------------------ _
	mul	\A0,\A2
	movw	\ACC_2,r0

	mul	\A0,\A4
	movw	\ACC_4,r0

	mul	\A1,\A5
	movw	\ACC_6,r0

	mul	\A3,\A5
	movw	\ACC_8,r0

//------------------ .
	mul	\A0,\A1
	mov	\ACC_1,r0
	add	\ACC_2,r1
	adc	\ACC_3,\ACC_11

	mul	\A0,\A3
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\ACC_11

	mul	\A0,\A5
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\ACC_11

//----------------- /
	mul	\A1,\A4
	movw	\TMP0,r0

	mul	\A1,\A2
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\TMP0
	adc	\TMP1,\ACC_11

	mul	\A1,\A3
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\TMP1,\ACC_11

	mul	\A2,\A5
	add	\ACC_6,\TMP1
	adc	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\ACC_11

//----------------- x
	mul	\A3,\A4
	movw	\TMP0,r0

	mul	\A2,\A3
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\TMP0
	adc	\TMP1,\ACC_11

	mul	\A2,\A4
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\TMP1,\ACC_11

	mul	\A4,\A5
	add	\ACC_8,\TMP1
	adc	\ACC_9,r0
        clr	\ACC_10
	adc	\ACC_10,r1


// maximal result is 00FF00 FF00FE 00FF00 FF0100, there is no carry to ACC_11

// double result
	add	\ACC_1,\ACC_1
	adc	\ACC_2,\ACC_2
	adc	\ACC_3,\ACC_3
	adc	\ACC_4,\ACC_4
	adc	\ACC_5,\ACC_5
	adc	\ACC_6,\ACC_6
	adc	\ACC_7,\ACC_7
	adc	\ACC_8,\ACC_8
	adc	\ACC_9,\ACC_9
	adc	\ACC_10,\ACC_10
	adc	\ACC_11,\ACC_11

	mul	\A3,\A3
	movw	\TMP4,r0

	mul	\A2,\A2
	movw	\TMP2,r0

	mul	\A1,\A1
	movw	\TMP0,r0

	mul	\A0,\A0
	std	Z+\M0,r0
	add	\ACC_1,r1
	adc	\ACC_2,\TMP0
	adc	\ACC_3,\TMP1
	adc	\ACC_4,\TMP2
	adc	\ACC_5,\TMP3
	adc	\ACC_6,\TMP4
	adc	\ACC_7,\TMP5
	rol	\ACC_11		//save carry

	mul	\A5,\A5
	movw	\TMP0,r0

	mul	\A4,\A4
	lsr	\ACC_11		//renew carry
	adc	\ACC_8,r0
	adc	\ACC_9,r1
	adc	\ACC_10,\TMP0
	adc	\ACC_11,\TMP1
.endm
// 0
// 1 0v1
// 2 0v2
// 3 0v3 1^2
// 4 0^4 1_3
// 5 0v5 1^4 2_3
// 6 1*5 2_4
// 7 2^5 3_4
// 8 3*5
// 9 4_5
//10
//11
// A5..A0 can be reused
.macro SQUARE_48_ADD  ACC_11 ACC_10 ACC_9 ACC_8 ACC_7 ACC_6 ACC_5 ACC_4 ACC_3 ACC_2 ACC_1 ACC_0  A5 A4 A3 A2 A1 A0  Z_TMP TMP  XTMP16h XTMP16l
#if 0
// old code, below new faster code
//load bit 0
	bst	\ACC_1,0
//divide 
	lsr	\ACC_5
	ror	\ACC_4
	ror	\ACC_3
	ror	\ACC_2
	ror	\ACC_1

	clr	\ACC_11

	mul	\A1,\A5
	movw	\ACC_6,r0
	mul	\A3,\A5
	movw	\ACC_8,r0

	mul	\A0,\A3
	movw	\XTMP16l,r0

	mul	\A0,\A1
	add	\ACC_1,r0
	adc	\ACC_2,r1
	adc	\ACC_3,\XTMP16l
	adc	\XTMP16h,\ACC_11	//ZERO

	mul	\A0,\A2
	add	\ACC_2,r0
	adc	\ACC_3,r1
	adc	\XTMP16h,\ACC_11	//ZERO

	mul	\A0,\A5
	add	\ACC_4,\XTMP16h
	adc	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\ACC_11  //ZERO
//// max FEFF81FEFFFF00FF
	mul	\A1,\A4
	movw	\XTMP16l,r0
	
	mul	\A1,\A2
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\XTMP16l
	adc	\XTMP16h,\ACC_11  //ZERO

	mul	\A0,\A4
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\XTMP16h,\ACC_11  //ZERO  XTMP16h is to be added to ACC_6

	mul	\A2,\A5
	add	\ACC_6,\XTMP16h
	adc	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\ACC_11  //ZERO
//
	mul	\A2,\A4
	movw	 \XTMP16l,r0
	
	mul	\A1,\A3
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\ACC_6,\XTMP16l
	adc	\XTMP16h,\ACC_11  //ZERO

	mul	\A2,\A3
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\XTMP16h,\ACC_11  //ZERO
//
	mul	\A3,\A4
	add	\ACC_7,r0
	adc	\ACC_8,r1
	adc	\ACC_9,\ACC_11  //ZERO

	mul	\A4,\A5
	add	\ACC_7,\XTMP16h
	adc	\ACC_8,\ACC_11  //ZERO
	adc	\ACC_9,r0
	adc	r1,\ACC_11  	//ZERO
	mov	\ACC_10,r1
// max in acc .. FF00FF00FF00FF00FF00FF there is no carry to ACC_11

// double result

	add	\ACC_1,\ACC_1
	adc	\ACC_2,\ACC_2
	adc	\ACC_3,\ACC_3
	adc	\ACC_4,\ACC_4
	adc	\ACC_5,\ACC_5
	adc	\ACC_6,\ACC_6
	adc	\ACC_7,\ACC_7
	adc	\ACC_8,\ACC_8
	adc	\ACC_9,\ACC_9
	adc	\ACC_10,\ACC_10
	adc	\ACC_11,\ACC_11
	bld	\ACC_1,0

	mul	\A2,\A2
	movw	\XTMP16l,r0

	mul	\A1,\A1
	movw	\TMP,r0

	mul	\A0,\A0
	add	\ACC_0,r0
	adc	\ACC_1,r1
	adc	\ACC_2,\TMP
	adc	\ACC_3,\Z_TMP
	adc	\ACC_4,\XTMP16l
	adc	\ACC_5,\XTMP16h
	rol	\ACC_11		//save carry

	mul	\A5,\A5
	movw	\XTMP16l,r0

	mul	\A4,\A4
	movw	\TMP,r0

	mul	\A3,\A3
	lsr	\ACC_11		//renew carry
	adc	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\ACC_8,\TMP
	adc	\ACC_9,\Z_TMP
	adc	\ACC_10,\XTMP16l
	adc	\ACC_11,\XTMP16h
#else
// ACC_5..ACC_0 FFFFFFFFFFFE

	mul	\A2,\A2
	movw	\ACC_10,r0

	mul	\A1,\A1
	movw	\ACC_8,r0

	mul	\A0,\A0
	add	\ACC_0,r0
	adc	\ACC_1,r1
	adc	\ACC_2,\ACC_8
	adc	\ACC_3,\ACC_9
	adc	\ACC_4,\ACC_10
	adc	\ACC_5,\ACC_11
// (carry) ACC_5..ACC_0 (1) FE01FE01FDFF

//load bit 0
	bst	\ACC_1,0
//divide (inclusive carry)
	ror	\ACC_5
	ror	\ACC_4
	ror	\ACC_3
	ror	\ACC_2
	ror	\ACC_1
// ACC_5..ACC_0 FF00FF00FEFF
// 0
// 1 0_1
// 2 0_2
// 3 0_3   1+2
// 4 0+4   1 3
// 5 0+5   1 4   2 3
// 6 1 5   2 4
// 7 2 5   3 4
// 8 3 5
// 9 4 5
//10
//11
// max ACC_5 .. ACC_0 = FF00FF 00FEFF
	mul	\A1,\A5
	movw	\ACC_6,r0

	mul	\A3,\A5
	movw	\ACC_8,r0
	clr	\ACC_10
	clr	\ACC_11
/////////////////////////////////////////// _
	mul	\A0,\A3
	movw	\XTMP16l,r0

	mul	\A0,\A1
	add	\ACC_1,r0
	adc	\ACC_2,r1
	adc	\ACC_3,\XTMP16l
	adc	\XTMP16h,\ACC_11	//zero

	mul	\A0,\A2
	add	\ACC_2,r0
	adc	\ACC_3,r1
	adc	\ACC_4,\XTMP16h
	adc	\ACC_5,\ACC_11		//zero
//  FE01 FE01 || FFFF FEFF FFFF
///////////////////////////////////////////// +
	mul	\A0,\A5
	movw	\XTMP16l,r0

	mul	\A1,\A2
	add	\ACC_3,r0
	adc	\ACC_4,r1
	adc	\ACC_5,\XTMP16l
	adc	\XTMP16h,\ACC_11	//zero

// not efective, but working (1843 - 4)
//XTMP16h: FF  FE01 FE01 || 01FD FFFF FFFF
	mul	\A0,\A4				//
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\ACC_6,\XTMP16h
	adc	\ACC_7,\ACC_11		//zero
// ACC_9..ACC_0:   FE01 FF00 || FFFE FFFF FFFF
	mul	\A2,\A4				//
	movw	\XTMP16l,r0

	mul	\A1,\A3				//
	add	\ACC_4,r0
	adc	\ACC_5,r1
	adc	\ACC_6,\XTMP16l
	adc	\ACC_7,\XTMP16h

	adc	\ACC_8,\ACC_11
	adc	\ACC_9,\ACC_11

	mul	\A2,\A5				//
	movw	\XTMP16l,r0

	mul	\A1,\A4				//
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\XTMP16l
	adc	\ACC_8,\XTMP16h
	adc	\ACC_9,\ACC_11

// FE03FB 04FC00 FFFFFF
	mul	\A3,\A4				//
	movw	\XTMP16l,r0

	mul	\A4,\A5				//
	movw	\TMP,r0

	mul	\A2,\A3				//
	add	\ACC_5,r0
	adc	\ACC_6,r1
	adc	\ACC_7,\XTMP16l
	adc	\ACC_8,\XTMP16h
	adc	\ACC_9,\TMP
	adc	\ACC_10,\Z_TMP

// double result

	add	\ACC_1,\ACC_1
	adc	\ACC_2,\ACC_2
	adc	\ACC_3,\ACC_3
	adc	\ACC_4,\ACC_4
	adc	\ACC_5,\ACC_5
	adc	\ACC_6,\ACC_6
	adc	\ACC_7,\ACC_7
	adc	\ACC_8,\ACC_8
	adc	\ACC_9,\ACC_9
	adc	\ACC_10,\ACC_10
	adc	\ACC_11,\ACC_11
	bld	\ACC_1,0

	mul	\A5,\A5
	movw	\XTMP16l,r0

	mul	\A4,\A4
	movw	\TMP,r0

	mul	\A3,\A3
	add	\ACC_6,r0
	adc	\ACC_7,r1
	adc	\ACC_8,\TMP
	adc	\ACC_9,\Z_TMP
	adc	\ACC_10,\XTMP16l
	adc	\ACC_11,\XTMP16h
#endif

.endm
.macro 	LOAD48_FROM_Y_MEM	A5 A4 A3 A2 A1 A0  M
	ldd	\A0,Y+\M+0
	ldd	\A1,Y+\M+1
	ldd	\A2,Y+\M+2
	ldd	\A3,Y+\M+3
	ldd	\A4,Y+\M+4
	ldd	\A5,Y+\M+5
.endm
.macro	STORE48_TO_MEM	 M  REG5 REG4 REG3 REG2 REG1 REG0
	std	Z+0+\M, \REG0
	std	Z+1+\M, \REG1
	std	Z+2+\M, \REG2
	std	Z+3+\M, \REG3
	std	Z+4+\M, \REG4
	std	Z+5+\M, \REG5
.endm
.macro	ABS_SUB48	RZ5 RZ4 RZ3 RZ2 RZ1 RZ0	A5 A4 A3 A2 A1 A0       TMP
	sub	\RZ0,\A0
	sbc	\RZ1,\A1
	sbc	\RZ2,\A2
	sbc	\RZ3,\A3
	sbc	\RZ4,\A4
	sbc	\RZ5,\A5
	
	sbc	\TMP,\TMP
	eor	\RZ0,\TMP
	eor	\RZ1,\TMP
	eor	\RZ2,\TMP
	eor	\RZ3,\TMP
	eor	\RZ4,\TMP
	eor	\RZ5,\TMP

	sub	\RZ0,\TMP
	sbc	\RZ1,\TMP
	sbc	\RZ2,\TMP
	sbc	\RZ3,\TMP
	sbc	\RZ4,\TMP
	sbc	\RZ5,\TMP
.endm
.macro	ADD48	RZ5 RZ4 RZ3 RZ2 RZ1 RZ0  A5 A4 A3 A2 A1 A0
	add	\RZ0,\A0
	adc	\RZ1,\A1
	adc	\RZ2,\A2
	adc	\RZ3,\A3
	adc	\RZ4,\A4
	adc	\RZ5,\A5
	
.endm
.macro	ADC48	RZ5 RZ4 RZ3 RZ2 RZ1 RZ0  A5 A4 A3 A2 A1 A0
	adc	\RZ0,\A0
	adc	\RZ1,\A1
	adc	\RZ2,\A2
	adc	\RZ3,\A3
	adc	\RZ4,\A4
	adc	\RZ5,\A5
.endm
.macro SUB48	RZ5 RZ4 RZ3 RZ2 RZ1 RZ0   A5 A4 A3 A2 A1 A0
	sub	\RZ0,\A0
	sbc	\RZ1,\A1
	sbc	\RZ2,\A2
	sbc	\RZ3,\A3
	sbc	\RZ4,\A4
	sbc	\RZ5,\A5
.endm
.macro SBC48	RZ5 RZ4 RZ3 RZ2 RZ1 RZ0   A5 A4 A3 A2 A1 A0
	sbc	\RZ0,\A0
	sbc	\RZ1,\A1
	sbc	\RZ2,\A2
	sbc	\RZ3,\A3
	sbc	\RZ4,\A4
	sbc	\RZ5,\A5
.endm
.macro	LOAD48_FROM_MEM_  REG5 REG4 REG3 REG2 REG1 REG0    M
	ldd	\REG0,Z+0+\M
	ldd	\REG1,Z+1+\M
	ldd	\REG2,Z+2+\M
	ldd	\REG3,Z+3+\M
	ldd	\REG4,Z+4+\M
	ldd	\REG5,Z+5+\M
.endm
.macro ABS96 ACC_11 ACC_10 ACC_9 ACC_8 ACC_7 ACC_6 ACC_5 ACC_4 ACC_3 ACC_2 ACC_1 ACC_0 CARRY
	eor	\ACC_0, \CARRY
	eor	\ACC_1, \CARRY
	eor	\ACC_2, \CARRY
	eor	\ACC_3, \CARRY
	eor	\ACC_4, \CARRY
	eor	\ACC_5, \CARRY
	eor	\ACC_6, \CARRY
	eor	\ACC_7, \CARRY
	eor	\ACC_8, \CARRY
	eor	\ACC_9, \CARRY
	eor	\ACC_10,\CARRY
	eor	\ACC_11,\CARRY
	sub	\ACC_0, \CARRY
	sbc	\ACC_1, \CARRY
	sbc	\ACC_2, \CARRY
	sbc	\ACC_3, \CARRY
	sbc	\ACC_4, \CARRY
	sbc	\ACC_5, \CARRY
	sbc	\ACC_6, \CARRY
	sbc	\ACC_7, \CARRY
	sbc	\ACC_8, \CARRY
	sbc	\ACC_9, \CARRY
	sbc	\ACC_10,\CARRY
	sbc	\ACC_11,\CARRY
.endm


// dependency check

#if \
defined (HAVE_RSA_SQUARE_1024_NO_ABI) || \
defined (HAVE_RSA_SQUARE_1024)
#if !defined (HAVE_RSA_SQUARE_512_NO_ABI)
#define HAVE_RSA_SQUARE_512_NO_ABI
#endif
#endif

#if \
defined (HAVE_RSA_SQUARE_512_NO_ABI) || \
defined (HAVE_RSA_SQUARE_512)
#if !defined (HAVE_RSA_SQUARE_256_NO_ABI)
#define HAVE_RSA_SQUARE_256_NO_ABI
#endif
#endif


#if defined (HAVE_RSA_SQUARE_1024)
	.global rsa_square_1024
	.type rsa_square_1024, @function
rsa_square_1024:
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
#if defined (HAVE_RSA_SQUARE_1024_NO_ABI)
	rcall	rsa_square_1024_no_abi
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
#endif //HAVE_RSA_SQUARE_1024_NO_ABI
#endif // HAVE_RSA_SQUARE_1024

#if defined (HAVE_RSA_SQUARE_1024_NO_ABI)
	.global rsa_square_1024_no_abi
	.type rsa_square_1024_no_abi, @function
rsa_square_1024_no_abi:
// input r22,23  result r24,25
#endif
#if defined (HAVE_RSA_SQUARE_1024_NO_ABI) || defined (HAVE_RSA_SQUARE_1024)

// create space on stack(128 bytes TMP variable, 2x pointer
	in	r26, 0x3d
	in	r27, 0x3e
	subi	r26, 128+2+2
	sbc	r27, r1
	LOAD_SP	r0, r26 r27

// save pointers to stack, rsa_square_512_no_abi uses _all_ registers
	adiw	r26,1
	st	X+,r22	// operand pointer
	st	X+,r23
	st	X+,r24	// Result
	st	X+,r25
// calculate a_low - a_high -> r
	movw	r30,r24		// r to Z
	movw	r28,r22		// OPERAND to Y

	ldi	r25,8		//8*8 = 64 bytes
	sub	r24,r24		//initial carry(s)
rsa_square_1024_loop1:
// load A into r0..r7, A+64 to r8..r15
.irp	pos,0,1,2,3,4,5,6,7
	ld	r\pos,Y+
.endr
.irp	pos,8,9,10,11,12,13,14,15
	ldd	r\pos,Y+48+\pos
.endr
// copy
.irp	reg,0,2,4,6
	movw	\reg+16,\reg
.endr
//calculate H-L and L-H, save both results
.irp	reg,0,1,2,3,4,5,6,7
	sbc	\reg,\reg+8
	st	Z+,\reg
.endr
	ror	r24	//save carry/renew carry
.irp	reg,0,1,2,3,4,5,6,7
	sbc	\reg+8,\reg+16
	std	Z+8+48+\reg,\reg+8
.endr
	rol	r24	//renew carry
	dec	r25
	brne	rsa_square_1024_loop1
// select RESULT  or RESULT + 64
	bst	r24,0
	bld	r25,6
	sub	r30,r25
	sbci	r31,0
	movw	r22,r30

	movw	r30,r26
	rcall    rsa_square_512_no_abi
// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	ldd	r22,Y+1	// OPERAND
	ldd	r23,Y+2
// a_low * a_low to r
	rcall	rsa_square_512_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
// a_high * a_high to r+128
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	subi	r30,lo8(-128)
	sbci	r31,hi8(-128)
	ldd	r22,Y+1	// OPERAND
	ldd	r23,Y+2
	subi	r22,lo8(-64)
	sbci	r23,hi8(-64)	//A+64
	rcall	rsa_square_512_no_abi

// load values back
	in	r28, 0x3d
	in	r29, 0x3e
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	movw	r26,r28
	adiw	r26,5		// skip variables on stack to point 128 byt TMP
// TODO, this code can be shared with 768 bit version to save FLASH

// 8 byt ACU in r0..r7
/*
     255...192 191...128 127...64 63...0
                      Y              Z
middle part is addressed by X
*/
	movw	r28,r30
	subi	r28,lo8(-128)
	sbci	r29,hi8(-128)

#define _CARRY r25
#define _ACC r24
#define _COUNT r23
	mov	_COUNT,r30
	subi	_COUNT,(-64)
	sub	_CARRY,_CARRY
rsa_square_1024_xloop1:
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
//subtract M
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+		//load M
	sbc	\pos,_ACC	//subtract
	std	Z+64-8+\pos,\pos	//save final B
.endr
	ror	_CARRY
	ror	_CARRY

	cpse	_COUNT,r30
	rjmp	rsa_square_1024_xloop1

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
rsa_square_1024_xloop2:
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
	sbc	\pos,_ACC
	st	Z+,\pos		// save final C
.endr
	ror	_CARRY
	ror	_CARRY

	dec	_COUNT
	brne	rsa_square_1024_xloop2
/*
     255...192 191...128 127...64 63...0
             Z
*/
// propagate carry to D
// renew borrow
	rol	_CARRY
	rol	_CARRY
// 0 or 0xffff
	sbc	r16,r16
	sbc	r17,r17

	clr	r1
	clr	_ACC
	bld	_ACC,0
	add	r16,_ACC
	adc	r17,r1

	ror	_CARRY
	andi	_CARRY,1
	adc	r16,_CARRY
	adc	r17,r1

	ld	_ACC,Z
	add	_ACC,r16
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

// return stack position (X is used to point variable on stack, correct X to get old SP)
	sbiw	r26,1
	LOAD_SP	r0   r26,r27

#if defined (HAVE_RSA_SQUARE_1024) && !defined (HAVE_RSA_SQUARE_1024_NO_ABI)
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
#endif // defined (HAVE_RSA_SQUARE_1024) && !defined (HAVE_RSA_SQUARE_1024_NO_ABI)
	ret
#endif //HAVE_RSA_SQUARE_1024 || HAVE_RSA_SQUARE_1024_NO_ABI



/////////////////////////////////////////////////////////////
#if defined(HAVE_RSA_SQUARE_512)
	.global rsa_square_512
	.type rsa_square_512, @function
rsa_square_512:
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
#if defined(HAVE_RSA_SQUARE_512_NO_ABI)
	rcall	rsa_square_512_no_abi
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
#endif //defined(HAVE_RSA_SQUARE_512_NO_ABI)
#endif //HAVE_RSA_SQUARE_512

#if defined(HAVE_RSA_SQUARE_512) || defined(HAVE_RSA_SQUARE_512_NO_ABI)
#if defined (HAVE_RSA_SQUARE_512_NO_ABI)
	.global rsa_square_512_no_abi
	.type rsa_square_512_no_abi, @function
rsa_square_512_no_abi:
#endif
// create space on stack(64 bytes TMP variable, 2x pointer
	in	r28, 0x3d
	in	r29, 0x3e
	subi	r28, lo8(64+2+2)
	sbci	r29, hi8(64+2+2)
	LOAD_SP	r0  r28,r29
// save pointers to stack, rsa_square_256_no_abi uses _all_ registers
	std	Y+1,r22	// A pointer
	std	Y+2,r23
	std	Y+3,r30	// Result
	std	Y+4,r31

// calculate a_low - a_high -> r
	movw	r28,r22		//A, A+32 is addressed by Y

	ldi	r25,4		//4*8 = 32 bytes
	sub	r24,r24		//initial carry(s)
rsa_square_512_loop1:
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
	brne	rsa_square_512_loop1
// select RESULT  or RESULT + 32
	bst	r24,0
	bld	r25,5

	sub	r30,r25
	sbci	r31,0

	movw	r28,r30

// multiply |a_low - a_high| * |a_low - a_high| into TMP
	in	r30, 0x3d
	in	r31, 0x3e
	adiw	r30,5		// skip variables on stack to point 64 byt TMP
	rcall	rsa_square_256_no_abi
// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	ldd	r26,Y+1	// OPERAND_A
	ldd	r27,Y+2
	movw	r28,r26
// a_low * a_low to r
	rcall	rsa_square_256_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
// a_high * a_high to r+64
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	subi	r30,-64
	sbci	r31,0xff
	ldd	r26,Y+1	// OPERAND_A
	ldd	r27,Y+2
	adiw	r26,32
	movw	r28,r26

	rcall	rsa_square_256_no_abi

// load values back 
	in	r30, 0x3d
	in	r31, 0x3e
	movw	r26,r30
	adiw	r26,5		// skip variables on stack to point 64 byt TMP

	ldd	r28,Z+3	// Result
	ldd	r29,Z+4

	movw	r30,r28

	subi	r30,lo8(-64)
	sbci	r31,hi8(-64)

// combine partial results
//       D          C           B          A          
//  127      96 95      64 63       32 31      0
//                      Z                      Y
// M is addressed by X
//-------------------------------------------------
#define _CARRY r25
#define _ACC r24
//-------------------------------------------------
////////// RESULT bytes 31.. 0 ////////////////////////////////
// no action needed
////////// RESULT bytes 63.. 32 ///////////////////////////////
// B+C cache in r23..r8, rest of B+C in memory
// ACU in r7..r0
// 8 bit accumulator _ACC
// carry is saved in _CARRY

// load B into r23..r8 (r23..r8 is B+C cache)
.irp	pos,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	ldd	\pos+8,Y+32+\pos
.endr
// load first 8 bytes into ACU from C
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Z+\pos
.endr
//summarize 1st part BC into B+C cache
	add	r8,r0
.irp	pos,1,2,3,4,5,6,7
	adc	\pos+8,\pos
.endr
// load 2nd 8 bytes from C
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Z+8+\pos
.endr
//summarize 2nd part BC into r23..r16
.irp	pos,0,1,2,3,4,5,6,7
	adc	\pos+16,\pos
.endr
	rol	_CARRY	//save carry from B+C
/////////////// B+C cache full
////////// RESULT bytes 63.. 32 ///////////////////////////////
// 39..32
// load 1st part of A
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Y+\pos
.endr
// summarize ACU = (B+C cache)+A
	add	r0,r8
.irp	pos,1,2,3,4,5,6,7
	adc	\pos,\pos+8
.endr	
	rol	_CARRY	//save carry ABC
// subtract M, store result to memory - final B
	ld	_ACC,X+
	sub	r0,_ACC
	std	Y+32,r0
.irp	pos,1,2,3,4,5,6,7
	ld	_ACC,X+
	sbc	\pos,_ACC
	std	Y+32+\pos,\pos
.endr
////////// RESULT bytes 63.. 32 ///////////////////////////////
// 47..40
	ror	_CARRY	// save borow, renew carry ABC
// load 2nd part of A
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Y+\pos+8
.endr
// summarize (B+C)+A
.irp	pos,0,1,2,3,4,5,6,7
	adc	\pos,\pos+16
.endr
	rol	_CARRY	//save carry ABC
// subtract M, store result to memory - final B
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+
	sbc	\pos,_ACC
	std	Y+32+8+\pos,\pos
.endr
////////// RESULT bytes 63.. 32 ///////////////////////////////
// 63..56, 55..48
// rest two parts
.irp	part,16,24
	ror	_CARRY	// save borow, renew carry ABC
	ror	_CARRY	// save carry ABC, renew BC
//load B into r7..r0
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Y+32+\part+\pos
.endr
//add C
.irp	pos,0,1,2,3,4,5,6,7
	ldd	_ACC,Z+\pos+\part
	adc	\pos,_ACC
	std	Z+\part+\pos,\pos	//no enough reg, store B+C into RAM
.endr
	rol	_CARRY  //save carry from B+C
//add A
.irp	pos,0,1,2,3,4,5,6,7
	ldd	_ACC,Y+\pos+\part
	adc	\pos,_ACC
.endr
	rol	_CARRY  //save carry from B+C+A
//subtract M
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+
	sbc	\pos,_ACC
	std	Y+32+\part+\pos,\pos
.endr
.endr	//parts..
// save carry for propagation into D
	bst	_CARRY,1
//--------------------------------------------------
////////// RESULT bytes 95..64 ///////////////////////////////
// 71..64
// continue in C part .. C+D bytes 64..79
	ror	_CARRY
	ror	_CARRY	//save carry ABC, renew carry BC
// r23..r8 B+C cache ..
// add D
.irp	pos,0,1,2,3,4,5,6,7
	ldd	_ACC,Z+32+\pos		//D - not cached
	adc	\pos+8,_ACC
.endr
	rol	_CARRY	//save carry BC, renew carry ABC
// propagate carry from previous B+C
	clr	_ACC
.irp	pos,0,1,2,3,4,5,6,7
	adc	\pos+8,_ACC
.endr
	rol	_CARRY	//save carry ABC, renew borrow

// subtract rest of M, store back to RAM
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+
	sbc	\pos+8,_ACC
	std	Z+\pos,\pos+8
.endr

// 79..71
// subtract M
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+
	sbc	\pos+16,_ACC
.endr
	ror	_CARRY	//renew carry ABC
// propagate carry from previous B+C
	clr	_ACC
.irp	pos,0,1,2,3,4,5,6,7
	adc	\pos+16,_ACC
.endr
	ror	_CARRY	//renew carry BC
// preload into r8..r15 D, summarize
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos+8,Z+32+\pos+8
	adc	\pos+16,\pos+8
	std	Z+\pos+8,\pos+16
.endr
// 87..80
// load B+C from mem into ACU
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Z+16+\pos
.endr
// preload into r16..r23 D, summarize
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos+16,Z+32+16+\pos
	adc	\pos,\pos+16
.endr
	rol	_CARRY	//save carry BC, renew ABC
// propagate carry
	clr	_ACC
.irp	pos,0,1,2,3,4,5,6,7
	adc	r\pos,_ACC
.endr
	rol	_CARRY	// save carry ABC, renew borrow
// subtract rest of M
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+
	sbc	r\pos,_ACC
	std	Z+16+\pos,r\pos
.endr
// 95..88
// load B+C from mem into ACU
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Z+24+\pos
.endr
// subtract rest of M
.irp	pos,0,1,2,3,4,5,6
	ld	_ACC,X+
	sbc	r\pos,_ACC
.endr
	ld	_ACC,X
	sbc	r7,_ACC

	sbc	r28,r28	// for carry propagation into D

	ror	_CARRY	//renew carry ABC
	clr	_ACC
.irp	pos,0,1,2,3,4,5,6,7
	adc	r\pos,_ACC
.endr
	ror	_CARRY	//renew carry BC
// preload D - _ACC,r0..r6, summarize
	ldd	_ACC,Z+32+24+0
	adc	r0,_ACC
	std	Z+24,r0
.irp	pos,1,2,3,4,5,6,7
	ldd	\pos-1,Z+32+24+\pos
	adc	\pos,\pos-1
	std	Z+24+\pos,\pos
.endr
#undef _ACC
#define _ACC r7
////////// RESULT bytes 127..96 ///////////////////////////////
//summarize borow carry, propagate to D
// create 0 or 0xffff from borrow
	clr	_ACC
	mov	r29,r28

	rol	_CARRY	 // A+B+C carry into C bit
	andi	_CARRY,1 // B+C carry into bit 0

	adc	r28,_CARRY	// sumarize
	adc	r29,_ACC

	bld	_CARRY,0		// carry BC
	add	r28,_CARRY
	adc	r29,_ACC

	ldd	_ACC,Z+32
	add	_ACC,r28
	std	Z+32,_ACC

.irp	pos,1,2,3,4,5,6,7
	ldd	_ACC,Z+32+\pos
	adc	_ACC,r29
	std	Z+32+\pos,_ACC
.endr
.irp	pos,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
	adc	\pos,r29
	std	Z+32+\pos,\pos
.endr
	adc	r24,r29
	std	Z+32+24,r24

.irp	pos,25,26,27,28,29,30,31
	adc	\pos-25,r29
	std	Z+32+\pos,\pos-25
.endr

#undef _ACC
#undef _CARRY

// return stack position
	LOAD_SP	r0, r26,r27
#undef L1
#undef L2
#undef L3
#undef L4
#undef L5
#undef L6
#undef L7
#if defined(HAVE_RSA_SQUARE_512) &&  !defined(HAVE_RSA_SQUARE_512_NO_ABI)
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
#endif // defined(HAVE_RSA_SQUARE_512) &&  !defined(HAVE_RSA_SQUARE_512_NO_ABI)
	ret
#endif // defined(HAVE_RSA_SQUARE_512) || defined(HAVE_RSA_SQUARE_512_NO_ABI)

#if defined(HAVE_RSA_SQUARE_256)
	.global rsa_square_256
	.type rsa_square_256, @function
rsa_square_256:
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
#if defined(HAVE_RSA_SQUARE_256_NO_ABI)
	rcall	rsa_square_256_no_abi

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
#endif // HAVE_RSA_SQUARE_256_NO_ABI
#endif // HAVE_RSA_SQUARE_256



#if defined(HAVE_RSA_SQUARE_256) || defined(HAVE_RSA_SQUARE_256_NO_ABI)

#if defined(HAVE_RSA_SQUARE_256_NO_ABI)
	.global	rsa_square_256_no_abi
	.type	rsa_square_256_no_abi, @function
// squaring,   input Y, result Z
rsa_square_256_no_abi:
#endif

#define ZERO	r27
#define TMP	r26
#define TMP2X  r27

#define SET_A	 r5,r4,r3,r2
#define SET_B	 r9,r8,r7,r6
#define SET_0    r13,r12,r11,r10
#define SET_1    r17,r16,r15,r14
#define SET_2    r21,r20,r19,r18
#define SET_3    r25,r24,r23,r22

#define SET_ZERO  ZERO,ZERO,ZERO,ZERO
#define SET_CARRY ZERO,ZERO,ZERO,TMP

/*
karatchuba squaring for 128 bites:

     15..........8              7...........0
    /             \            /             \
   /  square       \          /   square      \
  /31....24 23....16\        /15.....8  7.....0\
    D           C                 B        A
 save only D,C+B and A (carry from CB propagate to D)

*/

// square A_0 .. A_7

	LOAD32_FROM_Y_MEM	SET_A	0
	LOAD32_FROM_Y_MEM 	SET_B	4

	SQUARE_64_M   		SET_3,SET_2,SET_1,SET_0 0		SET_B,SET_A  TMP2X TMP
// SET_0 is already saved in SQUARE_64_M
	STORE32_TO_MEM    	4 	SET_1

// add square A_8 .. A_15, to bytes in SET_3,SET_2
// 
	LOAD32_FROM_Y_MEM	SET_A	8
	LOAD32_FROM_Y_MEM	SET_B	12

	SQUARE_ADD_64x       	16 SET_1,SET_0,SET_3,SET_2         SET_B,SET_A TMP2X TMP
// SET_2 is already saved in SQUARE_ADD_64x
	STORE32_TO_MEM	20	SET_3
	STORE32_TO_MEM	24	SET_0
	STORE32_TO_MEM	28	SET_1

// rotate sets, (reuse old value in SET_A,SET_B)
#undef SET_0
#undef SET_1
#undef SET_A
#undef SET_B
#define SET_0	 r5,r4,r3,r2
#define SET_1	 r9,r8,r7,r6
#define SET_A    r13,r12,r11,r10
#define SET_B    r17,r16,r15,r14
// compute middle part (64 bites)
	LOAD32_FROM_Y_MEM		SET_A	0
	LOAD32_FROM_Y_MEM		SET_B	4

	ABS_SUB64       	SET_B,SET_A       SET_1,SET_0   TMP

	SQUARE_64  		SET_3,SET_2,SET_1,SET_0		SET_B,SET_A  TMP2X TMP
//	SQUARE_64_n1  		r0 r25,r24,r23,r22 r21,r20,r19,r18 r17,r16,r15,r14 r13,r12,r11		SET_B,SET_A  TMP2X TMP

	LOAD_FROM_MEM_		SET_A 	0
	LOAD_FROM_MEM_		SET_B	4

	SUB64			SET_B,SET_A   SET_1,SET_0
// save borrow (TMP bit 7)
	ror	TMP
	LOAD_FROM_MEM_	SET_0 	16
	ADD32   	SET_A   SET_0
	STORE32_TO_MEM	8	SET_A

	LOAD_FROM_MEM_	SET_1 	20
	ADC32		SET_B   SET_1
	STORE32_TO_MEM	12	SET_B

// renew borow and save this carry
	rol	TMP
	SBC64		SET_1,SET_0   SET_3,SET_2
	sbc	r0,r0
	sbc	r1,r1

	LOAD_FROM_MEM_	SET_A	24
	LOAD_FROM_MEM_	SET_B 	28

//renew carry
	lsr	TMP
	ADC64 SET_1 SET_0   SET_B SET_A

	STORE32_TO_MEM	16	SET_0
	STORE32_TO_MEM	20	SET_1

// propagate carry to end
	ADC64		SET_B,SET_A	r1 r1 r1 r1 r1 r1 r1 r0
	STORE32_TO_MEM	24	SET_A
	STORE32_TO_MEM	28 	SET_B
///////////////////////////////////////////////////////////////////////
// all sets free
///////////////////////////////////////////////////////////////////////
//seek for result and operand
#define SEEK_R 32
#define SEEK_O 16
// square A_8 .. A_15

	LOAD32_FROM_Y_MEM	SET_A	0+SEEK_O
	LOAD32_FROM_Y_MEM	SET_B	4+SEEK_O

	SQUARE_64_M   SET_3,SET_2,SET_1,SET_0 SEEK_R  SET_B,SET_A     TMP2X TMP
// SET_0 is already saved in SQUARE_64_M
	STORE32_TO_MEM		4+SEEK_R 	SET_1

	LOAD32_FROM_Y_MEM	SET_A	8+SEEK_O
	LOAD32_FROM_Y_MEM	SET_B	12+SEEK_O

	SQUARE_ADD_64x       	16+SEEK_R SET_1,SET_0,SET_3,SET_2         SET_B,SET_A TMP2X TMP
// SET_2 is already saved in SQUARE_ADD_64x
	STORE32_TO_MEM	20+SEEK_R	SET_3
	STORE32_TO_MEM	24+SEEK_R	SET_0
	STORE32_TO_MEM	28+SEEK_R	SET_1

// rotate sets, (reuse old value in SET_A,SET_B)
#undef SET_0
#undef SET_1
#undef SET_A
#undef SET_B
#define SET_A	 r5,r4,r3,r2
#define SET_B	 r9,r8,r7,r6
#define SET_0    r13,r12,r11,r10
#define SET_1    r17,r16,r15,r14
// compute middle part (64 bites)
	LOAD32_FROM_Y_MEM	SET_A	0+SEEK_O
	LOAD32_FROM_Y_MEM	SET_B	4+SEEK_O

	ABS_SUB64	SET_B,SET_A       SET_1,SET_0  TMP

	SQUARE_64   		SET_3,SET_2,SET_1,SET_0		SET_B,SET_A  TMP2X TMP

	LOAD_FROM_MEM_ SET_A 	0+SEEK_R
	LOAD_FROM_MEM_ SET_B 	4+SEEK_R

	MEM_ADD64 0+SEEK_R  0+SEEK_O  SET_B,SET_A  r1

// save  carry
  	sbc	TMP,TMP

	SUB64	SET_B SET_A    SET_1 SET_0
	LOAD_FROM_MEM_	SET_0	24+SEEK_R
	LOAD_FROM_MEM_	SET_1	28+SEEK_R

	SBC64	SET_1,SET_0   SET_3,SET_2
	sbc r0, r0
  	sbc r1, r1

	LOAD_FROM_MEM_ SET_2 48
	LOAD_FROM_MEM_ SET_3 52 

	ADD64  SET_B SET_A    SET_3 SET_2
	ADC64  SET_1 SET_0    SET_3 SET_2

	clr	ZERO
	adc r0, ZERO
	adc r1, ZERO

// add upper part from square (A0..A7) 
	LOAD_FROM_MEM_	SET_2	24
	LOAD_FROM_MEM_	SET_3	28

	lsr	TMP
	ADC64	SET_B,SET_A	SET_3,SET_2
	ADC64   SET_1 SET_0   	SET_ZERO SET_ZERO

	STORE32_TO_MEM	40	SET_A
	STORE32_TO_MEM	44	SET_B
	STORE32_TO_MEM	48	SET_0
	STORE32_TO_MEM	52	SET_1

// propagate carry to end
	LOAD_FROM_MEM_	SET_0		24+SEEK_R
	LOAD_FROM_MEM_	SET_1		28+SEEK_R
	ADC64	        SET_1,SET_0	r1 r1 r1 r1 r1 r1 r1 r0
	STORE32_TO_MEM	24+SEEK_R	SET_0
	STORE32_TO_MEM	28+SEEK_R	SET_1

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// middle part (128 bites)
// subtract, create abs value

	LOAD32_FROM_Y_MEM	SET_A	0
	LOAD32_FROM_Y_MEM	SET_B	4
	LOAD32_FROM_Y_MEM	SET_0	8
	LOAD32_FROM_Y_MEM	SET_1	12

	REG_SUB_MEM128	SET_1,SET_0 SET_B,SET_A   16  TMP
	sbc TMP,TMP
	EOR128	SET_1,SET_0 SET_B,SET_A  TMP

	SUB64	SET_B,SET_A  TMP TMP TMP TMP TMP TMP TMP TMP
	SBC64	SET_1,SET_0  TMP TMP TMP TMP TMP TMP TMP TMP
//////////////////////////////////////////////////////////////////////////////////
/* 
 squaring middle part
 M_full  = abs(lo-hi) (16 bytes)
 
 M_half  = abs(M_full_lo - M_full_hi)

 save on stack M_half, M_full_hi 

 1. square M_full_lo  -> get A7..A0 into RAM, B15..B8 into reg
 2. load M_full_hi
 3. square M_full_hi  -> add C into B, save to RAM, D save to RAM

 4. load M_half
 5. square M_half

       M_full_hi                 M_full_lo
     15..........8              7...........0
    /             \            /             \
   /  square       \          /   square      \
  /31....24 23....16\        /15......8 7.....0\
    D           C                 B        A

 combine  with A,BC,D
 final:
 D7..0    /registers/  A7...A0

 combine this with  precalculated squares from upper and lower bytes from
 previous code

 store data into stack by push, then acces data by Y register
*/

#define M_0     29
#define M_4	25

#define A_0	21
#define A_4	17
#define BC_0	13
#define BC_4	9 

#define D_0	5
#define D_4	1
//#define SET_A	 r5,r4,r3,r2
//#define SET_B	 r9,r8,r7,r6
//#define SET_0    r13,r12,r11,r10
//#define SET_1    r17,r16,r15,r14
//#define SET_2    r21,r20,r19,r18
//#define SET_3    r25,r24,r23,r22

// store absolute value (lo-hi) into mem (parts)
	COPY64__ SET_3,SET_2  SET_B,SET_A
        ABS_SUB64               SET_3,SET_2   SET_1,SET_0  TMP

// save M_half	(M_0,M_4)
	PUSH32	SET_2
	PUSH32	SET_3

// save M_full_hi
	PUSH32	SET_0
// here r28,29 is free, use r28,r29 in SET_1 to prevent change of r17,r16
//	PUSH32	SET_1		//r17,r16,r15,r14
	push	r14
	push	r15
#undef SET_1
#define SET_1    r29,r28,r15,r14
	// square  M_full_lo
	SQUARE_64   		SET_3,SET_2,SET_1,SET_0		SET_B,SET_A  TMP2X TMP
// load M_full_hi 
//	POP32	SET_B		//r9,r8,r7,r6
#undef SET_B
#define SET_B r17,r16,r7,r6
	pop	r7
	pop	r6
	POP32	SET_A

// save A_0, A_4
	PUSH32	SET_0
	PUSH32	SET_1

	SQUARE_ADD_64x2       	SET_1,SET_0,SET_3,SET_2         SET_B,SET_A  TMP2X TMP  r9,r8

//save BC_0,BC_4
	PUSH32	SET_2
	PUSH32	SET_3
//save D_0,D_4
	PUSH32	SET_0
	PUSH32	SET_1

// get Y as pointer to stack variables
	in 	r28, 0x3d
	in 	r29, 0x3e
////////////////////////////////////////////////////////////////////////////////
//load M0..M15
#undef SET_2
#undef SET_3
#undef SET_0
#undef SET_1
#undef SET_B
#undef SET_A
// all register unused
// create new set names to get readable code

// TEMP
#define SET_TMP0    r5,r4,r3,r2
#define SET_TMP1    r9,r8,r7,r6
// C,B is held in registers:
#define SET_B3_0	r13 r12 r11 r10
#define SET_B7_4	r17,r16,r15,r14
#define SET_C3_0	r21,r20,r19,r18
#define SET_C7_4	r25,r24,r23,r22

// M_half
	LOAD32_FROM_Y_MEM		SET_B3_0	M_0
	LOAD32_FROM_Y_MEM		SET_B7_4	M_4

	SQUARE_64		SET_TMP1,SET_TMP0,SET_C7_4,SET_C3_0    SET_B7_4,SET_B3_0  TMP2X TMP

	LOAD32_FROM_Y_MEM		SET_B3_0	A_0
	LOAD32_FROM_Y_MEM		SET_B7_4	A_4
	SUB64			SET_B7_4,SET_B3_0	SET_C7_4,SET_C3_0

	LOAD32_FROM_Y_MEM		SET_C3_0	D_0
	LOAD32_FROM_Y_MEM		SET_C7_4	D_4
	SBC64			SET_C7_4,SET_C3_0	SET_TMP1,SET_TMP0
	sbc 	r0,r0
	sbc	r1,r1

	LOAD32_FROM_Y_MEM		SET_TMP0		BC_0
	LOAD32_FROM_Y_MEM		SET_TMP1		BC_4
	ADD64			SET_B7_4,SET_B3_0	SET_TMP1,SET_TMP0
	ADC64			SET_C7_4,SET_C3_0	SET_TMP1,SET_TMP0

// propagate carry
	LOAD32_FROM_Y_MEM		SET_TMP0	D_0
	LOAD32_FROM_Y_MEM		SET_TMP1	D_4
	ADC64			SET_TMP1,SET_TMP0	r1 r1 r1 r1 r1 r1 r1 r0
	STORE_TO_Y_MEM		D_0	SET_TMP0
	STORE_TO_Y_MEM		D_4	SET_TMP1

// result in mem(D7..D0) reg(SET_C7_4,SET_C3_0),reg(SET_B7_4,SET_B3_0)mem(A7..A0)
// middle part (256 bites) ready to combine with precalculated  squares from
// first part of code
////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
// no enough registers to get free set, create rotated sets to allow 
// (posible set r27,r26,r1,r0  but this generates slower code)
// MEM - set operation  in one step. Do not touch sets SET_C7_4,SET_C3_0!
// 
#define SET_0r	r3 r2 r1 r0
#define SET_1r	r7 r6 r5 r4
#define SET_2r	r11 r10 r9 r8
#define SET_3r  r15 r14 r13 r12

        LOAD32_FROM_Y_MEM	SET_TMP0	A_0
        LOAD32_FROM_Y_MEM	SET_TMP1	A_4

// in SET3..0  is result from square(lo-hi)
// 128 bit subtract  - from Z15..Z0 subtract 128 bit from middle part (square(lo-hi)
// result = MEM - operand

	REG_MEM_SUB_REG128	 SET_3r,SET_2r,SET_1r,SET_0r    0	SET_B7_4,SET_B3_0,SET_TMP1,SET_TMP0
// store borrow in "ZERO" (bit 0)
	sbc	ZERO,ZERO

// to result (in SET_3r..A) is now added  128 bits from square (16-31)
// (in this part is already added high part from square 0-15)

	MEM_ADD64 16 32    SET_1r SET_0r	TMP
	MEM_ADC64 24 40	   SET_3r,SET_2r  	TMP
// preserve carry flag (and full status register for LOAD_SP_SREG macro)
	in      TMP,0x3f

	LOAD32_FROM_Y_MEM		SET_B3_0	D_0
	LOAD32_FROM_Y_MEM		SET_B7_4	D_4

// release allocated space on stack, 
	adiw	r28,32

	LOAD_SP_SREG TMP, r28,r29

// warning, TMP is needed below!
// get borrow from ZERO
	lsr	ZERO
	REG_MEM_SBC_REG128	SET_3r,SET_2r,SET_1r,SET_0r   48  SET_B7_4,SET_B3_0,SET_C7_4,SET_C3_0
// get borrow
  	sbc 	r28,r28
	sbc	r29,r29

// saved carry in TMP in bite 0 (from "in TMP,0x3f")
  	lsr 	TMP
	MEM_ADC64  32 32	SET_1r SET_0r 	TMP
	MEM_ADC64  40 40	SET_3r SET_2r 	TMP

// propagate carry
	LOAD_FROM_MEM_	SET_0r	48
	LOAD_FROM_MEM_  SET_1r	52
	LOAD_FROM_MEM_	SET_2r	56
	LOAD_FROM_MEM_	SET_3r	60

	ADC64  SET_1r SET_0r	r29 r29 r29 r29 r29 r29 r29 r28
	ADC64  SET_3r SET_2r	r29 r29 r29 r29 r29 r29 r29 r29

	STORE32_TO_MEM 48  SET_0r
	STORE32_TO_MEM 52  SET_1r
	STORE32_TO_MEM 56  SET_2r
	STORE32_TO_MEM 60  SET_3r
#if defined(HAVE_RSA_SQUARE_256) && !defined(HAVE_RSA_SQUARE_256_NO_ABI)
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
#endif // defined(HAVE_RSA_SQUARE_256) && !defined(HAVE_RSA_SQUARE_256_NO_ABI)
	ret
#endif // defined(HAVE_RSA_SQUARE_256) || defined(HAVE_RSA_SQUARE_256_NO_ABI)
/////////////////////////////////////////////////////////////


// dependency check

#if \
defined (HAVE_RSA_SQUARE_768_NO_ABI) || \
defined (HAVE_RSA_SQUARE_768)
#if !defined (HAVE_RSA_SQUARE_384_NO_ABI)
#define HAVE_RSA_SQUARE_384_NO_ABI
#endif
#endif

#if \
defined (HAVE_RSA_SQUARE_384_NO_ABI) || \
defined (HAVE_RSA_SQUARE_384)
#if !defined (HAVE_RSA_SQUARE_192_NO_ABI)
#define HAVE_RSA_SQUARE_192_NO_ABI
#endif
#endif


#if defined (HAVE_RSA_SQUARE_768)
	.global	rsa_square_768
	.type	rsa_square_768, @function
rsa_square_768:
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
#if defined (HAVE_RSA_SQUARE_768_NO_ABI)
	rcall	rsa_square_768_no_abi
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
#endif // defined (HAVE_RSA_SQUARE_768_NO_ABI)
#endif // defined (HAVE_RSA_SQUARE_768)
#if defined (HAVE_RSA_SQUARE_768_NO_ABI)
	.global	rsa_square_768_no_abi
	.type	rsa_square_768_no_abi, @function

rsa_square_768_no_abi:
#endif // defined (HAVE_RSA_SQUARE_768_NO_ABI)
#if defined (HAVE_RSA_SQUARE_768_NO_ABI) || defined (HAVE_RSA_SQUARE_768)
// input is addressed by r22,r23 result by r24,r25

// create space on stack(96 bytes TMP variable, 2x pointer
	in	r28, 0x3d
	in	r29, 0x3e
	subi	r28, lo8(96+2+2)
	sbci	r29, hi8(96+2+2)
	LOAD_SP	r0,r28,r29
// save pointers to stack, rsa_square_384_no_abi uses _all_ registers

	std	Y+1,r22	// A pointer
	std	Y+2,r23
	std	Y+3,r24	// Result
	std	Y+4,r25

// calculate a_low - a_high -> r
	movw	r28,r22		//A, A+48 is addressed by Y
	movw	r30,r24

	ldi	r25,6		//6*8 = 48 bytes
	sub	r24,r24		//initial carry(s)

rsa_square_768_loop1xx:
// load A into r0..r7, A+48 to r8..r15
.irp	pos,0,1,2,3,4,5,6,7
	ld	r\pos,Y+
.endr
.irp	pos,8,9,10,11,12,13,14,15
	ldd	r\pos,Y+32+\pos
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
	std	Z+32+\pos,r\pos
.endr
	rol	r24	//renew carry

	dec	r25
	brne	rsa_square_768_loop1xx

// select RESULT  or RESULT + 24
        bst     r24,0   // save sign    
        bld     r25,4   // 0 or 48
        bld     r25,5

	sub	r30,r25
	sbci	r31,0

	movw	r22,r30
// multiply |a_low - a_high| * |a_low - a_high| into TMP
	in	r30,0x3d
	in	r31,0x3e
	adiw	r30,5		// skip variables on stack to point 96 byt TMP
	call	rsa_square_384_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	ldd	r22,Y+1	// OPERAND
	ldd	r23,Y+2
// a_low * a_low to r
	call	rsa_square_384_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
// a_high * a_high to r+128
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	subi	r30,lo8(-96)
	sbci	r31,hi8(-96)
	ldd	r22,Y+1	// OPERAND
	ldd	r23,Y+2
	subi	r22,lo8(-48)
	sbci	r23,hi8(-48)	//A+64
	call	rsa_square_384_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	movw	r26,r28
	adiw	r26,5		// skip variables on stack to point 128 byt TMP

// 8 byt ACU (12 byt ACU version is faster about 36 ticks but bigger code +128 bytes)
/*
     191...144 143...96 95...48 47...0
                      Y              Z
middle part is addressed by X
*/
	movw	r28,r30
	subi	r28,lo8(-96)
	sbci	r29,hi8(-96)

#define _CARRY r25
#define _ACC r24
#define _COUNT r23
	mov	_COUNT,r30
	subi	_COUNT,(-48)
	sub	_CARRY,_CARRY
rsa_square_768_xloop1:
// summarize B+C, store to MEM at position C
.irp	pos,0,1,2,3,4,5,6,7
	ldd	\pos,Z+48+\pos		//load B
	ldd	_ACC,Y+\pos		//load C
	adc	\pos,_ACC		//sum
.endr
.irp    pos,0,1,2,3,4,5,6,7
	st	Y+,\pos			//store BC into RAM
.endr
	rol	_CARRY		// save B+C carry
// add A
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,Z+		//load A
	adc	\pos,_ACC	//sum
.endr
	rol	_CARRY
//subtract M
.irp	pos,0,1,2,3,4,5,6,7
	ld	_ACC,X+		//load M
	sbc	\pos,_ACC	//subtract
	std	Z+48-8+\pos,\pos	//save final B
.endr
	ror	_CARRY
	ror	_CARRY

	cpse	_COUNT,r30
	rjmp	rsa_square_768_xloop1

// A,B part	 ok, add D
// prevent carry, correct Z to point C
	ror	_CARRY
	bst	_CARRY,7	//save B+C carry
	adiw	r30,48
	rol	_CARRY
/*
     191...144 143...96 95...48 47...0
             Y        Z
middle part is addressed by X
*/
	ldi	_COUNT,6
rsa_square_768_xloop2:
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
	sbc	\pos,_ACC
	st	Z+,\pos		// save final C
.endr
	ror	_CARRY
	ror	_CARRY

	dec	_COUNT
	brne	rsa_square_768_xloop2
/*
     191...140 139...92 91...48 47...0
             Z
*/
// propagate carry to D
// renew borrow
	rol	_CARRY
	rol	_CARRY
// 0 or 0xffff
	sbc	r20,r20
	sbc	r21,r21

	clr	r1
	clr	_ACC
	bld	_ACC,0
	add	r20,_ACC
	adc	r21,r1

	ror	_CARRY
	andi	_CARRY,1
	adc	r20,_CARRY
	adc	r21,r1

	ld	_ACC,Z
	add	_ACC,r20
	st	Z+,_ACC

.rept	47-8
	ld	_ACC,Z
	adc	_ACC,r21
	st	Z+,_ACC
.endr
//cached
.irp	pos,0,1,2,3,4,5,6,7
	adc	\pos+8,r21
	st	Z+,\pos+8
.endr

// return stack position (X is used to point variable on stack, correct X to get old SP)
	sbiw 	r26,1
	LOAD_SP	r0, r26,r27

#if defined (HAVE_RSA_SQUARE_768) && !defined (HAVE_RSA_SQUARE_768_NO_ABI)
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
#endif // defined (HAVE_RSA_SQUARE_768) && !defined (HAVE_RSA_SQUARE_768_NO_ABI)
	ret
#endif //defined (HAVE_RSA_SQUARE_768_NO_ABI) || defined (HAVE_RSA_SQUARE_768)

#if defined(HAVE_RSA_SQUARE_384)
	.global	rsa_square_384
	.type	rsa_square_384, @function
rsa_square_384:
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
#if defined (HAVE_RSA_SQUARE_384_NO_ABI)
	rcall	rsa_square_384_no_abi

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
#endif // HAVE_RSA_SQUARE_384_NO_ABI
#endif // HAVE_RSA_SQUARE_384

#if defined(HAVE_RSA_SQUARE_384_NO_ABI)
	.global	rsa_square_384_no_abi
	.type	rsa_square_384_no_abi, @function
// input is addressed by r22,23 result by r30,r31
rsa_square_384_no_abi:
#endif

#if defined(HAVE_RSA_SQUARE_384_NO_ABI) || defined(HAVE_RSA_SQUARE_384)

// create space on stack(64 bytes TMP variable, 2x pointer
	in	r28, 0x3d
	in	r29, 0x3e
//	subi	r28, lo8(48+2+2)
//	sbci	r29, hi8(48+2+2)
	sbiw	r28,(48+2+2)
	LOAD_SP	r0 r28,r29

// save pointers to stack, rsa_square_192_no_abi uses _all_ registers
	std	Y+1,r22	// A pointer
	std	Y+2,r23
	std	Y+3,r30	// Result
	std	Y+4,r31

// calculate a_low - a_high -> r
	movw	r28,r22		//A, A+24 is addressed by Y

	ldi	r25,3		//3*8 = 24 bytes
//	clr	r24		//initial carry(s)
//	clc
	sub	r24,r24		//initial carry(s)
rsa_square_384_loop1:
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
	brne	rsa_square_384_loop1
// select RESULT  or RESULT + 24
        bst     r24,0   // save sign    
        bld     r25,4   // 0 or 24
        bld     r25,3

	sub	r30,r25
	sbci	r31,0
	movw	r28,r30

// multiply |a_low - a_high| * |a_low - a_high| into TMP
	in	r30, 0x3d
	in	r31, 0x3e
	adiw	r30,5		// skip variables on stack to point 64 byt TMP

	rcall	rsa_square_192_no_abi
// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	ldd	r26,Y+1	// OPERAND_A
	ldd	r27,Y+2
	movw	r28,r26
// a_low * a_low to r
	rcall	rsa_square_192_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
// a_high * a_high to r+48
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4
	subi	r30,-48
	sbci	r31,0xff
	ldd	r26,Y+1	// OPERAND_A
	ldd	r27,Y+2
	adiw	r26,24
	movw	r28,r26
	rcall	rsa_square_192_no_abi

// load values back 
	in	r28, 0x3d
	in	r29, 0x3e
	ldd	r30,Y+3	// Result
	ldd	r31,Y+4

	movw	r26,r28
	adiw	r26,5		// skip variables on stack to point 64 byt TMP

	movw	r28,r30
	subi	r28,lo8(-48)
	sbci	r29,hi8(-48)

//       D          C           B          A          
//   95      72 71      48 47       24 23      0
//                      Y                      Z
//-------------------------------------------------
#define _ACC r24
#define _CARRY r25

////////// RESULT bytes 23.. 0 ////////////////////////////////
// no action needed
////////// RESULT bytes 47.. 24 ///////////////////////////////
// 29..24
// B+C cache in r23..r6, rest of B+C in memory
// ACU in r5..r0
// 8 bit accumulator _ACC
// carry is saved in _CARRY

// load B into r23..r6 (is B+C cache)
.irp	pos,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
	ldd	\pos+6,Z+24+\pos
.endr
// load first 6 bytes into ACU from C
.irp	pos,0,1,2,3,4,5
	ldd	\pos,Y+\pos
.endr
//summarize 1st part BC into B+C cache
	add	r6,r0
.irp	pos,1,2,3,4,5
	adc	\pos+6,\pos
.endr
.irp    pos,0,1,2,3,4,5
	ldd     \pos,Y+6+\pos
	adc	\pos+6+6,\pos
.endr
.irp    pos,0,1,2,3,4,5
	ldd     \pos,Y+12+\pos
	adc	\pos+6+12,\pos
.endr
	rol	_CARRY	//save carry from B+C
// load 1st part of A
.irp	pos,0,1,2,3,4,5
	ldd	\pos,Z+\pos
.endr
// summarize ACU = (B+C cache)+A
	add	r0,r6
.irp	pos,1,2,3,4,5
	adc	\pos,\pos+6
.endr
	rol	_CARRY	//save carry ABC
// subtract M, store result to memory - final B
	ld	_ACC,X+
	sub	r0,_ACC
	std	Z+24,r0
.irp	pos,1,2,3,4,5
	ld	_ACC,X+
	sbc	\pos,_ACC
	std	Z+24+\pos,\pos
.endr
////////// RESULT bytes 47.. 24 ///////////////////////////////
// 41..36, 35..30
.irp part,6,12
	ror	_CARRY	// save borow, renew carry ABC
// load 2nd part of A
.irp	pos,0,1,2,3,4,5
	ldd	\pos,Z+\pos+\part
.endr
// summarize (B+C)+A
.irp	pos,0,1,2,3,4,5
	adc	\pos,\pos+6+\part
.endr
	rol	_CARRY	//save carry ABC
// subtract M, store result to memory - final B
.irp	pos,0,1,2,3,4,5
	ld	_ACC,X+
	sbc	\pos,_ACC
	std	Z+24+\part+\pos,\pos
.endr
.endr	// part

////////// RESULT bytes 47.. 24 ///////////////////////////////
// 47..42
	ror	_CARRY	// save borow, renew carry ABC
	ror	_CARRY	// save carry ABC, renew BC
//load B into r5..r0
.irp	pos,0,1,2,3,4,5
	ldd	\pos,Z+24+18+\pos
.endr
//add C
.irp	pos,0,1,2,3,4,5
	ldd	_ACC,Y+\pos+18
	adc	\pos,_ACC
	std	Y+18+\pos,\pos	//no enough reg, store B+C into RAM
.endr
	rol	_CARRY  //save carry from B+C
//add A
.irp	pos,0,1,2,3,4,5
	ldd	_ACC,Z+\pos+18
	adc	\pos,_ACC
.endr
	rol	_CARRY  //save carry from B+C+A
//subtract M
.irp	pos,0,1,2,3,4,5
	ld	_ACC,X+
	sbc	\pos,_ACC
	std	Z+24+18+\pos,\pos
.endr
// save carry for propagation into D
	bst	_CARRY,1

//--------------------------------------------------
////////// RESULT bytes 71..48 ///////////////////////////////
// 65..48
// first subtract M from B+C
.irp	pos,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
	ld	_ACC,X+
	sbc	\pos+6,_ACC
.endr
	ror	_CARRY	// save borow, renew carry ABC
// propagate carry from previous B+C
	clr	_ACC
.irp	pos,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
	adc	\pos+6,_ACC
.endr
// add D, store result into RAM
	ror	_CARRY	//save carry ABC, renew carry BC

// Warning BC cache is reused for D cache, _ACC is used too!
// D is cached in r24,r6..r22 ..
	ldd	r24,Y+24	//D0
	adc	r6,r24
	std	Y+0,r6
.irp	pos,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
	ldd	\pos+5,Y+24+\pos
	adc	\pos+6,\pos+5
	std	Y+\pos,\pos+6
.endr
// change _ACC (old _ACC in r24 is used as cache for D0)
#undef _ACC
#define _ACC r23
////////// RESULT bytes 71..48 ///////////////////////////////
	rol	_CARRY	//save carry from B+C
	rol	_CARRY	//save carry ABC
// load B+C from mem into ACU
.irp	pos,0,1,2,3,4,5
	ldd	\pos,Y+18+\pos
.endr
// subtract rest of M
.irp	pos,0,1,2,3,4,5
	ld	_ACC,X+
	sbc	r\pos,_ACC
.endr
// from borrow creta 0 or 0xffff
	sbc	r26,r26
	sbc	r27,r27
// renew ABC carry
	ror	_CARRY
// propagate carry
	clr	_ACC
.irp	pos,0,1,2,3,4,5
	adc	r\pos,_ACC
.endr
	ror	_CARRY
// 1st part of D is cached in r24,r6..r22,
// cache rest of D into r23,r0..r4
//
	ldd	r23,Y+24+18	//D18
	adc	r0,r23
	std	Y+18,r0
.irp	pos,1,2,3,4,5
	ldd	\pos-1,Y+24+18+\pos
	adc	\pos,\pos-1
	std	Y+18+\pos,\pos
.endr
// change _ACC
#undef _ACC
#define _ACC r5
////////// RESULT bytes 95..72 ///////////////////////////////
//summarize borow carry, propagate to D
// create 0 or 0xffff from borrow
	clr	_ACC

	rol	_CARRY	// A+B+C carry into C bit, B+C carry into bit 0
	andi	_CARRY,1	// B+C carry into bit 0

	adc	r26,_CARRY	// sumarize
	adc	r27,_ACC

	bld	_CARRY,0	// carry BC
	add	r26,_CARRY
	adc	r27,_ACC

// 1st part of D is cached in r24,r6..r22
	add	r24,r26
	std	Y+24,r24
.irp	pos,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
	adc	\pos+5,r27
	std	Y+24+\pos,\pos+5
.endr
	adc	r23,r27
	adc	r0,r27
	adc	r1,r27
	adc	r2,r27
	adc	r3,r27
	adc	r4,r27
	std	Y+24+18,r23
	std	Y+24+19,r0
	std	Y+24+20,r1
	std	Y+24+21,r2
	std	Y+24+22,r3
	std	Y+24+23,r4

// return stack position
	in	r28, 0x3d
	in	r29, 0x3e
	subi	r28, lo8(-(48+2+2))
	sbci	r29, hi8(-(48+2+2))
	LOAD_SP	r0, r28,r29
#undef _ACC

#undef L1
#undef L2
#undef L3
#undef L4
#undef L5
#undef L6
#undef L7
#if defined (HAVE_RSA_SQUARE_384) && !defined (HAVE_RSA_SQUARE_384_NO_ABI)
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
#endif // defined (HAVE_RSA_SQUARE_384) && !defined (HAVE_RSA_SQUARE_384_NO_ABI)
	ret

#endif	// defined(HAVE_RSA_SQUARE_384_NO_ABI) || defined(HAVE_RSA_SQUARE_384)


#if defined(HAVE_RSA_SQUARE_192)
	.global	rsa_square_192
	.type	rsa_square_192, @function
rsa_square_192:
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
#if defined(HAVE_RSA_SQUARE_192_NO_ABI)
	rcall	rsa_square_192_no_abi
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
#endif // HAVE_RSA_SQUARE_192_NO_ABI
#endif // HAVE_RSA_SQUARE_192


#if defined (HAVE_RSA_SQUARE_192_NO_ABI)
	.global	rsa_square_192_no_abi
	.type	rsa_square_192_no_abi, @function
rsa_square_192_no_abi:
#endif
#if defined (HAVE_RSA_SQUARE_192_NO_ABI) || defined (HAVE_RSA_SQUARE_192)
///////////////////////////////////////////////////////////////////////////////////////////////////
// save operand pointer
	std	Z+47,r29
	std	Z+46,r28
	LOAD48_FROM_Y_MEM  r19,r18,r17,r16,r15,r14  0
//                                          result                          operand             temp registers
// r2 is not used, result byte 0 is directly stored to  memory ..
	SQUARE_48_z    r25,r24,r23,r22,r21,r20  r7,r6,r5,r4,r3,/*r2*/ 0   r19,r18,r17,r16,r15,r14 r13,r12,r11,r10,r9,r8
	std	Z+1,r3
	std	Z+2,r4
	std	Z+3,r5
	std	Z+4,r6
	std	Z+5,r7


	LOAD48_FROM_Y_MEM  r13,r12,r11,r10,r9,r8    6
	ABS_SUB48  r19,r18,r17,r16,r15,r14  r13,r12,r11,r10,r9,r8    r0
	                                                                               		//free tmp regs
	SQUARE_48_ADD  r5,r4,r3,r2,r7,r6  r25,r24,r23,r22,r21,r20    r13,r12,r11,r10,r9,r8	r27 r26  r29,r28
// not enough registers available,  use stack
	push	r7
	push	r6
	SQUARE_48c  r13,r12,r11,r10,r9,r8  r29 r28 r27 r26 r7 r6    r19,r18,r17,r16,r15,r14
	pop	r0
	pop	r1
// combine
	LOAD48_FROM_MEM_ r19,r18,r17,r16,r15,r14  0

	SUB48  r19,r18,r17,r16,r15,r14    r29 r28 r27 r26 r7 r6
	ror	r26
	ADD48   r19,r18,r17,r16,r15,r14    r25,r24,r23,r22,r21,r20
	ADC48   r25,r24,r23,r22,r21,r20    r5  r4  r3  r2  r1  r0
	rol	r26
	SBC48   r25,r24,r23,r22,r21,r20    r13,r12,r11,r10,r9,r8
	sbc 	r6, r6
	sbc 	r7, r7
	ror	r26
	ADC48   r5 r4 r3 r2 r1 r0    r7 r7 r7 r7 r7 r6	

	STORE48_TO_MEM 6  r19,r18,r17,r16,r15,r14
	STORE48_TO_MEM 12 r25,r24,r23,r22,r21,r20
	STORE48_TO_MEM 18 r5 r4 r3 r2 r1 r0

// restore operand pointer
	ldd	r29,Z+47
	ldd	r28,Z+46
///////////////////////////////////////////////////////////////////////////////////////////////////
	LOAD48_FROM_Y_MEM r19 r18 r17 r16 r15 r14   12
//                                          result                          operand             temp registers
// r6 is not used, result byte 0 is directly stored to  memory ..
	SQUARE_48_z      r25,r24,r23,r22,r21,r20   r5,r4,r3,r2,r7,/*r6*/ 24    r19 r18 r17 r16 r15 r14  r13 r12 r11 r10 r9 r8
	std	Z+25,r7
	std	Z+26,r2
	std	Z+27,r3
	std	Z+28,r4
	std	Z+29,r5

	LOAD48_FROM_Y_MEM r13 r12 r11 r10 r9 r8     18
	ABS_SUB48  r19 r18 r17 r16 r15 r14    r13 r12 r11 r10 r9 r8   r0

		                                                                               //free tmp regs
	SQUARE_48_ADD  	r5 r4 r3 r2 r7 r6  r25 r24 r23 r22 r21 r20    r13 r12 r11 r10 r9 r8	r27 r26 r29 r28

	push	r7
	push	r6
	SQUARE_48c   r13,r12,r11,r10,r9,r8  r29 r28 r27 r26 r7 r6   r19 r18 r17 r16 r15 r14
	pop	r0
	pop	r1

	LOAD48_FROM_MEM_ r19 r18 r17 r16 r15 r14   24

	SUB48   r19,r18,r17,r16,r15,r14    r29 r28 r27 r26 r7 r6
	ror	r26
	ADD48   r19,r18,r17,r16,r15,r14    r25,r24,r23,r22,r21,r20
	ADC48   r25,r24,r23,r22,r21,r20    r5  r4  r3  r2  r1  r0
	rol	r26
	SBC48   r25,r24,r23,r22,r21,r20    r13,r12,r11,r10,r9,r8
	sbc 	r6, r6
	sbc 	r7, r7
	ror	r26
	ADC48   r5 r4 r3 r2 r1 r0    r7 r7 r7 r7 r7 r6	

	STORE48_TO_MEM 36 r25 r24 r23 r22 r21 r20

// restore operand pointer
	ldd	r29,Z+47
	ldd	r28,Z+46
	STORE48_TO_MEM 42 r5 r4 r3 r2 r1 r0
///////////////////////////////////////////////////////////////////////////////////////////////////
// create B+C, propagate carry to D, save carry from B+C..

	LOAD48_FROM_MEM_ r11 r10 r9 r8 r7 r6  24

//       C_l            C_h               D_l              D_h
//6,7,8,9,10,11, 14,15,16,17,18,19,  20,21,22,23,24,25, 0,1,2,3,4,5
// first BC[reg] = C[reg] + B[mem]
.set pos,12
	ldd	r12,Z+pos
	add	r6,r12
.irp reg,7,8,9,10,11,14,15,16,17,18,19
.set pos,pos+1
	ldd	r12,Z+pos
	adc	r\reg,r12
.endr
// save carry (must be used for adding from low to high part)
	clr	r12
	clr	r13
	adc	r13, r12

// propagate carry D[reg] (for sum D[reg], BC[reg]  into C[mem])
	ADD48 r25 r24 r23 r22 r21 r20  r12 r12 r12 r12 r12 r13
	ADC48 r5 r4 r3 r2 r1 r0        r12 r12 r12 r12 r12 r12

// B[mem] = BC[reg] + A[mem]
.set pos,0
	ldd	r26,Z+pos
	add	r26,r6
	std	Z+12+pos,r26
.irp	reg,7,8,9,10,11,14,15,16,17,18,19
.set pos,pos+1
	ldd	r26,Z+pos
	adc	r26,r\reg
	std	Z+12+pos,r26
.endr
// C[mem] = BC[reg]+D[reg]
	ADC48 r25 r24 r23 r22 r21 r20  r11 r10 r9 r8 r7 r6
	ADC48 r5 r4 r3 r2 r1 r0        r19,r18,r17,r16,r15,r14
	STORE48_TO_MEM 24              r25 r24 r23 r22 r21 r20
	STORE48_TO_MEM 30              r5 r4 r3 r2 r1 r0

// summarize carry for D, save to stack ..
	adc	r13,r12
	push	r13

// save result pointer
	push	r30
	push	r31

// calculate middle part
	LOAD48_FROM_Y_MEM  r19 r18 r17 r16 r31 r30 0
	LOAD48_FROM_Y_MEM  r7  r6  r5  r4  r3  r2  6
	LOAD48_FROM_Y_MEM  r13 r12 r11 r10 r9  r8  12
	LOAD48_FROM_Y_MEM  r25 r24 r23 r22 r21 r20 18

	SUB48  r19,r18,r17,r16,r31,r30	r13 r12 r11 r10 r9  r8
	SBC48  r7,r6,r5,r4,r3,r2	r25 r24 r23 r22 r21 r20
	sbc r0,  r0
	ABS96	r7,r6,r5,r4,r3,r2	r19,r18,r17,r16,r31,r30		r0

// r13..r8 is saved in stack inside SQUARE_48_sp macro
	SQUARE_48_sp   r25 r24 r23 r22 r21 r20   r13 r12 r11 r10 r9 r8    r19 r18 r17 r16 r31 r30

	ABS_SUB48  r19 r18 r17 r16 r31 r30    r7 r6 r5 r4 r3 r2   r0

		                                                                               //free tmp regs
	SQUARE_48_ADD r13 r12 r11 r10 r15 r14   r25 r24 r23 r22 r21 r20   r7 r6 r5 r4 r3 r2        r9 r8 r29,r28

	SQUARE_48c   r3 r2 r9 r8 r5 r4  r29 r28 r27 r26 r7 r6    r19 r18 r17 r16 r31 r30

	in	r30,0x3d
	in	r31,0x3e
// load low part
	ldd	r0,Z+6
	ldd	r1,Z+5
	ldd	r16,Z+4
	ldd	r17,Z+3

	pop	r19
	pop	r18

// use r30,31 as cache for partial low part
	movw	r30,r18

	SUB48   r19,r18,r17,r16,r1,r0    r29 r28 r27 r26 r7 r6
	ror	r26
	ADD48   r19,r18,r17,r16,r1,r0    r25,r24,r23,r22,r21,r20
	ADC48   r25,r24,r23,r22,r21,r20    r13 r12  r11  r10  r15  r14
	rol	r26

	SBC48   r25,r24,r23,r22,r21,r20    r3 r2 r9  r8  r5 r4
	sbc 	r6, r6
	sbc 	r7, r7
	ror	r26
	ADC48   r13 r12 r11 r10 r15 r14    r7 r7 r7 r7 r7 r6

	pop	r3
	pop	r2
	pop	r9
	pop	r8

// load result pointer
	pop	r29
	pop	r28

// subtract middle part ..
.set pos,12
	ldd	r6,Y+pos
	sub	r6,r8
	std	Y+pos,r6
.irp	reg,9,2,3,30,31,0,1,16,17,18,19,20,21,22,23,24,25,14,15,10,11,12,13
.set pos,pos+1
	ldd	r6,Y+pos
	sbc	r6,r\reg
	std	Y+pos,r6
.endr
	pop	r26 	// renew carry for D (0,1,2)
	sbci	r26,0	// update carry
	sbc	r27,r27

// propagate carry  to D
.set pos,36
	ldd	r12,Y+pos
	add	r12,r26
	std	Y+pos,r12
.rept 11
.set pos,pos+1
	ldd	r12,Y+pos
	adc	r12,r27
	std	Y+pos,r12
.endr
#if defined(HAVE_RSA_SQUARE_192) && !defined(HAVE_RSA_SQUARE_192_NO_ABI)
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
#endif // defined(HAVE_RSA_SQUARE_192) && !defined(HAVE_RSA_SQUARE_192_NO_ABI)
	ret
#endif //defined (HAVE_RSA_SQUARE_192_NO_ABI) || defined (HAVE_RSA_SQUARE_192)
