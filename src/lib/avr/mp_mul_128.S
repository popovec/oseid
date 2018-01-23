/*
    This is part of OsEID (Open source Electronic ID)

    128 bit (interrupt safe) multiplication routine for AVR

    Copyright (C) 2015-2017 Peter Popovec, popovec.peter@gmail.com

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


    This part of code is based on Karatsuba-based Multiplication
    downloaded from http://mhutter.org/research/avr/
    Authors: Michael Hutter and Peter Schwabe
    Version: 2014-07-25 Public domain

    Code is modified for use in OsEID project:
    - speed up  orig: 1325/this:1307 ticks (without call/ret)
    - no C ABI
    - MACROS
    - bit varaibles to speed up code (for RAM below 32kB)


*/
// for RAM below 32kiB, bit 15 in RAM pointer can be used to store some bit variable
// this save 4 ticks
//#define RAM_LE32

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

// multiply only 1st 4 bytes of result, precalculate bytes 4,5
// ZERO, RS2,RS3,RS4 and RS5 must be cleared before ..
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

.macro ABS32  RS3,RS2,RS1,RS0 SIGN ZERO
	eor	\RS0,\SIGN
	eor	\RS1,\SIGN
	eor	\RS2,\SIGN
	eor	\RS3,\SIGN
	neg	\SIGN
	add	\RS0,\SIGN
	adc	\RS1,\ZERO
	adc	\RS2,\ZERO
	adc	\RS3,\ZERO
.endm

.macro ABS64  RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0 SIGN ZERO
	eor	\RS0,\SIGN
	eor	\RS1,\SIGN
	eor	\RS2,\SIGN
	eor	\RS3,\SIGN
	eor	\RS4,\SIGN
	eor	\RS5,\SIGN
	eor	\RS6,\SIGN
	eor	\RS7,\SIGN
	neg	\SIGN
	add	\RS0,\SIGN
	adc	\RS1,\ZERO
	adc	\RS2,\ZERO
	adc	\RS3,\ZERO
	adc	\RS4,\ZERO
	adc	\RS5,\ZERO
	adc	\RS6,\ZERO
	adc	\RS7,\ZERO
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


#include <avr/io.h>
  .global rsa_mul_128_no_abi
  .type rsa_mul_128_no_abi, @function
  .section .text.rsa_mul_128_no_abi,"ax",@progbits

rsa_mul_128_no_abi:
  ; init zero registers

  CLR R20
  CLR R21
  MOVW R16, R20

  ;--- level 2: compute L ---
  LD R2, X+
  LD R3, X+
  LD R4, X+
  LD R5, X+
  LDD R6, Y+0
  LDD R7, Y+1
  LDD R8, Y+2
  LDD R9, Y+3
//         result                             A                B    zero CC1 CC0
   MUL_32  r17,r16,r15,r14,r13,r12,r11,r10  r5,r4,r3,r2  r9,r8,r7,r6 r21 r19,r18

  STD Z+0, R10
  STD Z+1, R11
  STD Z+2, R12
  STD Z+3, R13
  
  ;--- load a4..a7 and b4..b7 ---
  MOVW R10, R20
  movw    r12,r20
  LD R18, X+
  LD R19, X+
  ; rest is loaded later
  LDD R22, Y+4
  LDD R23, Y+5
  LDD R24, Y+6
  LDD R25, Y+7

  ;--- level 2: compute H + (l3,l4,l5) ---
// upper bytes of operand A are readed from X+!
	MUL32_ADD_n 	r13,r12,r11,r10,r17,r16,r15,r14  r25,r24,r23,r22  r19,r18   r21

;--- subtract a0-a4 ---
  SUB R2, R18
  SBC R3, R19
  SBC R4, R13
  ; load a7 to R18
  LD R18, X+
  SBC R5, R18
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0

  ;--- subtract b0-b4 ---
  SUB R6, R22
  SBC R7, R23
  SBC R8, R24
  SBC R9, R25
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1

        ABS32   r5,r4,r3,r2  r0  r21
        ABS32   r9,r8,r7,r6  r1  r21

  EOR R0, R1
  BST R0, 0
	MUL32_ADD_cont_n  r13,r12,r11,r10,r17,r16,r15,r14  r25,r24,r23,r22  r19,r18   r21

  ;--- continue ---

  ;--- level 2: compute M ---
// r4,r3,r19,r18,r25,r24,r23,r22    r9,r8,r7,r6    r5,r4,r3,r2
// zeroize registers
        movw    r24,r20
        movw    r18,r20

// multiply only 1st 4 bytes of result, precalculate bytes 4,5
        MUL_32_8   /* r3 r2 */r19,r18,r25,r24,r23,r22   r9,r8,r7,r6  r5,r4,r3,r2 r20
// continue,  r20,r21 is zero!
        MUL_32_8contA /*r3,r2, */ r19,r18     r9,r8,r7,r6  r5,r4,r3,r2  r20

// middle part in
// r3,r2,r19,r18,r25,r24,r23,r22


  ;--- add l4+h0 to l0 and h4 ---
  LDD R6, Z+0
  LDD R7, Z+1
	ldd	r0,z+2
	ldd	r1,z+3
	movw	r4,r20

	ADD64	r17,r16,r15,r14,r1,r0,r7,r6  r13,r12,r11,r10,r17,r16,r15,r14
  ; store carry in R5
  ADC R5, R5
  
  ;--- process sign bit ---  
  BRTc sub_M_L
add_M_L: 
	ADD64   r17,r16,r15,r14,r1,r0,r7,r6     r3,r2,r19,r18,r25,r24,r23,r22
	ADC R5, R4
	RJMP final_L
sub_M_L:
	SUB64   r17,r16,r15,r14,r1,r0,r7,r6     r3,r2,r19,r18,r25,r24,r23,r22
  SBC R5, R4
  SBC R4, R4

final_L:
  STD Z+4, R6
  STD Z+5, R7
  STD Z+6, R0
  STD Z+7, R1

  ;--- propagate carry to end ---
  ADD R10, R5
  ADC R11, R4
  ADC R12, R4
  ADC R13, R4


  ; h8...h15 stored in 22,23,24,25,18,21,19,20

  ;------ level 1: compute H ------

  ; init zero registers
	movw	r22,r20
	movw	r24,r20
  ;--- level 2: compute L ---
  LD R2, X+
  LD R3, X+
  LD R4, X+
  LD R5, X+
  LDD R6, Y+8
  LDD R7, Y+9
  LDD R8, Y+10
  LDD R9, Y+11

	 MUL_32_8 /*r,r*/ r23,r22,r25,r24,r19,r18   r9,r8,r7,r6  r5,r4,r3,r2 r20
  ; now add h0+l8 and h0+l12
	ADD64	r25,r24,r19,r18, r17,r16,r15,r14   r13,r12,r11,r10, r25,r24,r19,r18

  STD Z+16, r14
  STD Z+17, r15
  STD Z+18, r16
  STD Z+19, r17
  STD Z+20, R18
  STD Z+21, R19

// preload operand b4..b7
  LDD R14, Y+12
  LDD R15, Y+13
  LDD r12, Y+14
  LDD r13, Y+15
#ifdef RAM_LE32
  ; store carry in bit 15 of RAM pointer
  ROL R29
#else
  ; store carry on stack
  SBC R0, R0
  PUSH R0
#endif
  movw	r16,r20
  ; continue
	MUL_32_8cont r17,r16,r23,r22   r9,r8,r7,r6  r5,r4,r3,r2  r21
/////////////////////////////////////////////////////////////////////////////////////////////////////

  ;--- load a4..a5  a6..a7 load later in macro..
  MOVW R18, R20
  LD R10, X+
  LD R11, X+
  ;--- level 2: compute H + (l3,l4,l5) ---
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

	MUL32_ADD_xx r20,r11,r19,r18,r17,r16,r23,r22  r13,r12,r15,r14    r11,r10  r21
  ;--- subtract a0-a4 ---
  SUB R2, R10
  SBC R3, R11
  SBC R4, R20
  ; load a7 to R18

  LD R10, X+
  SBC R5, R10
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0
  
  ;--- subtract b0-b4 ---
  SUB R6, R14
  SBC R7, R15

  SBC R8, r12
  SBC R9, r13
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1
	ABS32   r5,r4,r3,r2  r0 r21
	ABS32   r9,r8,r7,r6  r1 r21

  EOR R0, R1
  BST R0, 0

// A1 = RS6, A2 = RS7 !!!
.macro  MUL32_ADD_cont_swap_zero RS7 RS6,RS5,RS4,RS3   B3,B2,B1,B0  ZERO
	mul	r10,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO

	mul	r11,\B3
	clr	r11
	add	\RS4,r0
	adc	\RS5,r1
	adc	r21,r11
	mul	\RS7,\B2
	add	\RS4,r0
	adc	\RS5,r1
	adc	r21,r11
	mul	r10,\B1
	add	\RS4,r0
	adc	\RS5,r1
	adc	r21,r11

	mul	\RS7,\B3
	clr	\RS7
	add	\RS5,r0
	adc	r21,r1
	adc	\RS7,r11
	mul	r10,\B2
	add	\RS5,r0
	adc	r21,r1
	adc	\RS7,r11

	mul	r10,\B3
	add	r21,r0
	adc	\RS7,r1
.endm

  ;--- continue ---
// TODO .. better macro ..
//                               RS7 RS6 ........RS3       B            OLD_ZERO
	MUL32_ADD_cont_swap_zero r20 r11,r19,r18,r17   r13,r12,r15,r14 r21
// r11 is zero
  ;--- level 2: compute M ---
	clr	r10
	movw	r12,r10
	MUL32_ncc	r4,r3,r2,r10,r13,r12,r15,r14  r9,r8,r7,r6  r5,r4,r3,r2  r11
  ;--- add l4+h0 to l0 and h4 ---
  LDD R6, Z+20
  LDD R7, Z+21
	ADD64   r17,r16,r23,r22,r25,r24,r7,r6  r20,r21,r19,r18,r17,r16,r23,r22

  ; store carry in R21
  ADC R11, R11

  ;--- propagate carry ---  
// load carry ..
#ifdef RAM_LE32
  LSR r29
#else
  POP R0
  LSR R0
#endif
  CLR R0
  ADC R22, R0
  ADC R23, R0
  ADC R16, R0
  ADC R17, R0
  ; store carry in R21
  ADC R11, R0

  ;--- process sign bit ---  
  BRTc sub_M_H

	ADD64	r17,r16,r23,r22,r25,r24,r7,r6 r4,r3,r2,r10,r13,r12,r15,r14
  ADC R11, R0
  RJMP final_H
sub_M_H:
  ; subtract M
	SUB64	r17,r16,r23,r22,r25,r24,r7,r6 r4,r3,r2,r10,r13,r12,r15,r14
  SBC R11, R0
  SBC R0, R0

final_H:

  STD Z+20, R6
  STD Z+21, R7
  STD Z+22, r24
  STD Z+23, r25
  STD Z+24, R22
  STD Z+25, R23
  STD Z+26, R16
  STD Z+27, R17

  ;--- propagate carry to end ---
  ADD R18, R11
  ADC R19, R0
  ADC R21, R0
  ADC R20, R0
  
  STD Z+28, R18
  STD Z+29, R19
  STD Z+30, R21
  STD Z+31, R20
////////////////////////////////////////////////////////////////////////////////////////////////
  ;------ level 1: subtract a0-a7 ------
  SBIW R26, 16

.irp	Reg,2,3,4,5,18,25,20,21,10,11,12,13,14,15,16,17
	ld	r\Reg,X+
.endr
	SUB64 r21,r20,r25,r18,r5,r4,r3,r2  r17,r16,r15,r14,r13,r12,r11,r10
  ; 0xff if carry and 0x00 if no carry
  SBC R27, R27
  
  ;------ level 1: subtract b0-b7 ------
  LDD R6, Y+0
  LDD R7, Y+1
  LDD R8, Y+2
  LDD R9, Y+3
  LDD R22, Y+4
  LDD R23, Y+5
  LDD R24, Y+6
  LDD r19, Y+7
  LDD R10, Y+8
  LDD R11, Y+9
  LDD R12, Y+10
  LDD R13, Y+11
  LDD R14, Y+12
  LDD R15, Y+13
  LDD R16, Y+14
  LDD R17, Y+15
	SUB64	r19,r24,r23,r22,r9,r8,r7,r6  r17,r16,r15,r14,r13,r12,r11,r10
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1
    
  ;------ level 1: absolute values ------
	clr	r26
	ABS64   r21,r20,r25,r18,r5,r4,r3,r2  r27 r26
	ABS64   r19,r24,r23,r22,r9,r8,r7,r6  r1 r26
  EOR r27,r1
#ifdef RAM_LE32
  ror r27
  ROL r31
#else
  PUSH R27
  clr r27
#endif

  ;------ level 1: compute M ------
  MOVW R16, R26
//             result                             A                B    zero    CC1 CC0
	MUL_32  r17,r16,r15,r14,r13,r12,r11,r10  r5,r4,r3,r2  r9,r8,r7,r6  r26  r29,r28

  ;--- subtract a0-a4 ---  
  SUB R2, R18
  SBC R3, r25
  SBC R4, R20
  SBC R5, R21
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0
  
  ;--- subtract b0-b4 ---  
  SUB R6, R22
  SBC R7, R23
  SBC R8, R24
  SBC R9, r19
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1

	ABS32   r5,r4,r3,r2  r0  r26
	ABS32   r9,r8,r7,r6  r1  r26

  EOR R0, R1
  BST R0, 0 
  
  ;--- level 2: compute H + (l3,l4,l5) ---
  MUL R18, R24 ;a0*b2
  MOVW R28, R0
  MUL R18, R22 ;a0*b0
  ADD R14, R0
  ADC R15, R1
  ADC R16, R28
  ADC R29, R26
  MUL R18, R23 ;a0*b1
  ADD R15, R0
  ADC R16, R1
  ADC R29, R26
  MUL r25, r19 ;a1*b3
  ADD R17, R29
  ADC R26, R0
  ADC R27, R1

  MUL R18, r19 ;a0*b3
  MOVW R28, R0
  MUL r25, R22 ;a1*b0
  ADD R15, R0
  ADC R16, R1
  ADC R17, R28
  CLR R18
  ADC R29, R18
  MUL r25, R23 ;a1*b1
  ADD R16, R0
  ADC R17, R1
  ADC R29, R18
  MUL R20, r19 ;a2*b3
  ADD R26, R29
  ADC R27, R0
  ADC R18, R1

  MUL R20, R24 ;a2*b2
  MOVW R28, R0
  MUL R20, R22 ;a2*b0
  ADD R16, R0
  ADC R17, R1
  ADC R26, R28
  CLR R0
  ADC R29, R0
  MUL r25, R24 ;a1*b2
  ADD R17, R0
  ADC R26, R1
  CLR r25
  ADC R29, r25
  MUL R21, r19 ;a3*b3
  ADD R27, R29
  ADC R18, R0
  CLR r19
  ADC r19, R1
  
  MUL R21, R23 ;a3*b1
  MOVW R28,R0
  MUL R20, R23 ;a2*b1
  ADD R17, R0
  ADC R28, R1
  ADC R29, r25
  MUL R21, R22 ;a3*b0
  ADD R17, R0
  ADC R28, R1
  ADC R29, r25
  MUL R21, R24 ;a3*b2
  ADD R26, R28
  ADC R0, R29
  ADC R1, r25
  ADD R27, R0
  ADC R18, R1
  ADC r19, r25

  ;--- level 2: compute M ---
  MUL R2, R8 ;a0*b2
  MOVW R22, R0
  MUL R2, R6 ;a0*b0
  MOVW R20, R0
  MUL R2, R7 ;a0*b1
  ADD R21, R0
  ADC R22, R1
  ADC R23, r25
  MUL R3, R9 ;a1*b3
  MOV R24, R0
  MOV R0, R2
  MOV R2, R1

  MUL R0, R9 ;a0*b3
  MOVW R28, R0
  MUL R3, R6 ;a1*b0
  ADD R21, R0
  ADC R22, R1
  ADC R23, R28
  ADC R29, r25
  MUL R3, R7 ;a1*b1
  ADD R22, R0
  ADC R23, R1
  ADC R29, r25
  MUL R4, R9 ;a2*b3
  ADD R24, R29
  ADC R2, R0
  ADC r25, R1

  MUL R4, R8 ;a2*b2
  MOVW R28, R0
  MUL R4, R6 ;a2*b0
  ADD R22, R0
  ADC R23, R1
  ADC R24, R28
  CLR R0
  ADC R29, R0
  MUL R3, R8 ;a1*b2
  ADD R23, R0
  ADC R24, R1
  CLR R3
  ADC R29, R3
  MUL R5, R9 ;a3*b3
  ADD R2, R29
  ADC r25, R0
  CLR R9
  ADC R9, R1

  MUL R5, R7 ;a3*b1
  MOVW R28, R0
  MUL R4, R7 ;a2*b1
  ADD R23, R0
  ADC R28, R1
  ADC R29, R3
  MUL R5, R6 ;a3*b0
  ADD R23, R0
  ADC R28, R1
  ADC R29, R3
  MUL R5, R8 ;a3*b2
  ADD R24, R28
  ADC R0, R29
  ADC R1, R3
  ADD R2, R0
  ADC r25, R1
  ADC R9, R3

  ;--- add l4+h0 to l0 and h4 ---
  MOVW R4, R10
  MOVW R6, R12
	ADD64	r17,r16,r15,r14,r13,r12,r11,r10      r19,r18,r27,r26,r17,r16,r15,r14

  ; store carry in R3
  CLR R29
  ADC R3, R3
  
  ;--- process sign bit ---
  BRTc sub_M_M
  ; R29:R28 is -1,0, or 1

	ADD64	r17,r16,r15,r14,r13,r12,r11,r10  r9,r25,r2,r24,r23,r22,r21,r20
  ADC R3, R29
  RJMP final_M
sub_M_M:
  ;subtract M
	SUB64	r17,r16,r15,r14,r13,r12,r11,r10  r9,r25,r2,r24,r23,r22,r21,r20
  SBC R3, r29
  SBC R29, R29

final_M:
  ;--- propagate carry to end ---
  ADD R26, R3
  ADC R27, R29
  ADC R18, R29
  ADC r19, R29
  
  ;------ level 1: combine L, H, and M ------

  ;--- process sign bit ---
#ifdef RAM_LE32
  LSR r31
  CLR r1
#else
  POP R1
  LSR   R1    // test bit0  and create ZERO in R1
#endif

  LDD R20, Z+0
  LDD R21, Z+1
  LDD R22, Z+2
  LDD R23, Z+3
  LDD R24, Z+4  
  LDD R25, Z+5
  LDD R8, Z+6 
  LDD R9, Z+7

  BRCS add_M

  ;subtract M
	SUB64	r9,r8,r25,r24,r23,r22,r21,r20  r13,r12,r11,r10,r7,r6,r5,r4
  ; store borrow in R0
  SBC R0, R0
  LDD R2, Z+16
  LDD R3, Z+17
  ADD R20, R2
  ADC R21, R3
  STD Z+8, R20
  STD Z+9, R21

  LDD R20, Z+18
  LDD R21, Z+19
  ADC R22, R20
  ADC R23, R21
  STD Z+10, R22
  STD Z+11, R23

  LDD R22, Z+20
  LDD R23, Z+21
  ADC R24, R22
  ADC R25, R23
  STD Z+12, R24
  STD Z+13, R25

  LDD R24, Z+22
  LDD R25, Z+23
  ADC R8, R24
  ADC R9, R25
  STD Z+14, R8
  STD Z+15, R9
  ; store carry in R1
  ADC R1, R1

  LSR R0
	SBC64   r25,r24,r23,r22,r21,r20,r3,r2  r19,r18,r27,r26,r17,r16,r15,r14
  SBC R28, R28
  SBC R29, R29
  ; R29:R28 is -1,0, or 1  
  RJMP final

add_M: 
	ADD64   r9,r8,r25,r24,r23,r22,r21,r20 r13,r12,r11,r10,r7,r6,r5,r4
  ; store carry in R0
  SBC R0, R0

  LDD R2, Z+16
  LDD R3, Z+17
  ADD R20, R2
  ADC R21, R3
  STD Z+8, R20
  STD Z+9, R21

  LDD R20, Z+18
  LDD R21, Z+19
  ADC R22, R20
  ADC R23, R21
  STD Z+10, R22
  STD Z+11, R23

  LDD R22, Z+20
  LDD R23, Z+21
  ADC R24, R22
  ADC R25, R23
  STD Z+12, R24
  STD Z+13, R25

  LDD R24, Z+22
  LDD R25, Z+23
  ADC R8, R24
  ADC R9, R25
  STD Z+14, R8
  STD Z+15, R9
  ; store carry in R1
  ADC R1, R1

  LSR R0
	ADC64	r25,r24,r23,r22,r21,r20,r3,r2   r19,r18,r27,r26,r17,r16,r15,r14

  CLR R28
  CLR R29
  ADC R28, R28
  
final:
  LDD R4, Z+24
  LDD R5, Z+25
  LDD R6, Z+26
  LDD R7, Z+27
  LDD R10, Z+28
  LDD R11, Z+29
  LDD R12, Z+30
  LDD R13, Z+31

  LSR R1
	ADC64	r25,r24,r23,r22,r21,r20,r3,r2   r13,r12,r11,r10,r7,r6,r5,r4

  ; store carry in R29:R28
  ADC R28, R1
  ADC R29, R1

  STD Z+16, R2
  STD Z+17, R3
  STD Z+18, R20
  STD Z+19, R21
  STD Z+20, R22
  STD Z+21, R23
  STD Z+22, R24
  STD Z+23, R25

  ;--- propagate carry to end ---
	ADD64	r13,r12,r11,r10,r7,r6,r5,r4  R29,R29,R29,R29,R29,R29,R29,R28


  STD Z+24, R4
  STD Z+25, R5
  STD Z+26, R6
  STD Z+27, R7
  STD Z+28, R10
  STD Z+29, R11
  STD Z+30, R12
  STD Z+31, R13
  RET
