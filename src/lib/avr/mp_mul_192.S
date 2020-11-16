/*
    This is part of OsEID (Open source Electronic ID)

    192bit (interrupt safe) multiplication routine for AVR

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


    This part of code is based on Karatsuba-based Multiplication
    downloaded from http://mhutter.org/research/avr/

    Authors: Michael Hutter and Peter Schwabe
    Version: 2014-07-25  Public domain

  Differences to original code from Michael Hutter and Peter Schwabe:

  --  no stack register move forward/backwards
  --  The code uses macros - improved code readability
  --  code is faster and interrupt safe (please check LOAD_SP macro)

  orig code                                            2923 clock cycles
  size: 4600 bytes

  this code (MEM pointers 15 bit)                      2854 clock cycles
  size: 4424 bytes

  this code (MEM pointers 16 bit)                      2861 clock cycles
  size: 4424 + 26 bytes

  For ATMEGA (not XMEGA, please read xmega doc about SP change):
  For environment  enabled interrupts, I flag is saved before CLI and
  restored after SP manipulation or SEI is forced after SP manipulation.

  this code - I flag restored after stack pointer change	+3 clock cycles
								+6 bytes
  this code - I flag forced to interrupt enable 		+2 clock cycles
								+4 bytes

*/
//#undef RAM_LE32
#include "load_sp.h"


.macro ABS48  RS5,RS4,RS3,RS2,RS1,RS0 SIGN 
        eor     \RS0,\SIGN
        eor     \RS1,\SIGN
        eor     \RS2,\SIGN
        eor     \RS3,\SIGN
        eor     \RS4,\SIGN
        eor     \RS5,\SIGN
        sub     \RS0,\SIGN
        sbc     \RS1,\SIGN
        sbc     \RS2,\SIGN
        sbc     \RS3,\SIGN
        sbc     \RS4,\SIGN
        sbc     \RS5,\SIGN
.endm

.macro ABS96  RS11,RS10,RS9,RS8,RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0 SIGN
        eor     \RS0,\SIGN
        eor     \RS1,\SIGN
        eor     \RS2,\SIGN
        eor     \RS3,\SIGN
        eor     \RS4,\SIGN
        eor     \RS5,\SIGN
        eor     \RS6,\SIGN
        eor     \RS7,\SIGN
        eor     \RS8,\SIGN
        eor     \RS9,\SIGN
        eor     \RS10,\SIGN
        eor     \RS11,\SIGN
        sub	\RS0,\SIGN
        sbc     \RS1,\SIGN
        sbc     \RS2,\SIGN
        sbc     \RS3,\SIGN
        sbc     \RS4,\SIGN
        sbc     \RS5,\SIGN
        sbc     \RS6,\SIGN
        sbc     \RS7,\SIGN
        sbc     \RS8,\SIGN
        sbc     \RS9,\SIGN
        sbc     \RS10,\SIGN
        sbc     \RS11,\SIGN
.endm

.macro ADD96  RS11,RS10,RS9,RS8,RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0  A11,A10,A9,A8,A7,A6,A5,A4,A3,A2,A1,A0
	add	\RS0,\A0
	adc	\RS1,\A1
	adc	\RS2,\A2
	adc	\RS3,\A3
	adc	\RS4,\A4
	adc	\RS5,\A5
	adc	\RS6,\A6
	adc	\RS7,\A7
	adc	\RS8,\A8
	adc	\RS9,\A9
	adc	\RS10,\A10
	adc	\RS11,\A11
.endm
.macro ADC96  RS11,RS10,RS9,RS8,RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0  A11,A10,A9,A8,A7,A6,A5,A4,A3,A2,A1,A0
	adc	\RS0,\A0
	adc	\RS1,\A1
	adc	\RS2,\A2
	adc	\RS3,\A3
	adc	\RS4,\A4
	adc	\RS5,\A5
	adc	\RS6,\A6
	adc	\RS7,\A7
	adc	\RS8,\A8
	adc	\RS9,\A9
	adc	\RS10,\A10
	adc	\RS11,\A11
.endm
.macro SUB96  RS11,RS10,RS9,RS8,RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0  A11,A10,A9,A8,A7,A6,A5,A4,A3,A2,A1,A0
	sub	\RS0,\A0
	sbc	\RS1,\A1
	sbc	\RS2,\A2
	sbc	\RS3,\A3
	sbc	\RS4,\A4
	sbc	\RS5,\A5
	sbc	\RS6,\A6
	sbc	\RS7,\A7
	sbc	\RS8,\A8
	sbc	\RS9,\A9
	sbc	\RS10,\A10
	sbc	\RS11,\A11
.endm
.macro SUB48    RZ5 RZ4 RZ3 RZ2 RZ1 RZ0   A5 A4 A3 A2 A1 A0
        sub     \RZ0,\A0
        sbc     \RZ1,\A1
        sbc     \RZ2,\A2
        sbc     \RZ3,\A3
        sbc     \RZ4,\A4
        sbc     \RZ5,\A5
.endm
.macro SBC48    RZ5 RZ4 RZ3 RZ2 RZ1 RZ0   A5 A4 A3 A2 A1 A0
        sbc     \RZ0,\A0
        sbc     \RZ1,\A1
        sbc     \RZ2,\A2
        sbc     \RZ3,\A3
        sbc     \RZ4,\A4
        sbc     \RZ5,\A5
.endm
.macro ADD48    RZ5 RZ4 RZ3 RZ2 RZ1 RZ0   A5 A4 A3 A2 A1 A0
        add     \RZ0,\A0
        adc     \RZ1,\A1
        adc     \RZ2,\A2
        adc     \RZ3,\A3
        adc     \RZ4,\A4
        adc     \RZ5,\A5
.endm
.macro ADC48    RZ5 RZ4 RZ3 RZ2 RZ1 RZ0   A5 A4 A3 A2 A1 A0
        adc     \RZ0,\A0
        adc     \RZ1,\A1
        adc     \RZ2,\A2
        adc     \RZ3,\A3
        adc     \RZ4,\A4
        adc     \RZ5,\A5
.endm
.macro  LOAD48_FROM_X  REG5 REG4 REG3 REG2 REG1 REG0
        ld      \REG0,X+
        ld      \REG1,X+
        ld      \REG2,X+
        ld      \REG3,X+
        ld      \REG4,X+
        ld      \REG5,X+
.endm
.macro  LOAD48_FROM_Y  REG5 REG4 REG3 REG2 REG1 REG0    M
        ldd     \REG0,Y+0+\M
        ldd     \REG1,Y+1+\M
        ldd     \REG2,Y+2+\M
        ldd     \REG3,Y+3+\M
        ldd     \REG4,Y+4+\M
        ldd     \REG5,Y+5+\M
.endm
.macro  LOAD96_FROM_Y  REG11 REG10 REG9 REG8 REG7 REG6 REG5 REG4 REG3 REG2 REG1 REG0    M
        ldd     \REG0,Y+0+\M
        ldd     \REG1,Y+1+\M
        ldd     \REG2,Y+2+\M
        ldd     \REG3,Y+3+\M
        ldd     \REG4,Y+4+\M
        ldd     \REG5,Y+5+\M
        ldd     \REG6,Y+6+\M
        ldd     \REG7,Y+7+\M
        ldd     \REG8,Y+8+\M
        ldd     \REG9,Y+9+\M
        ldd     \REG10,Y+10+\M
        ldd     \REG11,Y+11+\M
.endm
.macro  LOAD48_FROM_Z  REG5 REG4 REG3 REG2 REG1 REG0    M
        ldd     \REG0,Z+0+\M
        ldd     \REG1,Z+1+\M
        ldd     \REG2,Z+2+\M
        ldd     \REG3,Z+3+\M
        ldd     \REG4,Z+4+\M
        ldd     \REG5,Z+5+\M
.endm
.macro  STORE48_TO_Z   REG5 REG4 REG3 REG2 REG1 REG0    M
        std     Z+0+\M,\REG0
        std     Z+1+\M,\REG1
        std     Z+2+\M,\REG2
        std     Z+3+\M,\REG3
        std     Z+4+\M,\REG4
        std     Z+5+\M,\REG5
.endm
.macro  STORE24_TO_Z   REG2 REG1 REG0    M
        std     Z+0+\M,\REG0
        std     Z+1+\M,\REG1
        std     Z+2+\M,\REG2
.endm
.macro  STORE96_TO_Z   REG11,REG10,REG9,REG8,REG7,REG6,REG5,REG4,REG3,REG2,REG1,REG0    M
        std     Z+0+\M,\REG0
        std     Z+1+\M,\REG1
        std     Z+2+\M,\REG2
        std     Z+3+\M,\REG3
        std     Z+4+\M,\REG4
        std     Z+5+\M,\REG5
        std     Z+6+\M,\REG6
        std     Z+7+\M,\REG7
        std     Z+8+\M,\REG8
        std     Z+9+\M,\REG9
        std     Z+10+\M,\REG10
        std     Z+11+\M,\REG11
.endm
.macro  STORE96_TO_Y   REG11,REG10,REG9,REG8,REG7,REG6,REG5,REG4,REG3,REG2,REG1,REG0    M
        std     Y+0+\M,\REG0
        std     Y+1+\M,\REG1
        std     Y+2+\M,\REG2
        std     Y+3+\M,\REG3
        std     Y+4+\M,\REG4
        std     Y+5+\M,\REG5
        std     Y+6+\M,\REG6
        std     Y+7+\M,\REG7
        std     Y+8+\M,\REG8
        std     Y+9+\M,\REG9
        std     Y+10+\M,\REG10
        std     Y+11+\M,\REG11
.endm
.macro  STORE48_TO_Y   REG5 REG4 REG3 REG2 REG1 REG0    M
        std     Y+0+\M,\REG0
        std     Y+1+\M,\REG1
        std     Y+2+\M,\REG2
        std     Y+3+\M,\REG3
        std     Y+4+\M,\REG4
        std     Y+5+\M,\REG5
.endm

  .global rsa_mul_192_no_abi
  .type rsa_mul_192_no_abi, @function
  .section .text.rsa_mul_192_no_abi,"ax",@progbits

rsa_mul_192_no_abi:
// positions in result (32..35) is used to store operands pointers
// (this part of result is unused in 1st part of calculation). 
	std	Z+32,r26
	std	Z+33,r27
	std	Z+34,r28
	std	Z+35,r29

	push	r30
	push	r31
  ;------ level 1: compute L ------

  ; init zero registers
  CLR R20
  CLR R21
  MOVW R22, R20
  MOVW R24, R20
  
  ;--- level 2: compute L ---
  LD R2, X+

	LOAD48_FROM_Y	r13,r12,r11,r10,r9,r8	0

  MUL R2, R10 ;a0 * b2
  MOVW R16, R0
  MUL R2, R8 ;a0 * b0
  MOVW R14, R0
  MUL R2, R9 ;a0 * b1
  ADD R15, R0
  ADC R16, R1
  ADC R17, R25
  MUL R2, R12 ;a0 * b4
  MOVW R18, R0
  MUL R2, R11 ;a0 * b3
  ADD R17, R0
  ADC R18, R1
  ADC R19, R25
  MUL R2, R13 ;a0 * b5
  ADD R19, R0
  ADC R20, R1

  LD R3, X+
  MUL R3, R10 ;a1 * b2
  MOVW R6, R0
  MUL R3, R8 ;a1 * b0
  ADD R15, R0
  ADC R16, R1
  ADC R17, R6
  ADC R7, R25
  MUL R3, R9 ;a1 * b1
  ADD R16, R0
  ADC R17, R1
  ADC R7, R25
  MUL R3, R12 ;a1 * b4
  ADD R18, R7
  ADC R19, R0
  ADC R20, R1
  ADC R21, R25
  MUL R3, R11 ;a1 * b3
  MOVW R6, R0
  MUL R3, R13 ;a1 * b5
  ADD R18, R6
  ADC R19, R7
  ADC R20, R0
  ADC R21, R1

  LD R4, X+
  MUL R4, R10 ;a2 * b2
  MOVW R6, R0
  MUL R4, R8 ;a2 * b0
  ADD R16, R0
  ADC R17, R1
  ADC R18, R6
  ADC R7, R25
  MUL R4, R9 ;a2 * b1
  ADD R17, R0
  ADC R18, R1
  ADC R7, R25
  MUL R4, R12 ;a2 * b4
  ADD R19, R7
  ADC R20, R0
  ADC R21, R1
  ADC R22, R25
  MUL R4, R11 ;a2 * b3
  MOVW R6, R0
  MUL R4, R13 ;a2 * b5
  ADD R19, R6
  ADC R20, R7
  ADC R21, R0
  ADC R22, R1
	STORE24_TO_Z	r16,r15,r14	0

  LD R5, X+
  MUL R5, R10 ;a3 * b2
  MOVW R14, R0
  MUL R5, R8 ;a3 * b0
  ADD R17, R0
  ADC R18, R1
  ADC R19, R14
  ADC R15, R25
  MUL R5, R9 ;a3 * b1
  ADD R18, R0
  ADC R19, R1
  ADC R15, R25
  MUL R5, R12 ;a3 * b4
  ADD R20, R15
  ADC R21, R0
  ADC R22, R1
  ADC R23, R25
  MUL R5, R11 ;a3 * b3
  MOVW R14, R0
  MUL R5, R13 ;a3 * b5
  ADD R20, R14
  ADC R21, R15
  ADC R22, R0
  ADC R23, R1

  LD R6, X+
  MUL R6, R10 ;a4 * b2
  MOVW R14, R0
  MUL R6, R8 ;a4 * b0
  ADD R18, R0
  ADC R19, R1
  ADC R20, R14
  ADC R15, R25
  MUL R6, R9 ;a4 * b1
  ADD R19, R0
  ADC R20, R1
  ADC R15, R25
  MUL R6, R12 ;a4 * b4
  ADD R21, R15
  ADC R22, R0
  ADC R23, R1
	movw	r4,r24		// save ZERO pair
  ADC R24, R25
  MUL R6, R11 ;a4 * b3
  MOVW R14, R0
  MUL R6, R13 ;a4 * b5
  ADD R21, R14
  ADC R22, R15
  ADC R23, R0
  ADC R24, R1

  LD R7, X+
  MUL R7, R10 ;a5 * b2
  MOVW R14, R0
  MUL R7, R8 ;a5 * b0
  ADD R19, R0
  ADC R20, R1
  ADC R21, R14
  ADC R15, R25
  MUL R7, R9 ;a5 * b1
  ADD R20, R0
  ADC R21, R1
  ADC R15, R25
  MUL R7, R12 ;a5 * b4
  ADD R22, R15
  ADC R23, R0
  ADC R24, R1
  ADC R25, R25
  MUL R7, R11 ;a5 * b3
  MOVW R14, R0
  MUL R7, R13 ;a5 * b5
  ADD R22, R14
  ADC R23, R15
  ADC R24, R0
  ADC R25, R1

	STORE24_TO_Z	r19,r18,r17	3

  ;--- load a6..a11 and b6..b11 ---
	LOAD48_FROM_X	r19,r18,r17,r16,r15,r14

	LOAD48_FROM_Y	r31,r30,r11,r10,r9,r8	6
  
  ;--- Compute H + (l6,l7,l8,l9,l10,l11) ---
// r4,5 zero
	movw	r2,r4
	movw	r6,r4
	movw	r12,r4

  MUL R8, R14
  ADD R20, R0   
  ADC R21, R1   
  ADC R22, R13
	adc	R2,R13	//  ADC R6, R13

  MUL R8, R15
  ADD R21, R0
  ADC R22, R1
	adc	R2,R13	//  ADC R6, R13
  MUL R9, R14
  ADD R21, R0
  ADC R22, R1
	adc	R23,R2	//  ADC R23, R6
	adc	R3,R13	//  ADC R7, R13

			//  CLR R6
  MUL R8, R16
  ADD R22, R0 
  ADC R23, R1
	adc	R3,R13	//  ADC R7, R13
  MUL R9, R15
  ADD R22, R0
  ADC R23, R1
	adc	R3,R13	//  ADC R7, R13
  MUL R10, R14
  ADD R22, R0
  ADC R23, R1
	adc	R24,R3	//  ADC R24, R7
  ADC R6, R13

	movw  R2,R12	//  CLR R7
  MUL R8, R17
  ADD R23, R0
  ADC R24, R1
  ADC R6, R13
  MUL R9, R16
  ADD R23, R0
  ADC R24, R1
  ADC R6, R13
  MUL R10, R15
  ADD R23, R0
  ADC R24, R1
  ADC R6, R13
  MUL R11, R14
  ADD R23, R0
  ADC R24, R1
  ADC R25, R6
  ADC R7, R13

  CLR R6		//
  MUL R8, R18
  ADD R24, R0
  ADC R25, R1
  ADC R7, R13
  MUL R9, R17
  ADD R24, R0
  ADC R25, R1
  ADC R7, R13
  MUL R10, R16
  ADD R24, R0
  ADC R25, R1
  ADC R7, R13
  MUL R11, R15
  ADD R24, R0
  ADC R25, R1
  ADC R7, R13
  MUL R30, R14
  ADD R24, R0
  ADC R25, R1
  ADC R7, R13

  MUL R8, R19
  ADD R25, R0
  ADC R7, R1
  ADC R6, R13
  MUL R9, R18
  ADD R25, R0
  ADC R7, R1
  ADC R6, R13
  MUL R10, R17
  ADD R25, R0
  ADC R7, R1
  ADC R6, R13
  MUL R11, R16
  ADD R25, R0
  ADC R7, R1
  ADC R6, R13
  MUL R30, R15
  ADD R25, R0
  ADC R7, R1
  ADC R6, R13
  MUL R31, R14
  ADD R25, R0
  ADC R7, R1
  ADC R6, R13

  MUL R15, R31
  ADD R7, R0
  ADC R6, R1
  ADC R2, R13
  MUL R16, R30
  ADD R7, R0
  ADC R6, R1
  ADC R2, R13
  MUL R17, R11
  ADD R7, R0
  ADC R6, R1
  ADC R2, R13
  MUL R18, R10
  ADD R7, R0
  ADC R6, R1
  ADC R2, R13
  MUL R19, R9
  ADD R7, R0
  ADC R6, R1
  ADC R2, R13

  MUL R16, R31
  ADD R6, R0
  ADC R2, R1
  ADC R3, R13
  MUL R17, R30
  ADD R6, R0
  ADC R2, R1
  ADC R3, R13
  MUL R18, R11
  ADD R6, R0
  ADC R2, R1
  ADC R3, R13
  MUL R19, R10
  ADD R6, R0
  ADC R2, R1
  ADC R3, R13

  MUL R17, R31
  ADD R2, R0
  ADC R3, R1
  ADC R4, R13
  MUL R18, R30
  ADD R2, R0
  ADC R3, R1
  ADC R4, R13
  MUL R19, R11
  ADD R2, R0
  ADC R3, R1
  ADC R4, R13

  MUL R18, R31
  ADD R3, R0
  ADC R4, R1
  ADC R5, R13
  MUL R19, R30
  ADD R3, R0
  ADC R4, R1
  ADC R5, R13

  MUL R19, R31
  ADD R4, R0
  ADC R5, R1
  
  ; push h6 and h7 on stack
  PUSH R6
  PUSH R7
  
  ;--- subtract a0-a5 ---
  SBIW R26, 12

  LD R0, X+
  SUB R14, R0
  LD R0, X+
  SBC R15, R0
  LD R0, X+
  SBC R16, R0
  LD R0, X+
  SBC R17, R0
  LD R0, X+
  SBC R18, R0
  LD R0, X+
  SBC R19, R0
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0

  ;--- subtract b0-b5 ---
  LDD R1, Y+0
  SUB R8, R1
  LDD R1, Y+1
  SBC R9, R1
  LDD R1, Y+2
  SBC R10, R1
  LDD R1, Y+3
  SBC R11, R1
  LDD R1, Y+4
  SBC R30, R1
  LDD R1, Y+5
  SBC R31, R1
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1

  ;--- absolute values ---   
  // zero in r13 
  ABS48 r19,r18,r17,r16,r15,r14  r0
  ABS48 r31,r30,r11,r10, r9, r8  r1

  EOR R0, R1
  BST R0, 0   
  
  ;--- Compute M ---
  MOVW R26, R12
  MOVW R28, R12
  
  MUL R14, R8
  MOVW R6, R0
  
  MUL R14, R9
  ADD R7, R0
  ADC R26, R1
  MUL R15, R8
  ADD R7, R0
  ADC R26, R1
  ADC R27, R13
  
  MUL R14, R10
  ADD R26, R0
  ADC R27, R1
  ADC R28, R13
  MUL R15, R9
  ADD R26, R0
  ADC R27, R1
  ADC R28, R13
  MUL R16, R8
  ADD R26, R0
  ADC R27, R1
  ADC R28, R13
  
  MUL R14, R11
  ADD R27, R0
  ADC R28, R1
  ADC R29, R13
  MUL R15, R10
  ADD R27, R0
  ADC R28, R1
  ADC R29, R13
  MUL R16, R9
  ADD R27, R0
  ADC R28, R1
  ADC R29, R13
  MUL R17, R8
  ADD R27, R0
  ADC R28, R1
  ADC R29, R13
  
  MUL R14, R30
  ADD R28, R0
  ADC R29, R1
  ADC R12, R13
  MUL R15, R11
  ADD R28, R0
  ADC R29, R1
  ADC R12, R13
  MUL R16, R10
  ADD R28, R0
  ADC R29, R1
  ADC R12, R13
  MUL R17, R9
  ADD R28, R0
  ADC R29, R1
  ADC R12, R13
  MUL R18, R8
  ADD R28, R0
  ADC R29, R1
  ADC R12, R13
  
  MUL R14, R31
  CLR R14
  ADD R29, R0
  ADC R12, R1
  ADC R13, R14
  MUL R15, R30
  ADD R29, R0
  ADC R12, R1
  ADC R13, R14
  MUL R16, R11
  ADD R29, R0
  ADC R12, R1
  ADC R13, R14
  MUL R17, R10
  ADD R29, R0
  ADC R12, R1
  ADC R13, R14
  MUL R18, R9
  ADD R29, R0
  ADC R12, R1
  ADC R13, R14
  MUL R19, R8
  ADD R29, R0
  ADC R12, R1
  ADC R13, R14
  
  CLR R8
  MUL R15, R31
  ADD R12, R0
  ADC R13, R1
  ADC R8, R14
  MUL R16, R30
  ADD R12, R0
  ADC R13, R1
  ADC R8, R14
  MUL R17, R11
  ADD R12, R0
  ADC R13, R1
  ADC R8, R14
  MUL R18, R10
  ADD R12, R0
  ADC R13, R1
  ADC R8, R14
  MUL R19, R9
  ADD R12, R0
  ADC R13, R1
  ADC R8, R14
  
  CLR R9
  MUL R16, R31
  ADD R13, R0
  ADC R8, R1
  ADC R9, R14
  MUL R17, R30
  ADD R13, R0
  ADC R8, R1
  ADC R9, R14
  MUL R18, R11
  ADD R13, R0
  ADC R8, R1
  ADC R9, R14
  MUL R19, R10
  ADD R13, R0
  ADC R8, R1
  ADC R9, R14
  
  CLR R10
  MUL R17, R31
  ADD R8, R0
  ADC R9, R1
  ADC R10, R14
  MUL R18, R30
  ADD R8, R0
  ADC R9, R1
  ADC R10, R14
  MUL R19, R11
  ADD R8, R0
  ADC R9, R1
  ADC R10, R14
  
  CLR R11
  MUL R18, R31
  ADD R9, R0
  ADC R10, R1
  ADC R11, R14
  MUL R19, R30
  ADD R9, R0
  ADC R10, R1
  ADC R11, R14
  
  MUL R19, R31
  ADD R10, R0
  ADC R11, R1

// restore Z register    in stack  26,27,28,29,30,31, r1,r0 ..
	in	r30,0x3d
	in	r31,0x3e
	ldd	r0,Z+4
	ldd	r1,Z+3
	movw	r30,r0
; restore h6 and h7
  POP R0
  POP R1
  
  ;--- add l5+h0 to l0 and h5 ---
	LOAD48_FROM_Z	r19,r18,r17,r16,r15,r14	0

  	ADD96 r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14    r5,r4,r3,r2,r1,r0 r25,r24,r23,r22,r21,r20
#ifdef RAM_LE32
	rol	r31
#endif
  ;--- process sign bit ---  
  BRTS add_M
#ifndef RAM_LE32
  ; store carry in T register
  ROL R5
  BST R5, 0
  ROR R5
#endif
  ; subtract M
	SUB96	r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14  r11,r10,r9,r8,r13,r12,r29,r28,r27,r26,r7,r6
	sbc	R6, R6
	rjmp	final_L

add_M:
#ifndef RAM_LE32
  ; store carry in T register
  ROL R5
  BST R5, 0
  ROR R5
#endif
	ADD96	r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14  r11,r10,r9,r8,r13,r12,r29,r28,r27,r26,r7,r6
	clr	R6
	adc	R6,R6
final_L:
	sbc	R7,R7	// extend r6 to R7:R6
; restore carry
#ifdef RAM_LE32
	lsr	r31
#else
  BLD R8, 0
  ASR R8
#endif
  ;--- propagate carry to end ---
	ADC48	r5,r4,r3,r2,r1,r0	r7,r7,r7,r7,r7,r6

	STORE48_TO_Z	r19,r18,r17,r16,r15,r14 6
	STORE48_TO_Z	r25,r24,r23,r22,r21,r20 12
	STORE48_TO_Z	r5,r4,r3,r2,r1,r0	18

// restore pointers to operands
	ldd	r26,Z+32
	ldd	r27,Z+33
	ldd	r28,Z+34
	ldd	r29,Z+35

	adiw	r26,12
  ;------ level 1: compute H ------

  ;init zero registers
  CLR R20
  CLR R21
  MOVW R22, R20
  MOVW R24, R20
  
  ;--- level 2: Compute L ---
  LD R2, X+
	LOAD48_FROM_Y	r13,r12,r11,r10,r9,r8	12

  MUL R2, R10 ;a0 * b2
  MOVW R16, R0
  MUL R2, R8 ;a0 * b0
  MOVW R14, R0
  MUL R2, R9 ;a0 * b1
  ADD R15, R0
  ADC R16, R1
  ADC R17, R25
  MUL R2, R12 ;a0 * b4
  MOVW R18, R0
  MUL R2, R11 ;a0 * b3
  ADD R17, R0
  ADC R18, R1
  ADC R19, R25
  MUL R2, R13 ;a0 * b5
  ADD R19, R0
  ADC R20, R1

  LD R3, X+
  MUL R3, R10 ;a1 * b2
  MOVW R6, R0
  MUL R3, R8 ;a1 * b0
  ADD R15, R0
  ADC R16, R1
  ADC R17, R6
  ADC R7, R25
  MUL R3, R9 ;a1 * b1
  ADD R16, R0
  ADC R17, R1
  ADC R7, R25
  MUL R3, R12 ;a1 * b4
  ADD R18, R7
  ADC R19, R0
  ADC R20, R1
  ADC R21, R25
  MUL R3, R11 ;a1 * b3
  MOVW R6, R0
  MUL R3, R13 ;a1 * b5
  ADD R18, R6
  ADC R19, R7
  ADC R20, R0
  ADC R21, R1

  LD R4, X+
  MUL R4, R10 ;a2 * b2
  MOVW R6, R0
  MUL R4, R8 ;a2 * b0
  ADD R16, R0
  ADC R17, R1
  ADC R18, R6
  ADC R7, R25
  MUL R4, R9 ;a2 * b1
  ADD R17, R0
  ADC R18, R1
  ADC R7, R25
  MUL R4, R12 ;a2 * b4
  ADD R19, R7
  ADC R20, R0
  ADC R21, R1
  ADC R22, R25
  MUL R4, R11 ;a2 * b3
  MOVW R6, R0
  MUL R4, R13 ;a2 * b5
  ADD R19, R6
  ADC R20, R7
  ADC R21, R0
  ADC R22, R1
	STORE24_TO_Z	r16,r15,r14	24

  LD R5, X+
  MUL R5, R10 ;a3 * b2
  MOVW R14, R0
  MUL R5, R8 ;a3 * b0
  ADD R17, R0
  ADC R18, R1
  ADC R19, R14
  ADC R15, R25
  MUL R5, R9 ;a3 * b1
  ADD R18, R0
  ADC R19, R1
  ADC R15, R25
  MUL R5, R12 ;a3 * b4
  ADD R20, R15
  ADC R21, R0
  ADC R22, R1
  ADC R23, R25
  MUL R5, R11 ;a3 * b3
  MOVW R14, R0
  MUL R5, R13 ;a3 * b5
  ADD R20, R14
  ADC R21, R15
  ADC R22, R0
  ADC R23, R1

  LD R6, X+
  MUL R6, R10 ;a4 * b2
  MOVW R14, R0
  MUL R6, R8 ;a4 * b0
  ADD R18, R0
  ADC R19, R1
  ADC R20, R14
  ADC R15, R25
  MUL R6, R9 ;a4 * b1
  ADD R19, R0
  ADC R20, R1
  ADC R15, R25
  MUL R6, R12 ;a4 * b4
  ADD R21, R15
  ADC R22, R0
  ADC R23, R1
	movw	r4,r24		// save ZERO pair
  ADC R24, R25
  MUL R6, R11 ;a4 * b3
  MOVW R14, R0
  MUL R6, R13 ;a4 * b5
  ADD R21, R14
  ADC R22, R15
  ADC R23, R0
  ADC R24, R1

  LD R7, X+
  MUL R7, R10 ;a5 * b2
  MOVW R14, R0
  MUL R7, R8 ;a5 * b0
  ADD R19, R0
  ADC R20, R1
  ADC R21, R14
  ADC R15, R25
  MUL R7, R9 ;a5 * b1
  ADD R20, R0
  ADC R21, R1
  ADC R15, R25
  MUL R7, R12 ;a5 * b4
  ADD R22, R15
  ADC R23, R0
  ADC R24, R1
  ADC R25, R25
  MUL R7, R11 ;a5 * b3
  MOVW R14, R0
  MUL R7, R13 ;a5 * b5
  ADD R22, R14
  ADC R23, R15
  ADC R24, R0
  ADC R25, R1
	STORE24_TO_Z	r19,r18,r17	27

  ;--- load a6..a11 and b6..b11 ---
	LOAD48_FROM_X	r19,r18,r17,r16,r15,r14
	LOAD48_FROM_Y	r31,r30,r11,r10,r9,r8	18
  
  ;--- Compute H + (l6,l7,l8,l9,l10,l11) ---
// r4,5 zero
	movw	r2,r4
	movw	r6,r4
	movw	r12,r4

  MUL R8, R14
  ADD R20, R0   
  ADC R21, R1   
  ADC R22, R13
	adc	R2,R13	//  ADC R6, R13

  MUL R8, R15
  ADD R21, R0
  ADC R22, R1
	adc	R2,R13	//  ADC R6, R13
  MUL R9, R14
  ADD R21, R0
  ADC R22, R1
	adc	R23,R2	//  ADC R23, R6
	adc	R3,R13	//  ADC R7, R13

			//  CLR R6
  MUL R8, R16
  ADD R22, R0 
  ADC R23, R1
	adc	R3,R13	//  ADC R7, R13
  MUL R9, R15
  ADD R22, R0
  ADC R23, R1
	adc	R3,R13	//  ADC R7, R13
  MUL R10, R14
  ADD R22, R0
  ADC R23, R1
	adc	R24,R3	//  ADC R24, R7
  ADC R6, R13

	movw  R2,R12	//  CLR R7

  MUL R8, R17
  ADD R23, R0
  ADC R24, R1
  ADC R6, R13
  MUL R9, R16
  ADD R23, R0
  ADC R24, R1
  ADC R6, R13
  MUL R10, R15
  ADD R23, R0
  ADC R24, R1
  ADC R6, R13
  MUL R11, R14
  ADD R23, R0
  ADC R24, R1
  ADC R25, R6
  ADC R7, R13

  CLR R6		//
  MUL R8, R18
  ADD R24, R0
  ADC R25, R1
  ADC R7, R13
  MUL R9, R17
  ADD R24, R0
  ADC R25, R1
  ADC R7, R13
  MUL R10, R16
  ADD R24, R0
  ADC R25, R1
  ADC R7, R13
  MUL R11, R15
  ADD R24, R0
  ADC R25, R1
  ADC R7, R13
  MUL R30, R14
  ADD R24, R0
  ADC R25, R1
  ADC R7, R13

  MUL R8, R19
  ADD R25, R0
  ADC R7, R1
  ADC R6, R13
  MUL R9, R18
  ADD R25, R0
  ADC R7, R1
  ADC R6, R13
  MUL R10, R17
  ADD R25, R0
  ADC R7, R1
  ADC R6, R13
  MUL R11, R16
  ADD R25, R0
  ADC R7, R1
  ADC R6, R13
  MUL R30, R15
  ADD R25, R0
  ADC R7, R1
  ADC R6, R13
  MUL R31, R14
  ADD R25, R0
  ADC R7, R1
  ADC R6, R13

  MUL R15, R31
  ADD R7, R0
  ADC R6, R1
  ADC R2, R13
  MUL R16, R30
  ADD R7, R0
  ADC R6, R1
  ADC R2, R13
  MUL R17, R11
  ADD R7, R0
  ADC R6, R1
  ADC R2, R13
  MUL R18, R10
  ADD R7, R0
  ADC R6, R1
  ADC R2, R13
  MUL R19, R9
  ADD R7, R0
  ADC R6, R1
  ADC R2, R13

  MUL R16, R31
  ADD R6, R0
  ADC R2, R1
  ADC R3, R13
  MUL R17, R30
  ADD R6, R0
  ADC R2, R1
  ADC R3, R13
  MUL R18, R11
  ADD R6, R0
  ADC R2, R1
  ADC R3, R13
  MUL R19, R10
  ADD R6, R0
  ADC R2, R1
  ADC R3, R13

  MUL R17, R31
  ADD R2, R0
  ADC R3, R1
  ADC R4, R13
  MUL R18, R30
  ADD R2, R0
  ADC R3, R1
  ADC R4, R13
  MUL R19, R11
  ADD R2, R0
  ADC R3, R1
  ADC R4, R13

  MUL R18, R31
  ADD R3, R0
  ADC R4, R1
  ADC R5, R13
  MUL R19, R30
  ADD R3, R0
  ADC R4, R1
  ADC R5, R13

  MUL R19, R31
  ADD R4, R0
  ADC R5, R1
  
  ; push h6 and h7 on stack
  PUSH R6
  PUSH R7
  
  ;--- subtract a0-a5 ---
  SBIW R26, 12
  LD R0, X+
  SUB R14, R0
  LD R0, X+
  SBC R15, R0
  LD R0, X+
  SBC R16, R0
  LD R0, X+
  SBC R17, R0
  LD R0, X+
  SBC R18, R0
  LD R0, X+
  SBC R19, R0
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0

  ;--- subtract b0-b5 ---
  LDD R1, Y+12
  SUB R8, R1
  LDD R1, Y+13
  SBC R9, R1
  LDD R1, Y+14
  SBC R10, R1
  LDD R1, Y+15
  SBC R11, R1
  LDD R1, Y+16
  SBC R30, R1
  LDD R1, Y+17
  SBC R31, R1
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1

  ;--- absolute values ---    
  // r13 zero, r0,1 sign
  ABS48 r19,r18,r17,r16,r15,r14  r0
  ABS48 r31,r30,r11,r10, r9, r8  r1

  EOR R0, R1
  BST R0, 0   
  
  ;--- Compute M ---
  MOVW R26, R12
  MOVW R28, R12
  
  MUL R14, R8
  MOVW R6, R0
  
  MUL R14, R9
  ADD R7, R0
  ADC R26, R1
  MUL R15, R8
  ADD R7, R0
  ADC R26, R1
  ADC R27, R13
  
  MUL R14, R10
  ADD R26, R0
  ADC R27, R1
  ADC R28, R13
  MUL R15, R9
  ADD R26, R0
  ADC R27, R1
  ADC R28, R13
  MUL R16, R8
  ADD R26, R0
  ADC R27, R1
  ADC R28, R13
  
  MUL R14, R11
  ADD R27, R0
  ADC R28, R1
  ADC R29, R13
  MUL R15, R10
  ADD R27, R0
  ADC R28, R1
  ADC R29, R13
  MUL R16, R9
  ADD R27, R0
  ADC R28, R1
  ADC R29, R13
  MUL R17, R8
  ADD R27, R0
  ADC R28, R1
  ADC R29, R13
  
  MUL R14, R30
  ADD R28, R0
  ADC R29, R1
  ADC R12, R13
  MUL R15, R11
  ADD R28, R0
  ADC R29, R1
  ADC R12, R13
  MUL R16, R10
  ADD R28, R0
  ADC R29, R1
  ADC R12, R13
  MUL R17, R9
  ADD R28, R0
  ADC R29, R1
  ADC R12, R13
  MUL R18, R8
  ADD R28, R0
  ADC R29, R1
  ADC R12, R13
  
  MUL R14, R31
  CLR R14
  ADD R29, R0
  ADC R12, R1
  ADC R13, R14
  MUL R15, R30
  ADD R29, R0
  ADC R12, R1
  ADC R13, R14
  MUL R16, R11
  ADD R29, R0
  ADC R12, R1
  ADC R13, R14
  MUL R17, R10
  ADD R29, R0
  ADC R12, R1
  ADC R13, R14
  MUL R18, R9
  ADD R29, R0
  ADC R12, R1
  ADC R13, R14
  MUL R19, R8
  ADD R29, R0
  ADC R12, R1
  ADC R13, R14
  
  CLR R8
  MUL R15, R31
  ADD R12, R0
  ADC R13, R1
  ADC R8, R14
  MUL R16, R30
  ADD R12, R0
  ADC R13, R1
  ADC R8, R14
  MUL R17, R11
  ADD R12, R0
  ADC R13, R1
  ADC R8, R14
  MUL R18, R10
  ADD R12, R0
  ADC R13, R1
  ADC R8, R14
  MUL R19, R9
  ADD R12, R0
  ADC R13, R1
  ADC R8, R14
  
  CLR R9
  MUL R16, R31
  ADD R13, R0
  ADC R8, R1
  ADC R9, R14
  MUL R17, R30
  ADD R13, R0
  ADC R8, R1
  ADC R9, R14
  MUL R18, R11
  ADD R13, R0
  ADC R8, R1
  ADC R9, R14
  MUL R19, R10
  ADD R13, R0
  ADC R8, R1
  ADC R9, R14
  
  CLR R10
  MUL R17, R31
  ADD R8, R0
  ADC R9, R1
  ADC R10, R14
  MUL R18, R30
  ADD R8, R0
  ADC R9, R1
  ADC R10, R14
  MUL R19, R11
  ADD R8, R0
  ADC R9, R1
  ADC R10, R14
  
  CLR R11
  MUL R18, R31
  ADD R9, R0
  ADC R10, R1
  ADC R11, R14
  MUL R19, R30
  ADD R9, R0
  ADC R10, R1
  ADC R11, R14
  
  MUL R19, R31
  ADD R10, R0
  ADC R11, R1
  
  ; restore h6 and h7 and Z register
  POP R0
  POP R1
  POP R31
  POP R30
  
  ;--- add l5+h0 to l0 and h5 ---
	LOAD48_FROM_Z	r19,r18,r17,r16,r15,r14		24
	ADD96 r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14   r5,r4,r3,r2,r1,r0,r25,r24,r23,r22,r21,r20
#ifdef RAM_LE32
	rol	r31
#endif
      
  ;--- process sign bit ---  
  BRTS add_M_H
#ifndef RAM_LE32
  ; store carry in T register
  ROL R5
  BST R5, 0
  ROR R5
#endif
  ; subtract M
	SUB96	r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14   r11,r10,r9,r8,r13,r12,r29,r28,r27,r26,r7,r6
	sbc	R6, R6
	rjmp	final_H

add_M_H:
#ifndef RAM_LE32
  ; store carry in T register
  ROL R5
  BST R5, 0
  ROR R5
#endif
	ADD96	r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14   r11,r10,r9,r8,r13,r12,r29,r28,r27,r26,r7,r6
	clr	R6
	adc	R6,R6
final_H:
	sbc	R7,R7	// extend r6 to r7:r6
; restore carry
#ifdef RAM_LE32
	lsr	r31
#else
  BLD R8, 0
  ASR R8
#endif
  ;--- propagate carry to end ---
	ADC48	r5,r4,r3,r2,r1,r0	r7,r7,r7,r7,r7,r6
	STORE96_TO_Z	r5,r4,r3,r2,r1,r0,r25,r24,r23,r22,r21,r20  36

  ;------ level 1: combine L and H ------
	LOAD48_FROM_Z	r11,r10,r9,r8,r7,r6	24
  ; H is stored in: 6,7,8,9,10,11,14,15,16,17,18,19,20,21,22,23,24,25,0,1,2,3,4,5
  ; add HIGH(L)
.set Off,12
	ldd	r12,Z+Off
	add	r6,r12
.irp	Reg,7,8,9,10,11,14,15,16,17,18,19
.set Off, Off+1
	ldd	r12,Z+Off
	adc	r\Reg,r12
.endr

  CLR R12
  CLR R13
  ADC R13, R12
  ; propagate carry to end
	ADD96 r5,r4,r3,r2,r1,r0 r25,r24,r23,r22,r21,r20  r12,r12,r12,r12,r12,r12,r12,r12,r12,r12,r12,r13
.set Off, 0
	ldd	r28,Z+Off
	add	r28,r6
	std	Z+Off+12,r28
.irp	Reg,7,8,9,10,11,14,15,16,17,18,19
.set Off, Off+1
	ldd	r28,Z+Off
	adc	r28,r\Reg
	std	Z+Off+12,r28
.endr
	ADC96	r5,r4,r3,r2,r1,r0,r25,r24,r23,r22,r21,r20  r19,r18,r17,r16,r15,r14,r11,r10,r9,r8,r7,r6
// restore pointers to operands X and Y
	ldd	r26,Z+32
	ldd	r27,Z+33
	ldd	r28,Z+34
	ldd	r29,Z+35
	STORE96_TO_Z	r5,r4,r3,r2,r1,r0,r25,r24,r23,r22,r21,r20	24

  ADC R13, R12		// update carry in R13 is 0, 1 or 2!

  ;------ level 1: subtract a0-a12 ------

	LOAD48_FROM_X	R7,R6,R5,R4,R3,R2
	LOAD48_FROM_X	R19,R18,R17,R16,R15,R14

	LOAD48_FROM_X					R23,R22,R11,R10,R9,R8
	SUB48		R7,R6,R5,R4,R3,R2		R23,R22,R11,R10,R9,R8

	LOAD48_FROM_X					R23,R22,R11,R10,R9,R8
	SBC48		R19,R18,R17,R16,R15,R14		R23,R22,R11,R10,R9,R8
	sbc	R0,R0	// sign to R0

	ABS96		R19,R18,R17,R16,R15,R14,R7,R6,R5,R4,R3,R2	R0

  // save part to stack 
.irp Reg,19,18,17,16,15,14,7,6,5,4,3,2
	push	r\Reg
.endr

	LOAD48_FROM_Y	R23,R22,R11,R10,R9,R8	0
	LOAD48_FROM_Y	R19,R18,R17,R16,R15,R14	6

	LOAD48_FROM_Y					R25,R24,R27,R26,R21,R20		12
	SUB48		R23,R22,R11,R10,R9,R8		R25,R24,R27,R26,R21,R20

	LOAD48_FROM_Y					R25,R24,R27,R26,R21,R20		18
	SBC48		R19,R18,R17,R16,R15,R14		R25,R24,R27,R26,R21,R20
	sbc	R1,R1	// sign to R1

	ABS96 R19,R18,R17,R16,R15,R14,R23,R22,R11,R10,R9,R8  R1
  // save part to stack
.irp Reg,19,18,17,16,15,14,23,22,11,10,9,8
	push	r\Reg
.endr
	eor	r0,r1
	rol	r0
	rol	r13
// combined value .. bit2,1 = carry, bit 0 sign
  	push	r13		// search HL1
    
  PUSH R30 ; save Z register
  PUSH R31

  ;------ level 1: compute M ------

  ; init zero registers
//  CLR   R12	// already cleared
  CLR	R13
  MOVW R24, R12
  MOVW R20, R24
  
  ;--- level 2: compute L ---
// r8.. R23 already loaded

  MUL R2, R10 ;a0 * b2
  MOVW R16, R0
  MUL R2, R8 ;a0 * b0
  MOVW R14, R0
  MUL R2, R9 ;a0 * b1
  ADD R15, R0
  ADC R16, R1
  ADC R17, R25
  MUL R2, R22 ;a0 * b4
  MOVW R18, R0
  MUL R2, R11 ;a0 * b3
  ADD R17, R0
  ADC R18, R1
  ADC R19, R25
  MUL R2, R23 ;a0 * b5
  ADD R19, R0
  ADC R20, R1

  MUL R3, R10 ;a1 * b2
  MOVW R26, R0
  MUL R3, R8 ;a1 * b0
  ADD R15, R0
  ADC R16, R1
  ADC R17, R26
  ADC R27, R25
  MUL R3, R9 ;a1 * b1
  ADD R16, R0
  ADC R17, R1
  ADC R27, R25
  MUL R3, R22 ;a1 * b4
  ADD R18, R27
  ADC R19, R0
  ADC R20, R1
  ADC R21, R25
  MUL R3, R11 ;a1 * b3
  MOVW R26, R0
  MUL R3, R23 ;a1 * b5
  ADD R18, R26
  ADC R19, R27
  ADC R20, R0
  ADC R21, R1

  MUL R4, R10 ;a2 * b2
  MOVW R26, R0
  MUL R4, R8 ;a2 * b0
  ADD R16, R0
  ADC R17, R1
  ADC R18, R26
  ADC R27, R25
  MUL R4, R9 ;a2 * b1
  ADD R17, R0
  ADC R18, R1
  ADC R27, R25
  MUL R4, R22 ;a2 * b4
  ADD R19, R27
  ADC R20, R0
  ADC R21, R1
  ADC R12, R25
  MUL R4, R11 ;a2 * b3
  MOVW R26, R0
  MUL R4, R23 ;a2 * b5
  ADD R19, R26
  ADC R20, R27
  ADC R21, R0
  ADC R12, R1
	push	r14
	push	r15
	push	r16
  MUL R5, R10 ;a3 * b2
  MOVW R14, R0
  MUL R5, R8 ;a3 * b0
  ADD R17, R0
  ADC R18, R1
  ADC R19, R14
  ADC R15, R25
  MUL R5, R9 ;a3 * b1
  ADD R18, R0
  ADC R19, R1
  ADC R15, R25
  MUL R5, R22 ;a3 * b4
  ADD R20, R15
  ADC R21, R0
  ADC R12, R1
  ADC R13, R25
  MUL R5, R11 ;a3 * b3
  MOVW R14, R0
  MUL R5, R23 ;a3 * b5
  ADD R20, R14
  ADC R21, R15
  ADC R12, R0
  ADC R13, R1

  MUL R6, R10 ;a4 * b2
  MOVW R14, R0
  MUL R6, R8 ;a4 * b0
  ADD R18, R0
  ADC R19, R1
  ADC R20, R14
  ADC R15, R25
  MUL R6, R9 ;a4 * b1
  ADD R19, R0
  ADC R20, R1
  ADC R15, R25
  MUL R6, R22 ;a4 * b4
  ADD R21, R15
  ADC R12, R0
  ADC R13, R1
	movw	r4,r24		// save ZERO pair

  ADC R24, R25
  MUL R6, R11 ;a4 * b3
  MOVW R14, R0
  MUL R6, R23 ;a4 * b5
  ADD R21, R14
  ADC R12, R15
  ADC R13, R0
  ADC R24, R1

  MUL R7, R10 ;a5 * b2
  MOVW R14, R0
  MUL R7, R8 ;a5 * b0
  ADD R19, R0
  ADC R20, R1
  ADC R21, R14
  ADC R15, R25
  MUL R7, R9 ;a5 * b1
  ADD R20, R0
  ADC R21, R1
  ADC R15, R25
  MUL R7, R22 ;a5 * b4
  ADD R12, R15
  ADC R13, R0
  ADC R24, R1
  ADC R25, R25
  MUL R7, R11 ;a5 * b3
  MOVW R14, R0
  MUL R7, R23 ;a5 * b5
  ADD R12, R14
  ADC R13, R15
  ADC R24, R0
  ADC R25, R1
	push	R17
	push	R18
	push	R19

	in	r28,0x3d
	in	r29,0x3e

  ;--- load a6..a11 and b6..b11 ---
	LOAD48_FROM_Y	r19,r18,r17,r16,r15,r14	28

	LOAD48_FROM_Y	r31,r30,r11,r10,r9,r8	16
  
  ;--- Compute H + (l6,l7,l8,l9,l10,l11) ---
// r4,5 zero
	movw	r2,r4
	movw	r6,r4
	movw	r22,r4

  MUL R8, R14
  ADD R20, R0   
  ADC R21, R1   
  ADC R12, R23
	adc	R2,R23	//  ADC R6, R23

  MUL R8, R15
  ADD R21, R0
  ADC R12, R1
	adc	R2,R23	//  ADC R6, R23
  MUL R9, R14
  ADD R21, R0
  ADC R12, R1
	adc	R13,R2	//  ADC R13, R6
	adc	R3,R23	//  ADC R7, R23

			//  CLR R6
  MUL R8, R16
  ADD R12, R0 
  ADC R13, R1
	adc	R3,R23	//  ADC R7, R23
  MUL R9, R15
  ADD R12, R0
  ADC R13, R1
	adc	R3,R23	//  ADC R7, R23
  MUL R10, R14
  ADD R12, R0
  ADC R13, R1
	adc	R24,R3	//  ADC R24, R7
  ADC R6, R23

	movw  R2,R22	//  CLR R7

  MUL R8, R17
  ADD R13, R0
  ADC R24, R1
  ADC R6, R23
  MUL R9, R16
  ADD R13, R0
  ADC R24, R1
  ADC R6, R23
  MUL R10, R15
  ADD R13, R0
  ADC R24, R1
  ADC R6, R23
  MUL R11, R14
  ADD R13, R0
  ADC R24, R1
  ADC R25, R6
  ADC R7, R23

  CLR R6		//
  MUL R8, R18
  ADD R24, R0
  ADC R25, R1
  ADC R7, R23
  MUL R9, R17
  ADD R24, R0
  ADC R25, R1
  ADC R7, R23
  MUL R10, R16
  ADD R24, R0
  ADC R25, R1
  ADC R7, R23
  MUL R11, R15
  ADD R24, R0
  ADC R25, R1
  ADC R7, R23
  MUL R30, R14
  ADD R24, R0
  ADC R25, R1
  ADC R7, R23

  MUL R8, R19
  ADD R25, R0
  ADC R7, R1
  ADC R6, R23
  MUL R9, R18
  ADD R25, R0
  ADC R7, R1
  ADC R6, R23
  MUL R10, R17
  ADD R25, R0
  ADC R7, R1
  ADC R6, R23
  MUL R11, R16
  ADD R25, R0
  ADC R7, R1
  ADC R6, R23
  MUL R30, R15
  ADD R25, R0
  ADC R7, R1
  ADC R6, R23
  MUL R31, R14
  ADD R25, R0
  ADC R7, R1
  ADC R6, R23

  MUL R15, R31
  ADD R7, R0
  ADC R6, R1
  ADC R2, R23
  MUL R16, R30
  ADD R7, R0
  ADC R6, R1
  ADC R2, R23
  MUL R17, R11
  ADD R7, R0
  ADC R6, R1
  ADC R2, R23
  MUL R18, R10
  ADD R7, R0
  ADC R6, R1
  ADC R2, R23
  MUL R19, R9
  ADD R7, R0
  ADC R6, R1
  ADC R2, R23

  MUL R16, R31
  ADD R6, R0
  ADC R2, R1
  ADC R3, R23
  MUL R17, R30
  ADD R6, R0
  ADC R2, R1
  ADC R3, R23
  MUL R18, R11
  ADD R6, R0
  ADC R2, R1
  ADC R3, R23
  MUL R19, R10
  ADD R6, R0
  ADC R2, R1
  ADC R3, R23

  MUL R17, R31
  ADD R2, R0
  ADC R3, R1
  ADC R4, R23
  MUL R18, R30
  ADD R2, R0
  ADC R3, R1
  ADC R4, R23
  MUL R19, R11
  ADD R2, R0
  ADC R3, R1
  ADC R4, R23

  MUL R18, R31
  ADD R3, R0
  ADC R4, R1
  ADC R5, R23
  MUL R19, R30
  ADD R3, R0
  ADC R4, R1
  ADC R5, R23

  MUL R19, R31
  ADD R4, R0
  ADC R5, R1

  ; push h6 and h7 on stack
  PUSH R6
  PUSH R7
  
  ;--- subtract a0-a5 ---
  LDD R0, Y+22
  SUB R14, R0
  LDD R0, Y+23
  SBC R15, R0
  LDD R0, Y+24
  SBC R16, R0
  LDD R0, Y+25
  SBC R17, R0
  LDD R0, Y+26
  SBC R18, R0
  LDD R0, Y+27
  SBC R19, R0
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0

  ;--- subtract b0-b5 ---
  LDD R1, Y+10
  SUB R8, R1
  LDD R1, Y+11
  SBC R9, R1
  LDD R1, Y+12
  SBC R10, R1
  LDD R1, Y+13
  SBC R11, R1
  LDD R1, Y+14
  SBC R30, R1
  LDD R1, Y+15
  SBC R31, R1
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1

  ;--- absolute values ---    
  // R23 zero, r0,1 sign
  ABS48 r19,r18,r17,r16,r15,r14  r0
  ABS48 r31,r30,r11,r10, r9, r8  r1

  EOR R0, R1
  BST R0, 0   
  
  ;--- Compute M ---
  MOVW R26, R22
  MOVW R28, R22
  
  MUL R14, R8
  MOVW R6, R0
  
  MUL R14, R9
  ADD R7, R0
  ADC R26, R1
  MUL R15, R8
  ADD R7, R0
  ADC R26, R1
  ADC R27, R23
  
  MUL R14, R10
  ADD R26, R0
  ADC R27, R1
  ADC R28, R23
  MUL R15, R9
  ADD R26, R0
  ADC R27, R1
  ADC R28, R23
  MUL R16, R8
  ADD R26, R0
  ADC R27, R1
  ADC R28, R23
  
  MUL R14, R11
  ADD R27, R0
  ADC R28, R1
  ADC R29, R23
  MUL R15, R10
  ADD R27, R0
  ADC R28, R1
  ADC R29, R23
  MUL R16, R9
  ADD R27, R0
  ADC R28, R1
  ADC R29, R23
  MUL R17, R8
  ADD R27, R0
  ADC R28, R1
  ADC R29, R23

  MUL R14, R30
  ADD R28, R0
  ADC R29, R1
  ADC R22, R23
  MUL R15, R11
  ADD R28, R0
  ADC R29, R1
  ADC R22, R23
  MUL R16, R10
  ADD R28, R0
  ADC R29, R1
  ADC R22, R23
  MUL R17, R9
  ADD R28, R0
  ADC R29, R1
  ADC R22, R23
  MUL R18, R8
  ADD R28, R0
  ADC R29, R1
  ADC R22, R23

  MUL R14, R31
  CLR R14
  ADD R29, R0
  ADC R22, R1
  ADC R23, R14
  MUL R15, R30
  ADD R29, R0
  ADC R22, R1
  ADC R23, R14
  MUL R16, R11
  ADD R29, R0
  ADC R22, R1
  ADC R23, R14
  MUL R17, R10
  ADD R29, R0
  ADC R22, R1
  ADC R23, R14
  MUL R18, R9
  ADD R29, R0
  ADC R22, R1
  ADC R23, R14
  MUL R19, R8
  ADD R29, R0
  ADC R22, R1
  ADC R23, R14

  CLR R8
  MUL R15, R31
  ADD R22, R0
  ADC R23, R1
  ADC R8, R14
  MUL R16, R30
  ADD R22, R0
  ADC R23, R1
  ADC R8, R14
  MUL R17, R11
  ADD R22, R0
  ADC R23, R1
  ADC R8, R14
  MUL R18, R10
  ADD R22, R0
  ADC R23, R1
  ADC R8, R14
  MUL R19, R9
  ADD R22, R0
  ADC R23, R1
  ADC R8, R14

  CLR R9
  MUL R16, R31
  ADD R23, R0
  ADC R8, R1
  ADC R9, R14
  MUL R17, R30
  ADD R23, R0
  ADC R8, R1
  ADC R9, R14
  MUL R18, R11
  ADD R23, R0
  ADC R8, R1
  ADC R9, R14
  MUL R19, R10
  ADD R23, R0
  ADC R8, R1
  ADC R9, R14

  CLR R10
  MUL R17, R31
  ADD R8, R0
  ADC R9, R1
  ADC R10, R14
  MUL R18, R30
  ADD R8, R0
  ADC R9, R1
  ADC R10, R14
  MUL R19, R11
  ADD R8, R0
  ADC R9, R1
  ADC R10, R14

  CLR R11
  MUL R18, R31
  ADD R9, R0
  ADC R10, R1
  ADC R11, R14
  MUL R19, R30
  ADD R9, R0
  ADC R10, R1
  ADC R11, R14

  MUL R19, R31
  ADD R10, R0
  ADC R11, R1

  POP R0
  POP R1

  ; now load stack pointer in R31:30
	in	r30,0x3d
	in	r31,0x3e

  ;--- add l5+h0 to l0 and h5 ---
	LOAD48_FROM_Z			r14,r15,r16,r17,r18,r19		1
	ADD96	r25,r24,r13,r12,r21,r20,r19,r18,r17,r16,r15,r14	 r5,r4,r3,r2,r1,r0,r25,r24,r13,r12,r21,r20
	rol	r31	// carry to r31
  ;--- process sign bit ---  
  BRTS add_M_M
  
  ;subtract M
	SUB96	r25,r24,r13,r12,r21,r20,r19,r18,r17,r16,r15,r14  r11,r10,r9,r8,r23,r22,r29,r28,r27,r26,r7,r6
	sbc	r6,r6
	rjmp	final_M

add_M_M: 
	ADD96	r25,r24,r13,r12,r21,r20,r19,r18,r17,r16,r15,r14  r11,r10,r9,r8,r23,r22,r29,r28,r27,r26,r7,r6
	clr	r6
	adc	r6,r6
final_M:
	sbc	r7,r7	// extend r6 to r7:r6
	// restore carry
	lsr	r31
#ifndef RAM_LE32
// restore r31
	in	r31, _SFR_IO_ADDR(SPH)
#endif
  ;--- propagate carry to end ---
	ADC48	r5,r4,r3,r2,r1,r0	r7,r7,r7,r7,r7,r6

	ldd	R29,Z+7	;load Y register - pointer to result
	ldd	R28,Z+8
  ;------ level 1: combine L, H, and M ------

  ; load m0..m5 in 8,9,10,11,12,13
	LOAD48_FROM_Z	r8,r9,r10,r11,r22,r23	1
  ; M is stored in: 8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,1,2,3,4,5

	clr	r27
// load sign bit, load carry (carry in bits 2,1 sign in bit 0)
	ldd	r26,Z+9		// search backwards for HL1
	lsr	r26		
	brcc	final_sub

final_addition:
// result(MEM) += registers
.set Off, 12
	ldd	r6,Y+Off
	add	r6,r8
.set Preg, 8
.irp Reg,9,10,11,22,23,14,15,16,17,18,19,20,21,12,13,24,25,0,1,2,3,4,5
.set Off, Off+1
	ldd	Preg,Y+Off
	adc	Preg,r\Reg
.set Preg, \Reg
.endr
	adc	r26, r27
	rjmp	final

final_sub:
// result(MEM) -= registers
.set Off, 12
	ldd	r6, Y+Off
	sub	r6,r8
.set Preg, 8
.irp Reg,9,10,11,22,23,14,15,16,17,18,19,20,21,12,13,24,25,0,1,2,3,4,5
.set Off, Off+1
	ldd	Preg,Y+Off
	sbc	Preg,r\Reg
.set Preg, \Reg
.endr
	sbc	r26,r27
	sbc	r27,r27
final:
	STORE96_TO_Y	r18,r17,r16,r15,r14,r23,r22,r11,r10,r9,r8,r6 12
	STORE96_TO_Y	r4,r3,r2,r1,r0,r25,r24,r13,r12,r21,r20,r19 24

// return stack back
	adiw	r30,33
// use atomic update of stack pointer
	LOAD_SP r0, r30,r31

// R27:R26 is -1,0,1,2,  propagate carry to end

	LOAD96_FROM_Y	r13,r12,r11,r10,r9,r8,r5,r4,r3,r2,r1,r0	36
	ADD96		r13,r12,r11,r10,r9,r8,r5,r4,r3,r2,r1,r0  r27,r27,r27,r27,r27,r27,r27,r27,r27,r27,r27,r26
	STORE96_TO_Y	r13,r12,r11,r10,r9,r8,r5,r4,r3,r2,r1,r0 36

	ret
