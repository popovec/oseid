/*
    This is part of OsEID (Open source Electronic ID)

    192bit (interrupt safe) multiplication routine for AVR

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
    Version: 2014-07-25  Public domain

  Differences to original code from Michael Hutter and Peter Schwabe:

  --  no stack register move forward/backwards
  --  code is faster and interrupt safe (please check LOAD_SP macro)
  --  removed unneded CLR R6 (3x)
  --  improved registers reuse/clear
  --  macros
  --  code speed up (orig:2923 this: 2889 ticks)
  --  -7 ticks if RAM_LE32 is defined (2882 ticks)

*/
//#undef RAM_LE32
#include "load_sp.h"

#if defined(HAVE_RSA_MUL_192_NO_ABI)
#include <avr/io.h>

.macro ABS48  RS5,RS4,RS3,RS2,RS1,RS0 SIGN ZERO
        eor     \RS0,\SIGN
        eor     \RS1,\SIGN
        eor     \RS2,\SIGN
        eor     \RS3,\SIGN
        eor     \RS4,\SIGN
        eor     \RS5,\SIGN
        neg     \SIGN
        add     \RS0,\SIGN
        adc     \RS1,\ZERO
        adc     \RS2,\ZERO
        adc     \RS3,\ZERO
        adc     \RS4,\ZERO
        adc     \RS5,\ZERO
.endm

.macro ABS96  RS11,RS10,RS9,RS8,RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0 SIGN ZERO
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
        neg     \SIGN
        add     \RS0,\SIGN
        adc     \RS1,\ZERO
        adc     \RS2,\ZERO
        adc     \RS3,\ZERO
        adc     \RS4,\ZERO
        adc     \RS5,\ZERO
        adc     \RS6,\ZERO
        adc     \RS7,\ZERO
        adc     \RS8,\ZERO
        adc     \RS9,\ZERO
        adc     \RS10,\ZERO
        adc     \RS11,\ZERO
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

  .global rsa_mul_192_no_abi
  .type rsa_mul_192_no_abi, @function

rsa_mul_192_no_abi:

  ;------ level 1: compute L ------

  ; init zero registers
  CLR R20
  CLR R21
  MOVW R22, R20
  MOVW R24, R20
  
  ;--- level 2: compute L ---
  LD R2, X+
  LDD R8,  Y+0
  LDD R9,  Y+1
  LDD R10, Y+2
  LDD R11, Y+3
  LDD R12, Y+4
  LDD R13, Y+5

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
  STD Z+0, R14
  STD Z+1, R15
  STD Z+2, R16

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
  STD Z+3, R17
  STD Z+4, R18
  STD Z+5, R19

  ;--- load a6..a11 and b6..b11 ---
  LD R14, X+
  LD R15, X+
  LD R16, X+
  LD R17, X+
  LD R18, X+
  LD R19, X+

  PUSH R26 ; save X register
  PUSH R27
  PUSH R28 ; save Y register
  PUSH R29
  PUSH R30 ; save Z register
  PUSH R31

  LDD R8,  Y+6
  LDD R9,  Y+7
  LDD R10, Y+8
  LDD R11, Y+9

  LDD R30, Y+10
  LDD R31, Y+11
  
  ;--- Compute H + (l6,l7,l8,l9,l10,l11) ---
  CLR R12
  CLR R13
  MOVW R2, R12
  MOVW R4, R12
  MOVW R6, R12

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

//  CLR R6		// already cleared
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
  ABS48 r19,r18,r17,r16,r15,r14  r0 r13
  ABS48 r31,r30,r11,r10, r9, r8  r1 r13

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
  LDD R14, Z+0
  LDD R15, Z+1
  LDD R16, Z+2
  LDD R17, Z+3
  LDD R18, Z+4
  LDD R19, Z+5

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
	SUB96 r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14  r11,r10,r9,r8,r13,r12,r29,r28,r27,r26,r7,r6

  SBC R6, R6
  SBC R7, R7  
  ; R7:R6 is -1,0, or 1
  RJMP final_L

add_M:
#ifndef RAM_LE32
  ; store carry in T register
  ROL R5
  BST R5, 0
  ROR R5
#endif
  	ADD96 r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14  r11,r10,r9,r8,r13,r12,r29,r28,r27,r26,r7,r6  

  CLR R6
  CLR R7
  ADC R6, R6

final_L:
; restore carry
#ifdef RAM_LE32
	lsr	r31
#else
  BLD R8, 0
  ASR R8
#endif
  ;--- propagate carry to end ---
  ADC R0, R6
  ADC R1, R7
  ADC R2, R7
  ADC R3, R7
  ADC R4, R7
  ADC R5, R7

  STD Z+6, R14
  STD Z+7, R15
  STD Z+8, R16
  STD Z+9, R17
  STD Z+10, R18
  STD Z+11, R19
  STD Z+12, R20
  STD Z+13, R21
  STD Z+14, R22
  STD Z+15, R23
  STD Z+16, R24
  STD Z+17, R25
  STD Z+18, R0
  STD Z+19, R1
  STD Z+20, R2
  STD Z+21, R3
  STD Z+22, R4
  STD Z+23, R5
  
  POP R29
  POP R28
  POP R27
  POP R26

  ;------ level 1: compute H ------

  ;init zero registers
  CLR R20
  CLR R21
  MOVW R22, R20
  MOVW R24, R20
  
  ;--- level 2: Compute L ---
  LD R2, X+
  LDD R8,  Y+12
  LDD R9,  Y+13
  LDD R10, Y+14
  LDD R11, Y+15
  LDD R12, Y+16
  LDD R13, Y+17

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
  STD Z+24, R14
  STD Z+25, R15
  STD Z+26, R16

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
  STD Z+27, R17
  STD Z+28, R18
  STD Z+29, R19

  ;--- load a6..a11 and b6..b11 ---
  LD R14, X+
  LD R15, X+
  LD R16, X+
  LD R17, X+
  LD R18, X+
  LD R19, X+
  
  PUSH R26 ; save X register
  PUSH R27
  PUSH R28 ; save Y register
  PUSH R29
  PUSH R30 ; save Z register
  PUSH R31

  LDD R8,  Y+18
  LDD R9,  Y+19
  LDD R10, Y+20
  LDD R11, Y+21

  LDD R30, Y+22
  LDD R31, Y+23
  
  ;--- Compute H + (l6,l7,l8,l9,l10,l11) ---
  CLR R12
  CLR R13
  MOVW R2, R12
  MOVW R4, R12
  MOVW R6, R12

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

//  CLR R6		// already cleared
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
  ABS48 r19,r18,r17,r16,r15,r14  r0 r13
  ABS48 r31,r30,r11,r10, r9, r8  r1 r13

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
  LDD R14, Z+24
  LDD R15, Z+25
  LDD R16, Z+26
  LDD R17, Z+27
  LDD R18, Z+28
  LDD R19, Z+29
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
	SUB96 r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14   r11,r10,r9,r8,r13,r12,r29,r28,r27,r26,r7,r6

  SBC R6, R6
  SBC R7, R7  
  ; R7:R6 is -1,0, or 1
  RJMP final_H

add_M_H:
#ifndef RAM_LE32
  ; store carry in T register
  ROL R5
  BST R5, 0
  ROR R5
#endif
	ADD96 r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14   r11,r10,r9,r8,r13,r12,r29,r28,r27,r26,r7,r6  
  CLR R6
  CLR R7
  ADC R6, R6

final_H:
; restore carry
#ifdef RAM_LE32
	lsr	r31
#else
  BLD R8, 0
  ASR R8
#endif
  ;--- propagate carry to end ---
  ADC R0, R6
  ADC R1, R7
  ADC R2, R7
  ADC R3, R7
  ADC R4, R7
  ADC R5, R7

  STD Z+36, R20
  STD Z+37, R21
  STD Z+38, R22
  STD Z+39, R23
  STD Z+40, R24
  STD Z+41, R25
  STD Z+42, R0
  STD Z+43, R1
  STD Z+44, R2
  STD Z+45, R3
  STD Z+46, R4
  STD Z+47, R5
  
  POP R29
  POP R28
  POP R27
  POP R26

  ;------ level 1: combine L and H ------
  LDD R6, Z+24
  LDD R7, Z+25
  LDD R8, Z+26
  LDD R9, Z+27
  LDD R10, Z+28
  LDD R11, Z+29

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

  ; store carry on stack
  CLR R12
  CLR R13
  ADC R13, R12
  ; propagate carry to end
	ADD96 r5,r4,r3,r2,r1,r0 r25,r24,r23,r22,r21,r20  r12,r12,r12,r12,r12,r12,r12,r12,r12,r12,r12,r13
.set Off, 0
	ldd	r12,Z+Off
	add	r12,r6
	std	Z+Off+12,r12
.irp	Reg,7,8,9,10,11,14,15,16,17,18,19
.set Off, Off+1
	ldd	r12,Z+Off
	adc	r12,r\Reg
	std	Z+Off+12,r12
.endr

  ADC R20, R6
  STD Z+24, R20
  ADC R21, R7
  STD Z+25, R21
  ADC R22, R8
  STD Z+26, R22
  ADC R23, R9
  STD Z+27, R23
  ADC R24, R10
  STD Z+28, R24
  ADC R25, R11
  STD Z+29, R25
  ADC R0, R14
  STD Z+30, R0
  ADC R1, R15
  STD Z+31, R1
  ADC R2, R16
  STD Z+32, R2
  ADC R3, R17
  STD Z+33, R3
  ADC R4, R18
  STD Z+34, R4
  ADC R5, R19
  STD Z+35, R5

  ; store carry in R13
  CLR R1
  ADC R13, R1		// R13 is 0, 1 or 2!
  PUSH R13		// search CARRY HL1 (where is readed from stack)

  ;------ level 1: subtract a0-a12 ------
  SBIW R26, 24
.irp	Reg,2,3,4,5,6,7,14,15,16,17,18,19,8,9,10,11,12,13,20,21,22,23,24,25
	ld	r\Reg,X+
.endr

	SUB96 r19,r18,r17,r16,r15,r14,r7,r6,r5,r4,r3,r2   r25,r24,r23,r22,r21,r20,r13,r12,r11,r10,r9,r8

  ; 0xff if carry and 0x00 if no carry
  SBC R0,  R0

  ;------ level 1: absolute values ------
  // r0 sign r1 zero
  ABS96 r19,r18,r17,r16,r15,r14,r7,r6,r5,r4,r3,r2 r0 r1

  // save part to stack 
.irp Reg,19,18,17,16,15,14,7,6,5,4,3,2
	push	r\Reg
.endr

  ;------ level 1: subtract b0-b12 ------
.irp	Reg,8,9,10,11,12,13,14,15,16,17,18,19
	ldd	r\Reg,Y+\Reg-8
.endr

.set Off, 12
	ldd	r20,Y+Off
	sub	r8,r20
.irp	Reg,9,10,11,12,13,14,15,16,17,18,19
.set Off, Off+1
	ldd	r20,Y+Off
	sbc	r\Reg,r20
.endr

  ; 0xff if carry and 0x00 if no carry
  SBC R25,  R25

  ;------ level 1: absolute values ------
// sign r25 zero r1
  ABS96 r19,r18,r17,r16,r15,r14,r13,r12,r11,r10,r9,r8  r25 r1

.irp Reg,19,18,17,16,15,14,13,12,11,10,9,8
	push	r\Reg
.endr

  EOR R0, R25
  PUSH R0		// search SIGN HL1
    
  PUSH R30 ; save Z register
  PUSH R31

  ;------ level 1: compute M ------

  ; init zero registers
  CLR R20
  CLR R21
  MOVW R22, R20
  MOVW R24, R20
  
  ;--- level 2: compute L ---
// r8.. r13 already loaded

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
  MUL R3, R12 ;a1 * b4
  ADD R18, R27
  ADC R19, R0
  ADC R20, R1
  ADC R21, R25
  MUL R3, R11 ;a1 * b3
  MOVW R26, R0
  MUL R3, R13 ;a1 * b5
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
  MUL R4, R12 ;a2 * b4
  ADD R19, R27
  ADC R20, R0
  ADC R21, R1
  ADC R22, R25
  MUL R4, R11 ;a2 * b3
  MOVW R26, R0
  MUL R4, R13 ;a2 * b5
  ADD R19, R26
  ADC R20, R27
  ADC R21, R0
  ADC R22, R1
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
  ADC R24, R25
  MUL R6, R11 ;a4 * b3
  MOVW R14, R0
  MUL R6, R13 ;a4 * b5
  ADD R21, R14
  ADC R22, R15
  ADC R23, R0
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
	push	R17
	push	R18
	push	R19

	in	r28, _SFR_IO_ADDR(SPL)
	in	r29, _SFR_IO_ADDR(SPH)

  ;--- load a6..a11 and b6..b11 ---
  LDD R14, Y+28
  LDD R15, Y+29
  LDD R16, Y+30
  LDD R17, Y+31
  LDD R18, Y+32
  LDD R19, Y+33

  LDD R8,  Y+16
  LDD R9,  Y+17
  LDD R10, Y+18
  LDD R11, Y+19
  LDD R30, Y+20
  LDD R31, Y+21
  
  ;--- Compute H + (l6,l7,l8,l9,l10,l11) ---
  CLR R12
  CLR R13
  MOVW R2, R12
  MOVW R4, R12
  MOVW R6, R12

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

//  CLR R6		// already cleared
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
  // r13 zero, r0,1 sign
  ABS48 r19,r18,r17,r16,r15,r14  r0 r13
  ABS48 r31,r30,r11,r10, r9, r8  r1 r13

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

  POP R0
  POP R1

  ; now load stack pointer in R31:30
  IN R30, _SFR_IO_ADDR(SPL)
  IN R31, _SFR_IO_ADDR(SPH) 

  ;--- add l5+h0 to l0 and h5 ---
  LDD R14, Z+6 
  LDD R15, Z+5 
  LDD R16, Z+4 
  LDD R17, Z+3 
  LDD R18, Z+2 
  LDD R19, Z+1 

	ADD96	r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14  r5,r4,r3,r2,r1,r0,r25,r24,r23,r22,r21,r20

//  ; store carry in r31
	rol	r31
  ;--- process sign bit ---  
  BRTS add_M_M
  
  ;subtract M
	SUB96	r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14         r11,r10,r9,r8,r13,r12,r29,r28,r27,r26,r7,r6

  SBC R6, R6
  SBC R7, R7
  ; R7:R6 is -1,0, or 1
  RJMP final_M

add_M_M: 
	ADD96	r25,r24,r23,r22,r21,r20,r19,r18,r17,r16,r15,r14		r11,r10,r9,r8,r13,r12,r29,r28,r27,r26,r7,r6

  CLR R6
  CLR R7
  ADC R6, R6

final_M:
	// restore carry
	lsr	r31
#ifndef RAM_LE32
// restore r31
	in R31, _SFR_IO_ADDR(SPH)
#endif
  ;--- propagate carry to end ---
  ADC R0, R6
  ADC R1, R7
  ADC R2, R7
  ADC R3, R7
  ADC R4, R7
  ADC R5, R7
  ; now load stack pointer in R31:30
	ldd	R29,Z+7	;load Y register - pointer to result
	ldd	R28,Z+8
  ;------ level 1: combine L, H, and M ------

  ; load m0..m5 in 8,9,10,11,12,13
  LDD R8,  Z+6
  LDD R9,  Z+5
  LDD R10, Z+4
  LDD R11, Z+3
  LDD R12, Z+2
  LDD R13, Z+1
  ; M is stored in: 8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,1,2,3,4,5

  ;--- process sign bit ---  
	ldd	R7,Z+9		// search SIGN HL1
  TST R7
  BREQ final_subtract
  RJMP final_addition

final_subtract:  
// result(MEM) -= registers
.set Off, 12
	ldd	r6, Y+Off
	sub	r6,r8
	std	Y+Off,r6
.irp Reg,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,1,2,3,4,5
.set Off, Off+1
	ldd	r6,Y+Off
	sbc	r6,r\Reg
	std	Y+Off,r6
.endr

  SBC R6, R6
  SBC R7, R7
  ; R7:R6 is -1,0, or 1  
  RJMP final

final_addition:
// result(MEM) += registers
.set Off, 12
	ldd	r6,Y+Off
	add	r6,r8
	std	Y+Off,r6
.irp Reg,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,1,2,3,4,5
.set Off, Off+1
	ldd	r6,Y+Off
	adc	r6,r\Reg
	std	Y+Off,r6
.endr

  CLR R6
  CLR R7
  ADC R6, R6

final:
  ; load carry from stack
  LDD R26, Z+34			// search CARRY HL1
//r26 is 0,1 or 2!
  // return stack back
  ADIW R30, 34
// use atomic update of stack pointer
	LOAD_SP R0, R30,R31

  CLR R0
  ADD R6, R26
  ADC R7, R0

  ;--- propagate carry to end ---
.set Off, 36
	ldd	r12,Y+Off
	add	r12,r6
	std	Y+Off,r12
.rept	11
.set Off, Off+1
	ldd	r12,Y+Off
	adc	r12,r7
	std	Y+Off,r12
.endr
	ret

#endif
