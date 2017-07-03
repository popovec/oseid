/*
    This is part of OsEID (Open source Electronic ID)

    256 bit (interrupt safe) multiplication routine for AVR

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
    Version: 2014-07-25
    Public domain

  Differences to original code from Michael Hutter and Peter Schwabe:

  --  no stack register move forward/backwards
  --  The code uses macros - improved code readability
  --  code is faster and interrupt safe (please check LOAD_SP macro)

  orig code                                            4797 clock cycles

  this code (MEM pointers 15 bit)                      4654 clock cycles
  this code (MEM pointers 16 bit)                      4667 clock cycles

  For environment with enabled interrupts:
  this code - I flag restored after stack pointer change +3 clock cycles
  this code - I flag forced to interrupt enable          +2 clock cycles

*/

#ifdef OsEID
#include <avr/io.h>
#endif

//define RAM_LE32 if your device RAM is max 32kiB, to speed up code
//#define RAM_LE32
#include "load_sp.h"

/*
// if you get this file without load_sp.h, next macros must be defined:

// atmega, for interrupt enabled environment:
.macro  LOAD_SP tmp   RL RH
        in      \tmp,0x3f
        cli
        out     0x3d,\RL
        out     0x3f,\tmp
        out     0x3e,\RH
.endm
// atmega, for interrupt disabled environment:
.macro  LOAD_SP tmp   RL RH
        out     0x3d,\RL
        out     0x3e,\RH
.endm
//atmega,interrupt always enabled:
.macro  LOAD_SP tmp   RL RH
        cli
        out     0x3d,\RL
        sei
        out     0x3e,\RH
.endm
// xmega:
// this device disables interrupts for 4 cycles after
// write to 0x3d register. No CLI is needed.
// For all three environments use same code:

.macro  LOAD_SP tmp   RL RH
        out     0x3d,\RL
        out     0x3e,\RH
.endm
*/


//clear RS7,RS6,ZERO  before call! (73 ticks)
.macro MUL_32	RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0   A3 A2 A1 A0   B3 B2 B1 B0  ZERO CC1 CC0
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
// RS =  B * A,no CARRY CATCHER,RS7..RS2 must be cleared before call,A,B
// reg can not overlap RS! (76 ticks)
.macro	MUL32_pure	RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0  A3,A2,A1,A0  ZERO
	mul	\A0,\B0
	movw	\RS0,r0

	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\ZERO	//12

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
	adc	\RS4,\ZERO	//27

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
	adc	\RS5,\ZERO	//47

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
	adc	\RS6,\ZERO	//62

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
	adc	\RS7,r1		//76
.endm

// mutiply without use of CC registers (79 ticks),
// high bytes of result overlap operand A!!!!
//                      A2  A1  A0
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

// multiply only 1st 4 bytes of result,precalculate bytes 4,5
// ZERO,RS2,RS3,RS4 and RS5 must be cleared before ..
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
// 29
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
//24+6 = 30
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

.macro  MUL32_ADD_cont  RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0   A1,A3  ZERO
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO

	mul	\A1,\B3
	clr	\A1
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

.macro  MUL32_ADD_n2  RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0   A1,A0  ZERO
	mul	\A0,\B0
	add	\RS0,r0
	adc	\RS1,r1
	adc	\RS2,\ZERO
	adc	\RS5,\ZERO

	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS5,\ZERO
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\RS5
	adc	\RS4,\ZERO

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

	clr	\RS5
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
.macro  MUL32_ADD_cont_n2  RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0  A3,A2,A1,A0  ZERO
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO

	mul	\A1,\B3
	clr	\A1
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

.macro SUB32	RZ3 RZ2 RZ1 RZ0  A3 A2 A1 A0
	sub	\RZ0,\A0
	sbc	\RZ1,\A1
	sbc	\RZ2,\A2
	sbc	\RZ3,\A3
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

#if defined(HAVE_RSA_MUL_256_NO_ABI) && defined(OsEID)
  .global rsa_mul_256_no_abi
  .type rsa_mul_256_no_abi,@function

rsa_mul_256_no_abi:
#endif

#if (defined(HAVE_RSA_MUL_256_NO_ABI) && defined (OsEID))
// store X,Y pointers on stack
	push	r28
	push	r29
	push	r26
	push	r27

;--------- level 1: compute L ---------

;------ level 2: compute L ------

; init zero registers
	clr	r20
	clr	r21
	movw	r16,r20

;--- level 3: compute L ---
	ld	r2,X+
	ld	r3,X+
	ld	r4,X+
	ld	r5,X+
	ldd	r6,Y+0
	ldd	r7,Y+1
	ldd	r8,Y+2
	ldd	r9,Y+3
//         result                                 A                B    zero  CC1 CC0
	MUL_32	r17,r16,r15,r14,r13,r12,r11,r10  r5,r4,r3,r2  r9,r8,r7,r6 r21 r19,r18

	std	 Z+0,r10
	std	 Z+1,r11
	std	 Z+2,r12
	std	 Z+3,r13
  
;--- load a4..a7 and b4..b7 ---
	movw	r10,r20
	movw	r12,r20
	ld	r18,X+
	ld	r19,X+

	ldd	r22,Y+4
	ldd	r23,Y+5
	ldd	r24,Y+6
	ldd	r25,Y+7

// upper bytes of operand A are readed from X+!
        MUL32_ADD_n     r13,r12, r11,r10,r17,r16,r15,r14  r25,r24,r23,r22  r19,r18   r21
;--- subtract a0-a4 ---
	sub	r2,r18
	sbc	r3,r19
	sbc	r4,r13
; load a7 to r18
	ld	r18,X+
	sbc	r5,r18
; 0xff if carry and 0x00 if no carry
	sbc	r0,r0
  
;--- subtract b0-b4 ---
	SUB32	r9,r8,r7,r6  r25,r24,r23,r22

; 0xff if carry and 0x00 if no carry
	sbc	r1,r1

;--- absolute values ---
	ABS32 r5,r4,r3,r2  r0 r21
	ABS32 r9,r8,r7,r6  r1 r21

	eor	r0,r1
	bst	r0,0

	MUL32_ADD_cont_n  r13,r12,r11,r10,r17,r16,r15,r14  r25,r24,r23,r22  r19,r18   r21

	movw	r24,r20
	movw	r18,r20
// multiply only 1st 4 bytes of result,precalculate bytes 4,5
        MUL_32_8   /* r3 r2 */r19,r18,r25,r24,r23,r22   r9,r8,r7,r6  r5,r4,r3,r2 r20
// continue, r20,r21 is zero!
        MUL_32_8contA /*r3,r2,*/ r19,r18     r9,r8,r7,r6  r5,r4,r3,r2  r20

// middle part in
// r3,r2,r19,r18,r25,r24,r23,r22


;--- add l4+h0 to l0 and h4 ---
	ldd	r6,Z+0
	ldd	r7,Z+1
	ldd	r0,z+2
	ldd	r1,z+3
	movw	r4,r20

	ADD64	r17,r16,r15,r14,r1,r0,r7,r6  r13,r12,r11,r10,r17,r16,r15,r14
; store carry in r5
	adc	r5,r5

;--- process sign bit ---
	brtc sub_M_L_L

	ADD64   r17,r16,r15,r14,r1,r0,r7,r6     r3,r2,r19,r18,r25,r24,r23,r22
	adc	r5,r4
	rjmp	final_L_L

sub_M_L_L:
	SUB64   r17,r16,r15,r14,r1,r0,r7,r6     r3,r2,r19,r18,r25,r24,r23,r22
	sbc	r5,r4
	sbc	r4,r4

final_L_L:
	std	 Z+4,r6
	std	 Z+5,r7
	std	 Z+6,r0
	std	 Z+7,r1

;--- propagate carry to end ---
	add	r10,r5
	adc	r11,r4
	adc	r12,r4
	adc	r13,r4

; h8...h15 stored in 22,23,24,25,18,19,2,3

;------ level 1: compute H ------

; init zero registers
	movw	r22,r20
	movw	r24,r20
;--- level 2: compute L ---
	ld	r2,X+
	ld	r3,X+
	ld	r4,X+
	ld	r5,X+
	ldd	r6,Y+8
	ldd	r7,Y+9
	ldd	r8,Y+10
	ldd	r9,Y+11

	MUL_32_8 /*r,r*/ r23,r22,r25,r24,r19,r18   r9,r8,r7,r6  r5,r4,r3,r2 r20
; now add h0+l8 and h0+l12
	ADD64	r25,r24,r19,r18,r17,r16,r15,r14   r13,r12,r11,r10,r25,r24,r19,r18

	std	 Z+16,r14
	std	 Z+17,r15
	std	 Z+18,r16
	std	 Z+19,r17
	std	 Z+20,r18
	std	 Z+21,r19

 ;--- load b4..b7 ---
	ldd	r14,Y+12
	ldd	r15,Y+13
	ldd	r12,Y+14
	ldd	r13,Y+15

; store carry on stack
#ifdef RAM_LE32
	rol	r29
#else
	sbc	r0,r0
	push	r0
#endif

	movw	r16,r20	//ZERO
	MUL_32_8cont r17,r16,r23,r22   r9,r8,r7,r6  r5,r4,r3,r2  r21
;--- load a4..a7 and b4..b7 ---
	movw	r18,r20 //ZERO
	ld	r10,X+
	ld	r11,X+
	MUL32_ADD_n     r20,r11, r19,r18,r17,r16,r23,r22  r13,r12,r15,r14  r11,r10   r21

;--- subtract a0-a4 ---
	sub	r2,r10
	sbc	r3,r11
	sbc	r4,r20
; load a7 to r10
	ld	r10,X+
	sbc	r5,r10
; 0xff if carry and 0x00 if no carry
	sbc	r0,r0

;--- subtract b0-b4 ---
	SUB32	r9,r8,r7,r6  r13,r12,r15,r14

; 0xff if carry and 0x00 if no carry
	sbc	r1,r1

	ABS32	r5,r4,r3,r2  r0 r21
	ABS32	r9,r8,r7,r6  r1 r21

	eor	r0,r1
	bst	r0,0

// A1 = RS6,A2 = RS7 !!!
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
// TODO better macro
	MUL32_ADD_cont_swap_zero r20,r11,r19,r18,r17  r13,r12,r15,r14    r21
;--- level 3: compute M ---
	clr	r10
	movw	r12,r10
	MUL32_ncc r4,r3,r2,r10,r13,r12,r15,r14  r9,r8,r7,r6  r5,r4,r3,r2  r11

;--- add l4+h0 to l0 and h4 ---
	ldd	r6,Z+20
	ldd	r7,Z+21

	ADD64 r17,r16,r23,r22,r25,r24,r7,r6  r20,r21,r19,r18,r17,r16,r23,r22
; store carry in r11
	adc	r11,r11

;--- propagate carry ---
#ifdef RAM_LE32
	lsr	r29
#else
	pop	r0
	lsr	r0
#endif
	clr	r0
	adc	r22,r0
	adc	r23,r0
	adc	r16,r0
	adc	r17,r0
; update carry in r11

	adc	r11,r0

;--- process sign bit ---
	brtc	sub_M_H_L
	ADD64 r17,r16,r23,r22,r25,r24,r7,r6 r4,r3,r2,r10,r13,r12,r15,r14

	adc	r11,r0
	rjmp	final_H_L

sub_M_H_L:
; subtract M
	SUB64 r17,r16,r23,r22,r25,r24,r7,r6 r4,r3,r2,r10,r13,r12,r15,r14

	sbc	r11,r0
	sbc	r0,r0
; r0:r21 is -1,0,or 1

final_H_L:
	std	Z+20,r6
	std	Z+21,r7
	std	Z+22,r24
	std	Z+23,r25
	std	Z+24,r22
	std	Z+25,r23
	std	Z+26,r16
	std	Z+27,r17

;--- propagate carry to end ---
	add	r18,r11
	adc	r19,r0
	adc	r21,r0
	adc	r20,r0
  
	std	Z+28,r18
	std	Z+29,r19
	std	Z+30,r21
	std	Z+31,r20
/////////////////////////////////////////////////////////////////////////////
;------ level 2: subtract a0-a7 ------
	sbiw	r26,16
	ld	r2,X+
	ld	r3,X+
	ld	r4,X+
	ld	r5,X+
	ld	r18,X+
	ld	r19,X+
	ld	r20,X+
	ld	r21,X+
	ld	r10,X+
	ld	r11,X+
	ld	r12,X+
	ld	r13,X+
	ld	r14,X+
	ld	r15,X+
	ld	r16,X+
	ld	r17,X+

	SUB64	r21,r20,r19,r18,r5,r4,r3,r2  r17,r16,r15,r14,r13,r12,r11,r10

; 0xff if carry and 0x00 if no carry
	sbc	r27,r27
  
;------ level 2: subtract b0-b7 ------
	ldd	r6,Y+0
	ldd	r7,Y+1
	ldd	r8,Y+2
	ldd	r9,Y+3
	ldd	r22,Y+4
	ldd	r23,Y+5
	ldd	r24,Y+6
	ldd	r25,Y+7
	ldd	r10,Y+8
	ldd	r11,Y+9
	ldd	r12,Y+10
	ldd	r13,Y+11
	ldd	r14,Y+12
	ldd	r15,Y+13
	ldd	r16,Y+14
	ldd	r17,Y+15

	SUB64	r25,r24,r23,r22,r9,r8,r7,r6  r17,r16,r15,r14,r13,r12,r11,r10

; 0xff if carry and 0x00 if no carry
	sbc	r1,r1
    
;------ level 2: absolute values ------
	clr	r26
	ABS64	r21,r20,r19,r18,r5,r4,r3,r2 r27 r26
	ABS64   r25,r24,r23,r22,r9,r8,r7,r6 r1 r26
	eor	r27,r1
#ifdef RAM_LE32
	ror	r27
	rol	r31
#else
	push	r27
	clr	r27
#endif
;------ level 2: compute M ------
	movw	r16,r26

//              result                             A                B    zero  CC1 CC0
	MUL_32  r17,r16,r15,r14,r13,r12,r11,r10  r5,r4,r3,r2  r9,r8,r7,r6 r26  r29,r28
;--- subtract a0-a4 ---
	sub	r2,r18
	sbc	r3,r19
	sbc	r4,r20
	sbc	r5,r21
; 0xff if carry and 0x00 if no carry
	sbc	r0,r0
  
;--- subtract b0-b4 ---
	sub	r6,r22
	sbc	r7,r23
	sbc	r8,r24
	sbc	r9,r25
; 0xff if carry and 0x00 if no carry
	sbc	r1,r1

;--- absolute values ---
	ABS32	r5,r4,r3,r2  r0 r26
	ABS32	r9,r8,r7,r6  r1 r26
	eor	r0,r1
	bst	r0,0
  
;--- level 3: compute H + (l3,l4,l5) ---
	mul	r18,r24 ;a0*b2
	movw	r28,r0
	mul	r18,r22 ;a0*b0
	add	r14,r0
	adc	r15,r1
	adc	r16,r28
	adc	r29,r26
	mul	r18,r23 ;a0*b1
	add	r15,r0
	adc	r16,r1
	adc	r29,r26
	mul	r19,r25 ;a1*b3
	add	r17,r29
	adc	r26,r0
	adc	r27,r1

	mul	r18,r25 ;a0*b3
	movw	r28,r0
	mul	r19,r22 ;a1*b0
	add	r15,r0
	adc	r16,r1
	adc	r17,r28
	clr	r18
	adc	r29,r18
	mul	r19,r23 ;a1*b1
	add	r16,r0
	adc	r17,r1
	adc	r29,r18
	mul	r20,r25 ;a2*b3
	add	r26,r29
	adc	r27,r0
	adc	r18,r1

	mul	r20,r24 ;a2*b2
	movw	r28,r0
	mul	r20,r22 ;a2*b0
	add	r16,r0
	adc	r17,r1
	adc	r26,r28
	clr	r0
	adc	r29,r0
	mul	r19,r24 ;a1*b2
	add	r17,r0
	adc	r26,r1
	clr	r19
	adc	r29,r19
	mul	r21,r25 ;a3*b3
	add	r27,r29
	adc	r18,r0
	clr	r25
	adc	r25,r1
  
	mul	r21,r23 ;a3*b1
	movw	r28,r0
	mul	r20,r23 ;a2*b1
	add	r17,r0
	adc	r28,r1
	adc	r29,r19
	mul	r21,r22 ;a3*b0
	add	r17,r0
	adc	r28,r1
	adc	r29,r19
	mul	r21,r24 ;a3*b2
	add	r26,r28
	adc	r0,r29
	adc	r1,r19
	add	r27,r0
	adc	r18,r1
	adc	r25,r19

;--- level 3: compute M ---
	mul	r2,r8 ;a0*b2
	movw	r22,r0
	mul	r2,r6 ;a0*b0
	movw	r20,r0
	mul	r2,r7 ;a0*b1
	add	r21,r0
	adc	r22,r1
	adc	r23,r19
	mul	r3,r9 ;a1*b3
	mov	r24,r0
	mov	r0,r2
	mov	r2,r1

	mul	r0,r9 ;a0*b3
	movw	r28,r0
	mul	r3,r6 ;a1*b0
	add	r21,r0
	adc	r22,r1
	adc	r23,r28
	adc	r29,r19
	mul	r3,r7 ;a1*b1
	add	r22,r0
	adc	r23,r1
	adc	r29,r19
	mul	r4,r9 ;a2*b3
	add	r24,r29
	adc	r2,r0
	adc	r19,r1

	mul	r4,r8 ;a2*b2
	movw	r28,r0
	mul	r4,r6 ;a2*b0
	add	r22,r0
	adc	r23,r1
	adc	r24,r28
	clr	r0
	adc	r29,r0
	mul	r3,r8 ;a1*b2
	add	r23,r0
	adc	r24,r1
	clr	r3
	adc	r29,r3
	mul	r5,r9 ;a3*b3
	add	r2,r29
	adc	r19,r0
	clr	r9
	adc	r9,r1

	mul	r5,r7 ;a3*b1
	movw	r28,r0
	mul	r4,r7 ;a2*b1
	add	r23,r0
	adc	r28,r1
	adc	r29,r3
	mul	r5,r6 ;a3*b0
	add	r23,r0
	adc	r28,r1
	adc	r29,r3
	mul	r5,r8 ;a3*b2
	add	r24,r28
	adc	r0,r29
	adc	r1,r3
	add	r2,r0
	adc	r19,r1
	adc	r9,r3

;--- add l4+h0 to l0 and h4 ---
	movw	r4,r10
	movw	r6,r12
	ADD64	r17,r16,r15,r14,r13,r12,r11,r10 r25,r18,r27,r26,r17,r16,r15,r14
; store carry in r3
	clr	r29
	adc	r3,r3
  
;--- process sign bit ---
	brtc	sub_M_M_L
	ADD64	r17,r16,r15,r14,r13,r12,r11,r10 r9,r19,r2,r24,r23,r22,r21,r20
	adc	r3,r29
	rjmp	final_M_L

sub_M_M_L:
; subtract M
	SUB64	r17,r16,r15,r14,r13,r12,r11,r10 r9,r19,r2,r24,r23,r22,r21,r20

	sbc	r3,r29
	sbc	r29,r29
; r29:r28 is -1,0,or 1

final_M_L:
;--- propagate carry to end ---
	add	r26,r3
	adc	r27,r29
	adc	r18,r29
	adc	r25,r29
;------ level 2: combine L,H,and M ------
;--- process sign bit ---
#ifdef RAM_LE32
	lsr	r31
	clr	r1
#else
	pop	r1
	lsr	r1    // test bit0  and create ZERO in r1
#endif

	ldd	r20,Z+0
	ldd	r21,Z+1
	ldd	r22,Z+2
	ldd	r23,Z+3
	ldd	r24,Z+4
	ldd	r19,Z+5
	ldd	r8,Z+6
	ldd	r9,Z+7

	brcs	add_M_L

  
; subtract M
	SUB64	r9,r8,r19,r24,r23,r22,r21,r20 r13,r12,r11,r10,r7,r6,r5,r4
; store borrow in r0
	sbc	r0,r0
	ldd	r2,Z+16
	ldd	r3,Z+17
	add	r20,r2
	adc	r21,r3
	std	Z+8,r20
	std	Z+9,r21

	ldd	r20,Z+18
	ldd	r21,Z+19
	adc	r22,r20
	adc	r23,r21
	std	Z+10,r22
	std	Z+11,r23

	ldd	r22,Z+20
	ldd	r23,Z+21
	adc	r24,r22
	adc	r19,r23
	std	Z+12,r24
	std	Z+13,r19

	ldd	r24,Z+22
	ldd	r19,Z+23
	adc	r8,r24
	adc	r9,r19
	std	Z+14,r8
	std	Z+15,r9

; store carry in r1
	adc	r1,r1

	lsr	r0
	SBC64	r19,r24,r23,r22,r21,r20,r3,r2  r25,r18,r27,r26,r17,r16,r15,r14
	sbc	r28,r28
	sbc	r29,r29
; r29:r28 is -1,0,or 1
	rjmp	final_L

add_M_L: 
	ADD64	r9,r8,r19,r24,r23,r22,r21,r20 r13,r12,r11,r10,r7,r6,r5,r4
; store carry in r0
	sbc	r0,r0
	ldd	r2,Z+16
	ldd	r3,Z+17
	add	r20,r2
	adc	r21,r3
	std	Z+8,r20
	std	Z+9,r21

	ldd	r20,Z+18
	ldd	r21,Z+19
	adc	r22,r20
	adc	r23,r21
	std	Z+10,r22
	std	Z+11,r23

	ldd	r22,Z+20
	ldd	r23,Z+21
	adc	r24,r22
	adc	r19,r23
	std	Z+12,r24
	std	Z+13,r19

	ldd	r24,Z+22
	ldd	r19,Z+23
	adc	r8,r24
	adc	r9,r19
	std	Z+14,r8
	std	Z+15,r9

; store carry in r1
	adc	r1,r1

	lsr	r0
	ADC64	r19,r24,r23,r22,r21,r20,r3,r2  r25,r18,r27,r26,r17,r16,r15,r14
	clr	r28
	clr	r29
	adc	r28,r28
final_L:
	ldd	r4,Z+24
	ldd	r5,Z+25
	ldd	r6,Z+26
	ldd	r7,Z+27
	ldd	r10,Z+28
	ldd	r11,Z+29
	ldd	r12,Z+30
	ldd	r13,Z+31

	lsr	r1
	ADC64   r19,r24,r23,r22,r21,r20,r3,r2 r13,r12,r11,r10,r7,r6,r5,r4
; store carry in r29:r28
	adc	r28,r1
	adc	r29,r1
	std	Z+16,r2
	std	Z+17,r3
	std	Z+18,r20
	std	Z+19,r21
	std	Z+20,r22
	std	Z+21,r23
	std	Z+22,r24
	std	Z+23,r19

;--- propagate carry to end ---
	ADD64	r13,r12,r11,r10,r7,r6,r5,r4 r29,r29,r29,r29 r29,r29,r29,r28
	std	Z+24,r4
	std	Z+25,r5
	std	Z+26,r6
	std	Z+27,r7
	std	Z+28,r10
	std	Z+29,r11
	std	Z+30,r12
	std	Z+31,r13

; restore X and Y register
	in	r28,0x3d
	in	r29,0x3e

	ldd	r27,Y+1
	ldd	r26,Y+2
	adiw	r26,16

	ldd	r21,Y+3
	ldd	r20,Y+4
	movw	r28,r20

;--------- level 1: compute H ---------

; init zero registers
	clr	r20
	clr	r21
	movw	r16,r20

;------ level 2: compute L ------
	ld	r2,X+
	ld	r3,X+
	ld	r4,X+
	ld	r5,X+
	ldd	r6,Y+16
	ldd	r7,Y+17
	ldd	r8,Y+18
	ldd	r9,Y+19

//              result                             A                B    zero  CC1 CC0
	MUL_32  r17,r16,r15,r14,r13,r12,r11,r10  r5,r4,r3,r2  r9,r8,r7,r6 r21 r19,r18

	std	 Z+32,r10
	std	 Z+33,r11
	std	 Z+34,r12
	std	 Z+35,r13
  
;--- load a4..a7 and b4..b7 ---
	movw	r10,r20
	ld	r18,X+
	ld	r19,X+

	ldd	r22,Y+20
	ldd	r23,Y+21
	ldd	r24,Y+22
	ldd	r25,Y+23
;------ level 2: compute H + (l3,l4,l5) ------
// upper bytes of operand A are readed from X+!
	movw	r12,r20
	MUL32_ADD_n     r13,r12, r11,r10,r17,r16,r15,r14  r25,r24,r23,r22  r19,r18   r21
;--- subtract a0-a4 ---
	sub	r2,r18
	sbc	r3,r19
	sbc	r4,r13
; now load a7 to r18
	ld	r18,X+
	sbc	r5,r18
; 0xff if carry and 0x00 if no carry
	sbc	r0,r0
  
;--- subtract b0-b4 ---
	sub	r6,r22
	sbc	r7,r23
	sbc	r8,r24
	sbc	r9,r25
; 0xff if carry and 0x00 if no carry
	sbc	r1,r1

;--- absolute values ---
	ABS32	r5,r4,r3,r2  r0 r21
	ABS32	r9,r8,r7,r6  r1 r21

	eor	r0,r1
	bst	r0,0
  
;--- continue ---
	MUL32_ADD_cont_n r13,r12,r11,r10,r17,r16,r15,r14  r25,r24,r23,r22  r19,r18   r21
;--- level 3: compute M ---
	movw	r24,r20
	movw	r18,r20

        MUL_32_8   /* r3 r2 */r19,r18,r25,r24,r23,r22   r9,r8,r7,r6  r5,r4,r3,r2 r20
// continue, r20,r21 is zero!
        MUL_32_8contA /*r3,r2,*/ r19,r18     r9,r8,r7,r6  r5,r4,r3,r2  r20

;--- add l4+h0 to l0 and h4 ---
	ldd	r6,Z+32
	ldd	r7,Z+33
	ldd	r0,Z+34
	ldd	r1,Z+35
	movw	r4,r20
	ADD64	r17,r16,r15,r14,r1,r0,r7,r6   r13,r12,r11,r10,r17,r16,r15,r14
; store carry in r5
	adc	r5,r5

;--- process sign bit ---
	brtc	sub_M_L_H
	ADD64	r17,r16,r15,r14,r1,r0,r7,r6    r3,r2,r19,r18,r25,r24,r23,r22
	adc	r5,r4
	rjmp	final_L_H
sub_M_L_H:
; subtract M
	SUB64	r17,r16,r15,r14,r1,r0,r7,r6  r3,r2,r19,r18,r25,r24,r23,r22
	sbc	r5,r4
	sbc	r4,r4
; r5,4 -1,0,or 1

final_L_H:
	std	 Z+36,r6
	std	 Z+37,r7
	std	 Z+38,r0
	std	 Z+39,r1

;--- propagate carry to end ---
	add	r10,r5
	adc	r11,r4
	adc	r12,r4
	adc	r13,r4

;------ level 2: compute H ------

; init zero registers

	movw	r22,r20
	movw	r24,r20

;--- level 3: compute L ---
	ld	r2,X+
	ld	r3,X+
	ld	r4,X+
	ld	r5,X+
	ldd	r6,Y+24
	ldd	r7,Y+25
	ldd	r8,Y+26
	ldd	r9,Y+27
	MUL_32_8 /*r,r*/ r23,r22,r25,r24,r19,r18   r9,r8,r7,r6  r5,r4,r3,r2  r20

; now add h0+l8 and h0+l12
	ADD64	r25,r24,r19,r18,r17,r16,r15,r14   r13,r12,r11,r10,r25,r24,r19,r18

	std	Z+48,r14
	std	Z+49,r15
	std	Z+50,r16
	std	Z+51,r17
	std	Z+52,r18
	std	Z+53,r19

;--- load b4..b7 ---
	ldd	r14,Y+28
	ldd	r15,Y+29
	ldd	r12,Y+30
	ldd	r13,Y+31
; store carry on stack
#ifdef RAM_LE32
	rol	r29
#else
	sbc	r0,r0
	push	r0
#endif
	movw	r16,r20
        MUL_32_8cont r17,r16,r23,r22   r9,r8,r7,r6  r5,r4,r3,r2  r21
; continue

;--- load a4..a7 and b4..b7 ---
	movw	r18,r20
	ld	r10,X+
	ld	r11,X+

;------ level 2: compute H + (l3,l4,l5) ------
	MUL32_ADD_n     r20,r11, r19,r18,r17,r16,r23,r22  r13,r12,r15,r14  r11,r10   r21

;--- subtract a0-a4 ---
	sub	r2,r10
	sbc	r3,r11
	sbc	r4,r20
; load a7 to r18
	ld	r10,X+
	sbc	r5,r10
; 0xff if carry and 0x00 if no carry
	sbc	r0,r0

;--- subtract b0-b4 ---
	sub	r6,r14
	sbc	r7,r15
	sbc	r8,r12
	sbc	r9,r13
; 0xff if carry and 0x00 if no carry
	sbc	r1,r1

;--- absolute values ---
	ABS32	r5,r4,r3,r2  r0 r21
	ABS32	r9,r8,r7,r6  r1 r21
	eor	r0,r1
	bst	r0,0

;--- continue ---
        MUL32_ADD_cont_swap_zero  r20,r11,r19,r18,r17  r13,r12,r15,r14  r21
;--- level 3: compute M ---
	clr	r10
	movw	r12,r10
        MUL32_ncc r4,r3,r2,r10,r13,r12,r15,r14  r9,r8,r7,r6  r5,r4,r3,r2 r11
;--- add l4+h0 to l0 and h4 ---
	ldd	r6,Z+52
	ldd	r7,Z+53
        ADD64	r17,r16,r23,r22,r25,r24,r7,r6  r20,r21,r19,r18,r17,r16,r23,r22
; store carry in r11
	adc	r11,r11

;--- propagate carry ---
#ifdef RAM_LE32
	lsr	r29
#else
	pop	r0
	lsr	r0
#endif
	clr	r0
	adc	r22,r0
	adc	r23,r0
	adc	r16,r0
	adc	r17,r0
; store carry in r11

	adc	r11,r0

;--- process sign bit ---
	brtc	sub_M_H_H
	ADD64	r17,r16,r23,r22,r25,r24,r7,r6 r4,r3,r2,r10,r13,r12,r15,r14
	adc	r11,r0
	rjmp	final_H_H

sub_M_H_H:
; subtract M
	SUB64	r17,r16,r23,r22,r25,r24,r7,r6 r4,r3,r2,r10,r13,r12,r15,r14
	sbc	r11,r0
	sbc	r0,r0
; r11:r0 is -1,0,or 1

final_H_H:
	std	Z+52,r6
	std	Z+53,r7
	std	Z+54,r24
	std	Z+55,r25
	std	Z+56,r22
	std	Z+57,r23
	std	Z+58,r16
	std	Z+59,r17

;--- propagate carry to end ---
	add	r18,r11
	adc	r19,r0
	adc	r21,r0
	adc	r20,r0
  
	std	Z+60,r18
	std	Z+61,r19
	std	Z+62,r21
	std	Z+63,r20


;------ level 1: subtract b0-b7 ------
	ldd	r6,Y+16
	ldd	r7,Y+17
	ldd	r8,Y+18
	ldd	r9,Y+19
	ldd	r22,Y+20
	ldd	r23,Y+21
	ldd	r24,Y+22
	ldd	r25,Y+23
	ldd	r10,Y+24
	ldd	r11,Y+25
	ldd	r12,Y+26
	ldd	r13,Y+27
	ldd	r14,Y+28
	ldd	r15,Y+29
	ldd	r16,Y+30
	ldd	r17,Y+31

	SUB64	r25,r24,r23,r22,r9,r8,r7,r6 r17,r16,r15,r14,r13,r12,r11,r10

; 0xff if carry and 0x00 if no carry
	sbc	r1,r1

;------ level 1: subtract a0-a7 ------
	sbiw	r26,32
	movw	r28,r26

	ldd	r2,Y+16
	ldd	r3,Y+17
	ldd	r4,Y+18
	ldd	r5,Y+19
	ldd	r18,Y+20
	ldd	r19,Y+21
	ldd	r20,Y+22
	ldd	r21,Y+23
	ldd	r10,Y+24
	ldd	r11,Y+25
	ldd	r12,Y+26
	ldd	r13,Y+27
	ldd	r14,Y+28
	ldd	r15,Y+29
	ldd	r16,Y+30
	ldd	r17,Y+31

	SUB64	r21,r20,r19,r18,r5,r4,r3,r2 r17,r16,r15,r14,r13,r12,r11,r10

; 0xff if carry and 0x00 if no carry
	sbc	r27,r27

;------ level 2: absolute values ------
	clr	r26
	ABS64	r21,r20,r19,r18,r5,r4,r3,r2 r27 r26
	ABS64   r25,r24,r23,r22,r9,r8,r7,r6 r1 r26
	eor	r27,r1
#ifdef RAM_LE32
	LSR	r27
        ROL	r31
#else
	push	r27
	clr	r27
#endif
;------ level 2: compute M ------
	movw	r16,r26
//               result                             A                B    zero  CC1 CC0
	MUL_32  r17,r16,r15,r14,r13,r12,r11,r10  r5,r4,r3,r2  r9,r8,r7,r6 r26  r29,r28
;--- subtract a0-a4 ---
	sub	r2,r18
	sbc	r3,r19
	sbc	r4,r20
	sbc	r5,r21
; 0xff if carry and 0x00 if no carry
	sbc	r0,r0
  
;--- subtract b0-b4 ---
	sub	r6,r22
	sbc	r7,r23
	sbc	r8,r24
	sbc	r9,r25
; 0xff if carry and 0x00 if no carry
	sbc	r1,r1

;--- absolute values ---
	ABS32	r5,r4,r3,r2  r0 r26
	ABS32	r9,r8,r7,r6  r1 r26
	eor	r0,r1
	bst	r0,0
  
;--- level 3: compute H + (l3,l4,l5) ---
	mul	r18,r24 ;a0*b2
	movw	r28,r0
	mul	r18,r22 ;a0*b0
	add	r14,r0
	adc	r15,r1
	adc	r16,r28
	adc	r29,r26
	mul	r18,r23 ;a0*b1
	add	r15,r0
	adc	r16,r1
	adc	r29,r26
	mul	r19,r25 ;a1*b3
	add	r17,r29
	adc	r26,r0
	adc	r27,r1

	mul	r18,r25 ;a0*b3
	movw	r28,r0
	mul	r19,r22 ;a1*b0
	add	r15,r0
	adc	r16,r1
	adc	r17,r28
	clr	r18
	adc	r29,r18
	mul	r19,r23 ;a1*b1
	add	r16,r0
	adc	r17,r1
	adc	r29,r18
	mul	r20,r25 ;a2*b3
	add	r26,r29
	adc	r27,r0
	adc	r18,r1

	mul	r20,r24 ;a2*b2
	movw	r28,r0
	mul	r20,r22 ;a2*b0
	add	r16,r0
	adc	r17,r1
	adc	r26,r28
	clr	r0
	adc	r29,r0
	mul	r19,r24 ;a1*b2
	add	r17,r0
	adc	r26,r1
	clr	r19
	adc	r29,r19
	mul	r21,r25 ;a3*b3
	add	r27,r29
	adc	r18,r0
	clr	r25
	adc	r25,r1
  
	mul	r21,r23 ;a3*b1
	movw	r28,r0
	mul	r20,r23 ;a2*b1
	add	r17,r0
	adc	r28,r1
	adc	r29,r19
	mul	r21,r22 ;a3*b0
	add	r17,r0
	adc	r28,r1
	adc	r29,r19
	mul	r21,r24 ;a3*b2
	add	r26,r28
	adc	r0,r29
	adc	r1,r19
	add	r27,r0
	adc	r18,r1
	adc	r25,r19

;--- level 3: compute M ---
	mul	r2,r8 ;a0*b2
	movw	r22,r0
	mul	r2,r6 ;a0*b0
	movw	r20,r0
	mul	r2,r7 ;a0*b1
	add	r21,r0
	adc	r22,r1
	adc	r23,r19
	mul	r3,r9 ;a1*b3
	mov	r24,r0
	mov	r0,r2
	mov	r2,r1

	mul	r0,r9 ;a0*b3
	movw	r28,r0
	mul	r3,r6 ;a1*b0
	add	r21,r0
	adc	r22,r1
	adc	r23,r28
	adc	r29,r19
	mul	r3,r7 ;a1*b1
	add	r22,r0
	adc	r23,r1
	adc	r29,r19
	mul	r4,r9 ;a2*b3
	add	r24,r29
	adc	r2,r0
	adc	r19,r1

	mul	r4,r8 ;a2*b2
	movw	r28,r0
	mul	r4,r6 ;a2*b0
	add	r22,r0
	adc	r23,r1
	adc	r24,r28
	clr	r0
	adc	r29,r0
	mul	r3,r8 ;a1*b2
	add	r23,r0
	adc	r24,r1
	clr	r3
	adc	r29,r3
	mul	r5,r9 ;a3*b3
	add	r2,r29
	adc	r19,r0
	clr	r9
	adc	r9,r1

	mul	r5,r7 ;a3*b1
	movw	r28,r0
	mul	r4,r7 ;a2*b1
	add	r23,r0
	adc	r28,r1
	adc	r29,r3
	mul	r5,r6 ;a3*b0
	add	r23,r0
	adc	r28,r1
	adc	r29,r3
	mul	r5,r8 ;a3*b2
	add	r24,r28
	adc	r0,r29
	adc	r1,r3
	add	r2,r0
	adc	r19,r1
	adc	r9,r3

;--- add l4+h0 to l0 and h4 ---
	movw	r4,r10
	movw	r6,r12
	ADD64	r17,r16,r15,r14,r13,r12,r11,r10,   r25,r18,r27,r26,r17,r16,r15,r14,
; store carry in r3
	clr	r29
	adc	r3,r3
  
;--- process sign bit ---
	brtc	sub_M_M_H
	ADD64	r17,r16,r15,r14,r13,r12,r11,r10,   r9,r19,r2,r24,r23,r22,r21,r20,
	adc	r3,r29
	rjmp	final_M_H

sub_M_M_H:
; subtract M
	SUB64	r17,r16,r15,r14,r13,r12,r11,r10,r9,r19,r2,r24,r23,r22,r21,r20

	sbc	r3,r29
	SBC	r29,r29
; r29:r3 is -1,0,or 1

  
final_M_H:
;--- propagate carry to end ---
	add	r26,r3
	adc	r27,r29
	adc	r18,r29
	adc	r25,r29
#ifdef RAM_LE32
	bst	r31,0
	lsr	r31
#endif
;------ level 2: combine L,H,and M ------
	ldd	r20,Z+32
	ldd	r21,Z+33
	ldd	r22,Z+34
	ldd	r23,Z+35
	ldd	r24,Z+36
	ldd	r19,Z+37
	ldd	r8,Z+38
	ldd	r9,Z+39


	ldd	r1,Z+16
	add	r1,r20
	std	Z+32,r1
	ldd	r1,Z+17
	adc	r1,r21
	std	Z+33,r1
	ldd	r1,Z+18
	adc	r1,r22
	std	Z+34,r1
	ldd	r1,Z+19
	adc	r1,r23
	std	Z+35,r1
	ldd	r1,Z+20
	adc	r1,r24
	std	Z+36,r1
	ldd	r1,Z+21
	adc	r1,r19
	std	Z+37,r1
	ldd	r1,Z+22
	adc	r1,r8
	std	Z+38,r1
	ldd	r1,Z+23
	adc	r1,r9
	std	Z+39,r1
; store carry in r28
	adc	r28,r28	// only carry is needed (into bit 0)

;--- process sign bit ---
#ifdef RAM_LE32
	clr	r3
	brts	add_M_H
#else
	pop	r3
	lsr	r3   // test bit0  and create ZERO in r3
	brcs	add_M_H
#endif
; subtract M
	SUB64	r9,r8,r19,r24,r23,r22,r21,r20 r13,r12,r11,r10,r7,r6,r5,r4

	ldd	r4, Z+56
	ldd	r5, Z+57
	ldd	r6, Z+58
	ldd	r7, Z+59
	ldd	r10,Z+60
	ldd	r11,Z+61
	ldd	r12,Z+62
	ldd	r13,Z+63

	SBC64	r13,r12,r11,r10,r7,r6,r5,r4 r25,r18,r27,r26,r17,r16,r15,r14

	sbc	r0,r0
	sbc	r1,r1
; r1:r0 is -1,0,or 1
	rjmp	final_H

add_M_H: 
	ADD64	r9,r8,r19,r24,r23,r22,r21,r20,   r13,r12,r11,r10,r7,r6,r5,r4

	ldd	r4, Z+56
	ldd	r5, Z+57
	ldd	r6, Z+58
	ldd	r7, Z+59
	ldd	r10,Z+60
	ldd	r11,Z+61
	ldd	r12,Z+62
	ldd	r13,Z+63

	ADC64	r13,r12,r11,r10,r7,r6,r5,r4,   r25,r18,r27,r26,r17,r16,r15,r14
; store borrow in r1:r0
	clr	r0
	clr	r1
	adc	r0,r0
final_H:
	ldd	r14,Z+48
	ldd	r15,Z+49
	ldd	r16,Z+50
	ldd	r17,Z+51
	ldd	r26,Z+52
	ldd	r27,Z+53
	ldd	r18,Z+54
	ldd	r25,Z+55
	ADD64	r9,r8,r19,r24,r23,r22,r21,r20,  r25,r18,r27,r26,r17,r16,r15,r14
	ADC64	r13,r12,r11,r10,r7,r6,r5,r4     r25,r18,r27,r26,r17,r16,r15,r14

; add carry to carry catcher
	adc	r0,r3
	adc	r1,r3

;--- add higher part of the first 128 bits ---
	lsr	r28
	ldd	r28,Z+24
	adc	r20,r28
	ldd	r28,Z+25
	adc	r21,r28
	ldd	r28,Z+26
	adc	r22,r28
	ldd	r28,Z+27
	adc	r23,r28
	ldd	r28,Z+28
	adc	r24,r28
	ldd	r28,Z+29
	adc	r19,r28
	ldd	r28,Z+30
	adc	r8,r28
	ldd	r28,Z+31
	adc	r9,r28

	ADC64	r13,r12,r11,r10,r7,r6,r5,r4,   r3,r3,r3,r3,r3,r3,r3,r3,
; add carry to carry catcher
	adc	r0,r3
	adc	r1,r3
    
	std	Z+40,r20
	std	Z+41,r21
	std	Z+42,r22
	std	Z+43,r23
	std	Z+44,r24
	std	Z+45,r19
	std	Z+46,r8
	std	Z+47,r9
	std	Z+48,r4
	std	Z+49,r5
	std	Z+50,r6
	std	Z+51,r7
	std	Z+52,r10
	std	Z+53,r11
	std	Z+54,r12
	std	Z+55,r13

;--- propagate carry to end ---
	ldd	r4,Z+56
	ldd	r5,Z+57
	ldd	r6,Z+58
	ldd	r7,Z+59
	ldd	r10,Z+60
	ldd	r11,Z+61
	ldd	r12,Z+62
	ldd	r13,Z+63

	ADD64	r13,r12,r11,r10,r7,r6,r5,r4,   r1,r1,r1,r1,r1,r1,r1,r0,

	std	Z+56,r4
	std	Z+57,r5
	std	Z+58,r6
	std	Z+59,r7
	std	Z+60,r10
	std	Z+61,r11
	std	Z+62,r12
	std	Z+63,r13
; restore X and Y register
	pop	r27
	pop	r26
	pop	r29
	pop	r28
/////////////////////////////////////////////////////////////////////////////
;--------- level 1: subtract a0-a15 ---------
.irp	Reg,2,3,4,5,18,19,20,21,10,11,12,13,14,15,16,17
	ld	r\Reg,X+
.endr

	ld	r0,X+
	sub	r2,r0
.irp	Reg,3,4,5,18,19,20,21,10,11,12,13,14,15,16,17
	ld	r0,X+
	sbc	r\Reg,r0
.endr
; store borrow in r0
	sbc	r0,r0

;--------- level 1: absolute values ---------
.irp    Reg,2,3,4,5,18,19,20,21,10,11,12,13,14,15,16,17
	eor	r\Reg,r0
.endr
	neg	r0
	clr	r26
	clr	r27
	ADD64	r21,r20,r19,r18,r5,r4,r3,r2      r26,r26,r26,r26,r26,r26,r26,r0
	ADC64	r17,r16,r15,r14,r13,r12,r11,r10  r26,r26,r26,r26,r26,r26,r26,r26

;--------- level 1: push absolute values on stack ---------
.irp	Reg,r17,r16,r15,r14,r13,r12,r11,r10,r21,r20,r19,r18,r5,r4,r3,r2
	push	\Reg
.endr
;--------- level 1: subtract b0-b15 ---------
//offset 15..0
.set Off, 15
.irp	Reg,r17,r16,r15,r14,r13,r12,r11,r10,r25,r24,r23,r22,r9,r8,r7,r6
	ldd	\Reg,Y+Off
.set Off, Off-1
.endr

	ldd	r1,Y+16
	sub	r6,r1
	ldd	r1,Y+17
	sbc	r7,r1
	ldd	r1,Y+18
	sbc	r8,r1
	ldd	r1,Y+19
	sbc	r9,r1
	ldd	r1,Y+20
	sbc	r22,r1
	ldd	r1,Y+21
	sbc	r23,r1
	ldd	r1,Y+22
	sbc	r24,r1
	ldd	r1,Y+23
	sbc	r25,r1
	ldd	r1,Y+24
	sbc	r10,r1
	ldd	r1,Y+25
	sbc	r11,r1
	ldd	r1,Y+26
	sbc	r12,r1
	ldd	r1,Y+27
	sbc	r13,r1
	ldd	r1,Y+28
	sbc	r14,r1
	ldd	r1,Y+29
	sbc	r15,r1
	ldd	r1,Y+30
	sbc	r16,r1
	ldd	r1,Y+31
	sbc	r17,r1
; store borrow in r1
	sbc	r1,r1

;--------- level 1: absolute values ---------
.irp	Reg, r17,r16,r15,r14,r13,r12,r11,r10,r25,r24,r23,r22,r9,r8,r7,r6
	eor	\Reg,r1
.endr
	neg	r1
	ADD64	r25,r24,r23,r22,r9,r8,r7,r6,     r26,r26,r26,r26,r26,r26,r26,r1
	ADC64	r17,r16,r15,r14,r13,r12,r11,r10   r26,r26,r26,r26,r26,r26,r26,r26

;--------- level 1: push absolute values on stack ---------
.irp	Reg, r17,r16,r15,r14,r13,r12,r11,r10,r25,r24,r23,r22,r9,r8,r7,r6
	push	\Reg
.endr
	eor	r0,r1
//	sign to stack
	push	r0

;--------- level 1: compute M ---------

;------ level 2: compute L ------

; init zero registers
	movw	r12,r26
	movw	r14,r26
	movw	r16,r26

;--- level 3: compute L ---

	MUL_32	r17,r16,r15,r14,r13,r12,r11,r10  r9,r8,r7,r6  r5,r4,r3,r2 r26  r29,r28
;--- level 3: compute H + (l3,l4,l5) ---
; pushZ+0...Z+7 on stack  1st part
	push	r10
	push	r11
	push	r12
	push	r13

	movw	r28,r26	//ZERO
// A in r21,r20,r19,r18..
	MUL32_ADD_n2   r20,r19     r29,r28,r17,r16,r15,r14   r25,r24,r23,r22  r19,r18  r26

;--- subtract a0-a4 ---
	sub	r2,r18
	sbc	r3,r19
	sbc	r4,r20
	sbc	r5,r21
; 0xff if carry and 0x00 if no carry
	sbc	r0,r0
  
;--- subtract b0-b4 ---
	sub	r6,r22
	sbc	r7,r23
	sbc	r8,r24
	sbc	r9,r25
; 0xff if carry and 0x00 if no carry
	sbc	r1,r1

;--- absolute values ---
	ABS32	r5,r4,r3,r2  r0 r26
	ABS32	r9,r8,r7,r6  r1 r26
	eor	r0,r1
	bst	r0,0
	MUL32_ADD_cont_n2 r20,r19  r29,r28,r17,r16,r15,r14   r25,r24,r23,r22 r21,r20,r19,r18  r26
;--- level 3: compute M ---
	movw	r24,r26
	clr	r18

	MUL32_ncc   r4,r3,r2,r18,r25,r24,r23,r22    r9,r8,r7,r6    r5,r4,r3,r2 r26

;--- add l4+h0 to l0 and h4 ---
	movw	r6,r26
	ADD64	r17,r16,r15,r14,r13,r12,r11,r10,   r20,r19,r29,r28,r17,r16,r15,r14,
; store carry in r6
	adc	r6,r6
  
;--- process sign bit ---
	brtc	sub_M_L_M
	ADD64	r17,r16,r15,r14,r13,r12,r11,r10,   r4,r3,r2,r18,r25,r24,r23,r22,
	adc	r6,r7
	rjmp	final_L_M

sub_M_L_M:
; subtract M
	SUB64 r17,r16,r15,r14,r13,r12,r11,r10,   r4,r3,r2,r18,r25,r24,r23,r22
	sbc	r6,r7
	sbc	r7,r7
; r26:r7 is -1,0,or 1

final_L_M: 
;--- propagate carry to end  ---
	add	r28,r6
	adc	r29,r7
	adc	r19,r7
	adc	r20,r7

	mov	r18,r28
	mov	r21,r29
; h8...h15 stored in 22,23,24,25,18,21,19,20

;------ level 2: compute H ------

; pushZ+0...Z+7 on stack  2nd part
	push	r10
	push	r11
	push	r12
	push	r13

; subtract stack pointer and load Y and X values
	in	r28,0x3D
	in	r29,0x3E

#define Yoff  34
#define Xoff  18
	ldd	r2,Y+Yoff+0
	ldd	r3,Y+Yoff+1
	ldd	r4,Y+Yoff+2
	ldd	r5,Y+Yoff+3

	ldd	r6,Y+Xoff+0
	ldd	r7,Y+Xoff+1
	ldd	r8,Y+Xoff+2
	ldd	r9,Y+Xoff+3

; init zero registers
	movw	r12,r26
	movw	r22,r26
	movw	r24,r26

;--- level 3: compute L ---
	MUL_32    r25,r24,r23,r22,r13,r12,r11,r10  r9,r8,r7,r6  r5,r4,r3,r2   r26  r29,r28

	in	r28,0x3D
	in	r29,0x3E

;--- add h0+l8 and h0+l12 ---
	ADD64	r13,r12,r11,r10,r17,r16,r15,r14  r20,r19,r21,r18,r13,r12,r11,r10

	push	r14
	push	r15
	push	r16
	push	r17
	ldd	r18,Y+Yoff+4
	ldd	r19,Y+Yoff+5
	ldd	r20,Y+Yoff+6
	ldd	r21,Y+Yoff+7

	ldd	r14,Y+Xoff+4
	ldd	r15,Y+Xoff+5
	ldd	r16,Y+Xoff+6
	ldd	r17,Y+Xoff+7
	movw	r28,r26	//ZERO
; store carry in r29
	adc	r29,r28
;--- level 3: compute H ---
	MUL32_ADD_n2   r20,null     r27,r26,r25,r24,r23,r22, r17,r16,r15,r14  r19,r18  r28
;--- subtract a0-a4 ---
	sub	r2,r18
	sbc	r3,r19
	sbc	r4,r20
	sbc	r5,r21
; 0xff if carry and 0x00 if no carry
	sbc	r0,r0
  
;--- subtract b0-b4 ---
	sub	r6,r14
	sbc	r7,r15
	sbc	r8,r16
	sbc	r9,r17
; 0xff if carry and 0x00 if no carry
	sbc	r1,r1

;--- absolute values ---
	ABS32	r5,r4,r3,r2  r0 r28
	ABS32	r9,r8,r7,r6  r1 r28
	eor	r0,r1
	bst	r0,0
  
.macro  MUL32_ADD_cont_n3  RS7,RS6,RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0  A3,A2,A1,A0  ZERO
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO

	mul	\A1,\B3
	clr	r19
	add	\RS4,r0
	adc	\RS5,r1
	adc	r28,r19
	mul	\A2,\B2
	add	\RS4,r0
	adc	\RS5,r1
	adc	r28,r19
	mul	\A3,\B1
	add	\RS4,r0
	adc	\RS5,r1
	adc	r28,r19

	mul	\A2,\B3
	clr	\RS7
	add	\RS5,r0
	adc	r28,r1
	adc	\RS7,r19
	mul	\A3,\B2
	add	\RS5,r0
	adc	r28,r1
	adc	\RS7,r19

	mul	\A3,\B3
	add	r28,r0
	adc	\RS7,r1
.endm
;--- continue ---
	MUL32_ADD_cont_n3 r20,r19  r27,r26,r25,r24,r23,r22,r17, r16,r15,r14 r21,r20,r19,null  r28
	clr	r18
	movw	r16,r18
;--- level 3: compute M ---
        MUL32_ncc   r4,r3,r2,r18,r17,r16,r15,r14    r9,r8,r7,r6 r5,r4,r3,r2   r19
;--- add l4+h0 to l0 and h4 ---
        ADD64	r25,r24,r23,r22,r13,r12,r11,r10, r20,r28,r27,r26,r25,r24,r23,r22


; store carry in r19
	adc	r19,r19

; load carry and propagate to end
	add	r22,r29
	clr	r0
	adc	r23,r0
	adc	r24,r0
	adc	r25,r0
; store carry in r19
	adc	r19,r0

;--- process sign bit ---
	brtc	sub_M_H_M

	ADD64	r25,r24,r23,r22,r13,r12,r11,r10,r4,r3,r2,r18,r17,r16,r15,r14
	adc	r19,r0
	rjmp	final_H_M

sub_M_H_M:
; subtract M
	SUB64	r25,r24,r23,r22,r13,r12,r11,r10, r4,r3,r2,r18,r17,r16,r15,r14
	sbc	r19,r0
	sbc	r0,r0
; r29:r28 is -1,0,or 1

final_H_M:

;--- propagate carry to end  ---
	add	r26,r19
	adc	r27,r0
	adc	r28,r0
	adc	r20,r0

	push	r10
	push	r11
	push	r12
	push	r13
	push	r22
	push	r23
	push	r24
	push	r25
	push	r26
	push	r27
	push	r28
	push	r20



;------ level 2: subtract a0-a7 ------
	in	r28,0x3D
	in	r29,0x3E

#define Aoff 26+16
	ldd	r2,Y+Aoff+0
	ldd	r3,Y+Aoff+1
	ldd	r4,Y+Aoff+2
	ldd	r5,Y+Aoff+3
	ldd	r18,Y+Aoff+4
	ldd	r19,Y+Aoff+5
	ldd	r20,Y+Aoff+6
	ldd	r21,Y+Aoff+7
	ldd	r10,Y+Aoff+8
	ldd	r11,Y+Aoff+9
	ldd	r12,Y+Aoff+10
	ldd	r13,Y+Aoff+11
	ldd	r14,Y+Aoff+12
	ldd	r15,Y+Aoff+13
	ldd	r16,Y+Aoff+14
	ldd	r17,Y+Aoff+15

	SUB64	r21,r20,r19,r18,r5,r4,r3,r2  r17,r16,r15,r14,r13,r12,r11,r10

; 0xff if carry and 0x00 if no carry
	sbc	r27,r27
  
;--- level 3: subtract b0-b7 ---
#define Boff 10+16
	ldd	r6,Y+Boff+0
	ldd	r7,Y+Boff+1
	ldd	r8,Y+Boff+2
	ldd	r9,Y+Boff+3
	ldd	r22,Y+Boff+4
	ldd	r23,Y+Boff+5
	ldd	r24,Y+Boff+6
	ldd	r25,Y+Boff+7
	ldd	r10,Y+Boff+8
	ldd	r11,Y+Boff+9
	ldd	r12,Y+Boff+10
	ldd	r13,Y+Boff+11
	ldd	r14,Y+Boff+12
	ldd	r15,Y+Boff+13
	ldd	r16,Y+Boff+14
	ldd	r17,Y+Boff+15

	SUB64	r25,r24,r23,r22,r9,r8,r7,r6  r17,r16,r15,r14,r13,r12,r11,r10

; 0xff if carry and 0x00 if no carry
	sbc	r1,r1
  
	clr	r26
;--- level 3: absolute values ---
	ABS64	r21,r20,r19,r18,r5,r4,r3,r2 r27 r26
	ABS64   r25,r24,r23,r22,r9,r8,r7,r6 r1 r26
	eor	r27,r1
#ifdef RAM_LE32
	lsr	r27      // create zero in r27,sign in CY
	rol	r31       // sign to bit 0
#else
	push	r27
	clr	r27
#endif
;------ level 2: compute M ------
; init zero registers
	movw	r12,r26
	movw	r14,r12
	movw	r16,r12
//	MUL_32   RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0   A3 A2 A1 A0   B3 B2 B1 B0 ZERO CC1 CC0
	MUL_32  r17,r16,r15,r14,r13,r12,r11,r10  r9,r8,r7,r6    r5,r4,r3,r2  r26  r29,r28

	movw	r28,r26	//ZERO
;--- level 3: compute H + (l3,l4,l5) ---
	MUL32_ADD_n2   r20,r19     r27,r26,r17,r16,r15,r14   r25,r24,r23,r22 r19,r18 r28
;--- subtract a0-a4 ---
	sub	r2,r18
	sbc	r3,r19
	sbc	r4,r20
	sbc	r5,r21
; 0xff if carry and 0x00 if no carry
	sbc	r0,r0
;--- subtract b0-b4 ---
	sub	r6,r22
	sbc	r7,r23
	sbc	r8,r24
	sbc	r9,r25
; 0xff if carry and 0x00 if no carry
	sbc	r1,r1
;--- absolute values ---
	ABS32 r5,r4,r3,r2  r0 r28
	ABS32 r9,r8,r7,r6  r1 r28
	eor	r0,r1
	bst	r0,0
;--- continue ---
	MUL32_ADD_cont_n2 r20,r19  r27,r26,r17,r16,r15,r14   r25,r24,r23,r22  r21,r20,r19,r18 r28
;--- level 3: compute M ---
	movw	r24,r28	//ZERO
	clr	r18
//posible optimization: free r21,r27 ..
	MUL32_ncc   r4,r3,r2,r18,r25,r24,r23,r22    r9,r8,r7,r6    r5,r4,r3,r2  r28
;--- add l4+h0 to l0 and h4 ---
	movw	r6,r10
	movw	r8,r12

	ADD64	r17,r16,r15,r14,r13,r12,r11,r10,   r20,r19,r27,r26,r17,r16,r15,r14
; store carry in r28
	adc	r28,r28
;--- process sign bit ---
	brtc	sub_M_M_M

	ADD64	r17,r16,r15,r14,r13,r12,r11,r10  r4,r3,r2,r18,r25,r24,r23,r22
	adc	r28,r29
	rjmp	final_M_M
sub_M_M_M:
	SUB64 r17,r16,r15,r14,r13,r12,r11,r10 r4,r3,r2,r18,r25,r24,r23,r22

	sbci	r28,0
	sbc	r29,r29
; r29:r28 is -1,0,or 1
final_M_M:
;--- propagate carry to end  ---
	add	r26,r28
	adc	r27,r29
	adc	r19,r29
	adc	r20,r29
;------ level 2: combine L,H,and M ------

;--- process sign bit (create carry from sign bit) ---
#ifdef RAM_LE32
	lsr	r31
	clr	r18
#else
	pop	r18
	lsr	r18    // test bit0  and create ZERO in r18
#endif
#define Zoff 17
	in	r28,0x3d
	in	r29,0x3e
	ldd	r24,Y+Zoff+0
	ldd	r23,Y+Zoff+1
	ldd	r22,Y+Zoff+2
	ldd	r21,Y+Zoff+3
	ldd	r5,Y+Zoff+4
	ldd	r4,Y+Zoff+5
	ldd	r3,Y+Zoff+6
	ldd	r2,Y+Zoff+7


;--- process sign bit ---
	brcs	add_M

 ; subtract M
	SUB64	r24,r23,r22,r21,r5,r4,r3,r2 r13,r12,r11,r10,r9,r8,r7,r6

	ldd	r13,Y+1
	ldd	r12,Y+2
	ldd	r11,Y+3
	ldd	r10,Y+4
	ldd	r9,Y+5
	ldd	r8,Y+6
	ldd	r7,Y+7
	ldd	r6,Y+8

	SBC64	r13,r12,r11,r10,r9,r8,r7,r6  r20,r19,r27,r26,r17,r16,r15,r14
	sbc	r0,r0
	sbc	r1,r1
; r1:r0 is -1,0,or 1
	rjmp	final_M

add_M: 
	ADD64	r24,r23,r22,r21,r5,r4,r3,r2,   r13,r12,r11,r10,r9,r8,r7,r6
	ldd	r13,Y+1
	ldd	r12,Y+2
	ldd	r11,Y+3
	ldd	r10,Y+4
	ldd	r9,Y+5
	ldd	r8,Y+6
	ldd	r7,Y+7
	ldd	r6,Y+8
	ADC64	r13,r12,r11,r10,r9,r8,r7,r6,   r20,r19,r27,r26,r17,r16,r15,r14
	clr	r0
	clr	r1
	adc	r0,r0
  
final_M:
	ldd	r20,Y+9
	ldd	r19,Y+10
	ldd	r27,Y+11
	ldd	r26,Y+12
	ldd	r17,Y+13
	ldd	r16,Y+14
	ldd	r15,Y+15
	ldd	r14,Y+16

	ADD64	r24,r23,r22,r21,r5,r4,r3,r2,   r20,r19,r27,r26,r17,r16,r15,r14
	ADC64   r13,r12,r11,r10,r9,r8,r7,r6    r20,r19,r27,r26,r17,r16,r15,r14

; add carry to carry catcher
	adc	r0, r18
	adc	r1, r18
;--- propagate carry to end ---
#define Joff 1
	ldd	r25,Y+0+Joff
	ldd	r20,Y+1+Joff
	ldd	r19,Y+2+Joff
	ldd	r18,Y+3+Joff
	ldd	r17,Y+4+Joff
	ldd	r16,Y+5+Joff
	ldd	r15,Y+6+Joff
	ldd	r14,Y+7+Joff
	ADD64	r25,r20,r19,r18,r17,r16,r15,r14,   r1,r1,r1,r1,r1,r1,r1,r0

;--------- level 1: combine L,H,and M ---------
#undef Joff
#define Joff 9
	std	Y+0+Joff,r25
	std	Y+1+Joff,r20
	std	Y+2+Joff,r19
	std	Y+3+Joff,r18
	std	Y+4+Joff,r17
	std	Y+5+Joff,r16
	std	Y+6+Joff,r15
	std	Y+7+Joff,r14
#undef Joff
#define Joff 17
	ldd	r25,Y+0+Joff
	ldd	r20,Y+1+Joff
	ldd	r19,Y+2+Joff
	ldd	r18,Y+3+Joff
	ldd	r17,Y+4+Joff
	ldd	r16,Y+5+Joff
	ldd	r15,Y+6+Joff
	ldd	r14,Y+7+Joff
	clr	r26
	ldd	r0,Y+8+Joff
	tst	r0
	breq	final_subtract
	rjmp	final_addition

final_subtract:
; subtract M
	ldd	r0,Z+0
	sub	r0,r14
	ldd	r1,Z+1
	sbc	r1,r15
	ldd	r14,Z+2
	sbc	r14,r16
	ldd	r15,Z+3
	sbc	r15,r17
	ldd	r16,Z+4
	sbc	r16,r18
	ldd	r17,Z+5
	sbc	r17,r19
	ldd	r18,Z+6
	sbc	r18,r20
	ldd	r19,Z+7
	sbc	r19,r25
	ldd	r20,Z+8
	sbc	r20,r2
	ldd	r25,Z+9
	sbc	r25,r3
	ldd	r2,Z+10
	sbc	r2,r4
	ldd	r3,Z+11
	sbc	r3,r5
	ldd	r4,Z+12
	sbc	r4,r21
	ldd	r5,Z+13
	sbc	r5,r22
	ldd	r21,Z+14
	sbc	r21,r23
	ldd	r22,Z+15
	sbc	r22,r24
; store borrow in r27
	sbc	r27,r27

; add h0+l8
	ldd	r23,Z+32
	add	r0,r23
	std	Z+16,r0
	ldd	r24,Z+33
	adc	r1,r24
	std	Z+17,r1
	ldd	r0,Z+34
	adc	r14,r0
	std	Z+18,r14
	ldd	r0,Z+35
	adc	r15,r0
	std	Z+19,r15
	ldd	r0,Z+36
	adc	r16,r0
	std	Z+20,r16
	ldd	r0,Z+37
	adc	r17,r0
	std	Z+21,r17
	ldd	r0,Z+38
	adc	r18,r0
	std	Z+22,r18
	ldd	r0,Z+39
	adc	r19,r0
	std	Z+23,r19
	ldd	r0,Z+40
	adc	r20,r0
	std	Z+24,r20
	ldd	r0,Z+41
	adc	r25,r0
	std	Z+25,r25
	ldd	r0,Z+42
	adc	r2,r0
	std	Z+26,r2
	ldd	r0,Z+43
	adc	r3,r0
	std	Z+27,r3
	ldd	r0,Z+44
	adc	r4,r0
	std	Z+28,r4
	ldd	r0,Z+45
	adc	r5,r0
	std	Z+29,r5
	ldd	r0,Z+46
	adc	r21,r0
	std	Z+30,r21
	ldd	r0,Z+47
	adc	r22,r0
	std	Z+31,r22
; store carry in r26
	adc	r26,r26

#define Loff  9
	ldd	r24,Y+0+Loff
	ldd	r23,Y+1+Loff
	ldd	r22,Y+2+Loff
	ldd	r21,Y+3+Loff
	ldd	r5,Y+4+Loff
	ldd	r4,Y+5+Loff
	ldd	r3,Y+6+Loff
	ldd	r2,Y+7+Loff

	adiw	r28,57
	LOAD_SP r0,r28,r29


	ldd	r0,Z+48
	ldd	r1,Z+49
	ldd	r14,Z+50
	ldd	r15,Z+51
	ldd	r16,Z+52
	ldd	r17,Z+53
	ldd	r18,Z+54
	ldd	r19,Z+55

	lsr	r27
	SBC64   r19,r18,r17,r16,r15,r14,r1,r0  r13,r12,r11,r10,r9,r8,r7,r6

	ldd	r20,Z+56
	sbc	r20,r2
	ldd	r25,Z+57
	sbc	r25,r3
	ldd	r2,Z+58
	sbc	r2,r4
	ldd	r3,Z+59
	sbc	r3,r5
	ldd	r4,Z+60
	sbc	r4,r21
	ldd	r5,Z+61
	sbc	r5,r22
	ldd	r21,Z+62
	sbc	r21,r23
	ldd	r22,Z+63
	sbc	r22,r24
; store borrow in r28:r27
	sbc	r27,r27
	sbc	r28,r28

; add h0+l8
	lsr	r26
	ldd	r23,Z+32
	adc	r0,r23
	std	Z+32,r0
	ldd	r24,Z+33
	adc	r1,r24
	std	Z+33,r1
	ldd	r0,Z+34
	adc	r14,r0
	std	Z+34,r14
	ldd	r0,Z+35
	adc	r15,r0
	std	Z+35,r15
	ldd	r0,Z+36
	adc	r16,r0
	std	Z+36,r16
	ldd	r0,Z+37
	adc	r17,r0
	std	Z+37,r17
	ldd	r0,Z+38
	adc	r18,r0
	std	Z+38,r18
	ldd	r0,Z+39
	adc	r19,r0
	std	Z+39,r19
	ldd	r0,Z+40
	adc	r20,r0
	std	Z+40,r20
	ldd	r0,Z+41
	adc	r25,r0
	std	Z+41,r25
	ldd	r0,Z+42
	adc	r2,r0
	std	Z+42,r2
	ldd	r0,Z+43
	adc	r3,r0
	std	Z+43,r3
	ldd	r0,Z+44
	adc	r4,r0
	std	Z+44,r4
	ldd	r0,Z+45
	adc	r5,r0
	std	Z+45,r5
	ldd	r0,Z+46
	adc	r21,r0
	std	Z+46,r21
	ldd	r0,Z+47
	adc	r22,r0
	std	Z+47,r22
; store carry in r28:r27
	adc	r27,r26
	adc	r28,r26

	rjmp	final

final_addition:
; subtract M
	ldd	r0,Z+0
	add	r0,r14
	ldd	r1,Z+1
	adc	r1,r15
	ldd	r14,Z+2
	adc	r14,r16
	ldd	r15,Z+3
	adc	r15,r17
	ldd	r16,Z+4
	adc	r16,r18
	ldd	r17,Z+5
	adc	r17,r19
	ldd	r18,Z+6
	adc	r18,r20
	ldd	r19,Z+7
	adc	r19,r25
	ldd	r20,Z+8
	adc	r20,r2
	ldd	r25,Z+9
	adc	r25,r3
	ldd	r2,Z+10
	adc	r2,r4
	ldd	r3,Z+11
	adc	r3,r5
	ldd	r4,Z+12
	adc	r4,r21
	ldd	r5,Z+13
	adc	r5,r22
	ldd	r21,Z+14
	adc	r21,r23
	ldd	r22,Z+15
	adc	r22,r24
; store carry in r27
	clr	r27
	adc	r27,r27

; now add h0+l8
	ldd	r23,Z+32
	add	r0,r23
	std	Z+16,r0
	ldd	r24,Z+33
	adc	r1,r24
	std	Z+17,r1
	ldd	r0,Z+34
	adc	r14,r0
	std	Z+18,r14
	ldd	r0,Z+35
	adc	r15,r0
	std	Z+19,r15
	ldd	r0,Z+36
	adc	r16,r0
	std	Z+20,r16
	ldd	r0,Z+37
	adc	r17,r0
	std	Z+21,r17
	ldd	r0,Z+38
	adc	r18,r0
	std	Z+22,r18
	ldd	r0,Z+39
	adc	r19,r0
	std	Z+23,r19
	ldd	r0,Z+40
	adc	r20,r0
	std	Z+24,r20
	ldd	r0,Z+41
	adc	r25,r0
	std	Z+25,r25
	ldd	r0,Z+42
	adc	r2,r0
	std	Z+26,r2
	ldd	r0,Z+43
	adc	r3,r0
	std	Z+27,r3
	ldd	r0,Z+44
	adc	r4,r0
	std	Z+28,r4
	ldd	r0,Z+45
	adc	r5,r0
	std	Z+29,r5
	ldd	r0,Z+46
	adc	r21,r0
	std	Z+30,r21
	ldd	r0,Z+47
	adc	r22,r0
	std	Z+31,r22
; store carry in r26
	adc	r26,r26
  
#define Loff  9
	ldd	r24,Y+0+Loff
	ldd	r23,Y+1+Loff
	ldd	r22,Y+2+Loff
	ldd	r21,Y+3+Loff
	ldd	r5,Y+4+Loff
	ldd	r4,Y+5+Loff
	ldd	r3,Y+6+Loff
	ldd	r2,Y+7+Loff

	adiw	r28,57
	LOAD_SP r0,r28,r29


	ldd	r0,Z+48
	ldd	r1,Z+49
	ldd	r14,Z+50
	ldd	r15,Z+51
	ldd	r16,Z+52
	ldd	r17,Z+53
	ldd	r18,Z+54
	ldd	r19,Z+55

	lsr	r27
	ADC64 	r19,r18,r17,r16,r15,r14,r1,r0  r13,r12,r11,r10,r9,r8,r7,r6

	ldd	r20,Z+56
	adc	r20,r2
	ldd	r25,Z+57
	adc	r25,r3
	ldd	r2,Z+58
	adc	r2,r4
	ldd	r3,Z+59
	adc	r3,r5
	ldd	r4,Z+60
	adc	r4,r21
	ldd	r5,Z+61
	adc	r5,r22
	ldd	r21,Z+62
	adc	r21,r23
	ldd	r22,Z+63
	adc	r22,r24
; store carry in r28:r27
	adc	r27,r27
	clr	r28

; now add h0+l8
	lsr	r26

	ldd	r23,Z+32
	adc	r0,r23
	std	Z+32,r0
	ldd	r24,Z+33
	adc	r1,r24
	std	Z+33,r1
	ldd	r0,Z+34
	adc	r14,r0
	std	Z+34,r14
	ldd	r0,Z+35
	adc	r15,r0
	std	Z+35,r15
	ldd	r0,Z+36
	adc	r16,r0
	std	Z+36,r16
	ldd	r0,Z+37
	adc	r17,r0
	std	Z+37,r17
	ldd	r0,Z+38
	adc	r18,r0
	std	Z+38,r18
	ldd	r0,Z+39
	adc	r19,r0
	std	Z+39,r19
	ldd	r0,Z+40
	adc	r20,r0
	std	Z+40,r20
	ldd	r0,Z+41
	adc	r25,r0
	std	Z+41,r25
	ldd	r0,Z+42
	adc	r2,r0
	std	Z+42,r2
	ldd	r0,Z+43
	adc	r3,r0
	std	Z+43,r3
	ldd	r0,Z+44
	adc	r4,r0
	std	Z+44,r4
	ldd	r0,Z+45
	adc	r5,r0
	std	Z+45,r5
	ldd	r0,Z+46
	adc	r21,r0
	std	Z+46,r21
	ldd	r0,Z+47
	adc	r22,r0
	std	Z+47,r22
; store carry in r28:r27
	adc	r27,r26
	adc	r28,r26

final:
;--- propagate carry to end ---
.set Off, 48
.irp	Reg,0,1,14,15,16,17,18,19,20,25,2,3,4,5,21,22
	ldd	r\Reg,Z+Off
.set Off, Off+1
.endr

	ADD64	r19,r18,r17,r16,r15,r14,r1,r0,   r28,r28,r28,r28,r28,r28,r28,r27
	ADC64	r22,r21,r5,r4,r3,r2,r25,r20      r28,r28,r28,r28,r28,r28,r28,r28
.set Off, 48
.irp	Reg,0,1,14,15,16,17,18,19,20,25,2,3,4,5,21,22
	std	Z+Off,r\Reg
.set Off, Off+1
.endr
	ret
#endif //(defined(HAVE_RSA_MUL_256_NO_ABI) && defined (OsEID))
