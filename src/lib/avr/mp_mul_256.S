/*
    This is part of OsEID (Open source Electronic ID)

    256 bit (interrupt safe) multiplication routine for AVR

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
  size: 8020 bytes

  this code (MEM pointers 15 bit)                      4551 clock cycles
  size: 7478 bytes

  this code (MEM pointers 16 bit)                      4562 clock cycles

  For environment with enabled interrupts, I flag is saved before CLI and
  restored after SP manipulation or SEI is forced after SP manipulation.

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
.macro  LOAD32_FROM_Y  REG3 REG2 REG1 REG0    M
        ldd     \REG0,Y+0+\M
        ldd     \REG1,Y+1+\M
        ldd     \REG2,Y+2+\M
        ldd     \REG3,Y+3+\M
.endm
.macro  LOAD32_FROM_X  REG3 REG2 REG1 REG0
        ld	\REG0,X+
        ld	\REG1,X+
        ld	\REG2,X+
        ld	\REG3,X+
.endm
.macro  LOAD64_FROM_X  REG7 REG6 REG5 REG4 REG3 REG2 REG1 REG0
        ld	\REG0,X+
        ld	\REG1,X+
        ld	\REG2,X+
        ld	\REG3,X+
        ld	\REG4,X+
        ld	\REG5,X+
        ld	\REG6,X+
        ld	\REG7,X+
.endm
.macro  STORE32_TO_Y  REG3 REG2 REG1 REG0    M
        std     Y+0+\M,\REG0
        std     Y+1+\M,\REG1
        std     Y+2+\M,\REG2
        std     Y+3+\M,\REG3
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
.macro  LOAD48_FROM_Y  REG5 REG4 REG3 REG2 REG1 REG0    M
        ldd     \REG0,Y+0+\M
        ldd     \REG1,Y+1+\M
        ldd     \REG2,Y+2+\M
        ldd     \REG3,Y+3+\M
        ldd     \REG4,Y+4+\M
        ldd     \REG5,Y+5+\M
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
.macro  STORE64_TO_Y  REG7 REG6 REG5 REG4 REG3 REG2 REG1 REG0    M
        std     Y+0+\M,\REG0
        std     Y+1+\M,\REG1
        std     Y+2+\M,\REG2
        std     Y+3+\M,\REG3
        std     Y+4+\M,\REG4
        std     Y+5+\M,\REG5
        std     Y+6+\M,\REG6
        std     Y+7+\M,\REG7
.endm
.macro  STORE48_TO_Y   REG5 REG4 REG3 REG2 REG1 REG0    M
        std     Y+0+\M,\REG0
        std     Y+1+\M,\REG1
        std     Y+2+\M,\REG2
        std     Y+3+\M,\REG3
        std     Y+4+\M,\REG4
        std     Y+5+\M,\REG5
.endm


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
// mutiply without use of CC registers (79)
// high bytes of result overlap operand A!!!!
.macro	MUL32_ncc_sw4	/*A0,A1*/RS5,RS4,RS3,RS2,RS1,RS0 B3,B2,B1,B0  A3,A2,A1,A0  ZERO
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

	mul	\A0,\B3		// A0 free ..
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
	movw	\A0,\ZERO	// clear A0,A1 reuse as result..

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
	add	\RS5,r0
	adc	\A1,r1
	adc	\A0,\ZERO
	mul	\A3,\B2
	add	\RS5,r0
	adc	\A1,r1
	adc	\A0,\ZERO

	mul	\A3,\B3
	add	\A1,r0
	adc	\A0,r1
.endm
// mutiply without use of CC registers (79 ticks),
// high bytes of result overlap operand A!!!!
// A2 is new ZERO
.macro	MUL32_ncc_sw2	/*ZERO,A1,A0*/RS4,RS3,RS2,RS1,RS0 B3,B2,B1,B0  A3,A2,A1,A0  ZERO
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
	adc	\A0,\ZERO
	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	adc	\A0,\ZERO
	mul	\A2,\B1
	add	\RS3,r0
	adc	\RS4,r1
	adc	\A0,\ZERO
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\A0,\ZERO

	mul	\A1,\B3
	clr	\A1
	add	\RS4,r0
	adc	\A0,r1
	adc	\A1,\ZERO
	mul	\A2,\B2
	add	\RS4,r0
	adc	\A0,r1
	adc	\A1,\ZERO
	mul	\A3,\B1
	add	\RS4,r0
	adc	\A0,r1
	adc	\A1,\ZERO

	mul	\A2,\B3
// swap ZERO and A2
	clr	\A2
	add	\A0,r0
	adc	\A1,r1
	adc	\ZERO,\A2
	mul	\A3,\B2
	add	\A0,r0
	adc	\A1,r1
	adc	\ZERO,\A2

	mul	\A3,\B3
	add	\A1,r0
	adc	\ZERO,r1
.endm


// multiply only 1st 4 bytes of result,precalculate bytes 4,5
// ZERO,RS2,RS3,RS4 and RS5 must be cleared before ..
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
.endm	// 49 clock cycles

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
.endm	// 29 clock cycles

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
.endm	// 30 clock cycles

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

.macro  MUL32_ADD_n2  RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0   A2,A1,A0  ZERO
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
	mul	\A2,\B0
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
	mul	\A2,\B1
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\ZERO
.endm
.macro  MUL32_ADD_cont2  /*A2,A1*/RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0  A3,A2,A1  ZERO
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
	adc	\A2,\ZERO
	mul	\A3,\B2
	add	\RS5,r0
	adc	\A1,r1
	adc	\A2,\ZERO

	mul	\A3,\B3
	add	\A1,r0
	adc	\A2,r1
.endm

//  RS6 must be cleared before call
//  A2 = RS7
//  A1 is cleared at end
.macro  MUL32_ADD_cont_n3 RS6,RS5,RS4,RS3   B3,B2,B1,B0  A3 A2 A1
	mul	\A3,\B0
	add	\RS3,r0
	adc	\RS4,r1
	adc	\RS5,\RS6	// ZERO

	mul	\A1,\B3
	clr	\A1
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\A1	// ZERO
	mul	\A2,\B2
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\A1	// ZERO
	mul	\A3,\B1
	add	\RS4,r0
	adc	\RS5,r1
	adc	\RS6,\A1	// ZERO

	mul	\A2,\B3
	clr	\A2
	add	\RS5,r0
	adc	\RS6,r1
	adc	\A2,\A1		// ZERO
	mul	\A3,\B2
	add	\RS5,r0
	adc	\RS6,r1
	adc	\A2,\A1		// ZERO

	mul	\A3,\B3
	add	\RS6,r0
	adc	\A2,r1
.endm
// RS6 is initial ZERO
.macro	MUL32_MP	RS7,RS6,/*A0*/RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0  A3,A2,A1,A0  CC1 CC0
	mul	\A0,\B2
	movw	\RS2,r0
	mul	\A0,\B0
	movw	\RS0,r0
	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\RS6	// ZERO
	mul	\A1,\B3
	mov	\RS4,r0
	mov	r0,\A0
	mov	\A0,r1

	mul	r0,\B3		//A0,B3
	movw	\CC0,r0
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\CC0
	adc	\CC1,\RS6	// ZERO
	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\CC1,\RS6	// ZERO
	mul	\A2,\B3
	add	\RS4,\CC1
	adc	\A0,r0		// RS 5
	adc	\RS6,r1

	mul	\A2,\B2
	movw	\CC0,r0
	mul	\A2,\B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\CC0
	clr	r0
	adc	\CC1,r0		// ZERO
	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	clr	\A1
	adc	\CC1,\A1	// ZERO

	mul	\A3,\B3
	add	\A0,\CC1	// RS 5
	adc	\RS6,r0
	clr	\RS7
	adc	\RS7,r1

	mul	\A3,\B1
	movw	\CC0,r0
	mul	\A2,\B1
	add	\RS3,r0
	adc	\RS4,r1
	adc	\CC1,\A1	// ZERO

	mul	\A3,\B0
	add	\RS3,r0
	adc	\CC0,r1
	adc	\CC1,\A1	// ZERO
	mul	\A3,\B2
	add	\RS4,\CC0
	adc	r0,\CC1
	adc	r1,\A1		// ZERO
	add	\A0,r0		// RS5
	adc	\RS6,r1
	adc	\RS7,\A1	// ZERO
.endm //(78)

//RS5,RS4  ZERO
.macro MUL32_ADD_x2  /*B3,A0*/RS5,RS4,RS3,RS2,RS1,RS0   B3,B2,B1,B0  A3,A2,A1,A0  CC1 CC0
	mul	\A0,\B2
	movw	\CC0,r0
	mul	\A0,\B0
	add	\RS0,r0
	adc	\RS1,r1
	adc	\RS2,\CC0
	adc	\CC1,\RS4	// ZERO
	mul	\A0,\B1
	add	\RS1,r0
	adc	\RS2,r1
	adc	\CC1,\RS4	// ZERO
	mul	\A1,\B3
	add	\RS3,\CC1
	adc	\RS4,r0
	adc	\RS5,r1

	mul	\A0,\B3
	movw	\CC0,r0
	mul	\A1,\B0
	add	\RS1,r0
	adc	\RS2,r1
	adc	\RS3,\CC0
	clr	\A0		// new ZERO
	adc	\CC1,\A0	// ZERO
	mul	\A1,\B1
	add	\RS2,r0
	adc	\RS3,r1
	adc	\CC1,\A0	// ZERO
	mul	\A2,\B3
	add	\RS4,\CC1
	adc	\RS5,r0
	adc	\A0,r1		// RS6

	mul	\A2,\B2
	movw	\CC0,r0
	mul	\A2,\B0
	add	\RS2,r0
	adc	\RS3,r1
	adc	\RS4,\CC0
	clr	r0
	adc	\CC1,r0		// ZERO
	mul	\A1,\B2
	add	\RS3,r0
	adc	\RS4,r1
	clr	\A1
	adc	\CC1,\A1	// ZERO
	mul	\A3,\B3
	add	\RS5,\CC1
	adc	\A0,r0		// RS6
	clr	\B3
	adc	\B3,r1

	mul	\A3,\B1
	movw	\CC0,r0
	mul	\A2,\B1
	add	\RS3,r0
	adc	\CC0,r1
	adc	\CC1,\A1	// ZERO
	mul	\A3,\B0
	add	\RS3,r0
	adc	\CC0,r1
	adc	\CC1,\A1	// ZERO

	mul	\A3,\B2
	add	\RS4,\CC0
	adc	r0,\CC1
	adc	r1,\A1		// ZERO
	adc	\RS5,r0
	adc	\A0,r1
	adc	\B3,\A1
.endm

.macro ABS32  RS3,RS2,RS1,RS0 SIGN
	eor	\RS0,\SIGN
	eor	\RS1,\SIGN
	eor	\RS2,\SIGN
	eor	\RS3,\SIGN
	sub	\RS0,\SIGN
	sbc	\RS1,\SIGN
	sbc	\RS2,\SIGN
	sbc	\RS3,\SIGN
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

.macro	ADD32	RZ3 RZ2 RZ1 RZ0   A3 A2 A1 A0
	add	\RZ0,\A0
	adc	\RZ1,\A1
	adc	\RZ2,\A2
	adc	\RZ3,\A3
.endm

.macro	ADC32	RZ3 RZ2 RZ1 RZ0   A3 A2 A1 A0
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

  .global rsa_mul_256_no_abi
  .type rsa_mul_256_no_abi,@function
  .section .text.rsa_mul_256_no_abi,"ax",@progbits

rsa_mul_256_no_abi:
// store X,Y pointers on stack
	push	r28
	push	r29
	push	r26
	push	r27
/////////////////////////////////////////////////////////////////////////////
// bytes [15..0]
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
// bytes [15..0]	bytes [7..0]
/////////////////////////////////////////////////////////////////////////////
	clr	r24
	clr	r25
	movw	r16,r24	// ZERO
// >>>>>  bytes [3..0]
	LOAD32_FROM_X	r5,r4,r3,r2
	LOAD32_FROM_Y	r9,r8,r7,r6	0
//              result                              A                B    zero  CC1 CC0
	MUL_32	r17,r16,r15,r14,r13,r12,r11,r10	 r5,r4,r3,r2  r9,r8,r7,r6  r24  r23,r22
	STORE32_TO_Z	r13,r12,r11,r10	0
// >>>>>  bytes [7..4]
	ld	r22,X+
	ld	r23,X+
	LOAD32_FROM_Y	r21,r20,r19,r18	4
	movw	r10,r24	// ZERO
	movw	r12,r24	// ZERO
// upper bytes of operand A (A6) are readed from X+!            B           A1  A0  ZERO
	MUL32_ADD_n	r13/*r12*/r11,r10,r17,r16,r15,r14  r21,r20,r19,r18  r23,r22  r24
// abs differences H-L
	sub	r2,r22
	sbc	r3,r23
	sbc	r4,r13
	ld	r22,X+
	sbc	r5,r22
	sbc	r0,r0		// sign to r0 (0x00/0xff)

	SUB32	r9,r8,r7,r6	r21,r20,r19,r18
	sbc	r1,r1		// sign to r1 (0x00/0xff)

	ABS32	r5,r4,r3,r2	r0
	ABS32	r9,r8,r7,r6	r1
	eor	r0,r1
	bst	r0,0		// combined sign to T
//                                                                 B           A3  A2  A1 ZERO
	MUL32_ADD_cont_n  /*r13*/r12,r11,r10,r17,r16,r15,r14 r21,r20,r19,r18  r22,r13,r23  r24

// >>>>>  midle part [7..4]  [3..0]
	MUL_32_8	/*r3,r2*/r23,r22,r21,r20,r19,r18   r9,r8,r7,r6  r5,r4,r3,r2 r24
	MUL_32_8contA	/*r3,r2*/r23,r22		   r9,r8,r7,r6  r5,r4,r3,r2 r24

// >>>>>  combine [7..0]  (middle part in r3,r2,r23,r22,r21,r20,r19,r18)
	LOAD32_FROM_Z	r9,r8,r7,r6	0

	movw	r0,r24	// ZERO
	ADD64	r17,r16,r15,r14,r9,r8,r7,r6	r13,r12,r11,r10,r17,r16,r15,r14
	adc	r1,r1	// carry
// add/subtract middle part
	brtc	sub_M_L_L

	ADD64	r17,r16,r15,r14,r9,r8,r7,r6	r3,r2,r23,r22,r21,r20,r19,r18
	adc	r1,r0	// carry
	rjmp	final_L_L
sub_M_L_L:
	SUB64	r17,r16,r15,r14,r9,r8,r7,r6	r3,r2,r23,r22,r21,r20,r19,r18
	sbc	r1,r0	// carry
	sbc	r0,r0
final_L_L:
	STORE32_TO_Z	r9,r8,r7,r6	4
// propagate carry to end
	ADD32	r13,r12,r11,r10		r0,r0,r0,r1
// =====  result in r13,r12,r11,r10    r17,r16,r15,r14,     mem:Z[7..0]
// free r21..r22,  r9..r2,  r1,r0 (ZERO in r25,r24)
/////////////////////////////////////////////////////////////////////////////
// bytes [15..0]	bytes [15..8]
/////////////////////////////////////////////////////////////////////////////

// >>>>>  bytes [11..8]
	LOAD32_FROM_X	r5,r4,r3,r2
	LOAD32_FROM_Y	r9,r8,r7,r6	8

	MUL_32_8 /*r,r*/ r19,r18,r21,r20,r23,r22	r9,r8,r7,r6  r5,r4,r3,r2  r24
; now add h0+l8 and h0+l12
	ADD64	r21,r20,r23,r22,r17,r16,r15,r14		r13,r12,r11,r10,r21,r20,r23,r22
	STORE32_TO_Z		r17,r16,r15,r14		16
// >>>>>  bytes [15..12]
	LOAD32_FROM_Y	r13,r12,r15,r14	12
#ifdef RAM_LE32
	rol	r29
#else
	sbc	r0,r0
	push	r0
#endif
// need more registers, use stack .. 
	push	r22
	push	r23
	MUL_32_8cont r17,r16,r19,r18	r9,r8,r7,r6  r5,r4,r3,r2  r24

	movw	r22,r24 // ZERO
	ld	r10,X+
	ld	r11,X+
	MUL32_ADD_n	r24,/*r11*/ r23,r22,r17,r16,r19,r18  r13,r12,r15,r14  r11,r10 r25
// abs differences H-L
	sub	r2,r10
	sbc	r3,r11
	sbc	r4,r24		// r24 is loaded in MUL32_ADD_n from X+
	ld	r10,X+
	sbc	r5,r10
	sbc	r0,r0		// sign to r0 (0x00/0xff)

	SUB32	r9,r8,r7,r6	r13,r12,r15,r14
	sbc	r1,r1		// sign to r1 (0x00/0xff)

	ABS32	r5,r4,r3,r2	r0
	ABS32	r9,r8,r7,r6	r1
	eor	r0,r1
	bst	r0,0		// combined sign to T
// ZERO in RS6 (r25)
//                         RS7   RS6 ....... RS3         B           A3  A2  A1
	MUL32_ADD_cont_n3 /*A2*/ r25,r23,r22,r17   r13,r12,r15,r14  r10 r24 r11
// zero in r11   result in r24,r25,r23,r22,r17,r16,r19,r18
// >>>>>  midle part [15..12]  [11..8]
	clr	r10
	movw	r12,r10
// 			result 				 B              A          ZERO
	MUL32_ncc_sw2 /*ZERO,r3,r2*/r10,r13,r12,r15,r14  r9,r8,r7,r6  r5,r4,r3,r2  r11
// new ZERO is in operand A2 - r4
// free r5 r8 r9, zero in r4
	clr	r5
	movw	r8,r4	// zero in r4,r5,r8,r9
	pop	r7
	pop	r6
;--- add l4+h0 to l0 and h4 ---
	ADD64	r17,r16,r19,r18,r21,r20,r7,r6	r24,r25,r23,r22,r17,r16,r19,r18
	adc	r4,r4
;--- propagate carry ---
#ifdef RAM_LE32
	lsr	r29
#else
	pop	r0
	lsr	r0
#endif
	ADC32	r17,r16,r19,r18	  r5,r5,r5,r5
	adc	r4,r5
// add/subtract middle part
	brtc	sub_M_H_L

	ADD64 	r17,r16,r19,r18,r21,r20,r7,r6	r11,r3,r2,r10,r13,r12,r15,r14
	adc	r4,r5
	rjmp	final_H_L
sub_M_H_L:
	SUB64 	r17,r16,r19,r18,r21,r20,r7,r6	r11,r3,r2,r10,r13,r12,r15,r14
	sbc	r4,r5
	sbc	r5,r5
final_H_L:
	STORE64_TO_Z	r17,r16,r19,r18,r21,r20,r7,r6	20
// propagate carry to end
	ADD32		r24,r25,r23,r22	  r5,r5,r5,r4
	STORE32_TO_Z	r24,r25,r23,r22			28
/////////////////////////////////////////////////////////////////////////////
// bytes [15..0]	middle part M[15..0]
/////////////////////////////////////////////////////////////////////////////
// ZERO in r9,r8
// free r25...r0
// pointers in r31..r26
	sbiw	r26,16
	LOAD64_FROM_X	r25,r24,r23,r22,r5,r4,r3,r2
	LOAD64_FROM_X	r17,r16,r15,r14,r13,r12,r11,r10

	SUB64	r25,r24,r23,r22,r5,r4,r3,r2  r17,r16,r15,r14,r13,r12,r11,r10
	sbc	r0,r0	// sign to r0 (0x00/0xff)

	LOAD64_FROM_Y	r21,r20,r19,r18,r27,r26,r7,r6	0
	LOAD64_FROM_Y	r17,r16,r15,r14,r13,r12,r11,r10	8

	SUB64	r21,r20,r19,r18,r27,r26,r7,r6	r17,r16,r15,r14,r13,r12,r11,r10
	sbc	r1,r1	// sign to r1 (0x00/0xff)

	ABS64	r25,r24,r23,r22,r5,r4,r3,r2	r0
	ABS64	r21,r20,r19,r18,r27,r26,r7,r6	r1
	eor	r0,r1
#ifdef RAM_LE32
	lsr	r0	// combined sign to carry
	rol	r31	// to bit 0 in Z pointer
#else
	push	r0	// combined sign to stack
#endif
/////////////////////////////////////////////////////////////////////////////
// bytes [15..0]	M[7..0]	
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
// bytes [15..0]        M[7..0] 	bytes M[3..0]
/////////////////////////////////////////////////////////////////////////////
	movw	r16,r8	// ZERO
//              result                             A                B    zero  CC1 CC0
	MUL_32	r17,r16,r15,r14,r13,r12,r11,r10  r5,r4,r3,r2  r27,r26,r7,r6 r8  r29,r28
// abs differences H-L
	SUB32	r5,r4,r3,r2 ,r25,r24,r23,r22
	sbc	r0,r0		// sign to r0 (0x00/0xff)

	SUB32	r27,r26,r7,r6	r21,r20,r19,r18
	sbc	r1,r1		// sign to r1 (0x00/0xff)

	ABS32	r5,r4,r3,r2	r0
	ABS32	r27,r26,r7,r6	r1
	eor	r0,r1
	bst	r0,0		// combined sign to T

/////////////////////////////////////////////////////////////////////////////
// bytes [15..0]        M[7..0] 	bytes M[7..4]
/////////////////////////////////////////////////////////////////////////////
// mul_add
//		r21,r22,r9,r8,r17,r16,r15,r14	r21,r20,r19,r18 r25,r24,r23,r22
// free r29,r28, zero r9:r8 ocupied: r27,r26,r7,r6  r5,r4,r3,r2 

//r9,r8 zero!
	MUL32_ADD_x2	/*r21,r22*/r9,r8,r17,r16,r15,r14   r21,r20,r19,r18  r25,r24,r23,r22  r29 r28
// r23 new zero
/////////////////////////////////////////////////////////////////////////////
// bytes [15..0]        M[15..0] 	middle bytes M[7..4] M[3..0]
/////////////////////////////////////////////////////////////////////////////
// r27,r23,r2,r20,r19,r18,r25,r24   r27,r26,r7,r6  r5,r4,r3,r2	
// ZERO in r23!

	MUL32_MP	r27,r23,/*r2*/r20,r19,r18,r25,r24   r27,r26,r7,r6  r5,r4,r3,r2  r29 r28
// r3=zero

;--- add l4+h0 to l0 and h4 ---
	movw	r4,r10
	movw	r6,r12
	ADD64	r17,r16,r15,r14,r13,r12,r11,r10 r21,r22,r9,r8,r17,r16,r15,r14
; store carry in r3
	clr	r29
	adc	r3,r3

;--- process sign bit ---
	brtc	sub_M_M_L
	ADD64	r17,r16,r15,r14,r13,r12,r11,r10 r27,r23,r2,r20,r19,r18,r25,r24
	adc	r3,r29
	rjmp	final_M_L

sub_M_M_L:
; subtract M
	SUB64	r17,r16,r15,r14,r13,r12,r11,r10 r27,r23,r2,r20,r19,r18,r25,r24
	sbc	r3,r29
	sbc	r29,r29
; r29:r28 is -1,0,or 1

final_M_L:
;--- propagate carry to end ---
	ADD32	r21,r22,r9,r8	r29,r29,r29 r3

;------ level 2: combine L,H,and M ------
;--- process sign bit ---
#ifdef RAM_LE32
	lsr	r31
#else
	pop	r1
	lsr	r1	// test bit0
#endif
	LOAD64_FROM_Z	r27,r26,r23,r20,r19,r18,r25,r24	0
	LOAD32_FROM_Z	r28,r3,r2,r1	16
	ldd	r29,Z+20

	brcs	add_M_L

; subtract M
	SUB64	r27,r26,r23,r20,r19,r18,r25,r24 r13,r12,r11,r10,r7,r6,r5,r4
	rol	r0	// borrow to r0

	ldd	r7,Z+21
	ldd	r10,Z+22
	ldd	r11,Z+23

	ADD64	r27,r26,r23,r20,r19,r18,r25,r24	r11,r10,r7,r29,r28,r3,r2,r1
	ror	r0	// carry into r0 bit 7, renew old borrow

	SBC64	r11,r10,r7,r29,r28,r3,r2,r1	r21,r22,r9,r8,r17,r16,r15,r14
	sbc	r5,r5	// borrow
	rjmp	final_L

add_M_L: 
	ADD64	r27,r26,r23,r20,r19,r18,r25,r24 r13,r12,r11,r10,r7,r6,r5,r4
	rol	r0	// carry to r0

	ldd	r7,Z+21
	ldd	r10,Z+22
	ldd	r11,Z+23

	ADD64	r27,r26,r23,r20,r19,r18,r25,r24	r11,r10,r7,r29,r28,r3,r2,r1
	ror	r0	// carry to r0 bit 7, renew old carry

	ADC64	r11,r10,r7,r29,r28,r3,r2,r1	r21,r22,r9,r8,r17,r16,r15,r14
	clr	r5
	adc	r5,r5	// carry
final_L:
	sbc	r6,r6	// extend r5 to r6:r5 (-1,0,1)

	STORE64_TO_Z	r27,r26,r23,r20,r19,r18,r25,r24	8

//////////////////
	LOAD64_FROM_Z	r13,r12,r19,r18,r27,r26,r25,r24	24

	lsl	r0	// renew carry
	ADC64	r11,r10,r7,r29,r28,r3,r2,r1 r13,r12,r19,r18,r27,r26,r25,r24
	
	STORE64_TO_Z	r11,r10,r7,r29,r28,r3,r2,r1	16

;--- propagate carry to end ---
	ADC64	r13,r12,r19,r18,r27,r26,r25,r24 r6,r6,r6,r6,r6,r6,r6,r5
	STORE64_TO_Z	r13,r12,r19,r18,r27,r26,r25,r24 24

; restore X and Y register
	in	r28,0x3d
	in	r29,0x3e

	ldd	r27,Y+1
	ldd	r26,Y+2
	adiw	r26,16

	ldd	r25,Y+3
	ldd	r24,Y+4
	movw	r28,r24

;--------- level 1: compute H ---------

; init zero registers
	clr	r24
	clr	r25
	movw	r16,r24	// ZERO

// >>>>>  bytes [19..16]
	LOAD32_FROM_X	r5,r4,r3,r2
	LOAD32_FROM_Y	r9,r8,r7,r6	16
//              result                              A                B    zero  CC1 CC0
	MUL_32	r17,r16,r15,r14,r13,r12,r11,r10  r5,r4,r3,r2  r9,r8,r7,r6  r24  r23,r22
	STORE32_TO_Z	r13,r12,r11,r10	32

// >>>>>  bytes [23..20]
	ld	r22,X+
	ld	r23,X+
	LOAD32_FROM_Y	r21,r20,r19,r18	20
	movw	r10,r24	// ZERO
	movw	r12,r24	// ZERO
// upper bytes of operand A (A22) are readed from X+!           B           A1  A0  ZERO
	MUL32_ADD_n	r13/*r12*/r11,r10,r17,r16,r15,r14  r21,r20,r19,r18  r23,r22  r24
// abs differences H-L
	sub	r2,r22
	sbc	r3,r23
	sbc	r4,r13
	ld	r22,X+
	sbc	r5,r22
	sbc	r0,r0		// sign to r0 (0x00/0xff)

	SUB32	r9,r8,r7,r6	r21,r20,r19,r18
	sbc	r1,r1		// sign to r1 (0x00/0xff)

	ABS32	r5,r4,r3,r2	r0
	ABS32	r9,r8,r7,r6	r1
	eor	r0,r1
	bst	r0,0		// combined sign to T
//                                                                 B           A3  A2  A1 ZERO
	MUL32_ADD_cont_n  /*r13*/r12,r11,r10,r17,r16,r15,r14 r21,r20,r19,r18  r22,r13,r23  r24

// >>>>>  midle part [23..20]  [19..16]
	MUL_32_8	/*r3,r2*/r23,r22,r21,r20,r19,r18   r9,r8,r7,r6  r5,r4,r3,r2 r24
	MUL_32_8contA	/*r3,r2*/r23,r22     		   r9,r8,r7,r6  r5,r4,r3,r2 r24

// >>>>>  combine [23..16]  (middle part in r3,r2,r23,r22,r21,r20,r19,r18)
	LOAD32_FROM_Z	r9,r8,r7,r6	32

	movw	r0,r24	// ZERO
	ADD64	r17,r16,r15,r14,r9,r8,r7,r6	r13,r12,r11,r10,r17,r16,r15,r14
	adc	r1,r1	// carry
// add/subtract middle part
	brtc	sub_M_L_H

	ADD64	r17,r16,r15,r14,r9,r8,r7,r6	r3,r2,r23,r22,r21,r20,r19,r18
	adc	r1,r0	// carry
	rjmp	final_L_H
sub_M_L_H:
	SUB64	r17,r16,r15,r14,r9,r8,r7,r6	r3,r2,r23,r22,r21,r20,r19,r18
	sbc	r1,r0	// carry
	sbc	r0,r0
final_L_H:
	STORE32_TO_Z	r9,r8,r7,r6	36
// propagate carry to end
	ADD32	r13,r12,r11,r10		r0,r0,r0,r1
// =====  result in r13,r12,r11,r10    r17,r16,r15,r14,     mem:Z[39..32]
// free r21..r22,  r9..r2,  r1,r0 (ZERO in r25,r24)

;------ level 2: compute H ------

;--- level 3: compute L ---
	LOAD32_FROM_X	r5,r4,r3,r2
	LOAD32_FROM_Y	r9,r8,r7,r6	24

	MUL_32_8 /*r,r*/ r19,r18,r21,r20,r23,r22	r9,r8,r7,r6  r5,r4,r3,r2 r24
; now add h0+l8 and h0+l12
	ADD64	r21,r20,r23,r22,r17,r16,r15,r14		r13,r12,r11,r10,r21,r20,r23,r22
	STORE32_TO_Z		r17,r16,r15,r14		48
//
 ;--- load b4..b7 ---
	LOAD32_FROM_Y	r13,r12,r15,r14	28

; store carry on stack
#ifdef RAM_LE32
	rol	r29
#else
	sbc	r0,r0
	push	r0
#endif
// need more registers, use stack ..
	push	r22
	push	r23
	MUL_32_8cont r17,r16,r19,r18	r9,r8,r7,r6  r5,r4,r3,r2  r24
;--- load a4..a7 and b4..b7 ---
	movw	r22,r24	// ZERO
	ld	r10,X+
	ld	r11,X+
	MUL32_ADD_n	r24/*r11*/ r23,r22,r17,r16,r19,r18  r13,r12,r15,r14  r11,r10   r25
// r11 is not updated here! r24 is readed form X+
// abs differences H-L
	sub	r2,r10
	sbc	r3,r11
	sbc	r4,r24
	ld	r10,X+
	sbc	r5,r10
	sbc	r0,r0		// sign to r0 (0x00/0xff)

	SUB32	r9,r8,r7,r6	r13,r12,r15,r14
	sbc	r1,r1		// sign to r1 (0x00/0xff)

	ABS32	r5,r4,r3,r2	r0
	ABS32	r9,r8,r7,r6	r1
	eor	r0,r1
	bst	r0,0		// combined sign to T

;--- continue ---
// ZERO in RS6 (r25)
//                   RS7   RS6 ....... RS3         B           A3   A2  A1
  MUL32_ADD_cont_n3 /*A2*/ r25,r23,r22,r17   r13,r12,r15,r14  r10 r24 r11
// zero in r11
// result in r24,r25,r23,r22,r17,r16,r19,r18
;--- level 3: compute M ---
	clr	r10
	movw	r12,r10
//			result			         B              A          ZERO
        MUL32_ncc_sw2 /*ZERO,r3,r2*/r10,r13,r12,r15,r14  r9,r8,r7,r6  r5,r4,r3,r2  r11
// new ZERO is in operand A2 - r4
// free r5 r8 r9, zero in r4
	clr	r5
	movw	r8,r4	// zero in r4,r5,r8,r9
;--- add l4+h0 to l0 and h4 ---
	pop	r7
	pop	r6

	ADD64 r17,r16,r19,r18,r21,r20,r7,r6	r24,r25,r23,r22,r17,r16,r19,r18
	adc	r4,r4
;--- propagate carry ---
#ifdef RAM_LE32
	lsr	r29
#else
	pop	r0
	lsr	r0
#endif
	ADC32	r17,r16,r19,r18		r5,r5,r5,r5
	adc	r4,r5
// add/subtract middle part
	brtc	sub_M_H_H

	ADD64 r17,r16,r19,r18,r21,r20,r7,r6 r11,r3,r2,r10,r13,r12,r15,r14
	adc	r4,r5
	rjmp	final_H_H
sub_M_H_H:
	SUB64 r17,r16,r19,r18,r21,r20,r7,r6 r11,r3,r2,r10,r13,r12,r15,r14
	sbc	r4,r5
	sbc	r5,r5
final_H_H:
	STORE64_TO_Z	r17,r16,r19,r18,r21,r20,r7,r6	52
// propagate carry to end
	ADD32		r24,r25,r23,r22	 r5,r5,r5,r4
	STORE32_TO_Z	r24,r25,r23,r22			60

/////////////////////////////////////////////////////////////////////////////
// ZERO in r9,r8
// free r25...r0
// pointers in r31..r26

;------ level 1: subtract b16-b24 ------
	LOAD64_FROM_Y	r25,r24,r23,r22,r5,r4,r3,r2	16
	LOAD64_FROM_Y	r17,r16,r15,r14,r13,r12,r11,r10	24

	SUB64	r25,r24,r23,r22,r5,r4,r3,r2	r17,r16,r15,r14,r13,r12,r11,r10
	sbc	r0,r0	// sign to r0 (0x00/0xff)

;------ level 1: subtract a16-a24 ------
	sbiw	r26,16
	LOAD64_FROM_X	r21,r20,r19,r18,r29,r28,r7,r6
	LOAD64_FROM_X	r17,r16,r15,r14,r13,r12,r11,r10

	SUB64	r21,r20,r19,r18,r29,r28,r7,r6	r17,r16,r15,r14,r13,r12,r11,r10
	sbc	r1,r1	// sign to r1 (0x00/0xff)

;------ level 2: absolute values ------
	ABS64	r25,r24,r23,r22,r5,r4,r3,r2 r0
	ABS64	r21,r20,r19,r18,r29,r28,r7,r6 r1
	eor	r0,r1
#ifdef RAM_LE32
	lsr	r0	// combined sign to carry
	rol	r31	// to bit 0 in Z pointer
#else
	push	r0	// combined sign to stack
#endif
;------ level 2: compute M ------
	movw	r16,r8	// ZERO

//              result                             A                B    zero  CC1 CC0
	MUL_32  r17,r16,r15,r14,r13,r12,r11,r10  r29,r28,r7,r6  r5,r4,r3,r2 r8  r27,r26
// abs differences H-L
	SUB32	r29,r28,r7,r6  r21,r20,r19,r18
	sbc	r0,r0		// sign to r0 (0x00/0xff)

	SUB32	r5,r4,r3,r2	r25,r24,r23,r22
	sbc	r1,r1		// sign to r1 (0x00/0xff)

	ABS32	r29,r28,r7,r6	r0
	ABS32	r5,r4,r3,r2	r1
	eor	r0,r1
	bst	r0,0		// combined sign to T

// r9,r8 initial ZERO    clamped:r27,r26
MUL32_ADD_x2    /*r25,r18*/r9,r8,r17,r16,r15,r14   r25,r24,r23,r22      r21,r20,r19,r18  r27 r26
// r19 new zero

// r19 is initial zero  clamped r27,r26
// compute M 
	 MUL32_MP        r5,r19,/*r6*/r24,r23,r22,r21,r20  r5,r4,r3,r2  r29,r28,r7,r6  r27 r26
// r7 = ZERO

;--- add l4+h0 to l0 and h4 ---
	movw	r28,r10
	movw	r2,r12
	ADD64	r17,r16,r15,r14,r13,r12,r11,r10		r25,r18,r9,r8,r17,r16,r15,r14
; store carry in r7
	clr	r27
	adc	r7,r7

;--- process sign bit ---
	brtc	sub_M_M_H

	ADD64	r17,r16,r15,r14,r13,r12,r11,r10		r5,r19,r6,r24,r23,r22,r21,r20
	adc	r7,r27
	rjmp	final_M_H
sub_M_M_H:
; subtract M
	SUB64	r17,r16,r15,r14,r13,r12,r11,r10		r5,r19,r6,r24,r23,r22,r21,r20
	sbc	r7,r27
	sbc	r27,r27
final_M_H:
;--- propagate carry to end ---
	ADD32	r25,r18,r9,r8	r27,r27,r27,r7

;------ level 2: combine L,H,and M ------
;--- process sign bit ---
#ifdef RAM_LE32
	bst	r31,0	// Z pointer need to be restored, move sign into T
	lsr	r31
#endif
;------ level 2: combine L,H,and M ------
	LOAD64_FROM_Z	r5,r4,r19,r24,r23,r22,r21,r20 	32

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
	adc	r1,r4
	std	Z+38,r1
	ldd	r1,Z+23
	adc	r1,r5
	std	Z+39,r1

	sbc	r26,r26	// carry to r26 (0/0xff)

;--- process sign bit ---
#ifdef RAM_LE32
	brts	add_M_H
#else
	pop	r7
	lsr	r7	// test bit0
	brcs	add_M_H
#endif
sub_M_H:
; subtract M
	SUB64		r5,r4,r19,r24,r23,r22,r21,r20	r13,r12,r11,r10,r3,r2,r29,r28

	LOAD64_FROM_Z	r13,r12,r11,r10,r3,r2,r29,r28	56
	SBC64		r13,r12,r11,r10,r3,r2,r29,r28	r25,r18,r9,r8,r17,r16,r15,r14
	sbc	r0,r0	// borrow
	rjmp	final_H
add_M_H: 
	ADD64		r5,r4,r19,r24,r23,r22,r21,r20	r13,r12,r11,r10,r3,r2,r29,r28

	LOAD64_FROM_Z	r13,r12,r11,r10,r3,r2,r29,r28	56
	ADC64		r13,r12,r11,r10,r3,r2,r29,r28	r25,r18,r9,r8,r17,r16,r15,r14
	clr	r0	// carry
	adc	r0,r0

final_H:
	sbc	r1,r1	// extend r0 to r1:r0 (-1,0,1)

	LOAD64_FROM_Z	r25,r18,r9,r8,r17,r16,r15,r14	48

	ADD64		r5,r4,r19,r24,r23,r22,r21,r20	r25,r18,r9,r8,r17,r16,r15,r14
	ADC64		r13,r12,r11,r10,r3,r2,r29,r28	r25,r18,r9,r8,r17,r16,r15,r14

; add carry to carry catcher
	clr	r7
	adc	r0,r7
	adc	r1,r7

;--- add higher part of the first 128 bits ---
	lsr	r26		// renew carry
	LOAD64_FROM_Z	r27,r26,r17,r16,r15,r14,r9,r8	24

	ADC64		r5,r4,r19,r24,r23,r22,r21,r20	r27,r26,r17,r16,r15,r14,r9,r8
	STORE64_TO_Z	r5,r4,r19,r24,r23,r22,r21,r20	40

	ADC64		r13,r12,r11,r10,r3,r2,r29,r28	r7,r7,r7,r7,r7,r7,r7,r7
	STORE64_TO_Z	r13,r12,r11,r10,r3,r2,r29,r28	48

;--- propagate carry to end ---
	LOAD64_FROM_Z	r26,r29,r28,r25,r24,r23,r22,r21	56

	ADC64		r26,r29,r28,r25,r24,r23,r22,r21	r1,r1,r1,r1,r1,r1,r1,r0
	STORE64_TO_Z	r26,r29,r28,r25,r24,r23,r22,r21 56
; restore X and Y register
	pop	r27
	pop	r26
	pop	r29
	pop	r28
// FREE registers:
// r25,r24,r23,r22,r21,r20,r19,r18,r17,
// r16,r15,r14,r13,r12,r11,r10,r9,r8
// (r7 ZERO),r6,r5,r4,r3,r2,r1,r0
/////////////////////////////////////////////////////////////////////////////
// Stack is used to store temp variables
//+50	8 bytes X[15..8]
//+42	8 bytes X[15..8] - X[7..0]
//+34	8 bytes Y[15..8]
//+26	8 bytes Y[15..8] - X[7..0]
//+25	1 byte SIGNs
//+21	4
//+17	4
//+13	4
// +1   12
 
;--------- level 1: subtract a0-a15 ---------
.irp	Reg,2,3,4,5,20,19,18,21,10,11,12,13,14,15,16,17
	ld	r\Reg,X+
.endr
	ld	r0,X+
	sub	r2,r0
.irp	Reg,3,4,5,20,19,18,21,10,11,12,13,14,15,16,17
	ld	r0,X+
	sbc	r\Reg,r0
.endr
	sbc	r0,r0	// sign to r0 (0x00/0xff)
;--------- level 1: absolute values ---------
.irp	Reg,2,3,4,5,20,19,18,21,10,11,12,13,14,15,16,17
	eor	r\Reg,r0
.endr
	SUB64	r21,r18,r19,r20,r5,r4,r3,r2		r0 r0 r0 r0 r0 r0 r0 r0
	SBC64	r17,r16,r15,r14,r13,r12,r11,r10		r0 r0 r0 r0 r0 r0 r0 r0
;--------- level 1: push absolute values on stack ---------
// ABS Xm[31..16] - X[15..0] in r17,r16,r15,r14,r13,r12,r11,r10,r21,r18,r19,r20,r5,r4,r3,r2

// save upper part to stack
.irp	Reg,r17,r16,r15,r14,r13,r12,r11,r10
	push	\Reg
.endr
// Xm: ABS(L-H) = ABS(H-L)
	SUB64	r17,r16,r15,r14,r13,r12,r11,r10 r21,r18,r19,r20,r5,r4,r3,r2
	sbc	r6,r6	// sign to r6 (0x00/0xff)
	ABS64	r17,r16,r15,r14,r13,r12,r11,r10	r6
// save difference to stack
.irp	Reg,r17,r16,r15,r14,r13,r12,r11,r10
	push	\Reg
.endr

;--------- level 1: subtract b0-b15 ---------
//offset 15..0
.set Off, 15
.irp	Reg,r17,r16,r15,r14,r13,r12,r11,r10,r25,r24,r23,r22,r9,r8,r27,r26
	ldd	\Reg,Y+Off
.set Off, Off-1
.endr
	ldd	r1,Y+16
	sub	r26,r1
	ldd	r1,Y+17
	sbc	r27,r1
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

	sbc	r1,r1	// sign to r1 (0x00/0xff)
	eor	r0,r1	// final sign m[31..16] - [15..0]

;--------- level 1: absolute values ---------
.irp	Reg, r17,r16,r15,r14,r13,r12,r11,r10,r25,r24,r23,r22,r9,r8,r27,r26
	eor	\Reg,r1
.endr
	SUB64	r25,r24,r23,r22,r9,r8,r27,r26		r1 r1 r1 r1 r1 r1 r1 r1
	SBC64	r17,r16,r15,r14,r13,r12,r11,r10		r1 r1 r1 r1 r1 r1 r1 r1
;--------- level 1: push absolute values on stack ---------
// ABS Ym[31..16] - Y[15..0]

.irp	Reg, r17,r16,r15,r14,r13,r12,r11,r10
	push	\Reg
.endr
// Ym H-L
	SUB64	r17,r16,r15,r14,r13,r12,r11,r10 r25,r24,r23,r22,r9,r8,r27,r26
	sbc	r1,r1	// sign to r1 (0x00/0xff)
	ABS64	r17,r16,r15,r14,r13,r12,r11,r10	r1
// save difference to stack
.irp	Reg,r17,r16,r15,r14,r13,r12,r11,r10
	push	\Reg
.endr
// sign m[15..8] - [7..0]
	eor	r6,r1
// to one byte
	rol	r6
	rol	r0
// save signs to stack
	push	r0	// SIGN HL1
;--------- level 1: compute M ---------

;------ level 2: compute L ------

; init zero registers
	clr	r6	// (R7 is zero)
	movw	r16,r6	// ZERO
	MUL_32	r17,r16,r15,r14,r29,r28,r11,r10  r9,r8,r27,r26  r5,r4,r3,r2 r6  r13,r12

;--- level 3: compute H + (l3,l4,l5) ---
// M16[3..0]
; pushZ+0...Z+7 on stack  1st part
	push	r10
	push	r11
	push	r28
	push	r29

	movw	r12,r6	// ZERO

	MUL32_ADD_n2	/*r18,r19*/r13,r12,r17,r16,r15,r14   r25,r24,r23,r22  /*21*/r18,r19,r20  r6
// abs differences H-L
	SUB32	r5,r4,r3,r2	r21,r18,r19,r20
	sbc	r0,r0		// sign to r0 (0x00/0xff)
  
	SUB32	r9,r8,r27,r26	r25,r24,r23,r22
	sbc	r1,r1		// sign to r1 (0x00/0xff)

	ABS32	r5,r4,r3,r2	r0
	ABS32	r9,r8,r27,r26	r1
	eor	r0,r1
	bst	r0,0		// combined sign to T
//                                                                            A3  A2  A1
	MUL32_ADD_cont2	/*r18,r19*/r13,r12,r17,r16,r15,r14   r25,r24,r23,r22 r21,r18,r19   r6
;--- level 3: compute M ---
	MUL32_ncc_sw4	/*r2,r3*/r21,r20,r25,r24,r23,r22    r9,r8,r27,r26    r5,r4,r3,r2 r6
// free r27,r26,r9,r8, r4	zero in r7,r6
;--- add l4+h0 to l0 and h4 ---
	movw	r26,r6	// ZERO
	ADD64	r17,r16,r15,r14,r29,r28,r11,r10,   r18,r19,r13,r12,r17,r16,r15,r14,
	adc	r26,r26	// carry to r26

;--- process sign bit ---
	brtc	sub_M_L_M
	ADD64	r17,r16,r15,r14,r29,r28,r11,r10,   r2,r3,r21,r20,r25,r24,r23,r22,
	adc	r26,r27	// update carry
	rjmp	final_L_M

sub_M_L_M:
; subtract M
	SUB64 r17,r16,r15,r14,r29,r28,r11,r10,   r2,r3,r21,r20,r25,r24,r23,r22
	sbc	r26,r27	// update carry/borow
	sbc	r27,r27
final_L_M: 
;--- propagate carry to end ---
	ADD32	r18,r19,r13,r12	  r27,r27,r27,r26

; h8...h15 stored in 22,23,24,25,18,21,19,20

;------ level 2: compute H ------

; pushZ+0...Z+7 on stack  2nd part
	push	r10
	push	r11
	push	r28
	push	r29

; subtract stack pointer and load Y and X values
	in	r28,0x3D
	in	r29,0x3E
// used r29,r28, r19,r18,r17,r16,r15,r14,r13,r12
// free  r27,r26,r25,r24,r23,r22,20,21  ,r11,r10,r9,r8,(ZERO r7,r6)r5,r4,r3,r2

	LOAD32_FROM_Y	r5,r4,r3,r2	34	// Xm[8..11]
	LOAD32_FROM_Y	r9,r8,r27,r26	18	// Ym[8..11]

	movw	r24,r6	// ZERO
	MUL_32	r25,r24,r23,r22,r21,r20,r11,r10  r9,r8,r27,r26  r5,r4,r3,r2   r6  r29,r28

	in	r28,0x3D
	in	r29,0x3E

;--- add h0+l8 and h0+l12 ---
	ADD64	r21,r20,r11,r10,r17,r16,r15,r14  r18,r19,r13,r12,r21,r20,r11,r10
// carry is handled below .. 
	push	r14
	push	r15
	push	r16
	push	r17

	LOAD32_FROM_Y	r13,r12,r19,r18 	38	// X[12..15]
	LOAD32_FROM_Y	r17,r16,r15,r14		22	// Y[12..15]

	movw	r28,r6	// ZERO
	adc	r29,r28 // store carry in r29

;--- level 3: compute H ---
//                                                                         A2  A1  A0
	MUL32_ADD_n2   /*r12,r28*/r7,r6,r25,r24,r23,r22, r17,r16,r15,r14  r12,r19,r18  r28
// abs differences H-L
	SUB32	r5,r4,r3,r2	r13,r12,r19,r18
	sbc	r0,r0		// sign to r0 (0x00/0xff)

	SUB32	r9,r8,r27,r26	r17,r16,r15,r14
	sbc	r1,r1		// sign to r1 (0x00/0xff)

	ABS32	r5,r4,r3,r2	r0
	ABS32	r9,r8,r27,r26	r1
	eor	r0,r1
	bst	r0,0		// combined sign to T

;--- continue ---
// ZERO in RS6 (r28)
//                           RS7 RS6 ...                                         A3  A2  A1
	MUL32_ADD_cont_n3 /*r12*/r28,r7,r6,r25/*r24,r23,r22*/ r17,r16,r15,r14   r13,r12,r19
// A1 - r19 is ZERO
	clr	r18
	movw	r16,r18	// ZERO
;--- level 3: compute M ---
	MUL32_ncc_sw2  /*r19,r3,r2*/r18,r17,r16,r15,r14    r9,r8,r27,r26 r5,r4,r3,r2   r19
	// r4=ZERO
	clr	r5
	movw	r0,r4	// ZERO
;--- add l4+h0 to l0 and h4 ---
	ADD64	r25,r24,r23,r22,r21,r20,r11,r10, r12,r28,r7,r6,r25,r24,r23,r22
	adc	r1,r1	// carry to r1 (0/1)

; load carry and propagate to end
	ADD32	r25,r24,r23,r22	  r0,r0,r0,r29
	adc	r1,r0	// store carry in r1 (update)

;--- process sign bit ---
	brtc	sub_M_H_M

	ADD64	r25,r24,r23,r22,r21,r20,r11,r10, r19,r3,r2,r18,r17,r16,r15,r14
	adc	r1,r0
	rjmp	final_H_M

sub_M_H_M:
; subtract M
	SUB64	r25,r24,r23,r22,r21,r20,r11,r10, r19,r3,r2,r18,r17,r16,r15,r14
	sbc	r1,r0
	sbc	r0,r0
; r29:r28 is -1,0,or 1
final_H_M:
;--- propagate carry to end ---
	ADD32	r12,r28,r7,r6	r0 r0 r0 r1
; save to stack ..
.irp	Reg, r10,r11,r20,r21,r22,r23,r24,r25,r6,r7,r28,r12
	push	\Reg
.endr
;------ level 2
	in	r28,0x3D
	in	r29,0x3E
// load ABS Xm H - L
	LOAD64_FROM_Y	r21,r18,r19,r20,r27,r26,r3,r2	42
// load ABS Ym H - L
	LOAD64_FROM_Y	r25,r24,r23,r22,r9,r8,r7,r6	26

;------ level 2: compute M ------
; init zero registers
	movw	r16,r4	// ZERO

//	MUL_32   RS7 RS6 RS5 RS4 RS3 RS2 RS1 RS0   A3 A2 A1 A0   B3 B2 B1 B0 ZERO CC1 CC0
	MUL_32	r17,r16,r15,r14,r13,r12,r11,r10  r9,r8,r7,r6    r27,r26,r3,r2 r4  r29,r28

	movw	r28,r4	// ZERO

;--- level 3: compute H + (l3,l4,l5) ---
	MUL32_ADD_n2	/*r18,r19*/r5,r4,r17,r16,r15,r14   r25,r24,r23,r22 r18,r19,r20 r28
// abs differences H-L
	SUB32	r27,r26,r3,r2	r21,r18,r19,r20
	sbc	r0,r0		// sign to r0 (0x00/0xff)

	SUB32	r9,r8,r7,r6	r25,r24,r23,r22
	sbc	r1,r1		// sign to r1 (0x00/0xff)

	ABS32	r27,r26,r3,r2	r0
	ABS32	r9,r8,r7,r6	r1
	eor	r0,r1
	bst	r0,0		// combined sign to T
//                                                                           A3  A2  A1
	MUL32_ADD_cont2	/*r18,r19*/r5,r4,r17,r16,r15,r14   r25,r24,r23,r22  r21,r18,r19 r28
;--- level 3: compute M ---
	MUL32_ncc_sw4	/*r2,r3*/r21,r20,r25,r24,r23,r22    r9,r8,r7,r6 r27,r26,r3,r2  r28
;--- add l4+h0 to l0 and h4 ---
	movw	r6,r10
	movw	r8,r12
// free r26,r27, r29,r28 = ZERO
	ADD64	r17,r16,r15,r14,r13,r12,r11,r10,   r18,r19,r5,r4,r17,r16,r15,r14
; store carry in r28
	adc	r28,r28
;--- process sign bit ---
	brtc	sub_M_M_M

	ADD64	r17,r16,r15,r14,r13,r12,r11,r10  r2,r3,r21,r20,r25,r24,r23,r22
	adc	r28,r29
	rjmp	final_M_M
sub_M_M_M:
	SUB64 r17,r16,r15,r14,r13,r12,r11,r10 r2,r3,r21,r20,r25,r24,r23,r22
	sbc	r28,r29
	sbc	r29,r29
; r29:r28 is -1,0,or 1
final_M_M:

;--- propagate carry to end ---
	ADD32	r18,r19,r5,r4	r29,r29,r29,r28
;------ level 2: combine L,H,and M ------

	in	r28,0x3d
	in	r29,0x3e
	ldd	r20,Y+25	// search backwards for SIGN HL1
	bst	r20,1		// sign m[31..16] - [15..0] to T
	lsr	r20		// sign m[15...8] - [ 7..0] to carry
	
// used: r18,r19,r5,r4,r17,r16,r15,r14  r13,r12,r11,r10,r9,r8,r7,r6
// free: 27,26,25,24,23,22,21,  18,3,2,(ZERO in 1,0)
	LOAD64_FROM_Y	r2,r3,r20,r25,r21,r24,r22,r23	17
	movw	r26,r22	// r26,r27 is free,  save two loads from mem (below)

	brcs	add_M
sub_M:
	SUB64		r23,r22,r24,r21,r25,r20,r3,r2	r13,r12,r11,r10,r9,r8,r7,r6

	LOAD64_FROM_Y	r6,r7,r8,r9,r10,r11,r12,r13	1
	SBC64		r13,r12,r11,r10,r9,r8,r7,r6	r18,r19,r5,r4,r17,r16,r15,r14
	sbc	r0,r0
	rjmp	final_M
add_M:
	ADD64		r23,r22,r24,r21,r25,r20,r3,r2,	r13,r12,r11,r10,r9,r8,r7,r6

	LOAD64_FROM_Y	r6,r7,r8,r9,r10,r11,r12,r13	1
	ADC64		r13,r12,r11,r10,r9,r8,r7,r6,	r18,r19,r5,r4,r17,r16,r15,r14
	clr	r0
	adc	r0,r0
final_M:
	sbc	r1,r1	// extend r0 to r1:r0

	LOAD64_FROM_Y				r14,r15,r16,r17,r4,r5,r19,r18 9
	ADD64	r23,r22,r24,r21,r25,r20,r3,r2,	r18,r19,r5,r4,r17,r16,r15,r14
	ADC64	r13,r12,r11,r10,r9,r8,r7,r6	r18,r19,r5,r4,r17,r16,r15,r14

;--- propagate carry to end ---
	LOAD64_FROM_Y	r16,r19,r18,r17,r14,r15,r4,r5	1

	ADC64	r5,r4,r15,r14,r17,r18,r19,r16	r1,r1,r1,r1,r1,r1,r1,r0

;--------- level 1: combine L,H,and M ---------
//	STORE64_TO_Y	r5,r4,r15,r14,r17,r18,r19,r16		9
	STORE32_TO_Y	r17,r18,r19,r16		9
	// do not store r5,r4,r15,r14 into mem

//	LOAD64_FROM_Y	r0,r1,r16,r17,r18,r19,r26,r27  17
// r26,27 already loaded
	LOAD48_FROM_Y	r0,r1,r16,r17,r18,r19	19

// used: r0,r1,r14,r15,r16,r17,r18,r19,r26,r27 r23,r22,r24,r21,r25,r20,r3,r2  r13,r12,r11,r10,r9,r8,r7,r6
// free r28,r29 
	brtc	final_sub
	rjmp	final_addition

final_sub:
//
//in     0, 1,16,17,20,19,26,27, 2, 3,18 25 21 24 22 23
//out   28 29, 0, 1,16,17,20,19,26,27, 2, 3,18,25,21,24
; subtract M
	ldd	r28,Z+0
	sub	r28,r0
	ldd	r29,Z+1
	sbc	r29,r1
	ldd	r0,Z+2
	sbc	r0,r16
	ldd	r1,Z+3
	sbc	r1,r17
	ldd	r16,Z+4
	sbc	r16,r18
	ldd	r17,Z+5
	sbc	r17,r19
	ldd	r18,Z+6
	sbc	r18,r26
	ldd	r19,Z+7
	sbc	r19,r27
	ldd	r26,Z+8
	sbc	r26,r2
	ldd	r27,Z+9
	sbc	r27,r3
	ldd	r2,Z+10
	sbc	r2,r20
	ldd	r3,Z+11
	sbc	r3,r25
	ldd	r20,Z+12
	sbc	r20,r21
	ldd	r25,Z+13
	sbc	r25,r24
	ldd	r21,Z+14
	sbc	r21,r22
	ldd	r24,Z+15
	sbc	r24,r23
	rol	r22	// borrow to r22
; add h0+l8
// add regs  to Z+32  -> Z+16 ..
	ldd	r23,Z+16+16
	add	r28,r23
	std	Z+16,r28
.set Off, 17
.irp	Reg,29,0,1,16,17,18,19,	26,27,2,3,20,25,21,24
	ldd	r23,Z+16+Off
	adc	r\Reg,r23
	std	Z+Off,r\Reg
.set Off, Off+1
.endr
	ror	r22	// carry to r22, renew borow
	LOAD64_FROM_Z	r19,r18,r17,r16,r24,r21,r1,r0	48
	SBC64		r19,r18,r17,r16,r24,r21,r1,r0	r13,r12,r11,r10,r9,r8,r7,r6

	in	r28,0x3d
	in	r29,0x3e
	LOAD32_FROM_Y	r25,r20,r3,r2			9
	// r5,r4 r15,r14 already preloaded
	LOAD64_FROM_Z	r13,r12,r11,r10,r9,r8,r7,r6	56
	SBC64		r13,r12,r11,r10,r9,r8,r7,r6	r5,r4,r15,r14,r25,r20,r3,r2
	sbc	r23,r23 // borrow to r3
	rjmp	final

final_addition:
//
//in     0, 1,16,17,20,19,26,27, 2, 3,18 25 21 24 22 23
//out   28 29, 0, 1,16,17,20,19,26,27, 2, 3,18,25,21,24
;add M
	ldd	r28,Z+0
	add	r28,r0
	ldd	r29,Z+1
	adc	r29,r1
	ldd	r0,Z+2
	adc	r0,r16
	ldd	r1,Z+3
	adc	r1,r17
	ldd	r16,Z+4
	adc	r16,r18
	ldd	r17,Z+5
	adc	r17,r19
	ldd	r18,Z+6
	adc	r18,r26
	ldd	r19,Z+7
	adc	r19,r27
	ldd	r26,Z+8
	adc	r26,r2
	ldd	r27,Z+9
	adc	r27,r3
	ldd	r2,Z+10
	adc	r2,r20
	ldd	r3,Z+11
	adc	r3,r25
	ldd	r20,Z+12
	adc	r20,r21
	ldd	r25,Z+13
	adc	r25,r24
	ldd	r21,Z+14
	adc	r21,r22
	ldd	r24,Z+15
	adc	r24,r23
	rol	r22	// carry to r22

; now add h0+l8
// add regs  to Z+32  -> Z+16 ..
	ldd	r23,Z+16+16
	add	r28,r23
	std	Z+16,r28
.set Off, 17
.irp	Reg,29,0,1,16,17,18,19,	26,27,2,3,20,25,21,24
	ldd	r23,Z+16+Off
	adc	r\Reg,r23
	std	Z+Off,r\Reg
.set Off, Off+1
.endr
	ror	r22	// carry to r22, renew old carry
	LOAD64_FROM_Z	r19,r18,r17,r16,r24,r21,r1,r0	48
	ADC64 		r19,r18,r17,r16,r24,r21,r1,r0	r13,r12,r11,r10,r9,r8,r7,r6

	in	r28,0x3d
	in	r29,0x3e
	LOAD32_FROM_Y	r25,r20,r3,r2			9
	// r5,r4 r15,r14 already preloaded
	LOAD64_FROM_Z	r13,r12,r11,r10,r9,r8,r7,r6	56
	ADC64		r13,r12,r11,r10,r9,r8,r7,r6	r5,r4,r15,r14,r25,r20,r3,r2
	clr	r23
	adc	r23,r23	// carry to r3

final:
	sbc	r3,r3		// extend r23 to r3:r23
	rol	r22		// renew carry
.set Off, 32
.irp	Reg,0,1,21,24,16,17,18,19,	6,7,8,9,10,11,12,13
	ldd	r22,Z+Off
	adc	r\Reg,r22
	std	Z+Off,r\Reg
.set Off, Off+1
.endr

;--- propagate carry to end ---
.set Off, 48
.irp	Reg,12,13,14,15,16,17,18,19,20,21,4,5,24,25,26,27
	ldd	r\Reg,Z+Off
.set Off, Off+1
.endr
	ADC64	r19,r20,r17,r16,r15,r14,r13 r12,	r3,r3,r3,r3,r3,r3,r3,r23
	ADC64	r27,r26,r25,r24,r5,r4,r21,r18		r3,r3,r3,r3,r3,r3,r3,r3
.set Off, 48
.irp	Reg,12,13,14,15,16,17,18,19,20,21,4,5,24,25,26,27
	std	Z+Off,r\Reg
.set Off, Off+1
.endr
// release space for TMP variables
	adiw	r28,57
	LOAD_SP r0,r28,r29
	ret
