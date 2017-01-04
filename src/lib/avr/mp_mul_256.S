; Authors: Michael Hutter and Peter Schwabe
; Version: 2014-07-25
; Public domain

#ifdef OsEID
#include <avr/io.h>
#endif

//#define ORIG
//#define OsEID

/*
    This file is modified from original Public domain source. 
    Original source can be recovered from this file:
    cpp -DORIG mp_mul_256.S|grep -v "#" > orig.S


            Licence for modifications in this code 
    ------------------------------------------------------------

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



  Differences to original code from Michael Hutter and Peter Schwabe:

  --  no stack register move forward/backwards
  --  code is faster and interrupt safe (4748 ticks without call/ret)
  --  to get original code, uncomment "ORIG" and undef "OsEID"
  (OsEID can run if ORIG is defined, but "card_io_cli" is called to get
   cli to prevent original code to crash). It is recomended to not define
  "ORIG" for use in OsEID project.
*/
#include "load_sp.h"

#if defined(ORIG )&& !defined(OsEID)
  .global karatsuba256_branched
  .type karatsuba256_branched, @function

; operand b: r21:r20
; operand a: r23:r22
; operand r: r25:r24

karatsuba256_branched:

  PUSH R2
  PUSH R3
  PUSH R4
  PUSH R5
  PUSH R6
  PUSH R7
  PUSH R8
  PUSH R9
  PUSH R10
  PUSH R11
  PUSH R12
  PUSH R13
  PUSH R14
  PUSH R15
  PUSH R16
  PUSH R17
  PUSH R28
  PUSH R29

  MOVW R30, R24
  MOVW R28, R20
  MOVW R26, R22
#endif

#if defined(HAVE_RSA_MUL_256_NO_ABI) && defined(OsEID)
  .global rsa_mul_256_no_abi
  .type rsa_mul_256_no_abi, @function

rsa_mul_256_no_abi:
#if defined(ORIG)
// interrupt must be disabled, because stack is moving back to get 
// variables pushed in stack. 
  call card_io_cli
#endif
#endif

#if (defined(ORIG) && !defined (OsEID)) \
 || (defined(HAVE_RSA_MUL_256_NO_ABI) && defined (OsEID))
  ;--------- level 1: compute L ---------

  ;------ level 2: compute L ------

  ; init zero registers
  CLR R20
  CLR R21
  MOVW R16, R20

  ;--- level 3: compute L ---
  LD R2, X+
  LD R3, X+
  LD R4, X+
  LD R5, X+
  LDD R6, Y+0
  LDD R7, Y+1
  LDD R8, Y+2
  LDD R9, Y+3

  MUL R2, R8 ;a0*b2
  MOVW R12, R0
  MUL R2, R6 ;a0*b0
  MOVW R10, R0
  MUL R2, R7 ;a0*b1
  ADD R11, R0
  ADC R12, R1
  ADC R13, R21
  MUL R3, R9 ;a1*b3
  MOVW R14, R0

  MUL R2, R9 ;a0*b3
  MOVW R18, R0
  MUL R3, R6 ;a1*b0
  ADD R11, R0
  ADC R12, R1
  ADC R13, R18
  ADC R19, R21
  MUL R3, R7 ;a1*b1
  ADD R12, R0
  ADC R13, R1
  ADC R19, R21
  MUL R4, R9 ;a2*b3
  ADD R14, R19
  ADC R15, R0
  ADC R16, R1

  MUL R4, R8 ;a2*b2
  MOVW R18, R0
  MUL R4, R6 ;a2*b0
  ADD R12, R0
  ADC R13, R1
  ADC R14, R18
  ADC R19, R21
  MUL R3, R8 ;a1*b2
  ADD R13, R0
  ADC R14, R1
  ADC R19, R21
  MUL R5, R9 ;a3*b3
  ADD R15, R19
  ADC R16, R0
  ADC R17, R1

  MUL R5, R7 ;a3*b1
  MOVW R18, R0
  MUL R4, R7 ;a2*b1
  ADD R13, R0
  ADC R18, R1
  ADC R19, R21
  MUL R5, R6 ;a3*b0
  ADD R13, R0
  ADC R18, R1
  ADC R19, R21
  MUL R5, R8 ;a3*b2
  ADD R14, R18
  ADC R0, R19
  ADC R1, R21
  ADD R15, R0
  ADC R16, R1
  ADC R17, R21
  STD Z+0, R10
  STD Z+1, R11
  STD Z+2, R12
  STD Z+3, R13
  
  ;--- load a4..a7 and b4..b7 ---
  MOVW R10, R20
  LD R18, X+
  LD R19, X+
  LD R20, X+
  ; R21 is loaded later
  LDD R22, Y+4
  LDD R23, Y+5
  LDD R24, Y+6
  LDD R25, Y+7

  ;--- level 3: compute H + (l3,l4,l5) ---
  MUL R18, R22
  ADD R14, R0
  ADC R15, R1
  ADC R16, R21
  ADC R11, R21  

  MUL R18, R23
  ADD R15, R0
  ADC R16, R1
  ADC R11, R21
  MUL R19, R22
  ADD R15, R0
  ADC R16, R1
  ADC R17, R11
  ADC R10, R21

  MUL R18, R24
  ADD R16, R0 
  ADC R17, R1
  ADC R10, R21
  MUL R19, R23
  ADD R16, R0
  ADC R17, R1
  ADC R10, R21
  MUL R20, R22
  ADD R16, R0
  ADC R17, R1
  ADC R10, R21

  CLR R11
  MUL R18, R25
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21
  MUL R19, R24
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21
  MUL R20, R23
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21
  
  ;--- subtract a0-a4 ---
  SUB R2, R18
  SBC R3, R19
  SBC R4, R20
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

  ;--- absolute values ---        
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0  
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1  
  NEG R0
  NEG R1
  ADD R2, R0
  ADC R3, R21
  ADC R4, R21
  ADC R5, R21  
  ADD R6, R1
  ADC R7, R21
  ADC R8, R21
  ADC R9, R21  
  EOR R0, R1
  BST R0, 0 
  
  ;--- continue ---
  MUL R18, R22
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21

  MUL R19, R25
  CLR R19
  ADD R10, R0
  ADC R11, R1
  ADC R19, R21
  MUL R20, R24
  ADD R10, R0
  ADC R11, R1
  ADC R19, R21
  MUL R18, R23
  ADD R10, R0
  ADC R11, R1
  ADC R19, R21

  MUL R20, R25
  CLR R20
  ADD R11, R0
  ADC R19, R1
  ADC R20, R21
  MUL R18, R24
  ADD R11, R0
  ADC R19, R1
  ADC R20, R21

  MUL R18, R25
  ADD R19, R0
  ADC R20, R1

  ;--- level 3: compute M ---
  CLR R24
  CLR R25
  CLR R18

  MUL R2, R6
  MOVW R22, R0

  MUL R2, R7
  ADD R23, R0
  ADC R24, R1
  MUL R3, R6
  ADD R23, R0
  ADC R24, R1
  ADC R25, R21

  MUL R2, R8
  ADD R24, R0
  ADC R25, R1
  ADC R18, R21
  MUL R3, R7
  ADD R24, R0
  ADC R25, R1
  ADC R18, R21
  MUL R4, R6
  ADD R24, R0
  ADC R25, R1
  ADC R18, R21

  MUL R2, R9
  CLR R2
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  MUL R3, R8
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  MUL R4, R7
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  MUL R5, R6
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21

  MUL R3, R9
  CLR R3
  ADD R18, R0
  ADC R2, R1
  ADC R3, R21
  MUL R4, R8
  ADD R18, R0
  ADC R2, R1
  ADC R3, R21
  MUL R5, R7
  ADD R18, R0
  ADC R2, R1
  ADC R3, R21

  MUL R4, R9
  CLR R4
  ADD R2, R0
  ADC R3, R1
  ADC R4, R21
  MUL R5, R8
  ADD R2, R0
  ADC R3, R1
  ADC R4, R21

  MUL R5, R9
  ADD R3, R0
  ADC R4, R1

  ;--- add l4+h0 to l0 and h4 ---
  LDD R6, Z+0
  LDD R7, Z+1
  ADD R6, R14
  ADC R7, R15
  ADC R12, R16
  ADC R13, R17  
  ADC R14, R10
  ADC R15, R11
  ADC R16, R19
  ADC R17, R20
  ; store carry in R21
  ADC R21, R21
  
  ;--- process sign bit ---  
  BRTS add_M_L_L

  ; subtract M
  SUB R6, R22
  SBC R7, R23
  SBC R12, R24
  SBC R13, R25
  SBC R14, R18
  SBC R15, R2
  SBC R16, R3
  SBC R17, R4
  SBCI R21, 0
  SBC R22, R22 
  ; R22:R21 is -1,0, or 1
  RJMP final_L_L

add_M_L_L: 
  ADD R6, R22
  ADC R7, R23
  ADC R12, R24
  ADC R13, R25  
  ADC R14, R18
  ADC R15, R2
  ADC R16, R3
  ADC R17, R4
  CLR R22
  ADC R21, R22
  NOP ; constant time (DO NOT REMOVE!)

final_L_L:
  STD Z+4, R6
  STD Z+5, R7
  STD Z+6, R12
  STD Z+7, R13

  ;--- propagate carry to end ---
  ADD R10, R21
  ADC R11, R22
  ADC R19, R22
  ADC R20, R22
  
  MOVW R22, R14
  MOVW R24, R16
  MOV R18, R10
  MOV R21, R11
  ; h8...h15 stored in 22,23,24,25,18,21,19,20

  ;------ level 2: compute H ------

  ; init zero registers
  CLR R12
  CLR R13
  MOVW R14, R12
  MOVW R16, R12

  ;--- level 3: compute L ---
  LD R2, X+
  LD R3, X+
  LD R4, X+
  LD R5, X+
  LDD R6, Y+8
  LDD R7, Y+9
  LDD R8, Y+10
  LDD R9, Y+11
  
  MUL R2, R6
  MOVW R10, R0

  MUL R2, R7
  ADD R11, R0
  ADC R12, R1
  MUL R3, R6
  ADD R11, R0
  ADC R12, R1
  ADC R13, R17

  MUL R2, R8
  ADD R12, R0
  ADC R13, R1
  ADC R14, R17
  MUL R3, R7
  ADD R12, R0
  ADC R13, R1
  ADC R14, R17
  MUL R4, R6
  ADD R12, R0
  ADC R13, R1
  ADC R14, R17

  MUL R2, R9
  ADD R13, R0
  ADC R14, R1
  ADC R15, R17
  MUL R3, R8
  ADD R13, R0
  ADC R14, R1
  ADC R15, R17
  MUL R4, R7
  ADD R13, R0
  ADC R14, R1
  ADC R15, R17
  MUL R5, R6
  ADD R13, R0
  ADC R14, R1
  ADC R15, R17

  ; now add h0+l8 and h0+l12
  ADD R22, R10
  STD Z+16, R22
  ADC R23, R11
  STD Z+17, R23
  ADC R24, R12
  STD Z+18, R24
  ADC R25, R13
  STD Z+19, R25
  ADC R10, R18
  STD Z+20, R10 
  ADC R11, R21
  STD Z+21, R11
  ADC R12, R19
  ADC R13, R20
  ; store carry on stack
  SBC R0, R0
  PUSH R0
  CLR R20
  CLR R21
  
  ; continue
  MUL R3, R9
  ADD R14, R0
  ADC R15, R1
  ADC R16, R21
  MUL R4, R8
  ADD R14, R0
  ADC R15, R1
  ADC R16, R21
  MUL R5, R7
  ADD R14, R0
  ADC R15, R1
  ADC R16, R21

  MUL R4, R9
  ADD R15, R0
  ADC R16, R1
  ADC R17, R21
  MUL R5, R8
  ADD R15, R0
  ADC R16, R1
  ADC R17, R21

  MUL R5, R9
  ADD R16, R0
  ADC R17, R1

  ;--- load a4..a7 and b4..b7 ---
  MOVW R10, R20
  LD R18, X+
  LD R19, X+
  LD R20, X+
  ; R21 is loaded later
  LDD R22, Y+12
  LDD R23, Y+13
  LDD R24, Y+14
  LDD R25, Y+15

  ;--- level 3: compute H + (l3,l4,l5) ---
  MUL R18, R22
  ADD R14, R0
  ADC R15, R1
  ADC R16, R21
  ADC R11, R21  

  MUL R18, R23
  ADD R15, R0
  ADC R16, R1
  ADC R11, R21
  MUL R19, R22
  ADD R15, R0
  ADC R16, R1
  ADC R17, R11
  ADC R10, R21

  MUL R18, R24
  ADD R16, R0 
  ADC R17, R1
  ADC R10, R21
  MUL R19, R23
  ADD R16, R0
  ADC R17, R1
  ADC R10, R21
  MUL R20, R22
  ADD R16, R0
  ADC R17, R1
  ADC R10, R21

  CLR R11
  MUL R18, R25
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21
  MUL R19, R24
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21
  MUL R20, R23
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21
  
  ;--- subtract a0-a4 ---
  SUB R2, R18
  SBC R3, R19
  SBC R4, R20
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

  ;--- absolute values ---
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0  
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1  
  NEG R0
  NEG R1
  ADD R2, R0
  ADC R3, R21
  ADC R4, R21
  ADC R5, R21  
  ADD R6, R1
  ADC R7, R21
  ADC R8, R21
  ADC R9, R21  
  EOR R0, R1
  BST R0, 0 
  
  ;--- continue ---
  MUL R18, R22
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21

  MUL R19, R25
  CLR R19
  ADD R10, R0
  ADC R11, R1
  ADC R19, R21
  MUL R20, R24
  ADD R10, R0
  ADC R11, R1
  ADC R19, R21
  MUL R18, R23
  ADD R10, R0
  ADC R11, R1
  ADC R19, R21

  MUL R20, R25
  CLR R20
  ADD R11, R0
  ADC R19, R1
  ADC R20, R21
  MUL R18, R24
  ADD R11, R0
  ADC R19, R1
  ADC R20, R21

  MUL R18, R25
  ADD R19, R0
  ADC R20, R1

  ;--- level 3: compute M ---
  CLR R24
  CLR R25
  CLR R18

  MUL R2, R6
  MOVW R22, R0

  MUL R2, R7
  ADD R23, R0
  ADC R24, R1
  MUL R3, R6
  ADD R23, R0
  ADC R24, R1
  ADC R25, R21

  MUL R2, R8
  ADD R24, R0
  ADC R25, R1
  ADC R18, R21
  MUL R3, R7
  ADD R24, R0
  ADC R25, R1
  ADC R18, R21
  MUL R4, R6
  ADD R24, R0
  ADC R25, R1
  ADC R18, R21

  MUL R2, R9
  CLR R2
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  MUL R3, R8
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  MUL R4, R7
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  MUL R5, R6
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21

  MUL R3, R9
  CLR R3
  ADD R18, R0
  ADC R2, R1
  ADC R3, R21
  MUL R4, R8
  ADD R18, R0
  ADC R2, R1
  ADC R3, R21
  MUL R5, R7
  ADD R18, R0
  ADC R2, R1
  ADC R3, R21

  MUL R4, R9
  CLR R4
  ADD R2, R0
  ADC R3, R1
  ADC R4, R21
  MUL R5, R8
  ADD R2, R0
  ADC R3, R1
  ADC R4, R21

  MUL R5, R9
  ADD R3, R0
  ADC R4, R1

  ;--- add l4+h0 to l0 and h4 ---
  LDD R6, Z+20
  LDD R7, Z+21
  ADD R6, R14
  ADC R7, R15
  ADC R12, R16
  ADC R13, R17  
  ADC R14, R10
  ADC R15, R11
  ADC R16, R19
  ADC R17, R20
  ; store carry in R21
  ADC R21, R21

  ;--- propagate carry ---  
  POP R0
  NEG R0
  ADD R14, R0
  CLR R0
  ADC R15, R0
  ADC R16, R0
  ADC R17, R0
  ; store carry in R21
  ADC R21, R0

  ;--- process sign bit ---  
  BRTS add_M_H_L

  ; subtract M
  SUB R6, R22
  SBC R7, R23
  SBC R12, R24
  SBC R13, R25
  SBC R14, R18
  SBC R15, R2
  SBC R16, R3
  SBC R17, R4
  SBCI R21, 0
  SBC R22, R22
  ; R22:R21 is -1,0, or 1
  RJMP final_H_L

add_M_H_L: 
  ADD R6, R22
  ADC R7, R23
  ADC R12, R24
  ADC R13, R25
  ADC R14, R18
  ADC R15, R2
  ADC R16, R3
  ADC R17, R4
  CLR R22
  ADC R21, R22
  NOP ; constant runtime (DO NOT REMOVE!)

final_H_L:
  STD Z+20, R6
  STD Z+21, R7
  STD Z+22, R12
  STD Z+23, R13
  STD Z+24, R14
  STD Z+25, R15
  STD Z+26, R16
  STD Z+27, R17

  ;--- propagate carry to end ---
  ADD R10, R21
  ADC R11, R22
  ADC R19, R22
  ADC R20, R22
  
  STD Z+28, R10
  STD Z+29, R11
  STD Z+30, R19
  STD Z+31, R20

  ;------ level 2: subtract a0-a7 ------
  SBIW R26, 16
  LD R2, X+
  LD R3, X+
  LD R4, X+
  LD R5, X+
  LD R18, X+
  LD R19, X+
  LD R20, X+
  LD R21, X+
  LD R10, X+
  LD R11, X+
  LD R12, X+
  LD R13, X+
  LD R14, X+
  LD R15, X+
  LD R16, X+
  LD R17, X+

  ; store X and Y register on stack
  PUSH R26
  PUSH R27
  PUSH R28
  PUSH R29
  
  SUB R2, R10
  SBC R3, R11
  SBC R4, R12
  SBC R5, R13
  SBC R18, R14
  SBC R19, R15
  SBC R20, R16
  SBC R21, R17
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0
  
  ;------ level 2: subtract b0-b7 ------
  LDD R6, Y+0
  LDD R7, Y+1
  LDD R8, Y+2
  LDD R9, Y+3
  LDD R22, Y+4
  LDD R23, Y+5
  LDD R24, Y+6
  LDD R25, Y+7
  LDD R10, Y+8
  LDD R11, Y+9
  LDD R12, Y+10
  LDD R13, Y+11
  LDD R14, Y+12
  LDD R15, Y+13
  LDD R16, Y+14
  LDD R17, Y+15
  SUB R6, R10
  SBC R7, R11
  SBC R8, R12
  SBC R9, R13
  SBC R22, R14
  SBC R23, R15
  SBC R24, R16
  SBC R25, R17
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1
    
  ;------ level 2: absolute values ------
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0
  EOR R18, R0
  EOR R19, R0
  EOR R20, R0
  EOR R21, R0
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1
  EOR R22, R1
  EOR R23, R1
  EOR R24, R1
  EOR R25, R1
  NEG R0
  NEG R1
  CLR R26
  CLR R27
  ADD R2, R0
  ADC R3, R26
  ADC R4, R26
  ADC R5, R26
  ADC R18, R26
  ADC R19, R26
  ADC R20, R26
  ADC R21, R26  
  ADD R6, R1
  ADC R7, R26
  ADC R8, R26
  ADC R9, R26
  ADC R22, R26
  ADC R23, R26
  ADC R24, R26
  ADC R25, R26  
  EOR R0, R1
  PUSH R0

  ;------ level 2: compute M ------
  MOVW R16, R26

  MUL R2, R8 ;a0*b2
  MOVW R12, R0
  MUL R2, R6 ;a0*b0
  MOVW R10, R0
  MUL R2, R7 ;a0*b1
  ADD R11, R0
  ADC R12, R1
  ADC R13, R26
  MUL R3, R9 ;a1*b3
  MOVW R14, R0

  MUL R2, R9 ;a0*b3
  MOVW R28, R0
  MUL R3, R6 ;a1*b0
  ADD R11, R0
  ADC R12, R1
  ADC R13, R28
  ADC R29, R26
  MUL R3, R7 ;a1*b1
  ADD R12, R0
  ADC R13, R1
  ADC R29, R26
  MUL R4, R9 ;a2*b3
  ADD R14, R29
  ADC R15, R0
  ADC R16, R1

  MUL R4, R8 ;a2*b2
  MOVW R28, R0
  MUL R4, R6 ;a2*b0
  ADD R12, R0
  ADC R13, R1
  ADC R14, R28
  ADC R29, R26
  MUL R3, R8 ;a1*b2
  ADD R13, R0
  ADC R14, R1
  ADC R29, R26
  MUL R5, R9 ;a3*b3
  ADD R15, R29
  ADC R16, R0
  ADC R17, R1

  MUL R5, R7 ;a3*b1
  MOVW R28, R0
  MUL R4, R7 ;a2*b1
  ADD R13, R0
  ADC R28, R1
  ADC R29, R26
  MUL R5, R6 ;a3*b0
  ADD R13, R0
  ADC R28, R1
  ADC R29, R26
  MUL R5, R8 ;a3*b2
  ADD R14, R28
  ADC R0, R29
  ADC R1, R26
  ADD R15, R0
  ADC R16, R1
  ADC R17, R26

  ;--- subtract a0-a4 ---  
  SUB R2, R18
  SBC R3, R19
  SBC R4, R20
  SBC R5, R21
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0
  
  ;--- subtract b0-b4 ---  
  SUB R6, R22
  SBC R7, R23
  SBC R8, R24
  SBC R9, R25
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1

  ;--- absolute values ---  
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0  
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1  
  NEG R0
  NEG R1
  ADD R2, R0
  ADC R3, R26
  ADC R4, R26
  ADC R5, R26  
  ADD R6, R1
  ADC R7, R26
  ADC R8, R26
  ADC R9, R26  
  EOR R0, R1
  BST R0, 0 
  
  ;--- level 3: compute H + (l3,l4,l5) ---
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
  MUL R19, R25 ;a1*b3
  ADD R17, R29
  ADC R26, R0
  ADC R27, R1

  MUL R18, R25 ;a0*b3
  MOVW R28, R0
  MUL R19, R22 ;a1*b0
  ADD R15, R0
  ADC R16, R1
  ADC R17, R28
  CLR R18
  ADC R29, R18
  MUL R19, R23 ;a1*b1
  ADD R16, R0
  ADC R17, R1
  ADC R29, R18
  MUL R20, R25 ;a2*b3
  ADD R26, R29
  ADC R27, R0
  CLR R18
  ADC R18, R1

  MUL R20, R24 ;a2*b2
  MOVW R28, R0
  MUL R20, R22 ;a2*b0
  ADD R16, R0
  ADC R17, R1
  ADC R26, R28
  CLR R0
  ADC R29, R0
  MUL R19, R24 ;a1*b2
  ADD R17, R0
  ADC R26, R1
  CLR R19
  ADC R29, R19
  MUL R21, R25 ;a3*b3
  ADD R27, R29
  ADC R18, R0
  CLR R25
  ADC R25, R1
  
  MUL R21, R23 ;a3*b1
  MOVW R28,R0
  MUL R20, R23 ;a2*b1
  ADD R17, R0
  ADC R28, R1
  ADC R29, R19
  MUL R21, R22 ;a3*b0
  ADD R17, R0
  ADC R28, R1
  ADC R29, R19
  MUL R21, R24 ;a3*b2
  ADD R26, R28
  ADC R0, R29
  ADC R1, R19
  ADD R27, R0
  ADC R18, R1
  ADC R25, R19

  ;--- level 3: compute M ---
  MUL R2, R8 ;a0*b2
  MOVW R22, R0
  MUL R2, R6 ;a0*b0
  MOVW R20, R0
  MUL R2, R7 ;a0*b1
  ADD R21, R0
  ADC R22, R1
  ADC R23, R19
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
  ADC R29, R19
  MUL R3, R7 ;a1*b1
  ADD R22, R0
  ADC R23, R1
  ADC R29, R19
  MUL R4, R9 ;a2*b3
  ADD R24, R29
  ADC R2, R0
  ADC R19, R1  

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
  ADC R19, R0
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
  ADC R19, R1
  ADC R9, R3

  ;--- add l4+h0 to l0 and h4 ---
  MOVW R4, R10
  MOVW R6, R12
  ADD R10, R14
  ADC R11, R15
  ADC R12, R16
  ADC R13, R17
  ADC R14, R26
  ADC R15, R27
  ADC R16, R18
  ADC R17, R25
  ; store carry in R28
  CLR R28
  ADC R28, R3
  
  ;--- process sign bit ---
  BRTS add_M_M_L

  ; subtract M
  SUB R10, R20
  SBC R11, R21
  SBC R12, R22
  SBC R13, R23
  SBC R14, R24
  SBC R15, R2
  SBC R16, R19
  SBC R17, R9
  SBCI R28, 0
  SBC R29, R29
  ; R29:R28 is -1,0, or 1
  RJMP final_M_L

add_M_M_L: 
  ADD R10, R20
  ADC R11, R21
  ADC R12, R22
  ADC R13, R23  
  ADC R14, R24
  ADC R15, R2
  ADC R16, R19
  ADC R17, R9
  CLR R29
  ADC R28, R29
  NOP ; constant runtime (DO NOT REMOVE!)

final_M_L:
  ;--- propagate carry to end ---
  ADD R26, R28
  ADC R27, R29
  ADC R18, R29
  ADC R25, R29
  
  MOV R19, R25

  ;------ level 2: combine L, H, and M ------
  LDD R20, Z+0
  LDD R21, Z+1
  LDD R22, Z+2
  LDD R23, Z+3
  LDD R24, Z+4  
  LDD R25, Z+5
  LDD R8, Z+6 
  LDD R9, Z+7

  ;--- process sign bit ---  
  POP R0  
  TST R0
  BRNE add_M_L
  
  ; subtract M
  SUB R20, R4
  SBC R21, R5
  SBC R22, R6
  SBC R23, R7
  SBC R24, R10
  SBC R25, R11
  SBC R8, R12
  SBC R9, R13
  ; store borrow in R0
  SBC R0, R0

  LDD R2, Z+16
  LDD R3, Z+17
  ADD R20, R2
  ADC R21, R3
  STD Z+8, R20
  STD Z+9, R21
  MOVW R20, R2
  LDD R2, Z+18
  LDD R3, Z+19
  ADC R22, R2
  ADC R23, R3
  STD Z+10, R22
  STD Z+11, R23
  MOVW R22, R2
  LDD R2, Z+20
  LDD R3, Z+21
  ADC R24, R2
  ADC R25, R3
  STD Z+12, R24
  STD Z+13, R25
  MOVW R24, R2
  LDD R2, Z+22
  LDD R3, Z+23
  ADC R8, R2
  ADC R9, R3
  STD Z+14, R8
  STD Z+15, R9
  MOVW R8, R2
  ; store carry in R1
  CLR R1
  ADC R1, R1

  LSR R0
  SBC R20, R14
  SBC R21, R15
  SBC R22, R16
  SBC R23, R17
  SBC R24, R26
  SBC R25, R27
  SBC R8, R18
  SBC R9, R19
  SBC R28, R28
  SBC R29, R29
  ; R29:R28 is -1,0, or 1  
  RJMP final_L

add_M_L: 
  ADD R20, R4
  ADC R21, R5
  ADC R22, R6
  ADC R23, R7
  ADC R24, R10
  ADC R25, R11
  ADC R8, R12
  ADC R9, R13
  ; store carry in R0
  SBC R0, R0

  LDD R2, Z+16
  LDD R3, Z+17
  ADD R20, R2
  ADC R21, R3
  STD Z+8, R20
  STD Z+9, R21
  MOVW R20, R2
  LDD R2, Z+18
  LDD R3, Z+19
  ADC R22, R2
  ADC R23, R3
  STD Z+10, R22
  STD Z+11, R23
  MOVW R22, R2
  LDD R2, Z+20
  LDD R3, Z+21
  ADC R24, R2
  ADC R25, R3
  STD Z+12, R24
  STD Z+13, R25
  MOVW R24, R2
  LDD R2, Z+22
  LDD R3, Z+23
  ADC R8, R2
  ADC R9, R3
  STD Z+14, R8
  STD Z+15, R9
  MOVW R8, R2
  ; store carry in R1
  CLR R1
  ADC R1, R1

  LSR R0
  ADC R20, R14
  ADC R21, R15
  ADC R22, R16
  ADC R23, R17
  ADC R24, R26
  ADC R25, R27
  ADC R8, R18
  ADC R9, R19
  CLR R28
  CLR R29
  ADC R28, R28
  
final_L:
  LDD R4, Z+24
  LDD R5, Z+25
  LDD R6, Z+26
  LDD R7, Z+27
  LDD R10, Z+28
  LDD R11, Z+29
  LDD R12, Z+30
  LDD R13, Z+31

  LSR R1
  ADC R20, R4
  ADC R21, R5
  ADC R22, R6
  ADC R23, R7
  ADC R24, R10
  ADC R25, R11
  ADC R8,  R12
  ADC R9,  R13
  ; store carry in R29:R28
  ADC R28, R1
  ADC R29, R1

  STD Z+16, R20
  STD Z+17, R21
  STD Z+18, R22
  STD Z+19, R23
  STD Z+20, R24
  STD Z+21, R25
  STD Z+22, R8
  STD Z+23, R9

  ;--- propagate carry to end ---
  ADD R4,  R28
  ADC R5,  R29
  ADC R6,  R29
  ADC R7,  R29
  ADC R10, R29
  ADC R11, R29
  ADC R12, R29
  ADC R13, R29

  STD Z+24, R4
  STD Z+25, R5
  STD Z+26, R6
  STD Z+27, R7
  STD Z+28, R10
  STD Z+29, R11
  STD Z+30, R12
  STD Z+31, R13

  ; restore X and Y register
  POP R29
  POP R28
  POP R27
  POP R26

  ;--------- level 1: compute H ---------

  ; init zero registers
  CLR R20
  CLR R21
  MOVW R16, R20

  ;------ level 2: compute L ------
  LD R2, X+
  LD R3, X+
  LD R4, X+
  LD R5, X+
  LDD R6, Y+16
  LDD R7, Y+17
  LDD R8, Y+18
  LDD R9, Y+19
  
  MUL R2, R8 ;a0*b2
  MOVW R12, R0
  MUL R2, R6 ;a0*b0
  MOVW R10, R0
  MUL R2, R7 ;a0*b1
  ADD R11, R0
  ADC R12, R1
  ADC R13, R21
  MUL R3, R9 ;a1*b3
  MOVW R14, R0

  MUL R2, R9 ;a0*b3
  MOVW R18, R0
  MUL R3, R6 ;a1*b0
  ADD R11, R0
  ADC R12, R1
  ADC R13, R18
  ADC R19, R21
  MUL R3, R7 ;a1*b1
  ADD R12, R0
  ADC R13, R1
  ADC R19, R21
  MUL R4, R9 ;a2*b3
  ADD R14, R19
  ADC R15, R0
  ADC R16, R1

  MUL R4, R8 ;a2*b2
  MOVW R18, R0
  MUL R4, R6 ;a2*b0
  ADD R12, R0
  ADC R13, R1
  ADC R14, R18
  ADC R19, R21
  MUL R3, R8 ;a1*b2
  ADD R13, R0
  ADC R14, R1
  ADC R19, R21
  MUL R5, R9 ;a3*b3
  ADD R15, R19
  ADC R16, R0
  ADC R17, R1

  MUL R5, R7 ;a3*b1
  MOVW R18, R0
  MUL R4, R7 ;a2*b1
  ADD R13, R0
  ADC R18, R1
  ADC R19, R21
  MUL R5, R6 ;a3*b0
  ADD R13, R0
  ADC R18, R1
  ADC R19, R21
  MUL R5, R8 ;a3*b2
  ADD R14, R18
  ADC R0, R19
  ADC R1, R21
  ADD R15, R0
  ADC R16, R1
  ADC R17, R21
  STD Z+32, R10
  STD Z+33, R11
  STD Z+34, R12
  STD Z+35, R13
  
  ;--- load a4..a7 and b4..b7 ---
  MOVW R10, R20
  LD R18, X+
  LD R19, X+
  LD R20, X+
  ; R21 is loaded later
  LDD R22, Y+20
  LDD R23, Y+21
  LDD R24, Y+22
  LDD R25, Y+23

  ;------ level 2: compute H + (l3,l4,l5) ------
  MUL R18, R22
  ADD R14, R0
  ADC R15, R1
  ADC R16, R21
  ADC R11, R21

  MUL R18, R23
  ADD R15, R0
  ADC R16, R1
  ADC R11, R21
  MUL R19, R22
  ADD R15, R0
  ADC R16, R1
  ADC R17, R11
  ADC R10, R21

  MUL R18, R24
  ADD R16, R0 
  ADC R17, R1
  ADC R10, R21
  MUL R19, R23
  ADD R16, R0
  ADC R17, R1
  ADC R10, R21
  MUL R20, R22
  ADD R16, R0
  ADC R17, R1
  ADC R10, R21

  CLR R11
  MUL R18, R25
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21
  MUL R19, R24
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21
  MUL R20, R23
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21
  
  ;--- subtract a0-a4 ---
  SUB R2, R18
  SBC R3, R19
  SBC R4, R20
  ; now load a7 to R18
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

  ;--- absolute values ---        
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0  
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1  
  NEG R0
  NEG R1
  ADD R2, R0
  ADC R3, R21
  ADC R4, R21
  ADC R5, R21  
  ADD R6, R1
  ADC R7, R21
  ADC R8, R21
  ADC R9, R21  
  EOR R0, R1
  BST R0, 0 
  
  ;--- continue ---
  MUL R18, R22
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21

  MUL R19, R25
  CLR R19
  ADD R10, R0
  ADC R11, R1
  ADC R19, R21
  MUL R20, R24
  ADD R10, R0
  ADC R11, R1
  ADC R19, R21
  MUL R18, R23
  ADD R10, R0
  ADC R11, R1
  ADC R19, R21

  MUL R20, R25
  CLR R20
  ADD R11, R0
  ADC R19, R1
  ADC R20, R21
  MUL R18, R24
  ADD R11, R0
  ADC R19, R1
  ADC R20, R21

  MUL R18, R25
  ADD R19, R0
  ADC R20, R1

  ;--- level 3: compute M ---
  CLR R24
  CLR R25
  CLR R18
  
  MUL R2, R6
  MOVW R22, R0
  
  MUL R2, R7
  ADD R23, R0
  ADC R24, R1
  MUL R3, R6
  ADD R23, R0
  ADC R24, R1
  ADC R25, R21
  
  MUL R2, R8
  ADD R24, R0
  ADC R25, R1
  ADC R18, R21
  MUL R3, R7
  ADD R24, R0
  ADC R25, R1
  ADC R18, R21
  MUL R4, R6
  ADD R24, R0
  ADC R25, R1
  ADC R18, R21
  
  MUL R2, R9
  CLR R2
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  MUL R3, R8
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  MUL R4, R7
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  MUL R5, R6
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  
  MUL R3, R9
  CLR R3
  ADD R18, R0
  ADC R2, R1
  ADC R3, R21
  MUL R4, R8
  ADD R18, R0
  ADC R2, R1
  ADC R3, R21
  MUL R5, R7
  ADD R18, R0
  ADC R2, R1
  ADC R3, R21
  
  MUL R4, R9
  CLR R4
  ADD R2, R0
  ADC R3, R1
  ADC R4, R21
  MUL R5, R8
  ADD R2, R0
  ADC R3, R1
  ADC R4, R21
  
  MUL R5, R9
  ADD R3, R0
  ADC R4, R1
  
  ;--- add l4+h0 to l0 and h4 ---
  LDD R6, Z+32
  LDD R7, Z+33
  ADD R6, R14
  ADC R7, R15
  ADC R12, R16
  ADC R13, R17  
  ADC R14, R10
  ADC R15, R11
  ADC R16, R19
  ADC R17, R20
  ; store carry in R21
  ADC R21, R21
  
  ;--- process sign bit ---  
  BRTS add_M_L_H

  ; subtract M
  SUB R6, R22
  SBC R7, R23
  SBC R12, R24
  SBC R13, R25
  SBC R14, R18
  SBC R15, R2
  SBC R16, R3
  SBC R17, R4
  SBCI R21, 0
  SBC R22, R22 
  ; R22:R21 is -1,0, or 1
  RJMP final_L_H

add_M_L_H: 
  ADD R6, R22
  ADC R7, R23
  ADC R12, R24
  ADC R13, R25  
  ADC R14, R18
  ADC R15, R2
  ADC R16, R3
  ADC R17, R4
  CLR R22
  ADC R21, R22
  NOP ; constant time (DO NOT REMOVE!)

final_L_H:
  STD Z+36, R6
  STD Z+37, R7
  STD Z+38, R12
  STD Z+39, R13

  ;--- propagate carry to end ---
  ADD R10, R21
  ADC R11, R22
  ADC R19, R22
  ADC R20, R22
  
  MOVW R22, R14
  MOVW R24, R16
  MOV R18, R10
  MOV R21, R11
  ; h8...h15 stored in 22,23,24,25,18,21,19,20

  ;------ level 2: compute H ------

  ; init zero registers
  CLR R12
  CLR R13
  MOVW R14, R12
  MOVW R16, R12

  ;--- level 3: compute L ---
  LD R2, X+
  LD R3, X+
  LD R4, X+
  LD R5, X+
  LDD R6, Y+24
  LDD R7, Y+25
  LDD R8, Y+26
  LDD R9, Y+27
  
  MUL R2, R6
  MOVW R10, R0

  MUL R2, R7
  ADD R11, R0
  ADC R12, R1
  MUL R3, R6
  ADD R11, R0
  ADC R12, R1
  ADC R13, R17
  
  MUL R2, R8
  ADD R12, R0
  ADC R13, R1
  ADC R14, R17
  MUL R3, R7
  ADD R12, R0
  ADC R13, R1
  ADC R14, R17
  MUL R4, R6
  ADD R12, R0
  ADC R13, R1
  ADC R14, R17
  
  MUL R2, R9
  ADD R13, R0
  ADC R14, R1
  ADC R15, R17
  MUL R3, R8
  ADD R13, R0
  ADC R14, R1
  ADC R15, R17
  MUL R4, R7
  ADD R13, R0
  ADC R14, R1
  ADC R15, R17
  MUL R5, R6
  ADD R13, R0
  ADC R14, R1
  ADC R15, R17

  ; now add h0+l8 and h0+l12
  ADD R22, R10
  STD Z+48, R22
  ADC R23, R11
  STD Z+49, R23
  ADC R24, R12
  STD Z+50, R24
  ADC R25, R13
  STD Z+51, R25
  ADC R10, R18
  STD Z+52, R10 
  ADC R11, R21
  STD Z+53, R11
  ADC R12, R19
  ADC R13, R20
  ; store carry on stack
  SBC R0, R0
  PUSH R0
  CLR R20
  CLR R21
  
  ; continue
  MUL R3, R9
  ADD R14, R0
  ADC R15, R1
  ADC R16, R21
  MUL R4, R8
  ADD R14, R0
  ADC R15, R1
  ADC R16, R21
  MUL R5, R7
  ADD R14, R0
  ADC R15, R1
  ADC R16, R21

  MUL R4, R9
  ADD R15, R0
  ADC R16, R1
  ADC R17, R21
  MUL R5, R8
  ADD R15, R0
  ADC R16, R1
  ADC R17, R21

  MUL R5, R9
  ADD R16, R0
  ADC R17, R1

  ;--- load a4..a7 and b4..b7 ---
  MOVW R10, R20
  LD R18, X+
  LD R19, X+
  LD R20, X+
  ; R21 is loaded later
  LDD R22, Y+28
  LDD R23, Y+29
  LDD R24, Y+30
  LDD R25, Y+31

  ;------ level 2: compute H + (l3,l4,l5) ------
  MUL R18, R22
  ADD R14, R0
  ADC R15, R1
  ADC R16, R21
  ADC R11, R21  

  MUL R18, R23
  ADD R15, R0
  ADC R16, R1
  ADC R11, R21
  MUL R19, R22
  ADD R15, R0
  ADC R16, R1
  ADC R17, R11
  ADC R10, R21

  MUL R18, R24
  ADD R16, R0 
  ADC R17, R1
  ADC R10, R21
  MUL R19, R23
  ADD R16, R0
  ADC R17, R1
  ADC R10, R21
  MUL R20, R22
  ADD R16, R0
  ADC R17, R1
  ADC R10, R21

  CLR R11
  MUL R18, R25
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21
  MUL R19, R24
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21
  MUL R20, R23
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21
  
  ;--- subtract a0-a4 ---
  SUB R2, R18
  SBC R3, R19
  SBC R4, R20
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

  ;--- absolute values ---
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0  
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1  
  NEG R0
  NEG R1
  ADD R2, R0
  ADC R3, R21
  ADC R4, R21
  ADC R5, R21  
  ADD R6, R1
  ADC R7, R21
  ADC R8, R21
  ADC R9, R21  
  EOR R0, R1
  BST R0, 0 
  
  ;--- continue ---
  MUL R18, R22
  ADD R17, R0
  ADC R10, R1
  ADC R11, R21

  MUL R19, R25
  CLR R19
  ADD R10, R0
  ADC R11, R1
  ADC R19, R21
  MUL R20, R24
  ADD R10, R0
  ADC R11, R1
  ADC R19, R21
  MUL R18, R23
  ADD R10, R0
  ADC R11, R1
  ADC R19, R21

  MUL R20, R25
  CLR R20
  ADD R11, R0
  ADC R19, R1
  ADC R20, R21
  MUL R18, R24
  ADD R11, R0
  ADC R19, R1
  ADC R20, R21

  MUL R18, R25
  ADD R19, R0
  ADC R20, R1

  ;--- level 3: compute M ---
  CLR R24
  CLR R25
  CLR R18

  MUL R2, R6
  MOVW R22, R0

  MUL R2, R7
  ADD R23, R0
  ADC R24, R1
  MUL R3, R6
  ADD R23, R0
  ADC R24, R1
  ADC R25, R21

  MUL R2, R8
  ADD R24, R0
  ADC R25, R1
  ADC R18, R21
  MUL R3, R7
  ADD R24, R0
  ADC R25, R1
  ADC R18, R21
  MUL R4, R6
  ADD R24, R0
  ADC R25, R1
  ADC R18, R21

  MUL R2, R9
  CLR R2
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  MUL R3, R8
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  MUL R4, R7
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21
  MUL R5, R6
  ADD R25, R0
  ADC R18, R1
  ADC R2, R21

  MUL R3, R9
  CLR R3
  ADD R18, R0
  ADC R2, R1
  ADC R3, R21
  MUL R4, R8
  ADD R18, R0
  ADC R2, R1
  ADC R3, R21
  MUL R5, R7
  ADD R18, R0
  ADC R2, R1
  ADC R3, R21

  MUL R4, R9
  CLR R4
  ADD R2, R0
  ADC R3, R1
  ADC R4, R21
  MUL R5, R8
  ADD R2, R0
  ADC R3, R1
  ADC R4, R21

  MUL R5, R9
  ADD R3, R0
  ADC R4, R1

  ;--- add l4+h0 to l0 and h4 ---
  LDD R6, Z+52
  LDD R7, Z+53
  ADD R6, R14
  ADC R7, R15
  ADC R12, R16
  ADC R13, R17
  ADC R14, R10
  ADC R15, R11
  ADC R16, R19
  ADC R17, R20
  ; store carry in R21
  ADC R21, R21

  ;--- propagate carry ---  
  POP R0
  NEG R0
  ADD R14, R0
  CLR R0
  ADC R15, R0
  ADC R16, R0
  ADC R17, R0
  ; store carry in R21
  ADC R21, R0

  ;--- process sign bit ---  
  BRTS add_M_H_H

  ; subtract M
  SUB R6, R22
  SBC R7, R23
  SBC R12, R24
  SBC R13, R25
  SBC R14, R18
  SBC R15, R2
  SBC R16, R3
  SBC R17, R4
  SBCI R21, 0
  SBC R22, R22
  ; R22:R21 is -1,0, or 1
  RJMP final_H_H

add_M_H_H: 
  ADD R6, R22
  ADC R7, R23
  ADC R12, R24
  ADC R13, R25
  ADC R14, R18
  ADC R15, R2
  ADC R16, R3
  ADC R17, R4
  CLR R22
  ADC R21, R22
  NOP ; constant runtime (DO NOT REMOVE!)

final_H_H:
  STD Z+52, R6
  STD Z+53, R7
  STD Z+54, R12
  STD Z+55, R13
  STD Z+56, R14
  STD Z+57, R15
  STD Z+58, R16
  STD Z+59, R17

  ;--- propagate carry to end ---
  ADD R10, R21
  ADC R11, R22
  ADC R19, R22
  ADC R20, R22
  
  STD Z+60, R10
  STD Z+61, R11
  STD Z+62, R19
  STD Z+63, R20

  ;------ level 1: subtract a0-a7 ------
  SBIW R26, 16
  LD R2, X+
  LD R3, X+
  LD R4, X+
  LD R5, X+
  LD R18, X+
  LD R19, X+
  LD R20, X+
  LD R21, X+
  LD R10, X+
  LD R11, X+
  LD R12, X+
  LD R13, X+
  LD R14, X+
  LD R15, X+
  LD R16, X+
  LD R17, X+

  ; store X and Y register on stack
  PUSH R26
  PUSH R27
  PUSH R28
  PUSH R29
  
  SUB R2, R10
  SBC R3, R11
  SBC R4, R12
  SBC R5, R13
  SBC R18, R14
  SBC R19, R15
  SBC R20, R16
  SBC R21, R17
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0
  
  ;------ level 1: subtract b0-b7 ------
  LDD R6, Y+16
  LDD R7, Y+17
  LDD R8, Y+18
  LDD R9, Y+19
  LDD R22, Y+20
  LDD R23, Y+21
  LDD R24, Y+22
  LDD R25, Y+23
  LDD R10, Y+24
  LDD R11, Y+25
  LDD R12, Y+26
  LDD R13, Y+27
  LDD R14, Y+28
  LDD R15, Y+29
  LDD R16, Y+30
  LDD R17, Y+31
  SUB R6, R10
  SBC R7, R11
  SBC R8, R12
  SBC R9, R13
  SBC R22, R14
  SBC R23, R15
  SBC R24, R16
  SBC R25, R17
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1
    
  ;------ level 2: absolute values ------
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0
  EOR R18, R0
  EOR R19, R0
  EOR R20, R0
  EOR R21, R0
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1
  EOR R22, R1
  EOR R23, R1
  EOR R24, R1
  EOR R25, R1
  NEG R0
  NEG R1
  CLR R26
  CLR R27
  ADD R2, R0
  ADC R3, R26
  ADC R4, R26
  ADC R5, R26
  ADC R18, R26
  ADC R19, R26
  ADC R20, R26
  ADC R21, R26  
  ADD R6, R1
  ADC R7, R26
  ADC R8, R26
  ADC R9, R26
  ADC R22, R26
  ADC R23, R26
  ADC R24, R26
  ADC R25, R26  
  EOR R0, R1
  PUSH R0

  ;------ level 2: compute M ------
  MOVW R16, R26

  MUL R2, R8 ;a0*b2
  MOVW R12, R0
  MUL R2, R6 ;a0*b0
  MOVW R10, R0
  MUL R2, R7 ;a0*b1
  ADD R11, R0
  ADC R12, R1
  ADC R13, R26
  MUL R3, R9 ;a1*b3
  MOVW R14, R0

  MUL R2, R9 ;a0*b3
  MOVW R28, R0
  MUL R3, R6 ;a1*b0
  ADD R11, R0
  ADC R12, R1
  ADC R13, R28
  ADC R29, R26
  MUL R3, R7 ;a1*b1
  ADD R12, R0
  ADC R13, R1
  ADC R29, R26
  MUL R4, R9 ;a2*b3
  ADD R14, R29
  ADC R15, R0
  ADC R16, R1

  MUL R4, R8 ;a2*b2
  MOVW R28, R0
  MUL R4, R6 ;a2*b0
  ADD R12, R0
  ADC R13, R1
  ADC R14, R28
  ADC R29, R26
  MUL R3, R8 ;a1*b2
  ADD R13, R0
  ADC R14, R1
  ADC R29, R26
  MUL R5, R9 ;a3*b3
  ADD R15, R29
  ADC R16, R0
  ADC R17, R1

  MUL R5, R7 ;a3*b1
  MOVW R28, R0
  MUL R4, R7 ;a2*b1
  ADD R13, R0
  ADC R28, R1
  ADC R29, R26
  MUL R5, R6 ;a3*b0
  ADD R13, R0
  ADC R28, R1
  ADC R29, R26
  MUL R5, R8 ;a3*b2
  ADD R14, R28
  ADC R0, R29
  ADC R1, R26
  ADD R15, R0
  ADC R16, R1
  ADC R17, R26

  ;--- subtract a0-a4 ---  
  SUB R2, R18
  SBC R3, R19
  SBC R4, R20
  SBC R5, R21
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0
  
  ;--- subtract b0-b4 ---  
  SUB R6, R22
  SBC R7, R23
  SBC R8, R24
  SBC R9, R25
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1

  ;--- absolute values ---  
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0  
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1  
  NEG R0
  NEG R1
  ADD R2, R0
  ADC R3, R26
  ADC R4, R26
  ADC R5, R26  
  ADD R6, R1
  ADC R7, R26
  ADC R8, R26
  ADC R9, R26  
  EOR R0, R1
  BST R0, 0 
  
  ;--- level 3: compute H + (l3,l4,l5) ---
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
  MUL R19, R25 ;a1*b3
  ADD R17, R29
  ADC R26, R0
  ADC R27, R1

  MUL R18, R25 ;a0*b3
  MOVW R28, R0
  MUL R19, R22 ;a1*b0
  ADD R15, R0
  ADC R16, R1
  ADC R17, R28
  CLR R18
  ADC R29, R18
  MUL R19, R23 ;a1*b1
  ADD R16, R0
  ADC R17, R1
  ADC R29, R18
  MUL R20, R25 ;a2*b3
  ADD R26, R29
  ADC R27, R0
  CLR R18
  ADC R18, R1

  MUL R20, R24 ;a2*b2
  MOVW R28, R0
  MUL R20, R22 ;a2*b0
  ADD R16, R0
  ADC R17, R1
  ADC R26, R28
  CLR R0
  ADC R29, R0
  MUL R19, R24 ;a1*b2
  ADD R17, R0
  ADC R26, R1
  CLR R19
  ADC R29, R19
  MUL R21, R25 ;a3*b3
  ADD R27, R29
  ADC R18, R0
  CLR R25
  ADC R25, R1
  
  MUL R21, R23 ;a3*b1
  MOVW R28,R0
  MUL R20, R23 ;a2*b1
  ADD R17, R0
  ADC R28, R1
  ADC R29, R19
  MUL R21, R22 ;a3*b0
  ADD R17, R0
  ADC R28, R1
  ADC R29, R19
  MUL R21, R24 ;a3*b2
  ADD R26, R28
  ADC R0, R29
  ADC R1, R19
  ADD R27, R0
  ADC R18, R1
  ADC R25, R19

  ;--- level 3: compute M ---
  MUL R2, R8 ;a0*b2
  MOVW R22, R0
  MUL R2, R6 ;a0*b0
  MOVW R20, R0
  MUL R2, R7 ;a0*b1
  ADD R21, R0
  ADC R22, R1
  ADC R23, R19
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
  ADC R29, R19
  MUL R3, R7 ;a1*b1
  ADD R22, R0
  ADC R23, R1
  ADC R29, R19
  MUL R4, R9 ;a2*b3
  ADD R24, R29
  ADC R2, R0
  ADC R19, R1  

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
  ADC R19, R0
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
  ADC R19, R1
  ADC R9, R3

  ;--- add l4+h0 to l0 and h4 ---
  MOVW R4, R10
  MOVW R6, R12
  ADD R10, R14
  ADC R11, R15
  ADC R12, R16
  ADC R13, R17
  ADC R14, R26
  ADC R15, R27
  ADC R16, R18
  ADC R17, R25
  ; store carry in R28
  CLR R28
  ADC R28, R3
  
  ;--- process sign bit ---
  BRTS add_M_M_H

  ; subtract M
  SUB R10, R20
  SBC R11, R21
  SBC R12, R22
  SBC R13, R23
  SBC R14, R24
  SBC R15, R2
  SBC R16, R19
  SBC R17, R9
  SBCI R28, 0
  SBC R29, R29
  ; R29:R28 is -1,0, or 1
  RJMP final_M_H

add_M_M_H: 
  ADD R10, R20
  ADC R11, R21
  ADC R12, R22
  ADC R13, R23  
  ADC R14, R24
  ADC R15, R2
  ADC R16, R19
  ADC R17, R9
  CLR R29
  ADC R28, R29
  NOP ; constant runtime (DO NOT REMOVE!)
  
final_M_H:
  ;--- propagate carry to end ---
  ADD R26, R28
  ADC R27, R29
  ADC R18, R29
  ADC R25, R29
  
  MOV R19, R25

  ;------ level 2: combine L, H, and M ------
  LDD R20, Z+32
  LDD R21, Z+33
  LDD R22, Z+34
  LDD R23, Z+35
  LDD R24, Z+36  
  LDD R25, Z+37
  LDD R8, Z+38
  LDD R9, Z+39

  ;--- process sign bit ---  
  POP R0  

  LDD R1, Z+16
  ADD R1, R20
  STD Z+32, R1
  LDD R1, Z+17
  ADC R1, R21
  STD Z+33, R1
  LDD R1, Z+18
  ADC R1, R22
  STD Z+34, R1
  LDD R1, Z+19
  ADC R1, R23
  STD Z+35, R1
  LDD R1, Z+20
  ADC R1, R24
  STD Z+36, R1
  LDD R1, Z+21
  ADC R1, R25
  STD Z+37, R1
  LDD R1, Z+22
  ADC R1, R8
  STD Z+38, R1
  LDD R1, Z+23
  ADC R1, R9
  STD Z+39, R1
  ; store carry in R28
  CLR R28
  ADC R28, R28

  ;--- process sign bit ---  
  TST R0
  BRNE add_M_H
  
  ; subtract M
  SUB R20, R4
  SBC R21, R5
  SBC R22, R6
  SBC R23, R7
  SBC R24, R10
  SBC R25, R11
  SBC R8,  R12
  SBC R9,  R13

  LDD R4,  Z+56
  LDD R5,  Z+57
  LDD R6,  Z+58
  LDD R7,  Z+59
  LDD R10, Z+60  
  LDD R11, Z+61
  LDD R12, Z+62 
  LDD R13, Z+63

  SBC R4,  R14
  SBC R5,  R15
  SBC R6,  R16
  SBC R7,  R17
  SBC R10, R26
  SBC R11, R27
  SBC R12, R18
  SBC R13, R19
  SBC R0, R0
  SBC R1, R1
  ; R1:R0 is -1,0, or 1  
  RJMP final_H

add_M_H: 
  ADD R20, R4
  ADC R21, R5
  ADC R22, R6
  ADC R23, R7
  ADC R24, R10
  ADC R25, R11
  ADC R8,  R12
  ADC R9,  R13

  LDD R4,  Z+56
  LDD R5,  Z+57
  LDD R6,  Z+58
  LDD R7,  Z+59
  LDD R10, Z+60 
  LDD R11, Z+61
  LDD R12, Z+62 
  LDD R13, Z+63

  ADC R4,  R14
  ADC R5,  R15
  ADC R6,  R16
  ADC R7,  R17
  ADC R10, R26
  ADC R11, R27
  ADC R12, R18
  ADC R13, R19
  ; store borrow in R1:R0
  CLR R0
  CLR R1
  ADC R0, R0
  
final_H:
  LDD R14, Z+48
  LDD R15, Z+49
  LDD R16, Z+50
  LDD R17, Z+51
  LDD R26, Z+52 
  LDD R27, Z+53
  LDD R18, Z+54
  LDD R19, Z+55
  ADD R20, R14
  ADC R21, R15
  ADC R22, R16
  ADC R23, R17
  ADC R24, R26
  ADC R25, R27
  ADC R8,  R18
  ADC R9,  R19
  ADC R4,  R14
  ADC R5,  R15
  ADC R6,  R16
  ADC R7,  R17
  ADC R10, R26
  ADC R11, R27
  ADC R12, R18
  ADC R13, R19
  ; add carry to carry catcher
  CLR R14
  ADC R0, R14
  ADC R1, R14

  ;--- add higher part of the first 128 bits ---
  LSR R28
  LDD R28, Z+24
  ADC R20, R28
  LDD R28, Z+25
  ADC R21, R28
  LDD R28, Z+26
  ADC R22, R28
  LDD R28, Z+27
  ADC R23, R28
  LDD R28, Z+28
  ADC R24, R28
  LDD R28, Z+29
  ADC R25, R28
  LDD R28, Z+30
  ADC R8, R28
  LDD R28, Z+31
  ADC R9, R28

  ADC R4, R14
  ADC R5, R14
  ADC R6, R14
  ADC R7, R14
  ADC R10, R14
  ADC R11, R14
  ADC R12, R14
  ADC R13, R14
  ; add carry to carry catcher
  ADC R0, R14
  ADC R1, R14
    
  STD Z+40, R20
  STD Z+41, R21
  STD Z+42, R22
  STD Z+43, R23
  STD Z+44, R24
  STD Z+45, R25
  STD Z+46, R8
  STD Z+47, R9
  STD Z+48, R4
  STD Z+49, R5
  STD Z+50, R6
  STD Z+51, R7
  STD Z+52, R10
  STD Z+53, R11
  STD Z+54, R12
  STD Z+55, R13

  ;--- propagate carry to end ---
  LDD R4, Z+56
  LDD R5, Z+57
  LDD R6, Z+58
  LDD R7, Z+59
  LDD R10, Z+60  
  LDD R11, Z+61
  LDD R12, Z+62 
  LDD R13, Z+63

  ADD R4, R0
  ADC R5, R1
  ADC R6, R1
  ADC R7, R1
  ADC R10, R1
  ADC R11, R1
  ADC R12, R1
  ADC R13, R1

  STD Z+56, R4
  STD Z+57, R5
  STD Z+58, R6
  STD Z+59, R7
  STD Z+60, R10
  STD Z+61, R11
  STD Z+62, R12
  STD Z+63, R13

  ; restore X and Y register
  POP R29
  POP R28
  POP R27
  POP R26

  ;--------- level 1: subtract a0-a15 ---------
  SBIW R26, 32
  LD R2, X+
  LD R3, X+
  LD R4, X+
  LD R5, X+
  LD R18, X+
  LD R19, X+
  LD R20, X+
  LD R21, X+
  LD R10, X+
  LD R11, X+
  LD R12, X+
  LD R13, X+
  LD R14, X+
  LD R15, X+
  LD R16, X+
  LD R17, X+

  LD R0, X+
  SUB R2, R0
  LD R0, X+
  SBC R3, R0
  LD R0, X+
  SBC R4, R0
  LD R0, X+
  SBC R5, R0
  LD R0, X+
  SBC R18, R0
  LD R0, X+
  SBC R19, R0
  LD R0, X+
  SBC R20, R0
  LD R0, X+
  SBC R21, R0  
  LD R0, X+
  SBC R10, R0
  LD R0, X+
  SBC R11, R0
  LD R0, X+
  SBC R12, R0
  LD R0, X+
  SBC R13, R0
  LD R0, X+
  SBC R14, R0
  LD R0, X+
  SBC R15, R0
  LD R0, X+
  SBC R16, R0
  LD R0, X
  SBC R17, R0
  ; store borrow in R0
  SBC R0, R0

  ;--------- level 1: absolute values ---------
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0
  EOR R18, R0
  EOR R19, R0
  EOR R20, R0
  EOR R21, R0
  EOR R10, R0
  EOR R11, R0
  EOR R12, R0
  EOR R13, R0
  EOR R14, R0
  EOR R15, R0
  EOR R16, R0
  EOR R17, R0
  NEG R0
  CLR R26
  CLR R27
  ADD R2, R0
  ADC R3, R26
  ADC R4, R26
  ADC R5, R26
  ADC R18, R26
  ADC R19, R26
  ADC R20, R26
  ADC R21, R26
  ADC R10, R26
  ADC R11, R26
  ADC R12, R26
  ADC R13, R26
  ADC R14, R26
  ADC R15, R26
  ADC R16, R26
  ADC R17, R26
 
  ;--------- level 1: push absolute values on stack ---------
  PUSH R17
  PUSH R16
  PUSH R15
  PUSH R14
  PUSH R13
  PUSH R12
  PUSH R11
  PUSH R10
  PUSH R21
  PUSH R20
  PUSH R19
  PUSH R18
  PUSH R5
  PUSH R4
  PUSH R3
  PUSH R2
  
  ;--------- level 1: subtract b0-b15 ---------
  LDD R6, Y+0
  LDD R7, Y+1
  LDD R8, Y+2
  LDD R9, Y+3
  LDD R22, Y+4
  LDD R23, Y+5
  LDD R24, Y+6
  LDD R25, Y+7
  LDD R10, Y+8
  LDD R11, Y+9 
  LDD R12, Y+10
  LDD R13, Y+11
  LDD R14, Y+12
  LDD R15, Y+13
  LDD R16, Y+14
  LDD R17, Y+15
  
  LDD R1, Y+16
  SUB R6, R1
  LDD R1, Y+17
  SBC R7, R1
  LDD R1, Y+18
  SBC R8, R1
  LDD R1, Y+19
  SBC R9, R1
  LDD R1, Y+20
  SBC R22, R1
  LDD R1, Y+21
  SBC R23, R1
  LDD R1, Y+22
  SBC R24, R1
  LDD R1, Y+23
  SBC R25, R1
  LDD R1, Y+24
  SBC R10, R1
  LDD R1, Y+25
  SBC R11, R1
  LDD R1, Y+26
  SBC R12, R1
  LDD R1, Y+27
  SBC R13, R1
  LDD R1, Y+28
  SBC R14, R1
  LDD R1, Y+29
  SBC R15, R1
  LDD R1, Y+30
  SBC R16, R1
  LDD R1, Y+31
  SBC R17, R1
  ; store borrow in R1
  SBC R1, R1

  ;--------- level 1: absolute values ---------
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1
  EOR R22, R1
  EOR R23, R1
  EOR R24, R1
  EOR R25, R1
  EOR R10, R1
  EOR R11, R1
  EOR R12, R1
  EOR R13, R1
  EOR R14, R1
  EOR R15, R1
  EOR R16, R1
  EOR R17, R1
  NEG R1
  ADD R6, R1
  ADC R7, R26
  ADC R8, R26
  ADC R9, R26
  ADC R22, R26
  ADC R23, R26
  ADC R24, R26
  ADC R25, R26
  ADC R10, R26
  ADC R11, R26
  ADC R12, R26
  ADC R13, R26
  ADC R14, R26
  ADC R15, R26
  ADC R16, R26
  ADC R17, R26

  ;--------- level 1: push absolute values on stack ---------
  PUSH R17
  PUSH R16
  PUSH R15
  PUSH R14
  PUSH R13
  PUSH R12
  PUSH R11
  PUSH R10
  PUSH R25
  PUSH R24
  PUSH R23
  PUSH R22
  PUSH R9
  PUSH R8
  PUSH R7
  PUSH R6
  EOR R0, R1
  PUSH R0

  ;--------- level 1: compute M ---------

  ;------ level 2: compute L ------

  ; init zero registers
  MOVW R12, R26
  MOVW R14, R26
  MOVW R16, R26

  ;--- level 3: compute L ---
  MUL R2, R6
  MOVW R10, R0

  MUL R2, R7
  ADD R11, R0
  ADC R12, R1
  MUL R3, R6
  ADD R11, R0
  ADC R12, R1
  ADC R13, R26

  MUL R2, R8
  ADD R12, R0
  ADC R13, R1
  ADC R14, R26
  MUL R3, R7
  ADD R12, R0
  ADC R13, R1
  ADC R14, R26
  MUL R4, R6
  ADD R12, R0
  ADC R13, R1
  ADC R14, R26

  MUL R2, R9
  ADD R13, R0
  ADC R14, R1
  ADC R15, R26
  MUL R3, R8
  ADD R13, R0
  ADC R14, R1
  ADC R15, R26
  MUL R4, R7
  ADD R13, R0
  ADC R14, R1
  ADC R15, R26
  MUL R5, R6
  ADD R13, R0
  ADC R14, R1
  ADC R15, R26

  MUL R3, R9
  ADD R14, R0
  ADC R15, R1
  ADC R16, R26
  MUL R4, R8
  ADD R14, R0
  ADC R15, R1
  ADC R16, R26
  MUL R5, R7
  ADD R14, R0
  ADC R15, R1
  ADC R16, R26

  MUL R4, R9
  ADD R15, R0
  ADC R16, R1
  ADC R17, R26
  MUL R5, R8
  ADD R15, R0
  ADC R16, R1
  ADC R17, R26

  MUL R5, R9
  ADD R16, R0
  ADC R17, R1

  ;--- level 3: compute H + (l3,l4,l5) ---
  PUSH R11
  PUSH R10

  MOVW R10, R26

  MUL R18, R22
  ADD R14, R0
  ADC R15, R1
  ADC R16, R26
  ADC R11, R26

  MUL R18, R23
  ADD R15, R0
  ADC R16, R1
  ADC R11, R26
  MUL R19, R22
  ADD R15, R0
  ADC R16, R1
  ADC R17, R11
  ADC R10, R26

  MUL R18, R24
  ADD R16, R0 
  ADC R17, R1
  ADC R10, R26
  MUL R19, R23
  ADD R16, R0
  ADC R17, R1
  ADC R10, R26
  MUL R20, R22
  ADD R16, R0
  ADC R17, R1
  ADC R10, R26

  CLR R11
  MUL R18, R25
  ADD R17, R0
  ADC R10, R1
  ADC R11, R26
  MUL R19, R24
  ADD R17, R0
  ADC R10, R1
  ADC R11, R26
  MUL R20, R23
  ADD R17, R0
  ADC R10, R1
  ADC R11, R26
  
  ;--- subtract a0-a4 ---
  
  SUB R2, R18
  SBC R3, R19
  SBC R4, R20
  SBC R5, R21
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0
  
  ;--- subtract b0-b4 ---
  SUB R6, R22
  SBC R7, R23
  SBC R8, R24
  SBC R9, R25
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1

  ;--- absolute values ---               
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0  
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1  
  NEG R0
  NEG R1
  ADD R2, R0
  ADC R3, R26
  ADC R4, R26
  ADC R5, R26  
  ADD R6, R1
  ADC R7, R26
  ADC R8, R26
  ADC R9, R26  
  EOR R0, R1
  BST R0, 0 
  
  ;--- continue ---
  MUL R21, R22
  ADD R17, R0
  ADC R10, R1
  ADC R11, R26

  MUL R19, R25
  CLR R19
  ADD R10, R0
  ADC R11, R1
  ADC R19, R26
  MUL R20, R24
  ADD R10, R0
  ADC R11, R1
  ADC R19, R26
  MUL R21, R23
  ADD R10, R0
  ADC R11, R1
  ADC R19, R26

  MUL R20, R25
  CLR R20
  ADD R11, R0
  ADC R19, R1
  ADC R20, R26
  MUL R21, R24
  ADD R11, R0
  ADC R19, R1
  ADC R20, R26

  MUL R21, R25
  ADD R19, R0
  ADC R20, R1

  ;--- level 3: compute M ---
  MOVW R24, R26
  CLR R18
  
  MUL R2, R6
  MOVW R22, R0

  MUL R2, R7
  ADD R23, R0
  ADC R24, R1
  MUL R3, R6
  ADD R23, R0
  ADC R24, R1
  ADC R25, R26

  MUL R2, R8
  ADD R24, R0
  ADC R25, R1
  ADC R18, R26
  MUL R3, R7
  ADD R24, R0
  ADC R25, R1
  ADC R18, R26
  MUL R4, R6
  ADD R24, R0
  ADC R25, R1
  ADC R18, R26

  MUL R2, R9
  CLR R2
  ADD R25, R0
  ADC R18, R1
  ADC R2, R26
  MUL R3, R8
  ADD R25, R0
  ADC R18, R1
  ADC R2, R26
  MUL R4, R7
  ADD R25, R0
  ADC R18, R1
  ADC R2, R26
  MUL R5, R6
  ADD R25, R0
  ADC R18, R1
  ADC R2, R26

  MUL R3, R9
  CLR R3
  ADD R18, R0
  ADC R2, R1
  ADC R3, R26
  MUL R4, R8
  ADD R18, R0
  ADC R2, R1
  ADC R3, R26
  MUL R5, R7
  ADD R18, R0
  ADC R2, R1
  ADC R3, R26

  MUL R4, R9
  CLR R4
  ADD R2, R0
  ADC R3, R1
  ADC R4, R26
  MUL R5, R8
  ADD R2, R0
  ADC R3, R1
  ADC R4, R26

  MUL R5, R9
  ADD R3, R0
  ADC R4, R1

  ;--- add l4+h0 to l0 and h4 ---
  POP R6
  POP R7
  MOVW R8, R6
  MOVW R28, R12
  ADD R6, R14
  ADC R7, R15
  ADC R12, R16
  ADC R13, R17  
  ADC R14, R10
  ADC R15, R11
  ADC R16, R19
  ADC R17, R20
  ; store carry in R26
  ADC R26, R26
  
  ;--- process sign bit ---  
  BRTS add_M_L_M

  ; subtract M
  SUB R6, R22
  SBC R7, R23
  SBC R12, R24
  SBC R13, R25
  SBC R14, R18
  SBC R15, R2
  SBC R16, R3
  SBC R17, R4
  SBCI R26, 0
  SBC R22, R22
  ; R22:R26 is -1,0, or 1
  RJMP final_L_M

add_M_L_M: 
  ADD R6, R22
  ADC R7, R23
  ADC R12, R24
  ADC R13, R25  
  ADC R14, R18
  ADC R15, R2
  ADC R16, R3
  ADC R17, R4
  CLR R22
  ADC R26, R22
  NOP ; constant runtime (DO NOT REMOVE!)

final_L_M: 
  ;--- propagate carry to end  ---
  ADD R10, R26
  ADC R11, R22
  ADC R19, R22
  ADC R20, R22
  
  MOVW R22, R14
  MOVW R24, R16
  MOV R18, R10
  MOV R21, R11
  ; h8...h15 stored in 22,23,24,25,18,21,19,20

  ;------ level 2: compute H ------
 
  ; push Z+0...Z+7 on stack
  PUSH R8
  PUSH R9
  PUSH R28
  PUSH R29
  PUSH R6
  PUSH R7
  PUSH R12
  PUSH R13

  ; subtract stack pointer and load Y and X values
  IN R28, 0x3D
  IN R29, 0x3E
#ifdef ORIG
  ADIW R28, 33
  OUT 0x3D, R28
  OUT 0x3E, R29
  
  ; load Y
  POP R2
  POP R3
  POP R4
  POP R5
   
  ; set correct address
  SBIW R28, 16
  OUT 0x3D, R28
  OUT 0x3E, R29

  ; load X
  POP R6
  POP R7
  POP R8
  POP R9
  
  ; set correct address
  SBIW R28, 17
  OUT 0x3D, R28
  OUT 0x3E, R29
#else
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
#endif
  
  ; init zero registers
  CLR R26
  MOVW R12, R26
  MOVW R14, R26
  MOVW R16, R26

  ;--- level 3: compute L ---
  
  MUL R2, R6
  MOVW R10, R0

  MUL R2, R7
  ADD R11, R0
  ADC R12, R1
  MUL R3, R6
  ADD R11, R0
  ADC R12, R1
  ADC R13, R26

  MUL R2, R8
  ADD R12, R0
  ADC R13, R1
  ADC R14, R26
  MUL R3, R7
  ADD R12, R0
  ADC R13, R1
  ADC R14, R26
  MUL R4, R6
  ADD R12, R0
  ADC R13, R1
  ADC R14, R26

  MUL R2, R9
  ADD R13, R0
  ADC R14, R1
  ADC R15, R26
  MUL R3, R8
  ADD R13, R0
  ADC R14, R1
  ADC R15, R26
  MUL R4, R7
  ADD R13, R0
  ADC R14, R1
  ADC R15, R26
  MUL R5, R6
  ADD R13, R0
  ADC R14, R1
  ADC R15, R26

  MUL R3, R9
  ADD R14, R0
  ADC R15, R1
  ADC R16, R26
  MUL R4, R8
  ADD R14, R0
  ADC R15, R1
  ADC R16, R26
  MUL R5, R7
  ADD R14, R0
  ADC R15, R1
  ADC R16, R26

  MUL R4, R9
  ADD R15, R0
  ADC R16, R1
  ADC R17, R26
  MUL R5, R8
  ADD R15, R0
  ADC R16, R1
  ADC R17, R26

  MUL R5, R9
  ADD R16, R0
  ADC R17, R1

  ;--- add h0+l8 and h0+l12 ---
  ADD R22, R10
  PUSH R22
  ADC R23, R11
  PUSH R23
  ADC R24, R12
  PUSH R24
  ADC R25, R13
  PUSH R25
  ADC R10, R18
  PUSH R10
  ADC R11, R21
  PUSH R11
  ADC R12, R19
  ADC R13, R20
  ; store carry in R27
  ADC R27, R26

#ifdef ORIG
  ; set correct address
  ADIW R28, 37
  OUT 0x3D, R28
  OUT 0x3E, R29

  ; load Y
  POP R18
  POP R19
  POP R20
  POP R21

  ; set correct address
  SBIW R28, 16
  OUT 0x3D, R28
  OUT 0x3E, R29

  ; load X
  POP R22
  POP R23
  POP R24
  POP R25
  
  ; set correct address
  SBIW R28, 27
  OUT 0x3D, R28
  OUT 0x3E, R29

#else
	ldd	r18,Y+Yoff+4
	ldd	r19,Y+Yoff+5
	ldd	r20,Y+Yoff+6
	ldd	r21,Y+Yoff+7

	ldd	r22,Y+Xoff+4
	ldd	r23,Y+Xoff+5
	ldd	r24,Y+Xoff+6
	ldd	r25,Y+Xoff+7
#endif
  ;--- level 3: compute H ---
  CLR R10
  CLR R11

  MUL R18, R22
  ADD R14, R0
  ADC R15, R1
  ADC R16, R26
  ADC R11, R26

  MUL R18, R23
  ADD R15, R0
  ADC R16, R1
  ADC R11, R26
  MUL R19, R22
  ADD R15, R0
  ADC R16, R1
  ADC R17, R11
  ADC R10, R26

  MUL R18, R24
  ADD R16, R0 
  ADC R17, R1
  ADC R10, R26
  MUL R19, R23
  ADD R16, R0
  ADC R17, R1
  ADC R10, R26
  MUL R20, R22
  ADD R16, R0
  ADC R17, R1
  ADC R10, R26
  
  CLR R11
  MUL R18, R25
  ADD R17, R0
  ADC R10, R1
  ADC R11, R26
  MUL R19, R24
  ADD R17, R0
  ADC R10, R1
  ADC R11, R26
  MUL R20, R23
  ADD R17, R0
  ADC R10, R1
  ADC R11, R26
  
  ;--- subtract a0-a4 ---
  SUB R2, R18
  SBC R3, R19
  SBC R4, R20
  SBC R5, R21
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0
  
  ;--- subtract b0-b4 ---
  SUB R6, R22
  SBC R7, R23
  SBC R8, R24
  SBC R9, R25
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1

  ;--- absolute values ---
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1
  NEG R0
  NEG R1
  ADD R2, R0
  ADC R3, R26
  ADC R4, R26
  ADC R5, R26
  ADD R6, R1
  ADC R7, R26
  ADC R8, R26
  ADC R9, R26
  EOR R0, R1
  BST R0, 0 
  
  ;--- continue ---
  MUL R21, R22
  ADD R17, R0
  ADC R10, R1
  ADC R11, R26

  MUL R19, R25
  CLR R19
  ADD R10, R0
  ADC R11, R1
  ADC R19, R26
  MUL R20, R24
  ADD R10, R0
  ADC R11, R1
  ADC R19, R26
  MUL R21, R23
  ADD R10, R0
  ADC R11, R1
  ADC R19, R26

  MUL R20, R25
  CLR R20
  ADD R11, R0
  ADC R19, R1
  ADC R20, R26
  MUL R21, R24
  ADD R11, R0
  ADC R19, R1
  ADC R20, R26

  MUL R21, R25
  ADD R19, R0
  ADC R20, R1

  ;--- level 3: compute M ---
  CLR R24
  CLR R25
  CLR R18
  MUL R2, R6
  MOVW R22, R0

  MUL R2, R7
  ADD R23, R0
  ADC R24, R1
  MUL R3, R6
  ADD R23, R0
  ADC R24, R1
  ADC R25, R26

  MUL R2, R8
  ADD R24, R0
  ADC R25, R1
  ADC R18, R26
  MUL R3, R7
  ADD R24, R0
  ADC R25, R1
  ADC R18, R26
  MUL R4, R6
  ADD R24, R0
  ADC R25, R1
  ADC R18, R26

  MUL R2, R9
  CLR R2
  ADD R25, R0
  ADC R18, R1
  ADC R2, R26
  MUL R3, R8
  ADD R25, R0
  ADC R18, R1
  ADC R2, R26
  MUL R4, R7
  ADD R25, R0
  ADC R18, R1
  ADC R2, R26
  MUL R5, R6
  ADD R25, R0
  ADC R18, R1
  ADC R2, R26

  MUL R3, R9
  CLR R3
  ADD R18, R0
  ADC R2, R1
  ADC R3, R26
  MUL R4, R8
  ADD R18, R0
  ADC R2, R1
  ADC R3, R26
  MUL R5, R7
  ADD R18, R0
  ADC R2, R1
  ADC R3, R26

  MUL R4, R9
  CLR R4
  ADD R2, R0
  ADC R3, R1
  ADC R4, R26
  MUL R5, R8
  ADD R2, R0
  ADC R3, R1
  ADC R4, R26

  MUL R5, R9
  ADD R3, R0
  ADC R4, R1

  ;--- add l4+h0 to l0 and h4 ---
  POP R7
  POP R6
  ADD R6, R14
  ADC R7, R15
  ADC R12, R16
  ADC R13, R17
  ADC R14, R10
  ADC R15, R11
  ADC R16, R19
  ADC R17, R20
  ; store carry in R26
  ADC R26, R26

  ; load carry and propagate to end
  ADD R14, R27
  CLR R27
  ADC R15, R27
  ADC R16, R27
  ADC R17, R27
  ; store carry in R26
  ADC R26, R27

  ;--- process sign bit ---  
  BRTS add_M_H_M

  ; subtract M
  SUB R6,  R22
  SBC R7,  R23
  SBC R12, R24
  SBC R13, R25
  SBC R14, R18
  SBC R15, R2
  SBC R16, R3
  SBC R17, R4
  SBCI R26, 0
  SBC R22, R22
  ; R22:R26 is -1,0, or 1
  RJMP final_H_M

add_M_H_M: 
  ADD R6,  R22
  ADC R7,  R23
  ADC R12, R24
  ADC R13, R25
  ADC R14, R18
  ADC R15, R2
  ADC R16, R3
  ADC R17, R4
  CLR R22
  ADC R26, R22
  NOP ; constant runtime (DO NOT REMOVE!)

final_H_M:
  ;--- propagate carry to end  ---
  ADD R10, R26
  ADC R11, R22
  ADC R19, R22
  ADC R20, R22
  
  PUSH R6
  PUSH R7
  PUSH R12
  PUSH R13
  PUSH R14
  PUSH R15
  PUSH R16
  PUSH R17
  PUSH R10
  PUSH R11
  PUSH R19
  PUSH R20

  ;------ level 2: subtract a0-a7 ------
#ifdef ORIG
  ADIW R28, 31
  OUT 0x3D, R28
  OUT 0x3E, R29
  POP R2
  POP R3
  POP R4
  POP R5
  POP R18
  POP R19
  POP R20
  POP R21
  POP R10
  POP R11
  POP R12
  POP R13
  POP R14
  POP R15
  POP R16
  POP R17
#else
#define Aoff 26
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
#endif
  SUB R2, R10
  SBC R3, R11
  SBC R4, R12
  SBC R5, R13
  SBC R18, R14
  SBC R19, R15
  SBC R20, R16
  SBC R21, R17
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0
  
  ;--- level 3: subtract b0-b7 ---
#ifdef ORIG
  SBIW R28, 16
  OUT 0x3D, R28
  OUT 0x3E, R29
  POP R6
  POP R7
  POP R8
  POP R9
  POP R22
  POP R23
  POP R24
  POP R25
  POP R10
  POP R11
  POP R12
  POP R13
  POP R14
  POP R15
  POP R16
  POP R17
  SBIW R28, 25
  OUT 0x3D, R28
  OUT 0x3E, R29
#else
#define Boff 10
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
#endif

  SUB R6, R10
  SBC R7, R11
  SBC R8, R12
  SBC R9, R13
  SBC R22, R14
  SBC R23, R15
  SBC R24, R16
  SBC R25, R17
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1
  
  ;--- level 3: absolute values ---
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0
  EOR R18, R0
  EOR R19, R0
  EOR R20, R0
  EOR R21, R0
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1
  EOR R22, R1
  EOR R23, R1
  EOR R24, R1
  EOR R25, R1
  NEG R0
  NEG R1
  CLR R26
  ADD R2, R0
  ADC R3, R26
  ADC R4, R26
  ADC R5, R26
  ADC R18, R26
  ADC R19, R26
  ADC R20, R26
  ADC R21, R26
  ADD R6, R1
  ADC R7, R26
  ADC R8, R26
  ADC R9, R26
  ADC R22, R26
  ADC R23, R26
  ADC R24, R26
  ADC R25, R26
  EOR R0, R1
  PUSH R0
  
  ;------ level 2: compute M ------

  ; init zero registers
  MOVW R12, R26
  MOVW R14, R12
  MOVW R16, R12
  MOVW R28, R12

  MUL R2, R6
  MOVW R10, R0
  
  MUL R2, R7
  ADD R11, R0
  ADC R12, R1
  MUL R3, R6
  ADD R11, R0
  ADC R12, R1
  ADC R13, R26
  
  MUL R2, R8
  ADD R12, R0
  ADC R13, R1
  ADC R14, R26
  MUL R3, R7
  ADD R12, R0
  ADC R13, R1
  ADC R14, R26
  MUL R4, R6
  ADD R12, R0
  ADC R13, R1
  ADC R14, R26
  
  MUL R2, R9
  ADD R13, R0
  ADC R14, R1
  ADC R15, R26
  MUL R3, R8
  ADD R13, R0
  ADC R14, R1
  ADC R15, R26
  MUL R4, R7
  ADD R13, R0
  ADC R14, R1
  ADC R15, R26
  MUL R5, R6
  ADD R13, R0
  ADC R14, R1
  ADC R15, R26
  
  MUL R3, R9
  ADD R14, R0
  ADC R15, R1
  ADC R16, R26
  MUL R4, R8
  ADD R14, R0
  ADC R15, R1
  ADC R16, R26
  MUL R5, R7
  ADD R14, R0
  ADC R15, R1
  ADC R16, R26
  
  MUL R4, R9
  ADD R15, R0
  ADC R16, R1
  ADC R17, R26
  MUL R5, R8
  ADD R15, R0
  ADC R16, R1
  ADC R17, R26
  
  MUL R5, R9
  ADD R16, R0
  ADC R17, R1

  ;--- level 3: compute H + (l3,l4,l5) ---
  MUL R18, R22
  ADD R14, R0
  ADC R15, R1
  ADC R16, R26
  ADC R29, R26

  MUL R18, R23
  ADD R15, R0
  ADC R16, R1
  ADC R29, R26
  MUL R19, R22
  ADD R15, R0
  ADC R16, R1
  ADC R17, R29
  ADC R28, R26
 
  MUL R18, R24
  ADD R16, R0 
  ADC R17, R1
  ADC R28, R26
  MUL R19, R23
  ADD R16, R0
  ADC R17, R1
  ADC R28, R26
  MUL R20, R22
  ADD R16, R0
  ADC R17, R1
  ADC R28, R26

  CLR R29
  MUL R18, R25
  ADD R17, R0
  ADC R28, R1
  ADC R29, R26
  MUL R19, R24
  ADD R17, R0
  ADC R28, R1
  ADC R29, R26
  MUL R20, R23
  ADD R17, R0
  ADC R28, R1
  ADC R29, R26
  
  ;--- subtract a0-a4 ---  
  SUB R2, R18
  SBC R3, R19
  SBC R4, R20
  SBC R5, R21
  ; 0xff if carry and 0x00 if no carry
  SBC R0, R0
  
  ;--- subtract b0-b4 ---  
  SUB R6, R22
  SBC R7, R23
  SBC R8, R24
  SBC R9, R25
  ; 0xff if carry and 0x00 if no carry
  SBC R1, R1

  ;--- absolute values ---  
  EOR R2, R0
  EOR R3, R0
  EOR R4, R0
  EOR R5, R0
  EOR R6, R1
  EOR R7, R1
  EOR R8, R1
  EOR R9, R1
  NEG R0
  NEG R1
  ADD R2, R0
  ADC R3, R26
  ADC R4, R26
  ADC R5, R26
  ADD R6, R1
  ADC R7, R26
  ADC R8, R26
  ADC R9, R26
  EOR R0, R1
  BST R0, 0 
  
  ;--- continue ---
  MUL R21, R22
  ADD R17, R0
  ADC R28, R1
  ADC R29, R26

  MUL R19, R25
  CLR R19
  ADD R28, R0
  ADC R29, R1
  ADC R19, R26
  MUL R20, R24
  ADD R28, R0
  ADC R29, R1
  ADC R19, R26
  MUL R21, R23
  ADD R28, R0
  ADC R29, R1
  ADC R19, R26

  MUL R20, R25
  CLR R20
  ADD R29, R0
  ADC R19, R1
  ADC R20, R26
  MUL R21, R24
  ADD R29, R0
  ADC R19, R1
  ADC R20, R26

  MUL R21, R25
  ADD R19, R0
  ADC R20, R1

  ;--- level 3: compute M ---
  CLR R24
  CLR R25
  CLR R18

  MUL R2, R6
  MOVW R22, R0

  MUL R2, R7
  ADD R23, R0
  ADC R24, R1
  MUL R3, R6
  ADD R23, R0
  ADC R24, R1
  ADC R25, R26

  MUL R2, R8
  ADD R24, R0
  ADC R25, R1
  ADC R18, R26
  MUL R3, R7
  ADD R24, R0
  ADC R25, R1
  ADC R18, R26
  MUL R4, R6
  ADD R24, R0
  ADC R25, R1
  ADC R18, R26

  MUL R2, R9
  CLR R2
  ADD R25, R0
  ADC R18, R1
  ADC R2, R26
  MUL R3, R8
  ADD R25, R0
  ADC R18, R1
  ADC R2, R26
  MUL R4, R7
  ADD R25, R0
  ADC R18, R1
  ADC R2, R26
  MUL R5, R6
  ADD R25, R0
  ADC R18, R1
  ADC R2, R26

  MUL R3, R9
  CLR R3
  ADD R18, R0
  ADC R2, R1
  ADC R3, R26
  MUL R4, R8
  ADD R18, R0
  ADC R2, R1
  ADC R3, R26
  MUL R5, R7
  ADD R18, R0
  ADC R2, R1
  ADC R3, R26

  MUL R4, R9
  CLR R4
  ADD R2, R0
  ADC R3, R1
  ADC R4, R26
  MUL R5, R8
  ADD R2, R0
  ADC R3, R1
  ADC R4, R26

  MUL R5, R9
  ADD R3, R0
  ADC R4, R1

  ;--- add l4+h0 to l0 and h4 ---
  MOVW R6, R10
  MOVW R8, R12

  ADD R10, R14
  ADC R11, R15
  ADC R12, R16
  ADC R13, R17
  ADC R14, R28
  ADC R15, R29
  ADC R16, R19
  ADC R17, R20
  ; store carry in R26
  ADC R26, R26
  
  ;--- process sign bit ---
  BRTS add_M_M_M

  ; subtract M
  SUB R10, R22
  SBC R11, R23
  SBC R12, R24
  SBC R13, R25
  SBC R14, R18
  SBC R15, R2
  SBC R16, R3
  SBC R17, R4
  SBCI R26, 0
  SBC R22, R22
  ; R22:R26 is -1,0, or 1
  RJMP final_M_M

add_M_M_M: 
  ADD R10, R22
  ADC R11, R23
  ADC R12, R24
  ADC R13, R25  
  ADC R14, R18
  ADC R15, R2
  ADC R16, R3
  ADC R17, R4
  CLR R22
  ADC R26, R22
  NOP ; constant runtime (DO NOT REMOVE!)

final_M_M:
  ;--- propagate carry to end  ---
  ADD R28, R26
  ADC R29, R22
  ADC R19, R22
  ADC R20, R22
  
  ;------ level 2: combine L, H, and M ------
  

  ;--- process sign bit ---  
  POP R0  

#ifdef ORIG
  ; set correct address
  IN R26, 0x3D
  IN R27, 0x3E
  ADIW R26, 16
  OUT 0x3D, R26
  OUT 0x3E, R27

  ; load Z+7...Z+0
  POP R24
  POP R23
  POP R22
  POP R21
  POP R5
  POP R4
  POP R3
  POP R2

  ; set correct address
  SBIW R26, 16
  OUT 0x3D, R26
  OUT 0x3E, R27
 
#else
#define Zoff 17
	movw	r26,r28
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

	movw	r28,r26
	in	r26,0x3d
	in	r27,0x3e
	adiw	r26,1
#endif
  TST R0
  
  ;--- process sign bit ---  
  BRNE add_M
  ; subtract M
  SUB R2, R6
  SBC R3, R7
  SBC R4, R8
  SBC R5, R9
  SBC R21, R10
  SBC R22, R11
  SBC R23, R12
  SBC R24, R13
#ifdef ORIG
  POP R13
  POP R12
  POP R11
  POP R10
  POP R9
  POP R8
  POP R7
  POP R6
#else
	ld	r13,X+
	ld	r12,X+
	ld	r11,X+
	ld	r10,X+
	ld	r9,X+
	ld	r8,X+
	ld	r7,X+
	ld	r6,X+
#endif
  SBC R6,  R14
  SBC R7,  R15
  SBC R8,  R16
  SBC R9,  R17
  SBC R10, R28
  SBC R11, R29
  SBC R12, R19
  SBC R13, R20
  SBC R0, R0
  SBC R1, R1
  ; R1:R0 is -1,0, or 1
  RJMP final_M

add_M: 
  ADD R2,  R6
  ADC R3,  R7
  ADC R4,  R8
  ADC R5,  R9
  ADC R21, R10
  ADC R22, R11
  ADC R23, R12
  ADC R24, R13
#ifdef ORIG
  POP R13
  POP R12
  POP R11
  POP R10
  POP R9
  POP R8
  POP R7
  POP R6
#else
	ld	r13,X+
	ld	r12,X+
	ld	r11,X+
	ld	r10,X+
	ld	r9,X+
	ld	r8,X+
	ld	r7,X+
	ld	r6,X+
#endif
  ADC R6,  R14
  ADC R7,  R15
  ADC R8,  R16
  ADC R9,  R17
  ADC R10, R28
  ADC R11, R29
  ADC R12, R19
  ADC R13, R20
  CLR R0
  CLR R1
  ADC R0, R0
  
final_M:
#ifdef ORIG
  POP R20
  POP R19
  POP R29
  POP R28
  POP R17
  POP R16
  POP R15
  POP R14
#else
	ld	r20,X+
	ld	r19,X+
	ld	r29,X+
	ld	r28,X+
	ld	r17,X+
	ld	r16,X+
	ld	r15,X+
	ld	r14,X+
#endif
  ADD R2,  R14
  ADC R3,  R15
  ADC R4,  R16
  ADC R5,  R17
  ADC R21, R28
  ADC R22, R29
  ADC R23, R19
  ADC R24, R20
  ADC R6,  R14
  ADC R7,  R15
  ADC R8,  R16
  ADC R9,  R17
  ADC R10, R28
  ADC R11, R29
  ADC R12, R19
  ADC R13, R20
  ; add carry to carry catcher
  CLR R27
  ADC R0,  R27
  ADC R1,  R27

  ;--- propagate carry to end ---
  IN R28, 0x3D
  IN R29, 0x3E
#ifdef ORIG
  SBIW R28, 16
  OUT 0x3D, R28
  OUT 0x3E, R29

  ; load Z+31...Z+24
  POP R25
  POP R20
  POP R19
  POP R18
  POP R17
  POP R16
  POP R15
  POP R14

#else
#define Joff 1
	ldd	r25,Y+0+Joff
	ldd	r20,Y+1+Joff
	ldd	r19,Y+2+Joff
	ldd	r18,Y+3+Joff
	ldd	r17,Y+4+Joff
	ldd	r16,Y+5+Joff
	ldd	r15,Y+6+Joff
	ldd	r14,Y+7+Joff
#endif
  ADD R14, R0
  ADC R15, R1
  ADC R16, R1
  ADC R17, R1
  ADC R18, R1
  ADC R19, R1
  ADC R20, R1
  ADC R25, R1

  ;--------- level 1: combine L, H, and M ---------
#ifdef ORIG
  ADIW R28, 16
  OUT 0x3D, R28
  OUT 0x3E, R29

  PUSH R14
  PUSH R15
  PUSH R16
  PUSH R17
  PUSH R18
  PUSH R19
  PUSH R20
  PUSH R25

  OUT 0x3D, R28
  OUT 0x3E, R29
  
  ; first load first 8 bytes of "m"
  POP R25
  POP R20
  POP R19
  POP R18
  POP R17
  POP R16
  POP R15
  POP R14
  
  CLR R26

  ;--- process sign bit ---  
  POP R0
  SBIW R28, 8
  OUT 0x3D, R28
  OUT 0x3E, R29
  
#else
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
#endif
  TST R0
  BREQ final_subtract
  RJMP final_addition

final_subtract:
  ; subtract M
  LDD R0, Z+0
  SUB R0, R14
  LDD R1, Z+1
  SBC R1, R15
  LDD R14, Z+2
  SBC R14, R16
  LDD R15, Z+3
  SBC R15, R17
  LDD R16, Z+4
  SBC R16, R18
  LDD R17, Z+5
  SBC R17, R19
  LDD R18, Z+6
  SBC R18, R20
  LDD R19, Z+7
  SBC R19, R25
  LDD R20, Z+8
  SBC R20, R2
  LDD R25, Z+9
  SBC R25, R3
  LDD R2, Z+10
  SBC R2, R4
  LDD R3, Z+11
  SBC R3, R5
  LDD R4, Z+12
  SBC R4, R21
  LDD R5, Z+13
  SBC R5, R22
  LDD R21, Z+14
  SBC R21, R23
  LDD R22, Z+15
  SBC R22, R24
  ; store borrow in R27
  SBC R27, R27

  ; add h0+l8
  LDD R23, Z+32
  ADD R0, R23
  STD Z+16, R0
  LDD R24, Z+33
  ADC R1, R24
  STD Z+17, R1
  LDD R0, Z+34
  ADC R14, R0
  STD Z+18, R14
  LDD R0, Z+35
  ADC R15, R0
  STD Z+19, R15
  LDD R0, Z+36
  ADC R16, R0
  STD Z+20, R16  
  LDD R0, Z+37
  ADC R17, R0
  STD Z+21, R17
  LDD R0, Z+38
  ADC R18, R0
  STD Z+22, R18  
  LDD R0, Z+39
  ADC R19, R0
  STD Z+23, R19
  LDD R0, Z+40
  ADC R20, R0
  STD Z+24, R20
  LDD R0, Z+41
  ADC R25, R0
  STD Z+25, R25
  LDD R0, Z+42
  ADC R2, R0
  STD Z+26, R2
  LDD R0, Z+43
  ADC R3, R0
  STD Z+27, R3
  LDD R0, Z+44
  ADC R4, R0
  STD Z+28, R4
  LDD R0, Z+45
  ADC R5, R0
  STD Z+29, R5
  LDD R0, Z+46
  ADC R21, R0
  STD Z+30, R21
  LDD R0, Z+47
  ADC R22, R0
  STD Z+31, R22
  ; store carry in R26
  ADC R26, R26

#ifdef ORIG
  ; restore last 8 bytes of M
  POP R24
  POP R23
  POP R22
  POP R21
  POP R5
  POP R4
  POP R3
  POP R2

#else
#define Loff  9
	ldd	r24,Y+0+Loff
	ldd	r23,Y+1+Loff
	ldd	r22,Y+2+Loff
	ldd	r21,Y+3+Loff
	ldd	r5,Y+4+Loff
	ldd	r4,Y+5+Loff
	ldd	r3,Y+6+Loff
	ldd	r2,Y+7+Loff
#endif
  LSR R27
  LDD R0, Z+48
  SBC R0, R6
  LDD R1, Z+49
  SBC R1, R7
  LDD R14, Z+50
  SBC R14, R8
  LDD R15, Z+51
  SBC R15, R9
  LDD R16, Z+52
  SBC R16, R10
  LDD R17, Z+53
  SBC R17, R11
  LDD R18, Z+54
  SBC R18, R12
  LDD R19, Z+55
  SBC R19, R13
  LDD R20, Z+56
  SBC R20, R2
  LDD R25, Z+57
  SBC R25, R3
  LDD R2, Z+58
  SBC R2, R4
  LDD R3, Z+59
  SBC R3, R5
  LDD R4, Z+60
  SBC R4, R21
  LDD R5, Z+61
  SBC R5, R22
  LDD R21, Z+62
  SBC R21, R23
  LDD R22, Z+63
  SBC R22, R24
  ; store borrow in R28:R27
  SBC R27, R27
  SBC R28, R28

  ; add h0+l8
  LSR R26
  LDD R23, Z+32
  ADC R0, R23
  STD Z+32, R0
  LDD R24, Z+33
  ADC R1, R24
  STD Z+33, R1
  LDD R0, Z+34
  ADC R14, R0
  STD Z+34, R14
  LDD R0, Z+35
  ADC R15, R0
  STD Z+35, R15
  LDD R0, Z+36
  ADC R16, R0
  STD Z+36, R16  
  LDD R0, Z+37
  ADC R17, R0
  STD Z+37, R17
  LDD R0, Z+38
  ADC R18, R0
  STD Z+38, R18  
  LDD R0, Z+39
  ADC R19, R0
  STD Z+39, R19
  LDD R0, Z+40
  ADC R20, R0
  STD Z+40, R20
  LDD R0, Z+41
  ADC R25, R0
  STD Z+41, R25
  LDD R0, Z+42
  ADC R2, R0
  STD Z+42, R2
  LDD R0, Z+43
  ADC R3, R0
  STD Z+43, R3
  LDD R0, Z+44
  ADC R4, R0
  STD Z+44, R4
  LDD R0, Z+45
  ADC R5, R0
  STD Z+45, R5
  LDD R0, Z+46
  ADC R21, R0
  STD Z+46, R21
  LDD R0, Z+47
  ADC R22, R0
  STD Z+47, R22
  ; store carry in R28:R27
  ADC R27, R26
  ADC R28, R26

RJMP final

final_addition:
  ; subtract M
  LDD R0, Z+0
  ADD R0, R14
  LDD R1, Z+1
  ADC R1, R15
  LDD R14, Z+2
  ADC R14, R16
  LDD R15, Z+3
  ADC R15, R17
  LDD R16, Z+4
  ADC R16, R18
  LDD R17, Z+5
  ADC R17, R19
  LDD R18, Z+6
  ADC R18, R20
  LDD R19, Z+7
  ADC R19, R25
  LDD R20, Z+8
  ADC R20, R2
  LDD R25, Z+9
  ADC R25, R3
  LDD R2, Z+10
  ADC R2, R4
  LDD R3, Z+11
  ADC R3, R5
  LDD R4, Z+12
  ADC R4, R21
  LDD R5, Z+13
  ADC R5, R22
  LDD R21, Z+14
  ADC R21, R23
  LDD R22, Z+15
  ADC R22, R24
  ; store carry in R27
  CLR R27
  ADC R27, R27

  ; now add h0+l8
  LDD R23, Z+32
  ADD R0, R23
  STD Z+16, R0
  LDD R24, Z+33
  ADC R1, R24
  STD Z+17, R1
  LDD R0, Z+34
  ADC R14, R0
  STD Z+18, R14
  LDD R0, Z+35
  ADC R15, R0
  STD Z+19, R15
  LDD R0, Z+36
  ADC R16, R0
  STD Z+20, R16  
  LDD R0, Z+37
  ADC R17, R0
  STD Z+21, R17
  LDD R0, Z+38
  ADC R18, R0
  STD Z+22, R18  
  LDD R0, Z+39
  ADC R19, R0
  STD Z+23, R19
  LDD R0, Z+40
  ADC R20, R0
  STD Z+24, R20
  LDD R0, Z+41
  ADC R25, R0
  STD Z+25, R25
  LDD R0, Z+42
  ADC R2, R0
  STD Z+26, R2
  LDD R0, Z+43
  ADC R3, R0
  STD Z+27, R3
  LDD R0, Z+44
  ADC R4, R0
  STD Z+28, R4
  LDD R0, Z+45
  ADC R5, R0
  STD Z+29, R5
  LDD R0, Z+46
  ADC R21, R0
  STD Z+30, R21
  LDD R0, Z+47
  ADC R22, R0
  STD Z+31, R22
  ; store carry in R26
  ADC R26, R26
  
#ifdef ORIG
  ; restore last 8 bytes of M
  POP R24
  POP R23
  POP R22
  POP R21
  POP R5
  POP R4
  POP R3
  POP R2

#else
#define Loff  9
	ldd	r24,Y+0+Loff
	ldd	r23,Y+1+Loff
	ldd	r22,Y+2+Loff
	ldd	r21,Y+3+Loff
	ldd	r5,Y+4+Loff
	ldd	r4,Y+5+Loff
	ldd	r3,Y+6+Loff
	ldd	r2,Y+7+Loff
#endif
  LSR R27
  LDD R0, Z+48
  ADC R0, R6
  LDD R1, Z+49
  ADC R1, R7
  LDD R14, Z+50
  ADC R14, R8
  LDD R15, Z+51
  ADC R15, R9
  LDD R16, Z+52
  ADC R16, R10
  LDD R17, Z+53
  ADC R17, R11
  LDD R18, Z+54
  ADC R18, R12
  LDD R19, Z+55
  ADC R19, R13
  LDD R20, Z+56
  ADC R20, R2
  LDD R25, Z+57
  ADC R25, R3
  LDD R2, Z+58
  ADC R2, R4
  LDD R3, Z+59
  ADC R3, R5
  LDD R4, Z+60
  ADC R4, R21
  LDD R5, Z+61
  ADC R5, R22
  LDD R21, Z+62
  ADC R21, R23
  LDD R22, Z+63
  ADC R22, R24
  ; store carry in R28:R27
  ADC R27, R27
  CLR R28

  ; now add h0+l8
  LSR R26
  LDD R23, Z+32
  ADC R0, R23
  STD Z+32, R0
  LDD R24, Z+33
  ADC R1, R24
  STD Z+33, R1
  LDD R0, Z+34
  ADC R14, R0
  STD Z+34, R14
  LDD R0, Z+35
  ADC R15, R0
  STD Z+35, R15
  LDD R0, Z+36
  ADC R16, R0
  STD Z+36, R16  
  LDD R0, Z+37
  ADC R17, R0
  STD Z+37, R17
  LDD R0, Z+38
  ADC R18, R0
  STD Z+38, R18  
  LDD R0, Z+39
  ADC R19, R0
  STD Z+39, R19
  LDD R0, Z+40
  ADC R20, R0
  STD Z+40, R20
  LDD R0, Z+41
  ADC R25, R0
  STD Z+41, R25
  LDD R0, Z+42
  ADC R2, R0
  STD Z+42, R2
  LDD R0, Z+43
  ADC R3, R0
  STD Z+43, R3
  LDD R0, Z+44
  ADC R4, R0
  STD Z+44, R4
  LDD R0, Z+45
  ADC R5, R0
  STD Z+45, R5
  LDD R0, Z+46
  ADC R21, R0
  STD Z+46, R21
  LDD R0, Z+47
  ADC R22, R0
  STD Z+47, R22
  ; store carry in R28:R27
  ADC R27, R26
  ADC R28, R26

final:
  ;--- propagate carry to end ---
  LDD R0, Z+48
  LDD R1, Z+49
  LDD R14, Z+50
  LDD R15, Z+51
  LDD R16, Z+52  
  LDD R17, Z+53
  LDD R18, Z+54 
  LDD R19, Z+55
  LDD R20, Z+56
  LDD R25, Z+57
  LDD R2, Z+58
  LDD R3, Z+59
  LDD R4, Z+60  
  LDD R5, Z+61
  LDD R21, Z+62 
  LDD R22, Z+63

  ADD R0, R27
  ADC R1, R28
  ADC R14, R28
  ADC R15, R28
  ADC R16, R28
  ADC R17, R28
  ADC R18, R28
  ADC R19, R28
  ADC R20, R28
  ADC R25, R28
  ADC R2, R28
  ADC R3, R28
  ADC R4, R28
  ADC R5, R28
  ADC R21, R28
  ADC R22, R28
  
  STD Z+48, R0
  STD Z+49, R1
  STD Z+50, R14
  STD Z+51, R15
  STD Z+52, R16
  STD Z+53, R17
  STD Z+54, R18
  STD Z+55, R19
  STD Z+56, R20
  STD Z+57, R25
  STD Z+58, R2
  STD Z+59, R3
  STD Z+60, R4
  STD Z+61, R5
  STD Z+62, R21
  STD Z+63, R22

#ifdef ORIG
  IN R28, 0x3D
  IN R29, 0x3E
  ADIW R28, 41
  OUT 0x3D, R28
  OUT 0x3E, R29
#ifndef OsEID

  CLR R1
  POP R29
  POP R28
  POP R17
  POP R16
  POP R15
  POP R14
  POP R13
  POP R12
  POP R11
  POP R10
  POP R9
  POP R8
  POP R7
  POP R6
  POP R5
  POP R4
  POP R3
  POP R2
#else	// OsEID
  SEI
#endif // OsEID
  RET

#else  // not ORIG and for OsEID
	in 	r28,0x3d
	in	r29,0x3e
	adiw	r28,57
	LOAD_SP r0, r28,r29
	ret
#endif
#endif //(defined(ORIG) && !defined (OsEID)) || (defined(HAVE_RSA_MUL_256_NO_ABI) && defined (OsEID))
