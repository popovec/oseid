/*
; Authors: Michael Hutter and Peter Schwabe
; Version: 2014-07-25
; Public domain

// modifications for OsEID by <popovec.peter@gmail.com>
// no C ABI needed for OsEID


  .global karatsuba128_branched
  .type karatsuba128_branched, @function

; operand b: r21:r20
; operand a: r23:r22
; operand r: r25:r24

*/
#if defined(HAVE_RSA_MUL_128_NO_ABI)
#include <avr/io.h>
  .global rsa_mul_128_no_abi
  .type rsa_mul_128_no_abi, @function
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

  ;--- level 2: compute H + (l3,l4,l5) ---
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

  ;--- level 2: compute M ---
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
  BRTS add_M_L

  ;subtract M
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
  RJMP final_L

add_M_L: 
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

final_L:
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

  ;------ level 1: compute H ------

  ; init zero registers
  CLR R12
  CLR R13
  MOVW R14, R12
  MOVW R16, R12

  ;--- level 2: compute L ---
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

  ;--- level 2: compute H + (l3,l4,l5) ---
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

  ;--- level 2: compute M ---
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
  BRTS add_M_H

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
  RJMP final_H

add_M_H: 
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

final_H:
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
  LD R17, X  
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
    
  ;------ level 1: absolute values ------
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

  ;------ level 1: compute M ------
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

  ;--- level 2: compute M ---
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
  BRTS add_M_M

  ;subtract M
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
  RJMP final_M

add_M_M: 
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

final_M:
  ;--- propagate carry to end ---
  ADD R26, R28
  ADC R27, R29
  ADC R18, R29
  ADC R25, R29
  
  MOV R19, R25

  ;------ level 1: combine L, H, and M ------
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
  BRNE add_M
  
  ;subtract M
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
  RJMP final

add_M: 
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
  RET
#endif
