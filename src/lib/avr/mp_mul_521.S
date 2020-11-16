/*
    mp_mul_521.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2018 Peter Popovec, popovec.peter@gmail.com

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

    Atmega assembler routines for 521 bit multiplications (for secp521r1)

*/

// enable this if some bytes of flash must be saved (22 bytes, code is
// slower, for secp521r1 about 1.75 milions clock cycles)
//#define SAVE_FLASH

  .global mp_square_521
  .type mp_square_521, @function

  .global mp_mul_521
  .type mp_mul_521, @function
  .section .text.mp_mul_521,"ax",@progbits

mp_square_521:
	push	r2
	push	r3
	push	r4
	push	r5
// save Y (ABI)
	push	r28
	push	r29
// save operands.result positions
	movw	r2,r24
	movw	r4,r22
	movw	r28,r22
	call	rsa_square_512
	rjmp	mp_mul_521_s	

mp_mul_521:
	push	r2
	push	r3
	push	r4
	push	r5
// save Y (ABI)
	push	r28
	push	r29
// save operands.result positions
	movw	r2,r24
	movw	r4,r22
	movw	r28,r20
	call	rsa_mul_512

mp_mul_521_s:
	movw	r26,r2	// result (now addressed by X)
// low 64 bytes of result is already final
	subi	r26,lo8(-64)
	sbci	r27,hi8(-64)
// operands A,B
//	movw	r28,	already in r28
	movw	r30,r4
// extract bits 520..512 from operands A, B
	adiw	r30,63
	adiw	r28,63
	ldd	r18,Y+1
	ldd	r20,Y+2
	ldd	r19,Z+1
	ldd	r21,Z+2
	neg	r20
	neg	r21
	sbiw	r30,63
	sbiw	r28,63

// operands B[520..512]: r21,r19    A[520..512]:r20,r18
// r21, r20 is 0 or ff!
// pointer to B: r31,r30 (Z), pointer to A: r29,r28 (Y)

// clear prev carry
	clr	r3
	clr	r4
// zero reg
	clr	r25
#ifdef SAVE_FLASH
	ldi	r24,66  //loop
#else
	ldi	r24,64
#endif
1:
	ld	r2,X
	ld	r22,Z+
#ifdef SAVE_FLASH
// do not use last bytes in result (over 128..)
// do not duplicate multiplication for last bytes in operand
	cpi	r24,3
	brcc	2f
	clr	r2
	clr	r22
2:
#endif
	ld	r23,Y+
// sumarize previous carry with partial result byte
	add	r2,r3
	adc	r4,r25
	mov	r3,r4
	clr	r4

// do multiplication (8x8bit)
	mul	r22,r18	//B A[519..512]
	add	r2,r0
	adc	r3,r1
	adc	r4,r25

	mul	r23,r19 //A B[B519..512]
	add	r2,r0
	adc	r3,r1
	adc	r4,r25

// do multiplication (1x8bit)
	and	r22,r20
	add	r3,r22
	adc	r4,r25

	and	r23,r21
	add	r3,r23
	adc	r4,r25

	st	X+,r2
	dec	r24
	brne	1b	
#ifdef SAVE_FLASH
// carry byte into result (already 64+66 bytes = 130 bytes)
// 521 bits*2= 1042 bits = 130.25 byte,
	st	X+,r3
#else
	mul	r18,r19
	add	r3,r0
	adc	r4,r1
	adc	r24,r25

	and	r18,r21
	add	r4,r18
	adc	r24,r25

	and	r19,r20
	add	r4,r19
	adc	r24,r25

	and	r20,r21
	andi	r20,1
	add	r24,r20

	st	X+,r3
	st	X+,r4
	st	X+,r24
#endif
// ABI
	clr	r1
// clean upper part (1042 bytes result = 131 bytes)
	ldi	r24,MP_BYTES*2-131
1:
	st	X+,r1
	dec	r24
	brne 1b
	
// restore Y (ABI)
	pop	r29
	pop	r28
	
	pop	r5
	pop	r4
	pop	r3
	pop	r2
	ret
