/*
    ex_fast_red.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2019,2020 Peter Popovec, popovec.peter@gmail.com

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

this file provides AVR (atmega/xmega) function for fast reduction
curves:

nistp192
secp256r1
secp256k1
secp384r1
secp512r1

This is original C code compiled by gcc-avr 5.4 with some optimizations.

There is no problem rewrite this code in unrolled way, but AVR flash is
almost full.

*/
//void field_reduction (bignum_t * r, bigbignum_t * bn)

	.global field_reduction
	.type field_reduction, @function
	.section .text.field_reduction,"ax",@progbits


field_reduction:
	lds	r20, curve_type
#if MP_BYTES >=72
	cpi	r20, 0x68	; 104
	brne	50f
;------------------------------------------------------------------------------
; secp521r1
// 28 instructions = 56 bytes + rjmp
	movw	r26, r24	// target
	subi	r26,lo8(-72)
	sbci	r27,hi8(-72)
	st	-X,r1	//71
	st	-X,r1	//70
	st	-X,r1	//69
	st	-X,r1	//68
	st	-X,r1	//67
	st	-X,r1	//66

	movw	r30,r22		// source
	subi	r30, lo8(-131)
	sbci	r31, hi8(-131)

// allowed: 1,2,3,6,11,22,33,66 (values over 6 are not recommended)
#ifndef SECP521R1_UNROLL
#define SECP521R1_UNROLL 3
#endif
// copy with rotation
	ldi	r20,66/SECP521R1_UNROLL
	clc
1:
.rept SECP521R1_UNROLL
	ld	r0,-Z	//130
	ror	r0
	st	-X,r0	//65
.endr

	dec	r20
	brne	1b
// mask to 521 bit
	ld	r20,Z	//65
	andi	r20,1
	st	Z+,r20	//65
	st	z+,r1	//66
	st	z+,r1	//67
	st	z+,r1	//68
	st	z+,r1	//69
	st	z+,r1	//70
	st	z+,r1	//71
// r22,r24 used as pointers, field add (r24)=(r24)+(r22), end
//	rjmp	65f
	jmp	field_add
#endif
;------------------------------------------------------------------------------------
50:
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
	movw	r14, r24
	movw	r16, r22
	cpi	r20, 0x60
	breq	1f
	rjmp	51f
;---------------------------------------------------------------------------------------
//secp384r1
1:
// S1(0,A23,A22,A21) || S4(a20) || 0 || S4(A23) || S6(A20)
/*
  memcpy (r + 0 * 4, ptr + 20 * 4, 4);  // S6(A20)
  memcpy (r + 1 * 4, ptr + 23 * 4, 4);  // S4(A23)
  memset (r + 2 * 4, 0, 4);     	// 0
  memcpy (r + 3 * 4, ptr + 20 * 4, 4);  // S4(A20)
  memset (r + 7 * 4, 0, 4);     	// 0
Construct part of S6(0, a23,a22,a21) in upper part of result
  memset (r + 4 * 11, 0, 4);
  memcpy (r + 4 * 8, ptr + 21 * 4, 3 * 4);
*/
	movw	r28, r16	// source
	subi	r28,lo8(-80)
	sbci	r29,hi8(-80)
	movw	r12,r28

	movw	r30, r14	// result
	ldi	r24,4
1:
	std	Z+8,r1		// memset (r + 2 * 4, 0,
	std	Z+28,r1		// memset (r + 7 * 4, 0,
	std	Z+44,r1		// memset (r + 4 * 11, 0,
	ldd	r0,Y+12		// memcpy (r + 1 * 4, ptr + 23 * 4,
	std	Z+4,r0
	ld	r0,Y+		// memcpy (r + 0 * 4, ptr + 20 * 4,
	std	Z+12,r0		// memcpy (r + 3 * 4, ptr + 20 * 4,
	st	Z+,r0
	dec	r24
	brne	1b

//  memcpy (r + 4 * 4, ptr + 21 * 4, 4 * 3);      // S1(A23..A21)
//  mp_shiftl ((bignum_t *) (r + 4 * 4));
	adiw	r30,12
	ldi	r18,12
//	clc			// C is cleared by adiw (address in r30 never overflow)
1:
	ld	r0,Y+
	std	Z+32-16,r0	// memcpy (r + 4 * 8, ptr + 21 * 4,
	rol	r0
	st	Z+,r0		// mp_shiftl ((bignum_t *) (r + 4 * 4));
	dec	r18
	brne	1b
	rol	r18
	mov	r3,r18
// r12  source + 80 (20*4)
// r14  result
// r16  source
//S6
// r[7 * 4] += mp_add ((bignum_t *) (r + 4 * 3), (bignum_t *) (r + 4 * 8));
	ldi	r18, 16
	sts	mod_len, r18

	adiw	r30,4		// result + 32
	movw	r22,r30

	movw	r24, r14	// result + 12
	adiw	r24, 12
	call	bn_add

	movw	r30,r14		// result
	add	r24,r3
	std	Z+28,r24
/*
// 1x S5
  r[8 * 4] = mp_add ((bignum_t *) (r + 4 * 4), (bignum_t *) (ptr + 20 * 4));
  memset (r + 8 * 4 + 1, 0, 15);
*/
	movw	r22, r12	// source + 80 (20*4)
	movw	r24, r14	// result
	adiw	r24, 16
	call	bn_add

	movw	r30, r14	// result
	std	Z+32, r24	// carry to r[8 * 4]

	adiw	r30, 33
	ldi	r24, 15
1:
	st	Z+,r1
	dec	r24
	brne	1b
// this is in C code after T,S2 addition ..
// 1x S4 - reuse upper part of BN  (A20,A23 already in result)
	ldi	r24,32
	sts	mod_len,r24

	movw	r30,r16
	adiw	r30,48
	movw	r22,r30
	movw	r24,r14
	adiw	r24,16
	call	bn_add
	mov	r19,r24

	ldi	r20, 48
	sts	mod_len, r20

// T:  carry = mp_add (result, (bignum_t *) bn);
// S2: carry += mp_add (result, (bignum_t *) & bn->value[48]);
// Z=  Z+X+Y, clamp r4..11, r24 loop counter (/4)  r25 initial carry
	movw	r30,r14		//result +=
	movw	r26,r16		// T
	movw	r28,r16
	adiw	r28,48		// S2
	clr	r25		// initial carry
	ldi	r24,12		//(48/4)
	call	mpro_add2
// summarize carry  (two carrys, one in C  one in R25 bit 0)
	adc	r19,r25
// 1x S3 - reuse upper part of BN a20..a12, copy only a23..a20 to low part
// memcpy (&bn->value[48 - 4 * 4], &bn->value[20 * 4], 4 * 4);

// WARNING ASM code here does not copy A20 (A20 is used for D2 in C code,
// here D2 is generated in different way)

// carry += mp_add (result, (bignum_t *) & bn->value[48 - 3 * 4]);
	movw	r30, r16	// source
	adiw	r30, 36		// + 36 = A9 (overwrite A11,A10,A9)
	movw	r22,r30

	ldi	r24,12
1:
	ldd	r0, Z+48
	st	Z+, r0
	dec	r24
	brne	1b

	movw	r24, r14
	call	bn_add
	add	r19,r24

// carry -= mp_sub (result, result, (bignum_t *) & bn->value[48 - 1 * 4]);
	movw	r20, r16	// source
	subi	r20, 0xD4	; 212
	sbci	r21, 0xFF	; 255
	movw	r22, r14	// result
	movw	r24, r14	// result
	call	bn_sub
	sub	r19,r24
/*
result - (D1+D2+D3) - because D1+D2+D3 < 2x P384, add 2x P384 to result to prevent undeflow
P384 =  0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFE FFFF FFFF 0000 0000 0000 0000 FFFF FFFF
2x P384 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFD FFFF FFFE 0000 0000 0000 0001 FFFF FFFE
negate    FE000000000000000000000000000000000000000000000000000000000000 0002 0000 0001 FFFF FFFF FFFF FFFE 0000 0002

10: d2    ( 0   ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || a23 ||     a22 ||     a21 ||     a20 ||  0  )
11: d3    ( 0   ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || a23 ||     a23 ||      0  ||      0  ||  0  )
                                                             0002  0000 0001  ffff ffff  ffff fffe  0000 0002
*/
// summarize D2,D3 (reuse A11,10,9,8 (7) as D2 )
	movw	r28, r16	// source
	adiw	r28,28
	movw	r20,r28

	ldi	r22,2
	st	Y+,r22
	st	Y+,r1
	st	Y+,r1
	st	Y+,r1

	ldi	r24,0xfe
	ldi	r23,8
//	clc			already cleared by adiw above
// Y point to source+32 = A8, need to read A20 => Y+ 12*4
1:
	ldd	r0,Y+48
	adc	r0,r24
	ldi	r24,0xff	// TODO
	st	Y+,r0
	dec	r23
	brne	1b

	ldd	r24,Y+48
	ldd	r25,Y+49
	ldd	r4,Y+50
	ldd	r5,Y+51

	ldd	r6,Y+52
	ldd	r7,Y+53
	ldd	r8,Y+54
	ldd	r0,Y+55

	adc	r24,r6
	adc	r25,r7
	adc	r4,r8
	adc	r5,r0
	adc	r6,r6
	adc	r7,r7
	adc	r8,r8
	adc	r0,r0
	adc	r23,r1

	adiw	r24,1
	adc	r4,r1
	adc	r5,r1
	adc	r6,r22
	adc	r7,r1
	adc	r8,r1
	adc	r0,r1
	adc	r23,r1

	st	Y+,r24
	st	Y+,r25
	st	Y+,r4
	st	Y+,r5
	st	Y+,r6
	st	Y+,r7
	st	Y+,r8
	st	Y+,r0
// save pointer to upper part of source Y = source + 48

	movw	r26,r28
	st	X+,r23
	add	r19,r22 	// update carry (+2)

	ldi	r18, 47		// here 27 bytes is enough, but clear whole upper part of source (reused below)
1:
	st	X+, r1
	dec	r18
	brne	1b

	movw	r22, r14
	movw	r24, r14
	call	bn_sub
	sub	r19,r24

/*
repeat reduction, already 384 bits in result + 8 bit variable in carry)
A12 is created from carry..
:*t      ( a11 || a10 || a9  || a8  || a7  || a6  || a5  || a4  || a3  || a2  || a1  || a0  )
: s2     (  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || a12 )
: s3     (  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || a12 ||  0  ||  0  ||  0  )
: s4     (  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || a12 ||  0  ||  0  ||  0  ||  0  )
: d1     (  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || a12 ||  0  )
// summarize s2+s3+s4-d1
*/
	std	Y+0,r19		// S2
	std	Y+16,r19		// S4
	mov	r18,r19
	neg	r19
	sbc	r25,r25		// 0 or FF

	std	Y+4,r19		// D1
	std	Y+5,r25
	std	Y+6,r25
	std	Y+7,r25
	std	Y+8,r25
	std	Y+9,r25
	std	Y+10,r25
	std	Y+11,r25

	add	r25,r18
	std	Y+12,r25	// S3

	movw	r22, r28
	jmp	61f

;-------------------------------------------------------------
51:
	cpi	r20, 0x58
	breq	1f
	rjmp	52f
;-------------------------------------------------------------
; sec256r1
// 0x FFFFFFFF  00000001 00000000   00000000  00000000  FFFFFFFF  FFFFFFFF  FFFFFFFF
//          ^^        ^^                            ^^                            ^^
//0x 3FFFFFFFC  00000004 00000000   00000000  00000003  FFFFFFFF  FFFFFFFF  FFFFFFFC
1:
#if 1
// 20 ins 40 bytes 103 clock cycles
	movw    r30, r14
// load constants to regs
	ldi	r24,0xfc
	ldi	r25,3
	ldi	r21,4
	ldi	r22,0xff

	std	Z+28,r24
	std	Z+12,r25
	std	Z+24,r21
	st	Z+,r24
// reuse constant in r25 as loop counter
1:
	std	Z+12,r1
	std	Z+24,r1
	std	z+28,r22
	st	Z+,r22
	dec	r25
	brne	1b

	ldi	r25,8

1:
	std	Z+12,r1
	st	Z+,r22
	dec	r25
	brne	1b

#else
// 17 ins 34 bytes  147
	movw	r30,r14
	ldi	r24,0xff
	ldi	r25,12
//3
1:
	std	Z+20,r24
	std	Z+16,r1
	std	Z+12,r1
	st	Z+,r24
	dec	r25
	brne	1b
//132
	movw	r30,r14
	ldi	r24,0xfc
	ldi	r25,3
	ldi	r21,4
	std	Z+28,r24
	std	Z+12,r25
	std	Z+24,r21
	std	Z+0,r24
//12


/*
// slow ..
//12 ins, 28(30) bytes
	ldi	r24, 32
	lds	r30, field_prime
	lds	r31, field_prime+1

	movw	r26, r14
	clc

1:
	ld	r0, Z+
	rol	r0
	st	X+, r0
	dec	r24
	brne	1b

	movw	r24, r14
	call	bn_shiftl
*/
#endif
#if 0
// result += T	carry += mp_add (result, (bignum_t *) bn);
	movw	r22, r16
	movw	r24, r14
	call	bn_add
	subi	r24,-3	// initial carry
	mov	r3, r24
// result +=s1	carry += mp_add (result, (bignum_t *) & bn->value[32]);
	movw	r26, r16
	adiw	r26, 32
	movw	r12, r26

	movw	r22, r12	// r16 + 32
	movw	r24, r14
	call	bn_add
	add	r3, r24
#else
// result += T     carry += mp_add (result, (bignum_t *) bn);
// result +=s1     carry += mp_add (result, (bignum_t *) & bn->value[32]);

//  Z=  Z+X+Y, clamp r4..11, r24 loop counter (/4)  r25 initial carry

	movw	r30,r14		//result +=
	movw	r26,r16		// T
	movw	r28,r16
	adiw	r28,32		// S1
	movw	r12,r28		// used below
	clr	r25		// initial carry(s)
	ldi	r24,8		//(32/4)
	call	mpro_add2
// summarize carry
        adc     r25,r1
	subi	r25,-3	// initial carry (from 4x {256)
        mov	r3,r25
#endif
/*
// use T as TMP
  //s4 to TMP
  memset (ptr_l, 0, 3 * 4);
  memcpy (ptr_l + 3 * 4, ptr_l + 13 * 4, 3 * 4);
*/
	movw	r30, r16
	ldi	r18, 12
1:
	ldd	r0,Z+52		// memcpy (ptr_l + 3 * 4, ptr_l + 13 * 4,
	std	Z+12,r0
	st	Z+,r1		// memset (ptr_l, 0
	dec	r18
	brne	1b

	movw	r10,r30		// r16 + 12
	adiw	r30,12
	movw	r8,r30		// r16 + 24
// memcpy (ptr_l + 6 * 4, ptr_l + 13 * 4, 1 * 4);
// memcpy (ptr_l + 7 * 4, ptr_l + 8 * 4, 1 * 4);
	ldi	r24, 4
1:
	ldd	r0,Z+8		// ptr_l+8*4
	std	Z+4,r0		// ptr_l+7*4
	ldd	r0,Z+7*4	// ptr_l+13*4
	st	Z+,r0		// ptr_l+6*4
	dec	r24
	brne	1b

// result +=S4  carry += mp_add (result, (bignum_t *) ptr_l);
	movw	r22, r16
	movw	r24, r14
	call	bn_add
	add	r3, r24
/*
  // S2 to TMP
  memcpy (ptr_l + 0 * 4, ptr_l + 9 * 4, 7 * 4);
  // TMP += S2X
  mp_set_len (16);
  *(ptr_l + 7 * 4) = mp_shiftl ((bignum_t *) (ptr_l + 3 * 4));
  memset (ptr_l + 7 * 4 + 1, 0, 3);
*/
	movw	r30, r16
	ldi	r24, 12
1:
	ldd	r0, Z+36
	st	Z+, r0
	dec	r24
	brne	1b

	ldi	r24, 16
	clc
1:
	ldd	r0, Z+36
	rol	r0
	st	Z+, r0
	dec	r24
	brne	1b
	rol	r24

	st	Z+,r24
	st	Z+,r1
	st	Z+,r1
	st	Z+,r1

/*
  // TMP += S3
  mp_set_len (8);
  carry +=
    mp_add ((bignum_t *) (ptr_l + 6 * 4), (bignum_t *) (ptr_l + 14 * 4));
*/
	ldi	r24, 8
	sts	mod_len, r24	; 0x8022f1 <mod_len>

	movw	r22, r16	// +56
	subi	r22, 0xC8	; 200
	sbci	r23, 0xFF	; 255

	movw	r24, r8		// r16 + 24
	call	bn_add
	add	r3, r24
/*
  mp_set_len (32);
  // R += TMP
  carry += mp_add (result, (bignum_t *) bn);
*/
	ldi	r24, 32
	sts	mod_len, r24	; 0x8022f1 <mod_len>

	movw	r22, r16
	movw	r24, r14
	call	bn_add
	add	r3, r24
/*
  //S1x
  memset (ptr_l, 0, 12);
  memcpy (ptr_l+12, ptr_l + 32+12, 32-12);
  carry += mp_add (result, (bignum_t *) bn);
*/
	movw	r30,r16
	ldi	r24,12
1:
	st	Z+,r1
	dec	r24
	brne	1b

	ldi	r24,20
1:
	ldd	r0,Z+32
	st	Z+,r0
	dec	r24
	brne	1b

	movw	r22, r16
	movw	r24, r14
	call	bn_add
	add	r3, r24
/*
  //D3
  memset (ptr_l + 11 * 4, 0, 4);
  memcpy (ptr_l, ptr_l + 32, 12);
  carry -= mp_sub (result, result, (bignum_t *) (ptr_l + 20));
*/
	movw	r30, r16
	std	Z+44,r1
	std	Z+45,r1
	std	Z+46,r1
	std	Z+47,r1

	ldi	r24,12
1:
	ldd	r0, Z+32
	st	Z+, r0
	dec	r24
	brne	1b

	movw	r20, r16
	subi	r20, 0xEC	; 236
	sbci	r21, 0xFF	; 255
	movw	r22, r14
	movw	r24, r14
	call	bn_sub
	sub	r3, r24		// CARRY
/*
  //D4
  memset (ptr_l + 8 * 4, 0, 4);
  memset (ptr_l + 12 * 4, 0, 4);
  memcpy (ptr_l + 11 * 4, ptr_l + 3 * 4, 4);
  carry -= mp_sub (result, result, (bignum_t *) (ptr_l + 24));
*/

// D4 clear A8
	movw	r30,r16
	ldi	r24,4
	adiw	r30,12
1:
	std	Z+32-12,r1	// memset (ptr_l + 8 * 4
	std	Z+48-12,r1	// memset (ptr_l + 12 * 4
	ld	r0,Z+
	std	Z+44-12-1,r0
	dec	r24
	brne	1b
///
	movw	r20, r8		// r16 +24
	movw	r22, r14
	movw	r24, r14
	call	bn_sub
	sub	r3, r24
/*
  //D2
  memcpy (ptr_l + 10 * 4, ptr_l + 9 * 4, 4);
  memset (ptr_l + 9 * 4, 0, 4);
  carry -= mp_sub (result, result, (bignum_t *) (ptr_l + 16));
*/
	movw	r30, r16
	adiw	r30,36
	ldi	r24,4
1:
	ld	r0,Z		// memcpy
	std	Z+4,r0		// memcpy
	st	Z+, r1		// memset ..
	dec	r24
	brne	1b

	movw	r20, r16
	subi	r20, 0xF0	; 240
	sbci	r21, 0xFF	; 255
	movw	r22, r14
	movw	r24, r14
	call	bn_sub
	sub	r3,r24
/*
  //D1
  memset (ptr_l + 24, 0, 12);
  memcpy (ptr_l + 9 * 4, ptr_l, 4);
  memcpy (ptr_l + 10 * 4, ptr_l + 2 * 4, 4);
  carry -= mp_sub (result, result, (bignum_t *) (ptr_l + 12));
*/
	movw	r30, r16
	ldi	r24,4
1:
	std	Z+24,r1		// memset (ptr_l + 24, 0, 12);
	std	Z+28,r1
	std	Z+32,r1
	ldd	r0,Z+8		// memcpy (ptr_l + 10 * 4, ptr_l + 2 * 4, 4);
	std	Z+40,r0		// memcpy (ptr_l + 10 * 4, ptr_l + 2 * 4, 4);
	ld	r0,Z+		// memcpy (ptr_l + 9 * 4, ptr_l, 4);
	std	Z+35,r0		// memcpy (ptr_l + 9 * 4, ptr_l, 4);
	dec	r24
	brne	1b

	movw	r20, r10	// r16 + 12
	movw	r22, r14
	movw	r24, r14
	call	bn_sub
	sub	r3,r24

// repeat only carry byte is eliminated
// summarize
//     ( A7  || A6  || A5  || A4  || A3  || A2  || A1  || A0  )
// s1  (  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || A8  )
// s4  ( A8  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  )
// d1  (  0  || A8  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  )
// d3  (  0  ||  0  ||  0  ||  0  || A8  ||  0  ||  0  ||  0  )

// generate S1|S3 -  D1|D3              (| - binary or)
//          S1|S3 +  neg(D1|D3)
	mov	r4,r3		// copy
	mov	r5,r3		// copy
	com	r5		// for D1
	neg	r4		// for D3
	sbc	r2,r2		// expand
// correction of D1 (for r3 == 0) normaly this is not needed because
// D1 part is updated by carry propagation from (com(D1|D3) + 1)  = neg(D1|D3)
	and	r5,r2

	movw	r30,r16
	st	Z+,r3		//S1(A0)
	ldi	r24,11
1:
	std	Z+12,r2
	st	Z+,r1
	dec	r24
	brne	1b

// Z is at offset 12 ..
	std	Z+12-12,r4		// D3(A3)

	std	Z+24-12,r5		// D1(A6)
	std	Z+25-12,r2
	std	Z+26-12,r2
	std	Z+27-12,r2

	add	r3,r2
	std	Z+28-12,r3		// S4(A7)
	std	Z+29-12,r1
	std	Z+30-12,r1
	std	Z+31-12,r1

// r22 = r16, r24 = r14, field add ..
	movw	r22, r16
	rjmp	61f
//
52:
	cpi	r20, 0xB0
	breq	1f
	rjmp	53f
// r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20
// r21 r22 r23 r24 r25 r26 r27 r28 r29 r30 r31
;---------------------------------------------------------------
;secp256k1
/*
FAST REDUCTION for secp256k1 curve
p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
//code based on   http://cse.iitkgp.ac.in/~debdeep/osscrypto/psec/downloads/PSEC-KEM_prime.pdf

1. c0 = a[255:0];
2. c1 = a[511:256];

4. w1 = {c1[223:0], 32'd0};
5. w2 = {c1[246:0], 9'd0};
6. w3 = {c1[247:0], 8'd0};
7. w4 = {c1[248:0], 7'd0};
8. w5 = {c1[249:0], 6'd0};
9. w6 = {c1[251:0], 4'd0};

11. k1 = c1[255:252] + c1[255:250];
12. k2 = k1 + c1[255:249];
13. k3 = k2 + c1[255:248];
14. k4 = k3 + c1[255:247];

15. s1 = k4 + c1[255:224];

16. k11 = {s1, 2'd0} + {s1, 1'd0} + s1;
17. k12 = {k11, 7'd0};
18. k13 = {s1, 4'd0} + s1;
19. k14 = {s1, 6'd0} + k13;
20. k = {s1, 32'd0} + k12 + k14;

21. s = c0 + c1 + k + w1 + w2 + w3 + w4 + w5 + w6;
22. Return s mod p.
(code below with small optimizations)


*/

secp256k1_rot_helper:
	lsr	r24
	ror	r23
	ror	r22
	ror	r21
	ror	r20
	ror	r19
	ret
secp256k1_add_helper:
	add	r2,r19
	adc	r3,r20
	adc	r4,r21
	adc	r5,r22
	adc	r12,r23
	adc	r13,r24
	ret
1:
	movw	r30, r24	// result
        movw    r28, r22	// source
/*
  acc = bn->value[63];
  k1 = acc >> 4;
  k1 += acc >> 2;
  k1 += (acc >> 1);
  k1 += acc;
*/

// load c1[255:224]
	ldd	r5,Y+63
	ldd	r4,Y+62
	ldd	r3,Y+61
	ldd	r2,Y+60

	movw	r24,r4		//r25 = c1[255:248]

	mov	r21,r5
	lsr	r21		//c1[255:249]
	mov	r20,r21
	lsr	r20		//c1[255:250]
	add	r21,r20		//c1[255:249] + c1[255:250]
	lsr	r20
	lsr	r20		//c1[255:252]
	add	r21,r20		//c1[255:249] + c1[255:250] + c1[255:252] // max 205

	lsl	r24
	rol	r25
	clr	r24
	rol	r24		//c1[255:247]

	add	r25,r5		//c1[255:247] + c1[255:248]
	adc	r24,r1

	add	r25,r21		//c1[255:247] + c1[255:248] + c1[255:249] + c1[255:250] + c1[255:252]
	adc	r24,r1
// k4 ok

// s1 = c1[255:224] + k4
	add	r2,r25
	adc	r3,r24
	adc	r4,r1
	adc	r5,r1

	clr	r10
	adc	r10,r1
// s1 in r10,5,4,3,2
/*
33 bit in S1 is represented  as | .... .... .... .... .... .... .... ....

summarize by next diagram:
                                          | .... .... .... .... .... .... .... .... A
                                     | .... .... .... .... .... .... .... .... 0000 B
                                   |.. .... .... .... .... .... .... .... ..00 0000 C
                                  |... .... .... .... .... .... .... .... .000 0000 D
                                | .... .... .... .... .... .... .... .... 0000 0000 E
                               |. .... .... .... .... .... .... .... ...0 0000 0000 F
  | .... .... .... .... .... .... .... .... 0000 0000 0000 0000 0000 0000 0000 0000 G
r10   r9         r8       r7         r6        r5        r4        r3         r2
*/

// copy
	mov	r24,r10
	movw	r22,r4
	movw	r20,r2
	clr	r19

// concatenate A, G bit 32 from A is not added!!!
	movw	r6,r2
	movw	r8,r4
// bit 32 from A
	mov	r12,r10		// bits 39..32 to be added to r10..r6
	clr	r13

// E
	rcall	secp256k1_add_helper
// F(1)
	rcall	secp256k1_add_helper
// F(2)
	rcall	secp256k1_add_helper
// D
	rcall	secp256k1_rot_helper
	rcall	secp256k1_add_helper
// C
	rcall	secp256k1_rot_helper
	rcall	secp256k1_add_helper
// B
	rcall	secp256k1_rot_helper
	rcall	secp256k1_rot_helper
	rcall	secp256k1_add_helper

// propagate carry
	add	r6,r12
	adc	r7,r13
	adc	r8,r1
	adc	r9,r1
	adc	r10,r1

/// r31:30 result
	movw	r16,r30

	st	Z+,r2
	st	Z+,r3
	st	Z+,r4
	st	Z+,r5
	st	Z+,r6
	st	Z+,r7
	st	Z+,r8
	st	Z+,r9
	st	Z+,r10
	ldi	r24,32-9
1:
	st	z+,r1
	dec	r24
	brne	1b
////////////////////////////////////// final K /////////////////////////////
// r29:28 - source
// r17:16 - result

//  mp_set_len (32);
//  mod_len is not changed in previous code ..

// c0
//  field_add (result, (bignum_t *) a);
	movw	r22, r28		// source
	movw	r24, r16		// result
	call	field_add
// c1
//  h = (bignum_t *) (a + 32);
//  field_add (result, h);

	movw	r22, r28	// source to r14
	subi	r22,lo8(-32)
	sbci	r23,hi8(-32)

	movw	r24, r16	// result
	call	field_add

 // w1
//  memset (a, 0, 4);
//  memcpy (a + 4, h, 28);
//  field_add (result, (bignum_t *) a);

	movw	r22,r28		// source
	st	Y+,r1
	st	Y+,r1
	st	Y+,r1
	st	Y+,r1

	ldi	r24, 28
1:
	ldd	r0, Y+32-4
	st	Y+, r0
	dec	r24
	brne	1b

// r28 now point to h

	movw	r24, r16	// result
	call	field_add
// w6   Hpart << 4
//  mp_shiftl4 (h);
//  field_add (result, h);
	movw	r24, r28	//h
	call	mp_shiftl4
	movw	r22, r28	//h
	movw	r24, r16	// result
	call	field_add
// w5   Hpart << 6
//  mp_shiftl2 (h);
//  field_add (result, h);
	movw	r24, r28	//h
	call	mp_shiftl2
	movw	r22, r28	//h
	movw	r24, r16	// result
	call	field_add
// W4   Hpart << 7
//  mp_shiftl (h);
//  field_add (result, h);
	movw	r24, r28	//h
	call	bn_shiftl
	movw	r22, r28	//h
	movw	r24, r16	// result
	call	field_add
// W3   Hpart << 8
//  mp_shiftl (h);
//  field_add (result, h);

	movw	r24, r28	// h
	call	bn_shiftl
	movw	r22, r28	// h
	movw	r24, r16	// result
	call	field_add

// W2   Hpart << 9
//  mp_shiftl (h);
//  field_add (result, h);
	movw	r24, r28	// h
	call	bn_shiftl

	movw	r22,r28		// h
	movw	r24,r16		// result

	rjmp	60f

53:
// do nistp192 reduction
//	cpi	r20, 0x50
//	brne	60f
;--------------------------------------------------------------------------
/*
 nist192p
 r14=r24 target, r16=r22 source
 T =  ( A2 || A1 || A0 )
 S1 = ( 0  || A3 || A3 )
 S2 = ( A4 || A4 || 0  )
 S3 = ( A5 || A5 || A5 )
 R =   T + S1 + S2 + S3
*/

// T = T + diagonal
	subi	r22, lo8(-24)
	sbci	r23, hi8(-24)
	movw	r24, r16

	call	field_add
// create:
// in target 0 || A5 || 0
// in source A4||A3||A5
	ldi	r24, 8
	movw	r30, r14	// target
	movw	r26, r16	// source
	adiw	r26,40		// A5 part
1:
	ld	r0,x+		// A5 part source
	std	Z+8,r0		// target A5
	std	Z+16,r1		// target 0
	st	Z+, r1		// target 0
	dec	r24
	brne	1b

// into target  (T+diagonal) + 0||A5||0
	movw	r24,r14		// target
	movw	r22,r16		// source
	call	field_add

// overwrite A2 by A5, add to target
	ldi	r24,8
	movw	r30,r16		// source
	adiw	r30,16		// A2 part
	movw	r22,r30		// address of A4 || A3 || A5
1:
	ldd	r0,Z+24		// A5 part
	st	Z+,r0
	dec	r24
	brne	1b

61:
	movw	r24, r14	// target
60:
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
65:
	jmp	field_add
