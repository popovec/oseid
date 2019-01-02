/*
    aes.S

    This is part of OsEID (Open source Electronic ID)

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

    AES(128,192,256) enc/dec routines for atmega/xmega 

This version of AES is designed for minimal flash space.  The design of the
algorithm does not make the speed as important for this code. Key is
expanded in RAM, minimum RAM needed in this version is about 270 bytes of
RAM. You can select from three version of this code:

1. SBOX calculation on fly - very slow, no secure! but very small code
   FLASH: 604, RAM about 280 bytes
2. SBOX in FLASH - lot of flash vasted by sboxes ..  good speed of execution.
   FLASH: 1036, RAM about  280 bytes
3. SBOX in RAM - small code but wasted lot of RAM.. good speed of execution
   one round = 16 bytes - below 40000 clock cycles for 256bit aes KEY .
   FLASH: 598 bytes, RAM: about 800 BYTES

There exist version of this code with minimal RAM usage (key is expanded on
fly, sbox in flash or calculated on fly), please check aes_smallram.S

*/

//#define AES_FLASH_SBOX
#define AES_RAM_SBOX
//#define AES_ONFLY_SBOX


#if !defined(AES_FLASH_SBOX) && !defined(AES_RAM_SBOX) && !defined (AES_ONFLY_SBOX)
#define AES_ONFLY_SBOX
#endif

#ifdef AES_ONFLY_SBOX
#ifdef AES_RAM_SBOX
#error Both AES_ONFLY_SBOX and AES_RAM_SBOX defined!
#endif
#ifdef AES_FLASH_SBOX
#error Both AES_ONFLY_SBOX and AES_FLASH_SBOX defined!
#endif
#warning This code is slow and there exist side channel that allow expose key!
#endif

#if defined(AES_FLASH_SBOX) && defined(AES_RAM_SBOX)
#error Both AES_FLASH_SBOX and AES_RAM_SBOX  defined
#endif


////////////////////////////////////////////////////////////////////////////////
#if defined (AES_FLASH_SBOX) //|| defined (AES_RAM_SBOX)

sbox_data:
.byte 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
.byte 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0
.byte 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15
.byte 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75
.byte 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84
.byte 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf
.byte 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8
.byte 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2
.byte 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73
.byte 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb
.byte 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79
.byte 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08
.byte 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a
.byte 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e
.byte 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf
.byte 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16

sbox_inv_data:
.byte 0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb
.byte 0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb
.byte 0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e
.byte 0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25
.byte 0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92
.byte 0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84
.byte 0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06
.byte 0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b
.byte 0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73
.byte 0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e
.byte 0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b
.byte 0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4
.byte 0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f
.byte 0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef
.byte 0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61
.byte 0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d

rj_sbox:
	movw	r22,r30
	ldi	r30,lo8(sbox_data)
	ldi	r31,hi8(sbox_data)
L_sbox_calc:
	add	r30,r24
	adc	r31,r1
	lpm	r24,Z
	movw	r30,r22
	ret

rj_sbox_inv:
	movw	r22,r30
	ldi	r30,lo8(sbox_inv_data)
	ldi	r31,hi8(sbox_inv_data)
	rjmp	L_sbox_calc
#endif
#ifdef AES_RAM_SBOX
rj_sbox:
rj_sbox_inv:
	movw    r22,r30
	movw	r30,r16
	add	r30,r24
	adc	r31,r1
	ld	r24,Z
	movw	r30,r22
	ret
#endif
#ifdef AES_ONFLY_SBOX
rj_sbox_inv:
	ldi     r25, 0x63
	eor     r25, r24
	add     r25, r25
	adc     r25, r1
	mov     r23, r25
	add     r23, r23
	adc     r23, r1
	add     r23, r23
	adc     r23, r1
	mov     r24, r23
	eor     r24, r25
	swap    r23
#if 0
	bst     r23, 0
	ror     r23
	bld     r23, 7
#else
	mov	r25,r23
	ror	r25
	ror	r23
#endif
	eor     r24, r23
/*
  y = x ^ 0x63;
  sb = y = (uint8_t) (y << 1) | (y >> 7);
  y = (uint8_t) (y << 2) | (y >> 6);
  sb ^= y;
  y = (uint8_t) (y << 3) | (y >> 5);
  sb ^= y;

*/
// continue in gf_mulinv...

gf_mulinv:
	tst r24
	breq 4f

// constant for rj_xtime
	ldi	r25,0x1b
// calculate gf_log  
	mov	r23,r24	//X in r23
	clr	r22	//I in r24
// loop init
	ldi	r24,1	//Y in r22
1:			//loop
	inc	r22
	rcall	L_xor_rj_xtime
	cp      r24,r23
	brne	1b
	mov	r23,r22

//
// gf_log in r23 ..
//	com	r23	// r23 = (255 - gf_log (x))
//	inc	r23
	neg	r23	// r23 = (256 - gf_log (x))
// calculate gf_alog  from r23

	ldi	r24,1	//Y in r24
3:
	subi	r23,1
	breq	4f
	rcall	L_xor_rj_xtime
	rjmp	3b
4:
	ret
L_xor_rj_xtime:
// copy
	mov	r21,r24
// rj_xtime (y);
	lsl	r24
	brcc	.+2
	eor	r24,r25
// Y ^= rj_xtime (y);
	eor	r24,r21	// new Y = new Y  xor old Y
	ret

rj_sbox:
	rcall gf_mulinv	
	mov	r23,r24	//      y
#if 0
	lsl	r23
	adc	r23,r1
	eor	r24,r23
	lsl	r23
	adc	r23,r1
	eor	r24,r23
	lsl	r23
	adc	r23,r1
	eor	r24,r23
	lsl	r23
	adc	r23,r1
	eor	r24,r23

	ldi	r23,0x63
	eor	r24,r23
	ret
#else
	rcall	L_rj_sbox_helper
	ldi	r23,0x63
	eor	r24,r23
	ret
L_rj_sbox_helper:
	rcall	1f
1:	rcall	2f
2:
	lsl	r23
	adc	r23,r1
	eor	r24,r23
	ret
#endif
#endif
////////////////////////////////////////////////////////////////////////////////

//clamp r25..r20
aes_subBytes:
	ldi	r20,16
1:
	ld	r24,Y
	rcall 	rj_sbox
	st	Y+,r24
	subi	r20,1
	brne 	1b
L_restore_STATE_pointer:
	sbiw	r28,16	//restore STATE pointer
	ret 

//clamp r25..r20
aes_subBytes_inv:
	ldi	r20,16
1:		
	ld	r24,Y
	rcall 	rj_sbox_inv
	st	Y+,r24
	subi	r20,1
	brne 	1b
	rjmp	L_restore_STATE_pointer

// clamp r25,r24
aes_shiftRows:
	ldd	r24, Y+1
	ldd	r25, Y+5
	std	Y+1, r25
	ldd	r25, Y+9
	std	Y+5, r25
	ldd	r25, Y+13
	std	Y+9, r25
	std	Y+13, r24
/*
	ldd	r24, Y+10
	ldd	r25, Y+2
	std	Y+10, r25
	std	Y+2, r24
*/
	ldd	r24, Y+3
	ldd	r25, Y+15
	std	Y+3, r25
	ldd	r25, Y+11
	std	Y+15, r25
	ldd	r25, Y+7
	std	Y+11, r25
	std	Y+7, r24
	rjmp	L_aes_shift_end

// clamp r25,r24
aes_shiftRows_inv:
	ldd	r24, Y+1
	ldd	r25, Y+13
	std	Y+1, r25
	ldd	r25, Y+9
	std	Y+13, r25
	ldd	r25, Y+5
	std	Y+9, r25
	std	Y+5, r24
/*
	ldd	r24, Y+2
	ldd	r25, Y+10
	std	Y+2, r25
	std	Y+10, r24
*/
	ldd	r24, Y+3
	ldd	r25, Y+7
	std	Y+3, r25
	ldd	r25, Y+11
	std	Y+7, r25
	ldd	r25, Y+15
	std	Y+11, r25
	std	Y+15, r24

L_aes_shift_end:
	ldd	r24, Y+2
	ldd	r25, Y+10
	std	Y+2, r25
	std	Y+10, r24

	ldd	r24, Y+14
	ldd	r25, Y+6
	std	Y+14, r25
	std	Y+6, r24
	ret

////////////////////////////////////////////////////////////////////////////////
//
// mix columns and mix columns inv
//
////////////////////////////////////////////////////////////////////////////////
// INPUT r29,r28
// CLAMP r27,r26,r25,r24,r23,r22,r21,r20

aes_mixColumns:
// number of loops
	ldi	r18,4
// constant
	ldi	r25,0x1b
// loop
1:
	rcall	L_mix_C_helper0	
	mov	r27,r26			// r26 = r27 = E
	rcall	L_mix_C_helper1
	brne	1b	  
	rjmp	L_restore_STATE_pointer

aes_mixColumns_inv:
// number of loops
	ldi	r18,4
// constant
	ldi	r25,0x1b
// loop
1:
	rcall	L_mix_C_helper0

	push	r26	//E 
// calculate Y = rj_xtime (e);
	mov	r24,r26
	rcall	3f		// rj_xtime

	mov	r27,r24	//Y

// final X = e ^ rj_xtime (rj_xtime (z ^ a ^ c));
	eor	r24,r20	//  ^a
	eor	r24,r22	//    ^ c
	rcall	2f	// rj_xtime(rj_xtime())
	eor	r26,r24	

// final y = e ^ rj_xtime (rj_xtime (z ^ b ^ d));
	eor	r27,r21	//  ^b
	eor	r27,r23	//    ^ d
	mov	r24,r27	
	rcall	2f	// rj_xtime(rj_xtime())
	pop	r27
	eor	r27,r24

	rcall 	L_mix_C_helper1
	brne	1b
	rjmp	L_restore_STATE_pointer

L_mix_C_helper0:
/*
	 a = state[i + 0];		// r20
	 b = state[i + 1];		// r21
	 c = state[i + 2];		// r22
	 d = state[i + 3];		// r23
	 e = a ^ b ^ c ^ d;	// r26
*/
	ldd	r20,Y+0
	ldd	r21,Y+1
	ldd	r22,Y+2
	ldd	r23,Y+3

	mov	r26,r23
	eor	r26,r22
	eor	r26,r21
	eor	r26,r20
	ret
	
L_mix_C_helper1:
/*
// x =r26, y=r27
	 state[i + 0] ^= x ^ rj_xtime (a ^ b);
	 state[i + 1] ^= y ^ rj_xtime (b ^ c);
	 state[i + 2] ^= x ^ rj_xtime (c ^ d);
	 state[i + 3] ^= y ^ rj_xtime (d ^ a);
*/
	mov	r24,r20
	eor	r24,r21	// a^ b
	rcall	3f
	eor	r24,r26
	eor	r24,r20
	st	Y+,r24

	mov	r24,r21	// b^ c
	eor	r24,r22	
	rcall	3f
	eor	r24,r27
	eor	r24,r21
	st	Y+,r24

	mov	r24,r22
	eor	r24,r23
	rcall	3f
	eor	r24,r26
	eor	r24,r22
	st	Y+,r24

	mov	r24,r20
	eor	r24,r23
	rcall	3f
	eor	r24,r27
	eor	r24,r23
	st	Y+,r24

	dec	r18
	ret

2:	rcall	3f
3:	
L_rj_xtime_helper:
	lsl	r24
	brcc	.+2
	eor	r24,r25
	ret

aes_addDecKey:
	sbiw	r30,32
aes_addEncKey:
	ldi	r20,16
1:
	ld	r24,Z+
	ld	r25,Y
	eor	r25,r24
	st	Y+,r25
	dec	r20
	brne	1b
	rjmp	L_restore_STATE_pointer

#ifdef AES_RAM_SBOX
L_sbox_helper:
#if 0
	lsl	r21
	adc	r21,r1
	eor	r24,r21
	lsl	r21
	adc	r21,r1
	eor	r24,r21
	lsl	r21
	adc	r21,r1
	eor	r24,r21
	lsl	r21
	adc	r21,r1
	eor	r24,r21
	ret
#else
	rcall	1f
1:	rcall	2f
2:
	lsl	r21
	adc	r21,r1
	eor	r24,r21
#endif
	ret
#endif
//////////////////////////////////////////////////////////////////////////
#define RCON r19
// r19 can be reused after key expansion
#define ROUND r19
#define KEYSIZE r18
// r18 is reused in mix columns

	.global aes_run
	.type   aes_run, @function

aes_run:
	bst	r18,0
L_aes_init:
#ifdef AES_RAM_SBOX
	push	r16
	push	r17
#endif
	push	r28
	push	r29

	movw	r28,r24	// STATE pointer in Y

// allocate space on stack
// plase read load_sp.h about SPL/SPH update

	in	r31,0x3e
#ifdef AES_RAM_SBOX
	subi	r31,3
#else
	subi	r31,1
#endif
	out	0x3e, r31
	in	r30,0x3d
	adiw    r30,1		// 1st free byte in stack

#ifdef AES_RAM_SBOX
// stack organization:
// alog      log    xxxx
// key       sbox,  inv sbox

// Precalculate SBOX/INVERSE SBOX into RAM
	movw	r18,r30 //alog table
	movw	r16,r30	// copy log table address
	inc	r17
	clr	r0	//i
	ldi	r24,1	//t
	ldi	r25,0x1b	
// Z point to alog table
1:
//alog[i] = t;
	st	Z+,r24
//log[t] = i
	movw	r26,r16	// log table start
	add	r26,r24
	adc	r27,r1
	st	X,r0
//
	mov	r21,r24
	rcall	L_rj_xtime_helper
	eor	r24,r21
//
	inc	r0
	brne	1b
// Z now point to log table (log table is reused as gf_mulinv table)
// gf inv mod:
// = (x) ? gf_alog (255 - gf_log (x)) : 0;
// at 1st position in gf_mulinv is 0:
	clr	r24
	ldi	r25,0x63
2:
	mov	r21,r24
	rcall	L_sbox_helper
	eor	r24,r25
//inv SBOX
	movw	r26,r18
	subi	r27,-2
	add	r26,r24
	adc	r27,r1
	st	X,r0
//SBOX
	st	Z+,r24

// get next value from log,alog -> calculate gf_mulinv
	ld	r24,Z	// log table
	com	r24
	movw    r26,r18	// alog table
	add	r26,r24
	adc	r27,r1
	ld	r24,X

	inc	r0
	brne	 2b

	movw	r30,r18
#endif
	mov	KEYSIZE,r20
////////////////////////////////////////////////////////////////
// AES expand key in RAM
////////////////////////////////////////////////////////////////
	movw	r26,r22	// KEY address in X
	movw	r22,r30	// Z - space for key expansion
// copy key into ram
1:
	ld	r0,X+
	st	Z+,r0
	dec	r20
	brne	1b
	ldi	RCON,1	// RCON
// expansion
// byte counter
	mov	r0,KEYSIZE
	movw	r26,r22	// pointer to expanded keys in RAM
	sbiw	r30,4	// 1st key  - last 4 bytes
4:
	ldd	r24,Z+1
	rcall	rj_sbox
	ld	r25,X+
	eor	r25,r24
	eor	r25,RCON	//RCON
	std	Z+4,r25

	ldd	r24,Z+2
	rcall	rj_sbox
	ld	r25,X+
	eor	r25,r24
	std	Z+5,r25

	ldd	r24,Z+3
	rcall	rj_sbox
	ld	r25,X+
	eor	r25,r24
	std	Z+6,r25

	ldd	r24,Z+0
	rcall	rj_sbox
	ld	r25,X+
	eor	r25,r24
	std	Z+7,r25

	adiw	r30,4
// xor (to key end, but for 256 bits key  more procesing is needed)
	ldi	r23,12
	sbrc	KEYSIZE,3	//24/16 bytes key
	ldi	r23,20
// xor loop
1:
	ld	r24,X+
	ld	r25,Z+
	eor	r25,r24
	std	Z+3,r25
	dec	r23
	brne	1b
// test  for 256 bit key
	sbrs	KEYSIZE,5
	rjmp	3f

// ok 256 bit key
	ldi	r20,16
// xor loop
2:
	ld	r24,Z+
// for 1st 4 bytes apply sbox ..
	cpi	r20,13
	brcs	.+2
	rcall 	rj_sbox

	ld	r25,X+
	eor	r25,r24
	std	Z+3,r25
	dec	r20
	brne	2b
3:
// rj_xtime
	ldi	r20,0x1b
	lsl	RCON	// RCON
	brcc	.+2
	eor	RCON,r20	// RCON ^ r20

	add	r0,KEYSIZE
	breq	5f
	mov	r20,r0
	cpi	r20,239
	brcs	4b
5:
///////////////////////////////////////////////////////////
// AES expand key in RAM  END
///////////////////////////////////////////////////////////
#ifdef AES_RAM_SBOX
	movw	r30,r16
	dec	r31
#else
	in	r30,0x3d
	in	r31,0x3e
	adiw	r30,1
#endif
// calculate rounds
	mov	r20,KEYSIZE
	lsr	r20
	lsr	r20
	subi    r20, 0xFB
	mov	ROUND, r20
	brts	L_aes_decrypt

L_aes_encrypt:
	rcall	aes_addEncKey
1:
	rcall	aes_subBytes
	rcall	aes_shiftRows
	subi	ROUND,1
	brcs	2f

	rcall	aes_mixColumns
	rcall	aes_addEncKey
	rjmp 	1b
2:
	rcall	aes_addEncKey
	rjmp	L_aes256_end

L_aes_decrypt:
#ifdef AES_RAM_SBOX
	inc	r17	// move r16 to INV_SBOX table
#endif
	mov	r20,ROUND
	subi	r20,-3
//// attiny is without HW multipier
1:
	adiw	r30,16
	dec	r20
	brne	1b

	rcall	aes_addDecKey
2:
	rcall	aes_shiftRows_inv
	rcall	aes_subBytes_inv
	subi	ROUND,1
	brcs	3f

	rcall	aes_addDecKey
	rcall	aes_mixColumns_inv
	rjmp	2b
3:
	rcall	aes_addDecKey
L_aes256_end:

	in	r31,0x3e
#ifdef AES_RAM_SBOX
	subi	r31,-3
#else
	subi	r31,-1
#endif
	out	0x3e,r31

	pop	r29
	pop	r28
#ifdef AES_RAM_SBOX
	pop	r17
	pop	r16
#endif
	ret
