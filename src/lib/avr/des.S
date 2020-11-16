/*
    des.S

    DES and 3DES cipher implementation for 8 bit AVR (attiny/atmega)

    This is designed to be a part of OsEID (Open source Electronic ID)
    https:/oseid.sourceforge.io

    Copyright (C) 2017,2019 Peter Popovec, popovec.peter@gmail.com

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

    DES cipher implementation for 8 bit AVR (attiny/atmega)
    -------------------------------------------------------

    Code is designed to be small, with minimal RAM usage, only 15 or 16 bytes 
    in stack, (depends on PC size), + 18 bytes in stack if C ABI is needed).
    Flash size: 800 bytes (inclusive C ABI). Speed below 49900 clock cycles
    for encrypt or decrypt 8 bytes in ECB mode. (C version about 177300)

    With enabled 3DES implementation - flash size 828 bytes, DES below 49900
    clock cycles, 3DES below 149500 clock cycles.  Two more bytes is needed
    in RAM if 3DES is enabled.

    Code is modified, does not use standard permutations as described by DES
    original (NIST) description.

    Message expansion (E), Permuted choice 1 (PC-1) and Permuted choice 2
    (PC-2) are merged into one 56 bit long message expansion.  This expanded
    message is directly XORed by plain key.  S-box addresses are selected from
    result of XOR operation by table.  S-boxes are merged to one table (256
    bytes).

    Initial and inverse initial permutation is done by procedures. Key
    expansion is in procedure too. Only permutation (P) is unchanged.

    Permutation tables are converted to get fast implementation on AVR. 
    (SHIFT instruction to rotate 4 bits in one step).

    Please check C version if some of ASM code is not self explained.

    WARNING! code uses 'lpm' not 'elpm' instruction to access tables. For
    bootloaders in address space over 64kiB set RAMPZ and use 'elpm'!

    WARNING! inverse initial permutation is not real inverse of initial
    permutation!  (to save some bytes in FLASH).  This is no problem for
    DES, but due this, 3DES version must call initial and inverse initial
    permutation more times. This adds about 1820 clock cycles. Define
    DES3FAST to eliminate this, code size is then 838 bytes.

    If you need conversion from 56 to 64 bit DES key, 28 more bytes is used
    in flash

*/

// undef this to save 6 bytes of FLASH, code is ten slower (about 59000
// clock cycles per one DES operation)
#define DES_ROT_FAST

// enable 3DES code (enable only one - DES3 or DES3FAST)
#define DES3
//#define DES3FAST
/*
 data = 8 bytes, this data is to be decrypt/encrypt, result comes here too

 key  = DES:  8 bytes (bit 0 is parity bit, same format as for openssl)
        3DES: 24 bytes (EDE mode)

 mode:  (plase use values from des.h)
         0 (DES_ENCRYPTION_MODE)            =>  DES encrypt
         3 (DES_DECRYPTION_MODE)            =>  DES decrypt
       0xc (DES_ENCRYPTION_MODE | DES_3DES) => 3DES encrypt
       0xf (DES_DECRYPTION_MODE | DES_3DES) => 3DES decrypt

 void des_run (uint8_t *data, uint8_t *key, uint8_t mode);
*/

#if ENABLE_DES56
	.global des_56to64
	.type	des_56to64, @function

// convert 56 bit key to 64 bit key (insert fake parity bits)
#if 0
// long version ..
des_56to64:
	movw	r26,r24
	ld	r24,X+
	ld	r23,X+
	ld	r22,X+
	ld	r21,X+
	ld	r20,X+
	ld	r19,X+
	ld	r18,X+
	ldi	r25,pm_lo8(des_l+14)
	ldi	r30,pm_lo8(des_l)
	ldi	r31,pm_hi8(des_l)
des_l:	rol	r18
	rol	r19
	rol	r20
	rol	r21
	rol	r22
	rol	r23
	rol	r24
	adiw	r30,1
	cpse	r30,r25
	ijmp

	st	x,r18
	st	-x,r19
	st	-x,r20
	st	-x,r21
	st	-x,r22
	st	-x,r23
	st	-x,r24
	ret
#else
// short version
des_56to64:
	movw	r30,r24
	adiw	r30,7
	ldi	r24,7
1:
	ld	r22,-Z
	ldd	r23,Z+1
	mov	r25,r24
2:
	ror	r22
	ror	r23
	dec	r25
	brne	2b

	std	Z+1,r23
	dec	r24
	brne	1b
	ret
#endif
#endif

        .global des_run
        .type   des_run, @function


// WARNING this function can be used in two modes:
// oneshot: set bit 7 in r24
//          Z = permutation table
//          result is in r22
// loop mode:
//          r24 set by macro PERM_END - number of bytes
//          X - position of result string
// clobber 22,23,24,25,r28,r29
// input position is coded in permutation table
// only reg 0..r15 can be used as input!

// number of loops (macro) - half carry is used to test loop end
// because full carry (C) or (M) is used to test one shot mode
#define PERM_END(a)	(0x1f+a)
des_permute_loop:
// XOR byte into result
	ld	r25,X
	eor	r22,r25
        st      X+,r22
	brhs	des_permute_end
des_permute:
        ldi     r22,0x80        // counter/byte result (test C bit after ROR.. )
des_permute_byte:
        lpm     r28,Z+          // load data from permutation table
        mov     r25,r28         // copy
        andi    r28,0x0f        // byte offset in FROM
        ld      r23,Y           // load byte, rotate to get selected bit into C
	sbrc	r25,4
	swap	r23
// rotate byte
#ifndef DES_ROT_FAST
des_permute_byte_rotation:
	subi	r25,(-0x20)	// test carry to bit 7
        rol     r23
        sbrs    r25,7
        rjmp    des_permute_byte_rotation
#else
	sbrs	r25,6
	rol	r23
	sbrs	r25,6
	rol	r23
	sbrs	r25,5
	rol	r23
	rol	r23
#endif
// store bit into result
        ror     r22
        brcc    des_permute_byte
// if bit 7 in R24 is set, do return, result byte in r22, no pointer in X is used
	subi	r24,1
	brpl	des_permute_loop
des_permute_end:
	ret

des_rot:
// one or two rotations
	sbrs    r25,0
	rcall	des_rot1
des_rot1:
// left or right rotation
	sbrc	r0,1
	rjmp	des_rot_r
des_rot_l:
	bst	r4,3
	rol	r1
	bld	r1,0
	bst	r7,7
	rol	r2
	rol	r3
	rol	r4
	rol	r5
	rol	r6
	rol	r7
	bld	r4,4
	ret

des_rot_r:
	bst	r4,4
	ror	r7
	bld	r7,7
	bst	r1,0
	ror	r6
	ror	r5
	ror	r4
	ror	r3
	ror	r2
	ror	r1
	bld	r4,3
	ret


des_run:
//////////////////////////////////////////////////
// save registers
.irp	reg,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,28,29
	push	\reg
.endr
// save encrypt/decrypt, des/3des mode ..
	mov	r0,r20
// key position
	movw	r30,r22
// data position
	movw	r26,r24	// from
#ifdef DES3
// adjust key position for 3des
	cpi	r20,15
	brne	des3_loop
	adiw	r30,16
des3_loop:
#endif
// save position of data (result)
	push	r26
	push	r27
#ifdef DES3FAST
// adjust key position for 3des
	cpi	r20,15
	brne	.+2
	adiw	r30,16
#endif
//Initial message permutation - permuted message in r12..r19
	clr	r29	 //r29 is ZERO in rest DES algo
	ldi	r28,12
	mov	r24,r26
des_ip_loop1:
        adiw    r26,8
	
des_ip_loop2:
        ld      r1,-X
        rol     r1      // tmp
        rol     r20     // byte A
        rol     r1      // tmp
        rol     r21     // byte B
        st      X,r1
        cp	r26,r24
        brne    des_ip_loop2

        std     Y+4,r21
        st      Y+,r20
        cpi	r28,16
        brne    des_ip_loop1
//////////////////////////////////////////////////
//--------------------------------------------------------------------------------------
// r22,23 key position
// r12..r19 permuted message
// r29 is ZERO
#ifdef DES3FAST
des3_loop:
#endif
// permute key
	ldi	r27,8
//
des_key_perm0:
	ld	r25,Z+
	ldi	r28,1
des_key_perm1:
	ld	r24,Y
	rol	r25
	ror	r24
	st	Y+,r24
	cpi	r28,8
	brne	des_key_perm1
	dec	r27
	brne	des_key_perm0
#if defined (DES3) || defined (DES3FAST)
// save key position
	push	r30
	push	r31
#endif
// convert key to get one 56 bit key for simple
// rotate operation

// first swap r1,r3, then swap nibbles in r4
	eor	r3,r1
	eor	r1,r3
	eor	r3,r1
	swap	r4
// r0 flag, r1-r7 key , r8..r11 free r12..r19 DATA r20..r31 working
//
// prerotation
	sbrc	r0,1
	rcall	des_rot_l
//////////////////////////////////////////////////
// here is main DES loop (16x)

// r27 is always zero in rest of code..
// r29 is always zero in rest of code..

// shift size (per bit,1/2 rotations, if all bits==0, this is loop end
	ldi	r24,0x81
	ldi	r25,0x03
//////////////////////////////////////////////////
des_loop:
////////////////////
	rcall	des_rot
// save shift size
	push	r24
	push	r25
//////////////////////////////////////////////////
// save KEY to stack, we need more registers
.irp	reg,1,2,3,4,5,6,7
	push	\reg
.endr
//////////////////////////////////////////////////
// permute R message part (in r12..15), expand to 56 bites not 48!
// XOR with key in r1..r7 (input position coded in permutation table)
// permutation table
	ldi	r30,lo8(PERM_MSG)
	ldi	r31,hi8(PERM_MSG)
// 8 bytes
	ldi	r24,PERM_END(7)
// result position
	ldi	r26,1	// result to r1..7
//	clr	r27	// cleared above, not changed
	rcall	des_permute

// save part of L into stack (to save some ticks in next loop)
	push	r14
	push	r15
//////////////////////////////////////////////////
// from key XORed with expanded message part create adresses into S-boxes
// use addresses to get nibbless
// sbox offset
	ldi	r20,3
// Flag in bit 7 in r24 for "permute" subroutine for oneshot mode
// Beware, permute decrement R24, and bit 0 is used in next code
// to get odd/even loop
	ldi	r24,0x89
// permutation table  (already in r30,31 by increment r30,31 in "permute")
//	ldi	r30,lo8(PERM_S_ADDR)
//	ldi	r31,hi8(PERM_S_ADDR)
// RESULT pointer in X (reg 8..11) - already in X (from previous permute)
// this is not for permute subroutine, bit 7 in reg r24 is set!
// FROM: read perm data from r1..r7 (input position coded in permutation table)
get_sbox_loop0:
	ldi	r22,0x20	// only 6 bits
	rcall	des_permute_byte
// do not change r30,31
	movw	r14,r30		//save Z
// load s-box offset
	or	r22,r20	// sbox offset
	ldi	r30,lo8(S_BOX)
	ldi	r31,hi8(S_BOX)
	add	r30,r22
	adc	r31,r27	//zero
// test odd/even round
	sbrs    r24,0
	rjmp	get_sbox_le0
	andi	r21,0xf0
	lpm	r28,Z+
	andi	r28,0x0f
	or	r28,r21
	st	X+,r28
// move to next sbox .. 
	dec	r20
get_sbox_le0:
// for odd and even round preload r18
        lpm     r21,Z+
// renew position in permutation table
	movw	r30,r14	//renew Z
	brpl	get_sbox_loop0
//////////////////////////////////////////////////
// R (r12,r13,stack,stack)  L (r16..r19),
// swap R , L
	movw    r20,r16
	movw	r14,r18

	pop	r19
	pop	r18
	movw	r16,r12
	movw	r12,r20

// permute data from S-box, XOR with old L into new R
// set from (only 8 bit value!)
// permutation table (already in r30,31 by increment r30,31 in "permute")
//	ldi	r30,lo8(PERM_R)
//	ldi	r31,hi8(PERM_R)
// input data r8..r11 (input position coded in permutation table)
// 4 bytes
	ldi	r24,PERM_END(4)
// result position (already in X)
//	clr	r27		// cleared above, not changed
	rcall	des_permute

//////////////////////////////////////////////////
// renew KEY
.irp    reg,7,6,5,4,3,2,1
        pop     \reg
.endr

//////////////////////////////////////////////////
// loop end

// load shift size
	pop	r25
	pop	r24
	lsr	r24
	ror	r25
// test main loop end
	brne	des_loop
//////////////////////////////////////////////////
//--------------------------------------------------------------------------------------
#if defined(DES3) || defined(DES3FAST)
// renew key
	pop	r31
	pop	r30
// adjust key position for 3DES decrypt
	sbrc	r0,0
	sbiw	r30,16
#endif
#ifdef DES3FAST
	ldi	r24,6
	sub	r0,r24
	brcs	des3_end
// convert result for next 3des loop
// (because not standard inverse initial permutation)
	movw	r2,r12
	movw	r12,r16
	movw	r16,r2
	movw	r2,r14
	movw	r14,r18
	movw	r18,r2
	rjmp	 des3_loop
des3_end:
#endif
// result position
	pop	r27
	pop	r26
// L,R position
// inverse initial permutation
	ldi	r24,8   //count
//	clr	r29		// cleared above, not changed
iip_loop1:      
	ldi	r28,12
iip_loop2:
	ldd	r25,Y+4
	ror	r25
	std	Y+4,r25
	rol	r22
	ld	r25,Y
	ror	r25
	st	Y+,r25
	rol	r22
	cpi	r28,16
	brne	iip_loop2

	st	X+,r22
	dec	r24
	brne	iip_loop1
#ifdef DES3
// move result position back
	sbiw	r26,8
	ldi	r24,6
	sub	r0,r24
	brcs	.+2
	rjmp	 des3_loop
#endif
//////////////////////////////////////////////////
// restore registers, clear r1 to conform C ABI
.irp	reg,29,28,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2
	pop	\reg
.endr
	clr	r1
//////////////////////////////////////////////////
	ret

//echo "0,0,0,0,3,10,12,0,5,0,0,0,9,15,0,7,12,2,24,8,14,6,15,0,11,11,1,3,13,4,23,4,0,0,0,0,29,19,0,27,23,18,26,31,31,20,28,17,16,0,27,8,19,30,0,21,25,0,28,16,7,22,20,24"
//|tr ',' '\n'|awk '{if(j>7){j=0;print""};j++;bit=and($1,7);nib=0;if(bit<4){nib=1;};printf("0x%1x%1x,",and(bit,3)*2+nib,int($1/8))}'
// warning, check C code for original tables, awk script may not correspond to the current state
// unused bites = 0x8c
PERM_MSG:
.byte 0x2c, 0x1c, 0x8c, 0x1c, 0x3d, 0x6d, 0x8c, 0x6c
.byte 0x0d, 0x5c, 0x1f, 0x1d, 0x4d, 0x4c, 0x6d, 0x8c
.byte 0x7d, 0x7d, 0x3c, 0x7c, 0x2d, 0x0c, 0x6e, 0x0c

.byte 0x7c, 0x5d, 0x0d, 0x8c, 0x2f, 0x7e, 0x8c, 0x7f

.byte 0x6e, 0x5e, 0x5f, 0x6f, 0x6f, 0x0e, 0x0f, 0x3e
.byte 0x1e, 0x8c, 0x7f, 0x1d, 0x7e, 0x4f, 0x8c, 0x2e
.byte 0x3f, 0x8c, 0x0f, 0x1e, 0x6c, 0x4e, 0x0e, 0x1f

//echo "31,8,21,15,27,18,0,0,11,26,17,4,22,29,0,0,6,28,20,13,24,9,0,0,19,12,5,25,30,16,0,0,45,55,61,40,37,51,0,0,59,47,41,52,44,62,0,0,58,36,53,43,39,48,0,0,63,56,42,50,60,46,0,0"|
//|tr ',' '\n'|awk '{if(j>7){j=0;print""};j++;bit=and($1,7);nib=0;if(bit<4){nib=1;};printf("0x%1x%1x,",and(bit,3)*2+nib,int($1/8))}'
// warning, check C code for original tables, awk script may not correspond to the current state
// this table must follow PERM_MSG table!
//PERM_S_ADDR:

.byte 0x63, 0x11, 0x22, 0x61, 0x73, 0x52
.byte 0x71, 0x53, 0x32, 0x14, 0x42, 0x23
.byte 0x54, 0x03, 0x02, 0x21, 0x13, 0x31
.byte 0x72, 0x01, 0x34, 0x33, 0x43, 0x12
.byte 0x25, 0x66, 0x27, 0x15, 0x24, 0x76
.byte 0x77, 0x65, 0x35, 0x06, 0x05, 0x47
.byte 0x57, 0x04, 0x26, 0x75, 0x64, 0x16
.byte 0x67, 0x17, 0x55, 0x56, 0x07, 0x45

// this table must follow PERM_S_ADDR table!
//PERM_R:
.byte 0x6a, 0x0b, 0x09, 0x7b, 0x7a, 0x0a, 0x38, 0x19
.byte 0x49, 0x3b, 0x4a, 0x78, 0x4b, 0x3a, 0x39, 0x68
.byte 0x69, 0x28, 0x2b, 0x1b, 0x59, 0x1a, 0x18, 0x48
.byte 0x6b, 0x08, 0x29, 0x5a, 0x58, 0x5b, 0x79, 0x2a

// S-boxes (vertical, in reverse order (1st byte = sbox 7,6  2nd 5,6 .. )
S_BOX:
.byte    0x4d, 0x2c, 0xa7, 0xef, 0xb2, 0xc1, 0x0d, 0x41
.byte    0x28, 0x4a, 0x9e, 0xd8, 0xe4, 0x1f, 0xe3, 0x1e
.byte    0xf6, 0x79, 0x60, 0x26, 0x0f, 0xa2, 0x36, 0xfb
.byte    0x8b, 0xb6, 0xf9, 0xb3, 0xd1, 0x68, 0x5a, 0x84
.byte    0x3a, 0x80, 0x11, 0x39, 0xc9, 0x5d, 0xd2, 0xa7
.byte    0x93, 0x33, 0xc8, 0x62, 0x7e, 0xf4, 0x75, 0xcd
.byte    0x55, 0xde, 0xbb, 0x5c, 0xa0, 0x07, 0x4c, 0x90
.byte    0x6c, 0xe5, 0x24, 0x05, 0x17, 0x9b, 0x8f, 0x7a
.byte    0xd1, 0xea, 0xdd, 0x03, 0x0f, 0xbf, 0x78, 0xfd
.byte    0xbd, 0x24, 0x0b, 0x74, 0x78, 0xc2, 0x95, 0x47
.byte    0x4a, 0x47, 0x36, 0xef, 0x93, 0x7c, 0x4f, 0x22
.byte    0x17, 0xd9, 0x60, 0xd8, 0xa4, 0x15, 0xa3, 0x1e
.byte    0xec, 0x56, 0x24, 0xac, 0x35, 0x01, 0x87, 0x60
.byte    0x56, 0xfd, 0x52, 0xc1, 0xcb, 0xae, 0xec, 0xba
.byte    0x20, 0x30, 0xc1, 0x96, 0xfe, 0x9b, 0xba, 0x59
.byte    0x89, 0x83, 0xfe, 0x3b, 0x62, 0x68, 0x19, 0x85
.byte    0x17, 0x49, 0xda, 0x40, 0x4b, 0x2e, 0x66, 0x1e
.byte    0xb4, 0x1f, 0x49, 0xe7, 0xd1, 0xb5, 0x90, 0x8b
.byte    0xc9, 0xa2, 0x8c, 0xda, 0x3c, 0xd8, 0xfb, 0x64
.byte    0x7e, 0x7c, 0x37, 0x2d, 0xe2, 0x83, 0x0d, 0xb1
.byte    0xa0, 0xf7, 0xbf, 0xf5, 0xf6, 0x90, 0x11, 0xc8
.byte    0x6a, 0xc4, 0x23, 0x9c, 0x8d, 0x5a, 0xce, 0x76
.byte    0x0f, 0x61, 0x55, 0x39, 0x53, 0x3d, 0xa2, 0xa3
.byte    0x95, 0x0b, 0xe8, 0x52, 0x28, 0xe6, 0x74, 0x0f
.byte    0x62, 0xb4, 0x13, 0xfd, 0xb1, 0x83, 0xaf, 0xc8
.byte    0xde, 0xc2, 0xd0, 0x8a, 0x87, 0x7c, 0x06, 0x21
.byte    0x14, 0x19, 0x6a, 0x43, 0x4a, 0xe5, 0x91, 0x9f
.byte    0xa8, 0x2f, 0x8d, 0x14, 0x7d, 0xda, 0x78, 0x72
.byte    0x9f, 0x6b, 0x49, 0x5b, 0x5c, 0xfe, 0xf4, 0xb6
.byte    0x09, 0x01, 0xe5, 0x37, 0xf0, 0x97, 0x3b, 0xec
.byte    0xe3, 0xa6, 0xbc, 0xa0, 0x25, 0x40, 0x57, 0x05
.byte    0x36, 0x58, 0x22, 0x6e, 0xcb, 0x3d, 0xce, 0xd9
