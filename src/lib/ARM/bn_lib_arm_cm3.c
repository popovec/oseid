/*
    bn_lib_arm_cm3.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2024 Peter Popovec, popovec.peter@gmail.com

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
    
    big number arithmetic - derived from lib/generic/bn_lib.c, optimized for
    ARM Cortex M3 (tested on STM32F102CB and STM clone MH2103A)

    the size of the operand is in the range 1..256 bytes (0 = 256 bytes!)

    The STM32F10X runs much faster if the jump destination is aligned (8/4),
    this core uses 2 x 128 bit prefetch buffer.

    More complex code (product scanning, Karatsuba multiplication) does not
    bring much acceleration if this is not followed.  The processor only has
    the "umlal" instruction and no "umaal", this also worsens the use of
    qualitatively better algorithms.

    STM32F10x is insecure (there is way to extract firmware from locked
    FLASH).  Because of this, the problem of executing code in constant time
    isn't even solved - it doesn't make sense.

    There is also a problem with the "umlal" instruction, which is not
    executed in constant time, but the execution time depends on the
    operands.

    Consider these shortcomings if you use this code in another project.

*/
#include <stdint.h>
#include "bn_lib.h"

/******************************************************************************
 * bn_shift_L_v
 ******************************************************************************/

uint8_t __attribute__((aligned(8))) __attribute__((naked)) bn_shift_L_v(void *r, uint8_t len)
{
	asm volatile (		//
// convert 0 to 256
			     "sub	r1, #1\n"	//
			     "and	r1, #0xff\n"	//
			     "add	r1, #1\n"	//
			     "rors	r1, #3\n"	// 8 bytes at once...
////////////////////////////////////////////////////////////////////////////
			     "movs	r3, 0xff\n"	//
			     "adds	r3, #0\n"	//clear carry
//
// loop:
			     "nop\n"	// align jump to multiple of 8..
			     "nop\n"	// align jump to multiple of 8..
			     "1:\n"	//
			     "ldr	r2, [r0]\n"	//
			     "adcs	r2, r2, r2\n"	//
			     "str       r2, [r0], #4\n"	//
//
			     "ldr	r2, [r0]\n"	//
			     "adcs	r2, r2, r2\n"	//
			     "str       r2, [r0], #4\n"	//
//
			     "add	r1, r3\n"	//
			     "ands	r1, r3\n"	//
			     "bne	1b\n"	//
// return exact 0/1 0 - no carry 1 carry
			     "movs	r0, #0\n"	//
			     "adcs	r0, r0\n"	//
			     "bx	lr\n"	//
	    );
}

/******************************************************************************
 * bn_shift_R_v_c
 ******************************************************************************/
#if 0
// 4 bytes at once)
// it is not necessary to rewrite it in ASM, it is quite efficient.
uint8_t __attribute__((aligned(8))) bn_shift_R_v_c(void *r, uint8_t len, uint8_t carry)
{
	uint32_t *R = (uint32_t *) r;
	uint32_t c2, c1 = 0, tmp1;
	uint32_t llen = len ? len : 256;

	llen /= 4;
	R += llen;
	if (carry)
		c1 = 1;
	do {
		R--;
		c1 <<= 31;
		c2 = *R & 1;
		tmp1 = *R >> 1;
		tmp1 |= c1;
		c1 = c2;
		*R = tmp1;
	} while (--llen);
	return c2;
}
#else
// 8 bytes at once
uint8_t __attribute__((aligned(8))) bn_shift_R_v_c(void *r, uint8_t len, uint8_t carry)
{
	uint32_t *R = (uint32_t *) r;
	uint32_t c2, c1 = 0, tmp1;
	uint32_t llen = len ? len : 256;

	llen /= 4;
	R += llen;
	llen /= 2;
	if (carry)
		c1 = 1;
	do {

		R--;
		c1 <<= 31;
		c2 = *R & 1;
		tmp1 = *R >> 1;
		tmp1 |= c1;
		c1 = c2;
		*R = tmp1;

		R--;
		c1 <<= 31;
		c2 = *R & 1;
		tmp1 = *R >> 1;
		tmp1 |= c1;
		c1 = c2;
		*R = tmp1;

	} while (--llen);
	return c2;
}

#endif

/******************************************************************************
 * bn_add_v
 ******************************************************************************/
// This code need 8/16 or 64 bit per round no 32!
// due overlap if operands in EC calculation
uint8_t __attribute__((aligned(8)))
    __attribute__((naked)) bn_add_v(void *r, void *a, uint8_t len, uint8_t carry)
{
	asm volatile (		//
			     "push	{r5, r6, lr}\n"	//
// convert 0 to 256
			     "sub	r2,#1\n"	//
			     "and	r2,#0xff\n"	//
			     "add	r2,#1\n"	//
			     "rors	r2,#3\n"	// 8 bytes at once...
////////////////////////////////////////////////////////////////////////////
//
//
			     "rors	r3, #1\n"	// set carry bit if needed
			     "movs	r3, #0xff\n"	//
// loop:
			     "1:\n"	//
			     "ldr	r5, [r0]\n"	//
			     "ldr	r6, [r1], #4\n"	//
			     "adcs	r5, r6\n"	//
			     "str       r5, [r0], #4\n"	//
//
			     "ldr	r5, [r0]\n"	//
			     "ldr	r6, [r1], #4\n"	//
			     "adcs	r5, r6\n"	//
			     "str       r5, [r0], #4\n"	//
//
			     "add	r2, r3\n"	//
			     "ands	r2, r3\n"	//
			     "bne	1b\n"	//
// return exact 0/1 0 - no carry 1 carry
			     "adcs	r0, r2, #0\n"	// r2 is zero
			     "pop	{r5, r6, pc}\n"	//
	    );
}

/******************************************************************************
 * bn_sub_v
 ******************************************************************************/
uint8_t __attribute__((aligned(8)))
    __attribute__((naked)) bn_sub_v(void *r, void *a, void *b, uint8_t len)
{
	asm volatile (		//
			     "push	{r4, r5, r6, lr}\n"	//
// convert 0 to 256
			     "sub	r3,#1\n"	//
			     "and	r3,#0xff\n"	//
			     "add	r3,#1\n"	//
			     "rors	r3,#3\n"	// 8 bytes at once...
////////////////////////////////////////////////////////////////////////////
//
			     "movs	r4, #1\n"	// indicate no borrow
			     "rors	r4, #1\n"	//
			     "mov	r4, #0xff\n"	//
// loop:
			     "1:\n"	//
			     "ldr	r5, [r1], #4\n"	//
			     "ldr	r6, [r2], #4\n"	//
			     "sbcs	r5, r6\n"	//
			     "str       r5, [r0], #4\n"	//
//
			     "ldr	r5, [r1], #4\n"	//
			     "ldr	r6, [r2], #4\n"	//
			     "sbcs	r5, r6\n"	//
			     "str       r5, [r0], #4\n"	//
//
			     "add	r3, r4\n"	//
			     "ands	r3, r4\n"	//
			     "bne	1b\n"	//
// return exact 0/1  (borrow..)
			     "movs	r0, #0\n"	//
			     "adcs	r0, r0\n"	//
			     "eors	r0, #1\n"	// ARM inverted carry ..
			     "pop	{r4, r5, r6, pc}\n"	//
	    );
}

// multiplication, squaring, Motntgomery and Barret reduction ..
//
// Karatsuba algorithm is not used here (as in the AVR processor).  The
// speed for RSA2048 is quite sufficient (under 2 seconds).

// limb size 64 bit for 1st line, the limb size is 32 bit
void __attribute__((aligned(8)))
    __attribute__((naked)) bn_mul_mod_v(void *R, void *A, void *B, uint8_t len)
{
	asm volatile (		//
			     "push      {r4, r5, r6, r7, r8, r9, r10, r11, lr}     \n\t"	//
// convert 0 to 256
			     "sub       r3, #1          \n\t"	//
			     "and       r3, #0xff       \n\t"	//
			     "add       r3, #1          \n\t"	//
			     "rors      r3, #2          \n\t"	// 4 bytes at once...
//
			     "mov	r9, r3		\n\t"	// save length
			     "mov	r10, r3		\n\t"	// length
// 1st line
			     "ldr       r11, [r2], #4   \n\t"	// B[0]
			     "push	{r0, r1}	\n\t"	//
			     "movs	r4, #0		\n\t"	//
//
			     "1:			\n\t"	//
			     "ldr	r8, [r1], #4	\n\t"	//
			     "ldr	r5, [r1], #4	\n\t"	//
			     "umull	r8, r6, r11, r8	\n\t"	//
			     "umull	r5, r7, r11, r5	\n\t"	//
			     "adds	r4, r4, r8	\n\t"	//
			     "adcs	r6, r6, r5	\n\t"	//
			     "str	r4, [r0], #4	\n\t"	//
			     "str	r6, [r0], #4	\n\t"	//
			     "adc	r4, r7,#0	\n\t"	//
			     "subs	r3, #2		\n\t"	//
			     "bne	1b		\n\t"	//
//
			     "pop	{r0, r1}	\n\t"	//
			     "add	r0, #4		\n\t"	//
			     "subs	r10, #1		\n\t"	//
//
// rest
			     "2:			\n\t"	//
			     "mov	r8, #0		\n\t"	// carry
			     "ldr	r11, [r2], #4	\n\t"	// B[j]
			     "push	{r0, r1}	\n\t"	//
			     "mov	r3, r10		\n\t"	// renew length
// muladd one line
			     "1:			\n\t"	//
			     "ldr	r4, [r1], #4	\n\t"	//
			     "ldr	r5, [r0]	\n\t"	//
			     "movs	r6, #0		\n\t"	//
			     "umlal	r8, r6, r11, r4	\n\t"	//
			     "adds	r5, r5, r8	\n\t"	//
			     "str	r5, [r0], #4	\n\t"	//
			     "adc	r8, r6, #0	\n\t"	//
			     "subs	r3, #1		\n\t"	//
			     "bne	1b		\n\t"	//
//
			     "pop	{r0, r1}	\n\t"	//
			     "add	r0, #4		\n\t"	//
			     "subs	r10, #1		\n\t"	//
			     "bne	2b		\n\t"	//
			     "pop       {r4, r5, r6, r7, r8, r9, r10, r11, pc}\n\t"	//
	    );
}

// limb size 64 bit!
void __attribute__((aligned(8)))
    __attribute__((naked)) bn_mul_v(void *R, void *A, void *B, uint8_t len)
{
	asm volatile (		//
			     "push      {r4, r5, r6, r7, r8, r9, r10, r11, lr}     \n\t"	//
// convert 0 to 256
			     "sub       r3, #1          \n\t"	//
			     "and       r3, #0xff       \n\t"	//
			     "add       r3, #1          \n\t"	//
			     "rors      r3, #2          \n\t"	// 4 bytes at once...
//
			     "mov	r9, r3		\n\t"	// save length
			     "mov	r10, r3		\n\t"	// length
// 1st line
			     "ldr       r11, [r2], #4   \n\t"	// B[0]
			     "mov	r8, #0		\n\t"	//
//
			     "1:			\n\t"	//
			     "ldr	r4, [r1], #4	\n\t"	//
			     "ldr	r5, [r1], #4	\n\t"	//
			     "umull	r4, r6, r11, r4	\n\t"	//
			     "umull	r5, r7, r11, r5	\n\t"	//
			     "adds	r8, r8, r4	\n\t"	//
			     "adcs	r6, r6, r5	\n\t"	//
			     "str	r8, [r0], #4	\n\t"	//
			     "str	r6, [r0], #4	\n\t"	//
			     "adc	r8, r7,#0	\n\t"	//
			     "subs	r3, #2		\n\t"	//
			     "bne	1b		\n\t"	//
//
			     "str	r8, [r0], #4	\n\t"	//
			     "sub	r0, r0, r9, lsl #2	\n\t"	//
			     "sub	r1, r1, r9, lsl #2	\n\t"	//
			     "subs	r10, #1		\n\t"	//
//
// rest
			     "2:			\n\t"	//
			     "mov	r8, #0		\n\t"	// carry
			     "ldr	r11, [r2], #4	\n\t"	// B[j]
			     "mov	r3, r9		\n\t"	// renew length
// muladd one line
			     "1:			\n\t"	//
			     "ldr	r4, [r1], #4	\n\t"	//
			     "ldr	r5, [r1], #4	\n\t"	//
			     "mov	r6, #0		\n\t"	//
			     "umlal	r8, r6, r11, r4	\n\t"	//
			     "mov	r7, #0		\n\t"	//
			     "umlal	r6, r7, r11, r5	\n\t"	//
			     "ldr	r4, [r0]	\n\t"	//
			     "ldr	r5, [r0, #4]	\n\t"	//
			     "adds	r4, r4, r8	\n\t"	//
			     "str	r4, [r0], #4	\n\t"	//
			     "adcs	r5, r5, r6	\n\t"	//
			     "adc	r8, r7, #0	\n\t"	//
			     "str	r5, [r0], #4	\n\t"	//
			     "subs	r3, #2		\n\t"	//
			     "bne	1b		\n\t"	//
//
			     "str	r8, [r0], #4	\n\t"	//
			     "sub	r0, r0, r9, lsl #2	\n\t"	//
			     "sub	r1, r1, r9, lsl #2	\n\t"	//
			     "subs	r10, #1		\n\t"	//
			     "bne	2b		\n\t"	//
			     "pop       {r4, r5, r6, r7, r8, r9, r10, r11, pc}\n\t"	//
	    );
}

uint32_t __attribute__((aligned(8)))
    __attribute__((naked)) bn_mul_add_v(void *R, void *A, void *B, uint8_t len)
{
	asm volatile (		//
			     "push      {r4, r5, r6, r7, r8, r9, r10, r11, lr}     \n\t"	//
// convert 0 to 256
			     "sub       r3, #1          \n\t"	//
			     "and       r3, #0xff       \n\t"	//
			     "add       r3, #1          \n\t"	//
			     "rors      r3, #2          \n\t"	// 4 bytes at once...
//
			     "mov	r9, r3		\n\t"	// save length
			     "mov	r10, r3		\n\t"	// length
			     "mov	r14, #0		\n\t"	// carry catcher
//
			     "2:			\n\t"	//
			     "movs	r4, #0		\n\t"	// carry
			     "ldr	r11, [r2], #4	\n\t"	// B[j]
			     "mov	r3, r9		\n\t"	// renew length
// muladd one line
			     "1:			\n\t"	//
			     "ldr	r8, [r1], #4	\n\t"	//
			     "ldr	r5, [r1], #4	\n\t"	//
			     "movs	r6, #0		\n\t"	//
			     "umlal	r4, r6, r11, r8	\n\t"	//
			     "movs	r7, #0		\n\t"	//
			     "umlal	r6, r7, r11, r5	\n\t"	//
			     "ldr	r8, [r0]	\n\t"	//
			     "ldr	r5, [r0, #4]	\n\t"	//
			     "adds	r8, r8, r4	\n\t"	//
			     "str	r8, [r0], #4	\n\t"	//
			     "adcs	r5, r5, r6	\n\t"	//
			     "adc	r4, r7, #0	\n\t"	//
			     "str	r5, [r0], #4	\n\t"	//
			     "subs	r3, #2		\n\t"	//
			     "bne	1b		\n\t"	//
//
			     "ldr       r8, [r0]	\n\t"	//
			     "adds	r4, r14		\n\t"	//
			     "adc	r14, r3, r3	\n\t"	// r3 is zero
			     "adds	r8, r4		\n\t"	//
			     "str	r8, [r0], #4	\n\t"	//
			     "adc	r14, r14, r3	\n\t"	// r3 is zero
//
			     "sub	r0, r0, r9, lsl #2	\n\t"	//
			     "sub	r1, r1, r9, lsl #2	\n\t"	//
			     "subs	r10, #1		\n\t"	//
			     "bne	2b		\n\t"	//
//
			     "mov	r0,r14		\n\t"	//
//
			     "pop       {r4, r5, r6, r7, r8, r9, r10, r11, pc}\n\t"	//
	    );
}

///////////////////////////////////////////////////////////////////////////////////////////
// squaring
//////////////
void __attribute__((aligned(8))) __attribute__((naked)) rsa_square_v(void *R, void *A, uint8_t len)
{
	asm volatile (		//
			     "push      {r4, r5, r6, r7, r8, r9, r10, lr}\n"	//
// convert 0 to 256
			     "sub	r2, #1		\n\t"	//
			     "and	r2, #0xff	\n\t"	//
			     "add	r2, #1		\n\t"	//
			     "rors	r2, #2		\n\t"	// 4 bytes at once...
			     "mov 	r10, r2\n"	//
//
			     "push	{r0, r1}	\n\t"	//
			     "sub	r9, r2, #2	\n\t"	//
			     "mov	r3, #0		\n\t"	//
			     "str	r3, [r0], #4	\n\t"	//
//
			     "ldr	r3, [r1], #4	\n\t"	//
			     "mov	r8, #0		\n\t"	//
			     "push	{r0, r1}	\n\t"	//
//
			     "subs      r2, #1          \n\t"	//
			     "1:			\n\t"	//
			     "ldr	r4, [r1], #4	\n\t"	//
			     "umull	r5, r6, r3, r4	\n\t"	//
			     "adds	r5, r5, r8	\n\t"	//
			     "adc	r8, r6, #0	\n\t"	//
			     "str	r5, [r0], #4	\n\t"	//
			     "subs	r2, #1		\n\t"	//
			     "bne	1b		\n\t"	//
//
			     "str	r8, [r0]	\n\t"	//
			     "pop	{r0, r1}	\n\t"	//
			     "nop			\n\t"	//
//
			     "2:			\n\t"	//
			     "ldr       r3, [r1], #4	\n\t"	//
			     "add       r0, r0, #8	\n\t"	//
			     "mov       r8, #0		\n\t"	//
			     "push      {r0, r1}	\n\t"	//
			     "mov       r2, r9		\n\t"	//
//
			     "1:			\n\t"	//
			     "ldr	r4, [r1], #4	\n\t"	//
			     "ldr	r6, [r0]	\n\t"	//
			     "movs	r5, #0		\n\t"	//
			     "umlal	r8, r5, r3, r4	\n\t"	//
			     "adds	r7, r6, r8	\n\t"	//
			     "adc	r8, r5, #0	\n\t"	//
			     "str	r7, [r0], #4	\n\t"	//
			     "subs	r2, #1		\n\t"	//
			     "bne	1b		\n\t"	//
//
			     "3:			\n\t"	//
			     "str	r8,[r0], #4	\n\t"	//
			     "str	r2,[r0], #4	\n\t"	//
			     "pop	{r0, r1}	\n\t"	//
			     "subs      r9, r9, #1	\n\t"	//
			     "bne	2b		\n\t"	//
//
			     "4:			\n\t"	//
			     "pop	{r0, r1}	\n\t"	//
			     "movs	r4, #0		\n\t"	//
//
			     "1:			\n\t"	//
			     "ldr	r8, [r1], #4	\n\t"	//
			     "mov	r7, #0		\n\t"	//
			     "umlal	r4, r7, r8, r8	\n\t"	//
			     "ldr	r8, [r0]	\n\t"	//
			     "ldr	r5, [r0, #4]	\n\t"	//
			     "mov	r3, r5, lsr #31	\n\t"	//
			     "adds	r8, r8		\n\t"	//
			     "adc	r5, r5		\n\t"	//
			     "adds	r8, r4		\n\t"	//
			     "adcs	r5, r7		\n\t"	//
			     "str	r8, [r0], #4	\n\t"	//
			     "str	r5, [r0], #4	\n\t"	//
			     "adc	r4, r3, #0	\n\t"	//
			     "subs	r10, #1		\n\t"	//
			     "bne	1b		\n\t"	//
			     "pop	{r4, r5, r6, r7, r8, r9, r10, pc}\n"	//
	    );
}

void rsa_square_192(uint8_t * r, uint8_t * a)
{
	rsa_square_v(r, a, 24);
}

void rsa_square_256(uint8_t * r, uint8_t * a)
{
	rsa_square_v(r, a, 32);
}

void rsa_square_384(uint8_t * r, uint8_t * a)
{
	rsa_square_v(r, a, 48);
}

void rsa_square_512(uint8_t * r, uint8_t * a)
{
	rsa_square_v(r, a, 64);
}

void rsa_square_768(uint8_t * r, uint8_t * a)
{
	rsa_square_v(r, a, 96);
}

void rsa_square_1024(uint8_t * r, uint8_t * a)
{
	rsa_square_v(r, a, 128);
}

void mp_square_521(uint8_t * r, uint8_t * a)
{
	rsa_square_v(r, a, 72);
}

uint8_t __attribute__((aligned(8)))
    __attribute__((naked)) bn_add_carry_v(void *r, uint8_t len, uint8_t carry)
{
	asm volatile (		//
			     "push	{r4, lr}\n"	//
// convert 0 to 256
			     "sub	r1,#1\n"	//
			     "and	r1,#0xff\n"	//
			     "add	r1,#1\n"	//
			     "rors	r1,#3\n"	// 8 bytes at once...
////////////////////////////////////////////////////////////////////////////
//
			     "adds	r1,#0\n"	// clear carry flag
			     "uxtb	r2,r2\n"	//
			     "movs	r3, #0xff\n"	//
// loop:
			     "1:\n"	//
			     "ldr	r4, [r0]\n"	//
			     "adcs	r4, r2\n"	//
			     "str       r4, [r0], #4\n"	//
//
			     "mov	r2,#0\n"	//
			     "ldr	r4, [r0]\n"	//
			     "adcs	r4, r2\n"	//
			     "str       r4, [r0], #4\n"	//
//
			     "add	r1, r3\n"	//
			     "ands	r1, r3\n"	//
			     "bne	1b\n"	//
// return exact 0/1 0 - no carry 1 carry
			     "movs	r0, #0\n"	//
			     "adcs	r0, r0\n"	//
			     "pop	{r4, pc}\n"	//
	    );
}

uint8_t bn_sub_v(void *r, void *a, void *b, uint8_t len);
// modular reduction
//---------------------
// upper part is reduced by modified Barrett reduction
// lower part is reduced by Montgomery reduction
// no need to use Karatsuba multiplication (with big overhead)
// only half multiplication is needed (4x) and one
// half truncated multiplication is needed

// return 0/1 (index of t/help1, result is in upper part of rsa_long_num)
extern uint8_t mod_len;

uint8_t
    __attribute__((aligned(8))) monPro0(uint8_t * t, uint8_t * help1, uint8_t * n, uint8_t * Mc,
					uint8_t * Bc)
{
	uint8_t carry;

	uint8_t mmod_len = mod_len;
	uint8_t offset = (mmod_len * 3) / 2;
	uint8_t *mm = (offset + (uint8_t *) help1);
	uint8_t hsize = mmod_len / 2;

	// T  = D|C|B|A  (| = concatenation, parts A,B,C,D are 1/2 bit len of modulus)
	// Bc = BcH|BcL (Bc is pecalculated from T 1|0|0|0 mod 'n'
	// Mc = Montgomery constant from  'r - n^-1 mod r', r is  1|0
	// n  = nH|nL - modulus
	// mm = montgomery coefficient, from truncated multiplicatiom of Mc and updted A

	// reduce upper part:
	// update T = B|A + D*BcL (do not change D,C, carry to C is processed later)

	carry = bn_mul_add_v(t, Bc, (offset + (uint8_t *) t), hsize);

	// truncated multiplication Mc * A (A is already updated by BcL)
	// calculate Montgomery part from low bits of partial result
	bn_mul_mod_v(mm, Mc, t, hsize);

	// update T = B|A + Mp * nL, (do not change D,C, carry to C is processed later)
	carry += bn_mul_add_v(t, mm, n, hsize);
	// ------------------
	// A is zero (by Montgomery reduction), propagate carry's
	carry = bn_add_carry_v((mmod_len + (uint8_t *) t), hsize, carry);

	// continue, Mp * nH is added to C|B
	carry += bn_mul_add_v((hsize + (uint8_t *) t), mm, (hsize + (uint8_t *) n), hsize);

	bn_mul_v(help1, (hsize + (uint8_t *) Bc), (offset + (uint8_t *) t), hsize);

	carry += bn_add_v(help1, (hsize + (uint8_t *) t), mmod_len, 0);

// this code is not perfect constant time, ASM code for atmega128 is
// designed to run this part of code in constant time.
	carry -= bn_sub_v(t, help1, n, mmod_len);
	if (carry == 0xff) {
		// correct result in help1, prevent SPA attack
		// (do not subtract  t = help1 - n, this can be detected in power trace)
		bn_sub_v(t, t, n, mmod_len);
		return 0;
	}
	carry -= bn_sub_v(help1, t, n, mmod_len);
	return carry == 0xff ? 1 : 0;
}
