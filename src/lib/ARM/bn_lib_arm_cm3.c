/*
    bn_lib_arm_cm3.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2024 Peter Popovec, popovec.peter@gmail.com

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
    
    big number arithmetic - derived from lib/generic/bn_lib.c,
    optimized for ARM Cortex M3 (tested on STM32F102CB)

    the size of the operand is in the range 1..256 bytes (0 = 256 bytes!)

*/
#include <stdint.h>
#include <string.h>
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
#if 0
// OK - use 64 bits .. EC fast reduction depends on it
// 8bit OK 16 bit Ok  32 bit FAIL!
// OK FAST-TEST
uint8_t __attribute__((aligned(8))) bn_add_v(void *r, void *a, uint8_t len, uint8_t carry)
{
	uint32_t *R = (uint32_t *) r;
	uint32_t *A = (uint32_t *) a;
	uint32_t c, i, tmp1, tmp2;
	uint32_t llen = len ? len : 256;
	llen /= 8;

	if (carry)
		c = 1;
	else
		c = 0;
	i = 0;
	do {
		tmp1 = R[i] + c;
		c = (tmp1 < c);
		tmp1 += A[i];
		c += (tmp1 < A[i]);

		tmp2 = R[i + 1] + c;
		c = (tmp2 < c);
		tmp2 += A[i + 1];
		c += (tmp2 < A[i + 1]);

		R[i] = tmp1;
		R[i + 1] = tmp2;
		i += 2;
	} while (--llen);

// return 0 or 1 only
	return c & 1;
}
#else
//  OK FAST-TEST  This code need 8/16 or 64 bit per round no 32!
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
			     "mov	r3, #0xff\n"	//
// loop:
			     "nop\n"	// align jump to multiple of 8..
			     "nop\n"	// align jump to multiple of 8..
			     "nop\n"	// align jump to multiple of 8..
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
			     "movs	r0, #0\n"	//
			     "adcs	r0, r0\n"	//
			     "pop	{r5, r6, pc}\n"	//
	    );
}
#endif
/******************************************************************************
 * bn_sub_v
 ******************************************************************************/
#if 0
// tested, OK - FAST-TEST
uint8_t __attribute__((aligned(8))) bn_sub_v(void *r, void *a, void *b, uint8_t len)
{
	uint16_t *A, *B, *R;
	uint16_t carry;
	uint16_t i = 0;
	int32_t pA, pB, Res;
	uint32_t llen = len ? len : 256;

	A = (uint16_t *) a;
	B = (uint16_t *) b;
	R = (uint16_t *) r;
	carry = 0;
	do {
		pA = A[i];
		pB = B[i];
		Res = pA - pB - carry;
		R[i] = Res & 0xffff;
		carry = (Res >> 16) & 1;
		i++;
		llen -= 2;
	} while (llen);
	return carry;
}
#else
//  OK FAST-TEST
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
#endif

// multiplication, squaring, Motntgomery and Barret reduction ..
//
// Karatsuba algorithm is not used here (as in the AVR processor).  The
// speed for RSA2048 is quite sufficient (under 2 seconds).

#if 0
// tested, OK
void bn_mul_v(void *R, void *A, void *B, uint8_t len)
{
	uint8_t i, j;
	uint32_t a_, c;
	uint64_t res;
	uint32_t *r = (uint32_t *) R;
	uint32_t *a = (uint32_t *) A;
	uint32_t *b = (uint32_t *) B;

	memset(r, 0, 2 * len);

	len /= 4;
	for (i = 0; i < len; i++) {
		c = 0;
		a_ = a[i];

		for (j = 0; j < len; j++) {
			res = (uint64_t) a_ *(uint64_t) b[j];
			res += r[i + j];
			res += c;

			c = res >> 32;
			r[i + j] = res & 0xffffffff;
		}
		r[i + len] = c;
	}
}
#else
#if 1
#define MUL_CORE2                                   \
	"ldr    r4, [r0], #4                \n\t"	\
	"ldr	r5, [r0], #4		    \n\t"	\
	"umull  r6, r7, r3, r4              \n\t"	\
	"adds   r2, r2, r6                  \n\t"	\
	"adc    r4, r7, #0                  \n\t"	\
	"umull  r6, r7, r3, r5              \n\t"	\
	"adds   r6, r6, r4                  \n\t"	\
	"str    r2, [r1], #4                \n\t"	\
	"str    r6, [r1], #4                \n\t"	\
	"adc    r2, r7, #0                  \n\t"
#else
// Why this is slower ? (STM32F102/ 1.728 previous code 1.704)
#define MUL_CORE2                                   \
	"ldr    r4, [r0], #4                \n\t"	\
	"ldr	r5, [r0], #4		    \n\t"	\
	"umull  r4, r6, r3, r4              \n\t"	\
	"umull  r5, r7, r3, r5              \n\t"	\
	"adds	r2, r2, r4		\n\t"	\
	"adcs	r6, r6, r5		\n\t"	\
	"str    r2, [r1], #4		\n\t"	\
	"str    r6, [r1], #4		\n\t"	\
	"adc	r2, r7,#0		\n\t"
#endif

#define MUL_CORE                                    \
	"ldr    r4, [r0], #4                \n\t"	\
	"umull  r5, r6, r3, r4              \n\t"	\
	"adds   r5, r5, r2                  \n\t"	\
	"adc    r2, r6, #0                  \n\t"	\
	"str    r5, [r1], #4                \n\t"

#define MULADDC2_CORE				\
	"ldr    r4, [r0], #4            \n\t"	\
	"ldr	r5, [r0], #4		\n\t"	\
	"mov	r6, #0			\n\t"	\
	"umlal	r2, r6, r3, r4		\n\t"	\
	"mov	r7, #0			\n\t"	\
	"umlal	r6, r7, r3, r5		\n\t"	\
	"ldr	r4, [r1]		\n\t"	\
	"ldr	r5, [r1, #4]		\n\t"	\
	"adds	r4, r4, r2		\n\t"	\
	"str	r4, [r1], #4		\n\t"	\
	"adcs	r5, r5, r6		\n\t"	\
	"adc	r2, r7, #0		\n\t"	\
	"str	r5, [r1], #4		\n\t"

#define MULADDC3_CORE				\
	"ldr    r4, [r0], #4            \n\t"	\
	"ldr	r5, [r0], #4		\n\t"	\
	"mov	r6, #0			\n\t"	\
	"umlal	r2, r6, r3, r4		\n\t"	\
	"mov	r7, #0			\n\t"	\
	"umlal	r6, r7, r3, r5		\n\t"	\
	"ldr	r4, [r0], #4 		\n\t"	\
	"mov	r5, #0			\n\t"	\
	"umlal	r7, r5, r3, r4		\n\t"	\
	"ldr	r4, [r1]		\n\t"	\
	"adds	r4, r4, r2		\n\t"	\
	"str	r4, [r1], #4		\n\t"	\
	"ldr	r2, [r1]		\n\t"	\
	"ldr	r4, [r1, #4]		\n\t"	\
	"adcs	r2, r2, r6		\n\t"	\
	"str	r2, [r1], #4		\n\t"	\
	"adcs	r4, r4, r7		\n\t"	\
	"str	r4, [r1], #4		\n\t"	\
	"adc	r2, r5, #0		\n\t"

// This code is borrowed from mbedtls (mbedtls-2.27.0) and slightly modified
// to improve speed thanks to MCU pipeline

/* *INDENT-OFF* */
#define MUL_INIT                                    \
	asm volatile(						\
	"ldr    r0, %3                      \n\t"	\
	"ldr    r1, %4                      \n\t"	\
	"ldr    r2, %5                      \n\t"	\
	"ldr    r3, %6                      \n\t"

#define MULADDC_CORE                                    \
	"ldr    r4, [r0], #4                \n\t"	\
	"ldr    r6, [r1]                    \n\t"	\
	"mov    r5, #0                      \n\t"	\
	"umlal  r2, r5, r3, r4              \n\t"	\
	"adds   r7, r6, r2                  \n\t"	\
	"adc    r2, r5, #0                  \n\t"	\
	"str    r7, [r1], #4                \n\t"

#define MUL_STOP	                                    \
	"str    r2, %0                      \n\t"	\
	"str    r1, %1                      \n\t"	\
	"str    r0, %2                      \n\t"	\
	: "=m" (c), "=m" (d), "=m" (s)			\
	: "m" (s), "m" (d), "m" (c), "m" (b)		\
	: "r0", "r1", "r2", "r3", "r4", "r5",		\
	"r6", "r7", "cc"				\
	);
/* *INDENT-ON* */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
static void
    __attribute__((always_inline)) sbn_mulx_line0(uint8_t i, uint32_t * s, uint32_t * d, uint32_t b)
{
	uint32_t c = 0;
/* *INDENT-OFF* */
	for (; i >= 16; i -= 16) {
		MUL_INIT
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_STOP
	}
	for (; i >= 6; i -= 6) {
		MUL_INIT
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_STOP
	}
	for (; i > 0; i--) {
		MUL_INIT
		MUL_CORE
		MUL_STOP
	}
 /* *INDENT-ON* */
}

static uint32_t
    __attribute__((always_inline)) sbn_mulx_line(uint8_t i, uint32_t * s, uint32_t * d, uint32_t b)
{
	uint32_t c = 0;
/* *INDENT-OFF* */
	for (; i >= 16; i -= 16) {
		MUL_INIT
		MULADDC3_CORE
		MULADDC3_CORE
		MULADDC3_CORE
		MULADDC3_CORE
		MULADDC2_CORE
		MULADDC2_CORE
		MUL_STOP
	}
	for (; i >= 6; i -= 6) {
		MUL_INIT
		MULADDC3_CORE
		MULADDC3_CORE
		MUL_STOP
	}
	for (; i >= 4; i -= 4) {
		MUL_INIT
		MULADDC2_CORE
		MULADDC2_CORE
		MUL_STOP
	}
	for (; i > 0; i--) {
		MUL_INIT
		MULADDC_CORE
		MUL_STOP
	}
 /* *INDENT-ON* */
	return c;
}

static void
    __attribute__((always_inline)) bn_mul_line0(uint8_t i, uint32_t * s, uint32_t * d, uint32_t b)
{
	uint32_t c = 0;

 /* *INDENT-OFF* */
	for (; i >= 16; i -= 16) {
		MUL_INIT
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_STOP
	}
	for (; i >= 8; i -= 8) {
		MUL_INIT
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_STOP
	}
	for (; i >= 4; i -= 4) {
		MUL_INIT
		MUL_CORE2
		MUL_CORE2
		MUL_STOP
	}
	for (; i > 0; i--) {
		MUL_INIT
		MUL_CORE
		MUL_STOP
	}
 /* *INDENT-ON* */
	while (c != 0) {
		*d += c;
		c = (*d < c);
		d++;
	}
}

static void
    __attribute__((always_inline)) bn_mul_line(uint8_t i, uint32_t * s, uint32_t * d, uint32_t b)
{
	uint32_t c = 0;

 /* *INDENT-OFF* */
	for (; i >= 16; i -= 16) {
		MUL_INIT
		MULADDC3_CORE
		MULADDC3_CORE
		MULADDC3_CORE
		MULADDC3_CORE
		MULADDC2_CORE
		MULADDC2_CORE
		MUL_STOP
	}
	for (; i >= 6; i -= 6) {
		MUL_INIT
		MULADDC3_CORE
		MULADDC3_CORE
		MUL_STOP
	}
	for (; i > 0; i--) {
		MUL_INIT
		MULADDC_CORE
		MUL_STOP
	}
 /* *INDENT-ON* */
	while (c != 0) {
		*d += c;
		c = (*d < c);
		d++;
	}
}

#pragma GCC diagnostic pop
// only low part of multiplication is needed (64 bytes..)
// len is 64 maximum (for RSA 2048) ..
void __attribute__((aligned(8))) bn_mul_mod_v(uint8_t * R, uint8_t * A, uint8_t * B, uint8_t len)
{
	uint32_t *r32 = (uint32_t *) R;
	uint32_t *a32 = (uint32_t *) A;
	uint32_t *b32 = (uint32_t *) B;
	int i;

	len /= 4;
	sbn_mulx_line0(len, a32, r32, b32[0]);
	for (i = 1; i < len; i++)
		sbn_mulx_line(len - i, a32, r32 + i, b32[i]);
}

#if 1
void __attribute__((aligned(8))) bn_mul_v(void *R, void *A, void *B, uint8_t len)
{
	uint32_t *r = (uint32_t *) R;
	uint32_t *a = (uint32_t *) A;
	uint32_t *b = (uint32_t *) B;
	uint8_t i, j;

	int llen = len ? len : 256;

	i = llen / 4;
	j = i;

	memset(r + i, 0, llen);
	bn_mul_line0(i, a, r, b[0]);
	for (j = 1; j < i; j++)
		bn_mul_line(i, a, r + j, b[j]);
}
#else
// working....
// this 1.500 MH2103 / 1.749 STM32F102
// not bether that previous code .. 1.479/1.704)

void __attribute__((naked)) bn_mul_v(void *R, void *A, void *B, uint8_t len)
{
	asm volatile (		//
			     "push	{r4, r5, r6, r7, r8, r9, r10, r11, r12, lr}\n"	//
// convert 0 to 256
			     "sub	r3, #1\n"	//
			     "and	r3, #0xff\n"	//
			     "add	r3, #1\n"	//
			     "rors	r3, #2\n"	// 4 bytes at once...
////////////////////////////////////////////////////////////////////////////
//
			     "mov	r6, #0\n"	//
			     "mov	r7, #0\n"	//
			     "mov	r8, #0\n"	//
			     "mov	r4, #0\n"	//loop counter .. 0;r4 < r3;r4++
//
			     "mov 	r10, r1\n"	//
			     "1:\n"	//
			     "add	r2, r2, r4, lsl #2\n"	//
			     "mov	r5, r4\n"	//
//
			     "2:\n"	//
			     "ldr	r11, [r1], #4\n"	//
			     "ldr	r12, [r2], #-4\n"	//
			     "mov	r9, #0\n"	//
			     "umlal	r6, r9, r11, r12\n"	//
			     "adds	r7, r9\n"	//
			     "adcs	r8, #0\n"	//
			     "subs	r5, #1\n"	//
			     "bpl	2b\n"	//
//
			     "str	r6, [r0], #4\n"	//
			     "mov	r6, r7\n"	//
			     "mov	r7, r8\n"	//
			     "mov	r8, #0\n"	//
			     "add	r2, #4\n"	//
			     "mov	r1, r10\n"	//
			     "add	r4, #1\n"	//
			     "cmp	r4, r3\n"	//
			     "bne	1b\n"	//
// part1 end
			     "mov	r4, #1\n"	//
//
			     "mov	r10, r2\n"	//
			     "1:\n"	//
			     "add	r2, r2, r3, lsl #2\n"	//
			     "mov	r5, r4\n"	//
//
			     "2:\n"	//
			     "ldr	r11, [r1, r5, lsl #2]\n"	//
			     "ldmdb	r2!, {r12}\n"	//
			     "mov	r9, #0\n"	//
			     "umlal	r6, r9, r11, r12\n"	//
			     "adds	r7, r9\n"	//
			     "adcs	r8, #0\n"	//
			     "add	r5, #1\n"	//
			     "cmp	r5, r3\n"	//
			     "blt	2b\n"	//
//
			     "str	r6, [r0], #4\n"	//
			     "mov	r6, r7\n"	//
			     "mov	r7, r8\n"	//
			     "mov	r8, #0\n"	//
			     "mov	r2, r10\n"	//
			     "add	r4, #1\n"	//
			     "cmp	r4, r3\n"	//
			     "blt	1b\n"	//
//
			     "str	r6, [r0], #4\n"	//
			     "pop	{r4, r5, r6, r7, r8, r9, r10, r11, r12, pc}\n"	//
	    );
}
#endif
#if 1
uint32_t __attribute__((aligned(8))) bn_mul_add_v(void *R, void *A, void *B, uint8_t len)
{
	uint32_t *r = (uint32_t *) R;
	uint32_t *a = (uint32_t *) A;
	uint32_t *b = (uint32_t *) B;
	uint32_t c;
	uint8_t i, j;

	int llen = len ? len : 256;

	i = llen / 4;

	for (j = 0; j < i - 1; j++)
		bn_mul_line(i, a, r + j, b[j]);
	c = sbn_mulx_line(i, a, r + i - 1, b[i - 1]);
	r += 2 * i - 1;
	*r += c;
	return c = (*r < c);
}
#endif

///////////////////////////////////////////////////////////////////////////////////////////
// squaring
//////////////

#define SQR_INIT				\
	asm volatile (				\
	"ldr    r0, %3                      \n\t"	\
	"ldr    r1, %4                      \n\t"	\
	"ldr    r2, %5                      \n\t"

// result * 2 + Rx*Rx
#define SQR_ADDC_CORE				\
	"ldr    r4, [r0], #4		\n\t"	\
	"mov	r7, #0			\n\t"	\
	"umlal  r2, r7, r4, r4		\n\t"	\
	"ldr    r4, [r1]		\n\t"	\
	"ldr    r5, [r1, #4]		\n\t"	\
	"mov	r3, r5, lsr #31		\n\t"	\
	"adds	r4, r4			\n\t"	\
	"adc	r5, r5			\n\t"	\
	"adds	r4, r2			\n\t"	\
	"adcs	r5, r7			\n\t"	\
	"str	r4, [r1], #4		\n\t"	\
	"str	r5, [r1], #4		\n\t"	\
	"adc	r2, r3, #0		\n\t"

#define SQR_STOP	                                    \
	"str    r2, %0                      \n\t"	\
	"str    r1, %1                      \n\t"	\
	"str    r0, %2                      \n\t"	\
	: "=m" (c), "=m" (d), "=m" (s)			\
	: "m" (s), "m" (d), "m" (c)			\
	: "r0", "r1", "r2", "r3", "r4", "r5",		\
	"r6", "r7", "cc"				\
	);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"

static void
    __attribute__((always_inline)) bn_mul_line0_sqr(uint8_t i, uint32_t * s, uint32_t * d,
						    uint32_t b)
{
	uint32_t c = 0;

 /* *INDENT-OFF* */
	for (; i >= 16; i -= 16) {
		MUL_INIT
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_STOP
	}
	for (; i >= 6; i -= 6) {
		MUL_INIT
		MUL_CORE2
		MUL_CORE2
		MUL_CORE2
		MUL_STOP
	}
	for (; i > 0; i--) {
		MUL_INIT
		MUL_CORE
		MUL_STOP
	}
 /* *INDENT-ON* */
	while (c != 0) {
		*d += c;
		c = (*d < c);
		d++;
	}
}

static void __attribute__((always_inline)) bn_sqr_line(uint8_t i, uint32_t * s, uint32_t * d)
{
	uint32_t c = 0;

 /* *INDENT-OFF* */
	for (; i >= 16; i -= 16) {
		SQR_INIT
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_STOP
	}
	for (; i >= 6; i -= 6) {
		SQR_INIT
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_ADDC_CORE
		SQR_STOP
	}
	for (; i > 0; i--) {
		SQR_INIT
		SQR_ADDC_CORE
		SQR_STOP
	}
 /* *INDENT-ON* */
}

static void
    __attribute__((always_inline)) bn_mul_line_sqr(uint8_t i, uint32_t * s, uint32_t * d,
						   uint32_t b)
{
	uint32_t c = 0;

 /* *INDENT-OFF* */
	for (; i >= 16; i -= 16) {
		MUL_INIT
		MULADDC3_CORE
		MULADDC3_CORE
		MULADDC3_CORE
		MULADDC3_CORE
		MULADDC2_CORE
		MULADDC2_CORE
		MUL_STOP
	}
	for (; i >= 6; i -= 6) {
		MUL_INIT
		MULADDC3_CORE
		MULADDC3_CORE
		MUL_STOP
	}
	for (; i > 0; i--) {
		MUL_INIT
		MULADDC_CORE
		MUL_STOP
	}
 /* *INDENT-ON* */
	while (c != 0) {
		*d += c;
		c = (*d < c);
		d++;
	}
}

#pragma GCC diagnostic pop

void __attribute__((aligned(8))) rsa_square_v(void *R, void *A, uint8_t len)
{
	uint32_t *r = (uint32_t *) R;
	uint32_t *a = (uint32_t *) A;
	uint32_t *b = (uint32_t *) A;
	int i, j;
	int bi;
	int llen = len ? len : 256;

	i = llen / 4;
	j = i;

	r[0] = 0;
	memset(&r[i], 0, llen);

	bn_mul_line0_sqr(--i, ++a, r + 1, b[0]);
	for (bi = 1; bi < j - 1; bi++)
		bn_mul_line_sqr(--i, ++a, r + 1 + bi * 2, b[bi]);

	bn_sqr_line(llen / 4, (uint32_t *) A, r);
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

#endif
#if 1
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
			     "mov	r3, #0xff\n"	//
// loop:
			     "nop\n"	// align jump to multiple of 8..
			     "nop\n"	// align jump to multiple of 8..
			     "nop\n"	// align jump to multiple of 8..
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
#endif
uint8_t bn_sub_v(void *r, void *a, void *b, uint8_t len);
#if 1
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
#endif
