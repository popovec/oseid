/*
    ec.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2021 Peter Popovec, popovec.peter@gmail.com

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

    elliptic curve cryptography routines

    Code is optimized for 8 bit CPU with small RAM (atmega128..)

    WARNING:

    tested curves (with fast reduction algo):

    secp192r1/nistp192/prime192v1
    secp256r1/nistp256/prime256v1
    secp384r1
    secp521r1
    secp256k1

    All curves in format Y^2 = X^3 -a * X + b
*/


/*
    There is support for blinding in scalar * point multiplication (ec_mul).
    Blinding is realized by adding (random value * curve order) to scalar.
    Up to 8 bytes of random data can be used.  This blinding slow down
    multiplication.  3 or 4 bytes of random data are recomended.  If speed
    is preferred to security, use 0 bytes in blinding.
*/

#define DEBUG_ECC
#include "debug.h"


//    number of bytes for blinding key in ec_mul, (tested for 0 and 4 only)
#define EC_BLIND 4

#include <string.h>
#include <stdint.h>
#include "rnd.h"
#include "ec.h"
#include "bn_lib.h"

#ifndef EC_BLIND
#define EC_BLIND 0
#endif

#ifndef EC_MUL_WINDOW
#define  EC_MUL_WINDOW 4
#endif


uint8_t
mp_get_len (void)
{
  return mod_len;
}

static void
mp_set_len (uint8_t a)
{
  mod_len = a;
}

//extern void mp_mul_521 (uint8_t * r, uint8_t * a, uint8_t * b);
extern void rsa_mul_384 (uint8_t * r, uint8_t * a, uint8_t * b);
extern void rsa_mul_256 (uint8_t * r, uint8_t * a, uint8_t * b);
extern void rsa_mul_192 (uint8_t * r, uint8_t * a, uint8_t * b);
extern void mp_square_521 (uint8_t * r, uint8_t * a);
extern void rsa_square_384 (uint8_t * r, uint8_t * a);
extern void rsa_square_256 (uint8_t * r, uint8_t * a);
extern void rsa_square_192 (uint8_t * r, uint8_t * a);


typedef struct
{
  uint8_t value[MP_BYTES * 2];
} bigbignum_t;


// functions map ..  FINAL is function that not call any other functions (except memcpy/memset)
//

// ec mathematics (point in projective representation!)
static void ec_double (ec_point_t * a);
static void ec_add (ec_point_t * a, ec_point_t * b);
static void ec_mul (ec_point_t * point, uint8_t * f);
static void ec_projectify (ec_point_t * r);

//return projective representation to affinite
static uint8_t ec_affinify (ec_point_t * point, struct ec_param *ec);
/**************************************************************************
*                   field mathematics                                     *
***************************************************************************/
static void field_sqr (bignum_t * r, bignum_t * a);
static void field_mul (bignum_t * r, bignum_t * a, bignum_t * b);
/**************************************************************************
*                       modular arithmetic                               *
***************************************************************************/
static void mul_mod (bignum_t * result, bignum_t * a, bignum_t * b,
		     bignum_t * mod);
/**************************************************************************
*                     basic multiple precision arithmetic                *
***************************************************************************/
uint8_t __attribute__((weak)) mp_is_zero (bignum_t * a)
{
  return bn_is_zero (a);
}

uint8_t __attribute__((weak)) mp_add (bignum_t * r, bignum_t * a)
{
  return bn_add (r, a);
}

uint8_t
  __attribute__((weak)) mp_sub (bignum_t * r, bignum_t * a, bignum_t * b)
{
  return bn_sub (r, a, b);
}

uint8_t __attribute__((weak)) mp_cmpGE (bignum_t * c, bignum_t * d)
{
  return bn_cmpGE (c, d);
}

void
  __attribute__((weak)) add_mod (bignum_t * r, bignum_t * a, bignum_t * mod)
{
  bn_add_mod (r, a, mod);
}

void
  __attribute__((weak)) sub_mod (bignum_t * r, bignum_t * a, bignum_t * mod)
{
  bn_sub_mod (r, a, mod);
}

uint8_t __attribute__((weak)) mp_shiftl (bignum_t * r)
{
  return bn_shiftl (r);
}

void __attribute__((weak)) mp_shiftl2 (bignum_t * r)
{
  mp_shiftl (r);
  mp_shiftl (r);
}

void __attribute__((weak)) mp_shiftl4 (bignum_t * r)
{
  mp_shiftl2 (r);
  mp_shiftl2 (r);
}

uint8_t __attribute__((weak)) mp_shiftr (bignum_t * r)
{
  return bn_shiftr (r);
}
/*
uint8_t __attribute__((weak)) mp_shiftr_c (bignum_t * r, uint8_t carry)
{
  return bn_shiftr_c (r, carry);
}
*/
void __attribute__((weak)) mp_mod (bigbignum_t * result, bignum_t * mod)
{
  bn_mod (result, mod);
}

uint8_t
  __attribute__((weak)) mp_inv_mod (bignum_t * result, bignum_t * a,
				    bignum_t * mod)
{
  return bn_inv_mod (result, a, mod);
}

void __attribute__((weak))
mp_mul_192 (bigbignum_t * r, bignum_t * a, bignum_t * b)
{
  bn_mul_v (r, a, b, 24);
}

void __attribute__((weak))
mp_mul_256 (bigbignum_t * r, bignum_t * a, bignum_t * b)
{
  bn_mul_v (r, a, b, 32);
}

void __attribute__((weak))
mp_mul_384 (bigbignum_t * r, bignum_t * a, bignum_t * b)
{
  bn_mul_v (r, a, b, 48);
}

void __attribute__((weak))
mp_mul_521 (bigbignum_t * r, bignum_t * a, bignum_t * b)
{
  bn_mul_v (r, a, b, 72);
}

static void mp_mul (bigbignum_t * r, bignum_t * b, bignum_t * a);

static void mp_square (bigbignum_t * r, bignum_t * a);


#define mp_set(r,c) memcpy (r, c, mp_get_len ())
#define mp_clear(r) memset (r, 0, mp_get_len ());


// to fast access prime, A, curve_type .. fill this in any public fcion!
static bignum_t *field_prime __attribute__((section (".noinit")));
static bignum_t *param_a __attribute__((section (".noinit")));
uint8_t curve_type __attribute__((section (".noinit")));
static bigbignum_t bn_tmp __attribute__((section (".noinit")));

//Change point from affine to projective
static void
ec_projectify (ec_point_t * r)
{
  DPRINT ("%s\n", __FUNCTION__);

  memset (&(r->Z), 0, MP_BYTES);
  r->Z.value[0] = 1;
}

void
field_add (bignum_t * r, bignum_t * a)
{
  add_mod (r, a, field_prime);
}

static void
field_sub (bignum_t * r, bignum_t * a)
{
  sub_mod (r, a, field_prime);
}

static void
mul_mod (bignum_t * c, bignum_t * a, bignum_t * b, bignum_t * mod)
{
  DPRINT ("%s\n", __FUNCTION__);

  mp_mul (&bn_tmp, a, b);
  mp_mod (&bn_tmp, mod);
  memset (c, 0, MP_BYTES);
  memcpy (c, &bn_tmp, mp_get_len ());
}


#ifndef NIST_ONLY
#if MP_BYTES >= 32
/*
FAST REDUCTION for secp256k1 curve
p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
//code based on   http://cse.iitkgp.ac.in/~debdeep/osscrypto/psec/downloads/PSEC-KEM_prime.pdf

1. c0 = a[255:0];
2. c1 = a[511:256];
3. w0 = c0;
4. w1 = {c1[223:0], 32'd0};
5. w2 = {c1[246:0], 9'd0};
6. w3 = {c1[247:0], 8'd0};
7. w4 = {c1[248:0], 7'd0};
8. w5 = {c1[249:0], 6'd0};
9. w6 = {c1[251:0], 4'd0};
10. w7 = c1;
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
21. s = k + w0 + w1 + w2 + w3 + w4 + w5 + w6 + w7;
22. Return s mod p.
(code below with small optimizations)
*/
static void
secp256k1reduction (bignum_t * result, bigbignum_t * bn)
{
  bignum_t *h;
  uint8_t *a = (uint8_t *) bn;
  uint16_t acc, k1;
  uint8_t *s1 = 16 + (uint8_t *) result;

  acc = bn->value[63];
  k1 = acc >> 4;
  k1 += acc >> 2;
  k1 += (acc >> 1);
  k1 += acc;
  k1 += (acc << 1);
  acc = bn->value[62] >> 7;
//14.
  k1 += acc;
// there is enough to calculate 80 bites for k, use 16 bytes
// because mp_add in ASM is designed to use 64 bit in one loop

// 15. prepare k4 part into "result"
  memset (result, 0, 32);

  result->value[0] = k1 & 0xff;
  result->value[1] = (k1 >> 8) & 0xff;

  mp_set_len (16);
// prepare s1 part c1[255:224]
  memcpy (s1, a + 60, 4);
// generate s1, (5 bytes)
  mp_add ((bignum_t *) s1, result);

  result->value[0] = 0;
  result->value[1] = 0;

// 20. s1 << 32
  memcpy (4 + (uint8_t *) result, s1, 5);
  mp_add (result, (bignum_t *) s1);

// k13
  mp_shiftl4 ((bignum_t *) s1);
  mp_add (result, (bignum_t *) s1);	//4
// k14
  mp_shiftl2 ((bignum_t *) s1);
  mp_add (result, (bignum_t *) s1);	//6
// k11,k12
  mp_shiftl ((bignum_t *) s1);
  mp_add (result, (bignum_t *) s1);	//7
  mp_shiftl ((bignum_t *) s1);
  mp_add (result, (bignum_t *) s1);	//8
  mp_shiftl ((bignum_t *) s1);
  mp_add (result, (bignum_t *) s1);	//9
  memset (s1, 0, 16);

  mp_set_len (32);
  // c0
  field_add (result, (bignum_t *) a);
  // c1
  h = (bignum_t *) (a + 32);
  field_add (result, h);
  // w1
  memset (a, 0, 4);
  memcpy (a + 4, h, 28);
  field_add (result, (bignum_t *) a);
// w6   Hpart << 4
  mp_shiftl4 (h);
  field_add (result, h);
// w5   Hpart << 6
  mp_shiftl2 (h);
  field_add (result, h);
// W4   Hpart << 7
  mp_shiftl (h);
  field_add (result, h);
// W3   Hpart << 8
  mp_shiftl (h);
  field_add (result, h);
// W2   Hpart << 9
  mp_shiftl (h);
  field_add (result, h);

/*
second loop - carry in bits xxxx
                                 xxxx0000
                              xx xx000000
                             xxx x0000000
                            xxxx 00000000
                           xxxx0 00000000
 xxxx 00000000 00000000 00000000 00000000
                        (14 bits enough)

  memset (result,0,32);
  result->value[4] = carry;
  result->value[1] = carry + carry <<1;
  result->value[0] = carry << 4;
TODO ..

*/

}
#endif
#endif


#if MP_BYTES >= 48
static void fast384reduction (bignum_t * result, bigbignum_t * bn);
/*
FAST REDUCTION for secp384r1 curve
P384 = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
P384 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFE FFFF FFFF 0000 0000 0000 0000 FFFF FFFF
(2^384-2^128-2^96+2^32-1)

1: {Note: the Ai are 32bit quantities.}
2:*t      ( a11 || a10 || a9  || a8  || a7  || a6  || a5  || a4  || a3  || a2  || a1  || a0  )
3:*s1     ( 0   ||  0  ||  0  ||  0  ||  0  || a23 || a22 || a21 ||  0  ||  0  ||  0  ||  0  )
4: s2     ( a23 || a22 || a21 || a20 || a19 || a18 || a17 || a16 || a15 || a14 || a13 || a12 )
5: s3     ( a20 || a19 || a18 || a17 || a16 || a15 || a14 || a13 || a12 || a23 || a22 || a21 )
6: s4     ( a19 || a18 || a17 || a16 || a15 || a14 || a13 || a12 || a20 ||  0  || a23 ||  0  )
7:*s5     ( 0   ||  0  ||  0  ||  0  || a23 || a22 || a21 || a20 ||  0  ||  0  ||  0  ||  0  )
8:*s6     ( 0   ||  0  ||  0  ||  0  ||  0  ||  0  || a23 || a22 || a21 ||  0  ||  0  || a20 )

9: d1     ( a22 || a21 || a20 || a19 || a18 || a17 || a16 || a15 || a14 || a13 || a12 || a23 )
10: d2    ( 0   ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || a23 || a22 || a21 || a20 ||  0  )
11: d3    ( 0   ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || a23 || a23 ||  0  ||  0  ||  0  )
12: d1 = p384 - d1
13: r = t + 2 s1 + s2 + s3 + s4 + s5 + s6 - d1 - d2 - d3
14: Reduce r mod p384 by subtraction of up to four multiples of p384

here slightly changed calculation is used:
12: r = t + 2 s1 + s2 + s3 + s4 + s5 + s6 + (2*P384)- d1 - (d2 + d3)
*/
static void
fast384reduction (bignum_t * result, bigbignum_t * bn)
{
  uint8_t *ptr = (void *) bn;
  uint8_t *r = (void *) result;
  uint8_t carry;

  mp_set_len (16);
  // S1(0,A23,A22,A21) || S4(a20) || 0 || S4(A23) || S6(A20)
  memcpy (r + 0 * 4, ptr + 20 * 4, 4);	//S6(A20)
  memcpy (r + 1 * 4, ptr + 23 * 4, 4);	//S4(A23)
  memset (r + 2 * 4, 0, 4);	// 0
  memcpy (r + 3 * 4, ptr + 20 * 4, 4 * 4);	// S1(A23..A21)||S4(A20)
  memset (r + 7 * 4, 0, 4);	// 0
//2xS1
  mp_shiftl ((bignum_t *) (r + 4 * 4));
// Construct part of S6(0, a23,a22,a21) in upper part of result
  memset (r + 4 * 11, 0, 4);
  memcpy (r + 4 * 8, ptr + 21 * 4, 3 * 4);
  r[7 * 4] += mp_add ((bignum_t *) (r + 4 * 3), (bignum_t *) (r + 4 * 8));
// 1x S5
  r[8 * 4] = mp_add ((bignum_t *) (r + 4 * 4), (bignum_t *) (ptr + 20 * 4));

  memset (r + 8 * 4 + 1, 0, 15);

//////////////////////////////////////////////////////////////////
  mp_set_len (48);
// T
  carry = mp_add (result, (bignum_t *) bn);
// 1x S2
  carry += mp_add (result, (bignum_t *) & bn->value[48]);

// 1x S4 - reuse upper part of BN  (A20,A23 already in result)
  memset (&bn->value[48 - 4 * 4], 0, 4 * 4);
  carry += mp_add (result, (bignum_t *) & bn->value[48 - 4 * 4]);

// 1x S3 - reuse upper part of BN a20..a12, copy only a23..a20 to low part
  memcpy (&bn->value[48 - 4 * 4], &bn->value[20 * 4], 4 * 4);
  carry += mp_add (result, (bignum_t *) & bn->value[48 - 3 * 4]);

// 2x p384.. (to eliminate borrow in -D1  and -(D2+D3)
  carry += mp_add (result, field_prime);
  carry += mp_add (result, field_prime);
// D1  reuse upper part of BN
  carry -= mp_sub (result, result, (bignum_t *) & bn->value[48 - 1 * 4]);

  mp_set_len (8);
// Create A23,A23 for D3 overwrite A22 by A23 in operand
  memcpy (ptr + 22 * 4, ptr + 23 * 4, 4);
  // A23..A20 already in T.., summarize D3,D2
  ptr[12 * 4] =
    mp_add ((bignum_t *) (ptr + 10 * 4), (bignum_t *) (ptr + 22 * 4));
// T: A23||A22||A21||A20||0
  memset (ptr + 7 * 4, 0, 4);
  memset (ptr + 12 * 4 + 1, 0, 7 * 4 - 1);
  mp_set_len (48);
// subtract (D2+D3)
  carry -= mp_sub (result, result, (bignum_t *) (ptr + 7 * 4));
/*
repeat reduction, already 384 bits in result + 8 bit variable in carry)
A12 is created from carry..
:*t      ( a11 || a10 || a9  || a8  || a7  || a6  || a5  || a4  || a3  || a2  || a1  || a0  )
: s2     (  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || a12 )
: s3     (  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || a12 ||  0  ||  0  ||  0  )
: s4     (  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || a12 ||  0  ||  0  ||  0  ||  0  )
: d1     (  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || a12 ||  0  )
result=t+s2+s3+s4 -d1

 S3 > D1, there is enoungh to calculate with 16 bytes
 from previous D2+D3 there is some part of zeros in BN

 reuse zeros in upper part of PTR
 96.................................   48 .. 47.................. 31........................11
 xxxxx 0000 0000 0000 0000 0000 0000 000x    xxxx xxxx xxxxx xxxx 0000 xxxx xxxx xxxxx xxxxx
 need 48+16 zeros .., have 27 ..
*/
  ptr += 12;
  memset (ptr, 0, 48 + 16 - 27);
  mp_set_len (16);

  ptr[4 + 48] = carry;		// D1
  ptr[0] = carry;		// S2
  ptr[12] = carry;		// S3
  ptr[16] = carry;		// S4
  mp_sub ((bignum_t *) ptr, (bignum_t *) ptr, (bignum_t *) (ptr + 48));

  mp_set_len (48);
// final summarization and reduction
  field_add (result, (bignum_t *) ptr);

  return;
}
#endif

/*
FAST REDUCTION for nistp256/secp256r1/prime256v1 OID 1.2.840.10045.3.1.7 curve

result = bn (mod P256)

P256 = 115792089210356248762697446949407573530086143415290314195533631308867097853951
P256 = 0xFF FF FF FF  00 00 00 01  00 00 00 00   00 00 00 00  00 00 00 00  FF FF FF FF  FF FF FF FF  FF FF FF FF

// original NIST desc..
1: { Ai in 32bit quantities.}
2: t   ( A7  || A6  || A5  || A4  || A3  || A2  || A1  || A0  )
3: s1  ( A15 || A14 || A13 || A12 || A11 || 0   || 0   || 0   )
4: s2  ( 0   || A15 || A14 || A13 || A12 || 0   || 0   || 0   )
5: s3  ( A15 || A14 || 0   || 0   || 0   || A10 || A9  || A8  )
6: s4  ( A8  || A13 || A15 || A14 || A13 || A11 || A10 || A9  )
7: d1  ( A10 || A8  || 0   || 0   || 0   || A13 || A12 || A11 )
8: d2  ( A11 || A9  || 0   || 0   || A15 || A14 || A13 || A12 )
9: d3  ( A12 || 0   || A10 || A9  || A8  || A15 || A14 || A13 )
10: d4 ( A13 || 0   || A11 || A10 || A9  || 0   || A15 || A14 )
11: d1 = 2p256 - d1
12: d2 = 2p256 - d2
13: d3 = p256 - d3
14: d4 = p256 - d4
15: r = t + 2 s1 + 2 s2 + s3 + s4 + d1 + d2 + d3 + d4
reduce r mod p256 by substraction up to 10 multiples of p256

// first some changes to minimize memory copy
move some part of S4 to S2, from S3 to S1, then use field_sub/add

: t   ( A7  || A6  || A5  || A4  || A3  || A2  || A1  || A0  )
: s1  ( A15 || A14 || A13 || A12 || A11 || A10 || A9  || A8  )
: s1x ( A15 || A14 || A13 || A12 || A11 || 0   || 0   || 0   )
: s3  ( A15 || A14 || 0   || 0   || 0   || 0   || 0   || 0   )
: s2  ( 0   || A15 || A14 || A13 || A12 || A11 || A10 || A9  )
: s2x ( 0   || A15 || A14 || A13 || A12 || 0   || 0   || 0   )
: s4  ( A8  || A13 || A15 || A14 || A13 || 0   || 0   || 0   )

: d1  ( A10 || A8  || 0   || 0   || 0   || A13 || A12 || A11 )
: d2  ( A11 || A9  || 0   || 0   || A15 || A14 || A13 || A12 )
: d3  ( A12 || 0   || A10 || A9  || A8  || A15 || A14 || A13 )
: d4  ( A13 || 0   || A11 || A10 || A9  || 0   || A15 || A14 )

: r = t + s1 + s1x + s2 + s2x + s3 + s4 + (4*P256)- d1 - d2 - d3 - d4
*/
#if MP_BYTES >= 32

static void
fast256reduction (bignum_t * result, bigbignum_t * bn)
{
  uint8_t *ptr_l = (void *) bn;
  uint8_t carry;

  memcpy (result, field_prime, 32);
  mp_shiftl (result);
  mp_shiftl (result);
  carry = 3;
  // result += T
  carry += mp_add (result, (bignum_t *) bn);
  // result +=s1
  carry += mp_add (result, (bignum_t *) & bn->value[32]);

// use T as TMP
  //s4 to TMP
  memset (ptr_l, 0, 3 * 4);
  memcpy (ptr_l + 3 * 4, ptr_l + 13 * 4, 3 * 4);
  memcpy (ptr_l + 6 * 4, ptr_l + 13 * 4, 1 * 4);
  memcpy (ptr_l + 7 * 4, ptr_l + 8 * 4, 1 * 4);
  //result +=S4
  carry += mp_add (result, (bignum_t *) ptr_l);

  // S2 to TMP
  memcpy (ptr_l + 0 * 4, ptr_l + 9 * 4, 7 * 4);
  memset (ptr_l + 7 * 4 + 1, 0, 3);
  // TMP += S2X
  mp_set_len (16);
  *(ptr_l + 7 * 4) = mp_shiftl ((bignum_t *) (ptr_l + 3 * 4));
  // TMP += S3
  mp_set_len (8);
  carry +=
    mp_add ((bignum_t *) (ptr_l + 6 * 4), (bignum_t *) (ptr_l + 14 * 4));

  mp_set_len (32);
  // R += TMP
  carry += mp_add (result, (bignum_t *) bn);
  //S1x
  memcpy (ptr_l + 12, ptr_l + 32 + 12, 32 - 12);
  memset (ptr_l, 0, 12);
  carry += mp_add (result, (bignum_t *) bn);

//: d3  ( A12 || 0   || A10 || A9  || A8  || A15 || A14 || A13 )
//: d4  ( A13 || 0   || A11 || A10 || A9  || 0   || A15 || A14 )
//: d2  ( A11 || A9  || 0   || 0   || A15 || A14 || A13 || A12 )
//: d1  ( A10 || A8  || 0   || 0   || 0   || A13 || A12 || A11 )
  memcpy (ptr_l, ptr_l + 32, 12);
  //D3
  memset (ptr_l + 11 * 4, 0, 4);
  carry -= mp_sub (result, result, (bignum_t *) (ptr_l + 20));
  //D4
  memset (ptr_l + 8 * 4, 0, 4);
  memset (ptr_l + 12 * 4, 0, 4);
  memcpy (ptr_l + 11 * 4, ptr_l + 3 * 4, 4);
  carry -= mp_sub (result, result, (bignum_t *) (ptr_l + 24));
  //D2
  memcpy (ptr_l + 10 * 4, ptr_l + 9 * 4, 4);
  memset (ptr_l + 9 * 4, 0, 4);
  carry -= mp_sub (result, result, (bignum_t *) (ptr_l + 16));
  //D1
  memset (ptr_l + 24, 0, 12);
  memcpy (ptr_l + 9 * 4, ptr_l, 4);
  memcpy (ptr_l + 10 * 4, ptr_l + 2 * 4, 4);
  carry -= mp_sub (result, result, (bignum_t *) (ptr_l + 12));
// continue reduction 256+8 bits ..
/*
: t   ( A7  || A6  || A5  || A4  || A3  || A2  || A1  || A0  )
: s1  (  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  || A8  )
: s4  ( A8  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  ||  0  )

: d1  (  0  || A8  || 0   || 0   || 0   ||  0  ||  0  ||  0  )
: d3  (  0  || 0   || 0   || 0   || A8  ||  0  ||  0  ||  0  )
*/
  memset (ptr_l, 0, 64);
  ptr_l[0] = carry;
  ptr_l[7 * 4] = carry;
  ptr_l[11 * 4] = carry;
  ptr_l[14 * 4] = carry;
  mp_sub ((bignum_t *) ptr_l, (bignum_t *) ptr_l, (bignum_t *) (ptr_l + 32));
  field_add (result, (bignum_t *) ptr_l);
}
#endif
/*
 FAST REDUCTION for nistp192/prime192v1/secp192r1 OID 1.2.840.10045.3.1.1 curve

 result = bn (mod P192)

 P192 = 6277101735386680763835789423207666416083908700390324961279
 P192 = 0xFF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FE   FF FF FF FF FF FF FF FF

 (Ai  in 64 bit quantities)

 T =  ( A2 || A1 || A0 )
 S1 = ( 0  || A3 || A3 )
 S2 = ( A4 || A4 || 0  )
 S3 = ( A5 || A5 || A5 )
 R =   T + S1 + S2 + S3
 reduce R by subtraction up to three multiples of p192
*/

static void
fast192reduction (bignum_t * result, bigbignum_t * bn)
{
//  DPRINT ("%s\n", __FUNCTION__);

// use field_add - code is small but fast enough

  // ADD the diagonal parts to T
  field_add ((bignum_t *) bn, (bignum_t *) & bn->value[3 * 8]);
  // generate (0 || A5 || 0) in result
  // coverity[suspicious_sizeof]
  memset (result, 0, 3 * 8);
  memcpy (&result->value[1 * 8], &bn->value[5 * 8], 8);
  // result = T + diagonal parts +  (0 || A5 || 0) (in result)
  field_add (result, (bignum_t *) bn);
  // A5 copy over A2 (A2 is not needed anymore)
  // this create line (A4 || A3 || A5)
  memcpy (&bn->value[2 * 8], &bn->value[5 * 8], 8);
  field_add (result, (bignum_t *) & bn->value[2 * 8]);

}

#if MP_BYTES >= 66
static void
fast521reduction (bignum_t * result, bigbignum_t * bn)
{
  memcpy (result, 65 + (uint8_t *) bn, MP_BYTES);
  bn->value[65] &= 1;
  memset (66 + (uint8_t *) bn, 0, MP_BYTES - 66);
  mp_shiftr (result);
  field_add (result, (bignum_t *) bn);
}
#endif

void __attribute__((weak)) field_reduction (bignum_t * r, bigbignum_t * bn)
{
// known curves/primes:
#if MP_BYTES >= 66
  if (curve_type == (C_SECP521R1 | C_SECP521R1_MASK))
    return fast521reduction (r, bn);
#endif
#if MP_BYTES >= 48
  if (curve_type == (C_SECP384R1 | C_SECP384R1_MASK))
    return fast384reduction (r, bn);
#endif
#if MP_BYTES >= 32
  if (curve_type == (C_P256V1 | C_P256V1_MASK))
    return fast256reduction (r, bn);
#endif
#if MP_BYTES >= 32
  if (curve_type == (C_SECP256K1 | C_SECP256K1_MASK))
    return secp256k1reduction (r, bn);
#endif

#if 1
// no another fast reduction algo, run fast192reduction()...
  fast192reduction (r, bn);
#else
// for tests only - real run without fast reduction is too slow
  if (curve_type == (C_P192V1 | C_P192V1_MASK))
    return fast192reduction (r, bn);
  mp_mod (bn, field_prime);
  memset (r, 0, MP_BYTES);
  memcpy (r, bn, mp_get_len ());
#endif
}

static void
field_mul (bignum_t * r, bignum_t * a, bignum_t * b)
{
  mp_mul (&bn_tmp, a, b);
  field_reduction (r, &bn_tmp);
}

static void
field_sqr (bignum_t * r, bignum_t * a)
{
  mp_square (&bn_tmp, a);
  field_reduction (r, &bn_tmp);
}

static uint8_t
ec_is_point_affine (ec_point_t * p, struct ec_param *ec)
{
  bignum_t yy;
  bignum_t xx;
  bignum_t xxx;

// only supported curves are checked, all others are handled as OK
  if (!(ec->curve_type & 0xc0))
    return 1;
  // Y^2
  field_sqr (&yy, &p->Y);
  // X^2
  field_sqr (&xx, &p->X);
  // X^3
  field_mul (&xxx, &xx, &p->X);
  // X^3 -b
  field_add (&xxx, &ec->b);
  if (ec->curve_type & 0x40)
    {
      // -3 * X - all NIST curves
      field_sub (&xxx, &p->X);
      field_sub (&xxx, &p->X);
      field_sub (&xxx, &p->X);
    }
  mp_sub (&xxx, &xxx, &yy);
  return mp_is_zero (&xxx);
}

static uint8_t
ec_affinify (ec_point_t * point, struct ec_param *ec)
{
  bignum_t n0, n1;

  DPRINT ("%s\n", __FUNCTION__);

  if (mp_is_zero (&(point->Z)))
    {
      DPRINT ("Zero in Z, cannot affinify\n");
      return 1;
    }
  mp_inv_mod (&n0, &point->Z, &ec->prime);	// n0=Z^-1
  field_sqr (&n1, &n0);		// n1=Z^-2
  field_mul (&point->X, &point->X, &n1);	// X*=n1
  field_mul (&n0, &n0, &n1);	// n0=Z^-3
  field_mul (&point->Y, &point->Y, &n0);
  memset (&point->Z, 0, MP_BYTES);
//  memset (&point->Z, 0, mp_get_len ());
  point->Z.value[0] = 1;

  return 0;
}

static void
ec_point_1_1_0 (ec_point_t * a)
{
  memset (a, 0, sizeof (ec_point_t));
  a->X.value[0] = 1;
  a->Y.value[0] = 1;
}

static void
ec_double (ec_point_t * a)
{
  bignum_t S, M, YY, T;
//  DPRINT ("%s\n", __FUNCTION__);

  if (mp_is_zero (&(a->Z)))
    return ec_point_1_1_0 (a);

  field_sqr (&YY, &a->Y);

#ifdef NIST_ONLY
  // only if coefficient A = -3
  field_sqr (&S, &a->Z);
  memcpy (&T, &S, sizeof (bignum_t));
  field_add (&T, &a->X);

  memcpy (&M, &a->X, sizeof (bignum_t));
  field_sub (&M, &S);

  field_mul (&M, &M, &T);	//M=3*(X-Z^2)*(X+X^2)
  memcpy (&T, &M, sizeof (bignum_t));
#else
  if (curve_type & 0x40)	// optimize for A=-3
    {
      field_sqr (&S, &a->Z);
      memcpy (&T, &S, sizeof (bignum_t));
      field_add (&T, &a->X);

      memcpy (&M, &a->X, sizeof (bignum_t));
      field_sub (&M, &S);

      field_mul (&M, &M, &T);
      memcpy (&T, &M, sizeof (bignum_t));
    }
  else if (curve_type & 0x80)	// optimize for A=0
    {				// M = 3* X^2
      field_sqr (&M, &a->X);
      memcpy (&T, &M, sizeof (bignum_t));
    }
  else
    {
      field_sqr (&M, &a->X);	// M=3* X^2
      memcpy (&T, &M, sizeof (bignum_t));
      field_sqr (&S, &a->Z);
      field_sqr (&S, &S);
      field_mul (&S, param_a, &S);	// T=a*Z^4
      field_add (&M, &S);
    }
#endif
  field_add (&T, &T);
  field_add (&M, &T);

  field_mul (&a->Z, &a->Y, &a->Z);
  field_add (&a->Z, &a->Z);	// Z = 2*Y*Z

  field_mul (&a->Y, &a->X, &YY);	// S into Y
  field_add (&a->Y, &a->Y);
  field_add (&a->Y, &a->Y);	// S = 4*X*Y^2

  field_sqr (&a->X, &M);	// X = M^2 - 2*S
  field_sub (&a->X, &a->Y);	// -S
  field_sub (&a->X, &a->Y);	// -S

  field_sqr (&T, &YY);

  field_add (&T, &T);
  field_add (&T, &T);
  field_add (&T, &T);

  field_sub (&a->Y, &a->X);
  field_mul (&a->Y, &M, &a->Y);
  field_sub (&a->Y, &T);	//Y'=M*(S-X') - 8*Y^4
}

/**************************************************/

static void
ec_add (ec_point_t * a, ec_point_t * b)
{
  bignum_t u1, u2, s1, s2, t1, t2;

//  DPRINT ("%s\n", __FUNCTION__);

// NIST tests in ec_full_add:
  if (mp_is_zero (&(a->Z)))
    {
      memcpy (a, b, sizeof (ec_point_t));
      return;
    }
  if (mp_is_zero (&(b->Z)))
    return;

// continue with normal ec_add, check if double is needed

  field_sqr (&t1, &b->Z);
  field_mul (&u1, &a->X, &t1);	//u1 = X1*Z2^2

  field_sqr (&t2, &a->Z);
  field_mul (&u2, &b->X, &t2);	//u2 = X2*Z1^2

  field_mul (&t1, &t1, &b->Z);
  field_mul (&s1, &a->Y, &t1);	//s1 = Y1*Z2^3

  field_mul (&t2, &t2, &a->Z);
  field_mul (&s2, &b->Y, &t2);	//s2 = Y2*Z1^3

  field_sub (&u2, &u1);
  field_sub (&s2, &s1);

  if (mp_is_zero (&u2))		// NIST t4 == zero
    {
      if (mp_is_zero (&s2))	// NIST t5 == zero
	return ec_double (a);
      else
	return ec_point_1_1_0 (a);
    }
#define	H u2
#define R s2

  field_sqr (&t1, &H);		//t1 = H^2
  field_mul (&t2, &H, &t1);	//t2 = H^3
  field_mul (&a->Y, &u1, &t1);	//t3 = u1*h^2

  field_sqr (&a->X, &R);
  field_sub (&a->X, &t2);

  field_sub (&a->X, &a->Y);
  field_sub (&a->X, &a->Y);	//X3=R^2 - H^3 - 2*U1*H^2

  field_sub (&a->Y, &a->X);
  field_mul (&a->Y, &a->Y, &R);

  field_mul (&t1, &s1, &t2);
  field_sub (&a->Y, &t1);

  field_mul (&a->Z, &a->Z, &b->Z);
  field_mul (&a->Z, &a->Z, &H);
  return;
}

#undef H
#undef R

//ec_full_add (R, S, T ): Set R to S+T . All points projective
static void
ec_full_add (ec_point_t * result, ec_point_t * s, ec_point_t * t)
{
  // this is only wrapper for ec_add, all tests for valid 's'/'t' or
  // doubling of 's' can be found inside ec_add...
  memcpy (result, s, sizeof (ec_point_t));
  ec_add (result, t);
}


#if EC_MUL_WINDOW == 2
// constant time - do ec_add into false result for zero bit(s) in k
static void
ec_mul (ec_point_t * point, uint8_t * k)
{
  int8_t i;
  uint8_t b, b2, j;
  uint8_t index;

//  DPRINT ("%s\n", __FUNCTION__);

  ec_point_t r[2];
  ec_point_t table[4];

  memcpy (&table[1], point, sizeof (ec_point_t));
  memcpy (&table[2], point, sizeof (ec_point_t));
  ec_double (&table[2]);
  ec_full_add (&table[3], &table[2], &table[1]);

  memcpy (&r[1], &table[2], sizeof (ec_point_t));
  memset (&r[0], 0, sizeof (ec_point_t));

  i = mp_get_len () - 1 + EC_BLIND;
#if MP_BYTES >= 66
  if (curve_type == (C_SECP521R1 | C_SECP521R1_MASK))
    i = 66 + EC_BLIND - 1;
#endif
  for (; i >= 0; i--)
    {
      b = k[i];
      for (j = 0; j < 4; j++)
	{
	  ec_double (&r[0]);
	  ec_double (&r[0]);
	  b2 = b >> 6;
	  index = (b2 == 0);
	  b2 |= index;
	  //ec_full_add (&r[index], &r[index], &table[b2]);
	  ec_add (&r[index], &table[b2]);
	  b <<= 2;
	}
    }
  memcpy (point, &r[0], sizeof (ec_point_t));
}
#elif EC_MUL_WINDOW == 3
#if EC_BLIND > 0
#error this code must be fixed for blinding
#endif
static void
ec_mul (ec_point_t * point, uint8_t * k)
{
  int16_t i;
  uint8_t b;
  uint8_t index;

//  DPRINT ("%s\n", __FUNCTION__);
  bignum_t kk;
  memcpy (&kk, k, sizeof (bignum_t));
  ec_point_t data[9];		// 0,1 used as result, 2..17 as precomputed table

  ec_point_t *r = &data[0];
  ec_point_t *table = &data[1];	// table 0 is not used .. but index is from 0

  memcpy (&table[1], point, sizeof (ec_point_t));

  for (index = 2; index < 8; index += 2)
    {
      memcpy (&table[index], &table[index / 2], sizeof (ec_point_t));
      ec_double (&table[index]);
      ec_full_add (&table[index + 1], &table[index], &table[1]);
    }

  memcpy (&r[1], &table[2], sizeof (ec_point_t));
  memset (&r[0], 0, sizeof (ec_point_t));
  switch (mp_get_len ())
    {
    case 32:
      i = 86;
      b = 0;
      goto ec_mul_32;
      break;
    case 24:
      i = 64;
      break;
    case 48:
      i = 128;
      break;
    default:
      return;
    }
  for (;;)
    {
      b = mp_shiftl (&kk);
      b <<= 1;
      b |= mp_shiftl (&kk);
      b <<= 1;
    ec_mul_32:
      b |= mp_shiftl (&kk);
      index = (b == 0);
      b |= index;
      //ec_full_add (&r[index], &r[index], &table[b]);
      ec_add (&r[index], &table[b]);
      if (!(--i))
	break;
      ec_double (&r[0]);
      ec_double (&r[0]);
      ec_double (&r[0]);
    }
  memcpy (point, &r[0], sizeof (ec_point_t));
}

#elif EC_MUL_WINDOW == 4
static void
ec_mul (ec_point_t * point, uint8_t * k)
{
  int8_t i;
  uint8_t b, j;
  uint8_t index;

  DPRINT ("%s\n", __FUNCTION__);

  ec_point_t data[17];		// 0,1 used as result, 2..17 as precomputed table

  ec_point_t *r = &data[0];
  ec_point_t *table = &data[1];	// table 0 is not used .. but index is from 0

  memcpy (&table[1], point, sizeof (ec_point_t));

  for (index = 2; index < 16; index += 2)
    {
      memcpy (&table[index], &table[index / 2], sizeof (ec_point_t));
      ec_double (&table[index]);
      ec_full_add (&table[index + 1], &table[index], &table[1]);
    }

  memcpy (&r[1], &table[2], sizeof (ec_point_t));
  memset (&r[0], 0, sizeof (ec_point_t));
  i = mp_get_len () - 1 + EC_BLIND;
#if MP_BYTES >= 66
  if (curve_type == (C_SECP521R1 | C_SECP521R1_MASK))
    i = 66 + EC_BLIND - 1;
#endif
  for (; i >= 0; i--)
    {
      b = k[i];
      for (j = 0; j < 2; j++)
	{
	  ec_double (&r[0]);
	  ec_double (&r[0]);
	  ec_double (&r[0]);
	  ec_double (&r[0]);
	  index = (b & 0xf0) == 0;
	  //ec_full_add (&r[index], &r[index], &table[(b >> 4) | index]);
	  ec_add (&r[index], &table[(b >> 4) | index]);
	  b <<= 4;
	}
    }
  memcpy (point, &r[0], sizeof (ec_point_t));
}
#else
#error Unknown EC_MUL_WINDOW
#endif

/*
a=2048 b=7  mask=80              b = a[i] & 255;
a=1536 b=5  mask=20              b |= (b & 0xC0) >> 5;
a=1024 b=3  mask=08              b |= (b & 0x40) >> 6;
a=768 b=2  mask=04               b |= a[i] >> 8;
a=512 b=1  mask=02               b &= 0xf;
a=384 b=4  mask=10               b--;
a=256 b=0  mask=01               d = 1 << b;
a=192 b=6  mask=40
*/
static void
ec_set_param (struct ec_param *ec)
{

  mp_set_len (ec->mp_size);
#if MP_BYTES >= 66
  if (ec->mp_size == 66)
    mp_set_len (72);
#endif
  field_prime = &ec->prime;
  param_a = &ec->a;
  curve_type = ec->curve_type;
}

#if EC_BLIND > 0
#if EC_BLIND > 7
#error too many blinding bytes
#endif
static void
  __attribute__((noinline)) ec_blind_key (uint8_t * blind_key,
					  bignum_t * order)
{
  uint8_t blind_rnd[sizeof (bignum_t)];
  uint8_t len;

  memset (blind_rnd, 0, sizeof (bignum_t));
  rnd_get (blind_rnd, EC_BLIND);
  blind_rnd[EC_BLIND - 1] &= 0x3f;
  blind_rnd[EC_BLIND - 1] |= 0x20;

  mp_mul (&bn_tmp, (bignum_t *) blind_rnd, order);
  len = mp_get_len ();
  mp_set_len (len + 8);
  mp_add ((bignum_t *) blind_key, (bignum_t *) (&bn_tmp));

  mp_set_len (len);
}
#endif

// point = k * point
static uint8_t
ec_calc_key (bignum_t * k, ec_point_t * point, struct ec_param *ec)
{
  uint8_t blind_key[sizeof (bignum_t) + 8];

  DPRINT ("%s\n", __FUNCTION__);
  ec_set_param (ec);

  if (mp_is_zero (k))
    return 1;

  // is key below curve order ?
  if (mp_cmpGE (k, &ec->order))
    return 1;

  memset (blind_key, 0, sizeof (blind_key));
  mp_set (blind_key, k);
#if EC_BLIND > 0
  ec_blind_key (blind_key, &(ec->order));
#endif

  DPRINT ("multiplication\n");

  ec_projectify (point);
  ec_mul (point, blind_key);

  if (ec_affinify (point, ec))
    return 1;

  if (mp_is_zero (&(point->X)))	// Rx  mod order != 0
    return 1;
  if (mp_cmpGE (&(point->X), &ec->order))
    return 1;
  DPRINT ("point ok\n");
  return 0;
}


uint8_t
ec_derive_key (ec_point_t * pub_key, struct ec_param *ec)
{
  DPRINT ("%s\n", __FUNCTION__);
  ec_set_param (ec);

  if (!(ec_is_point_affine (pub_key, ec)))
    return 1;

  return ec_calc_key (&ec->working_key, pub_key, ec);
}


uint8_t
ec_key_gener (ec_point_t * pub_key, struct ec_param *ec)
{
  uint8_t i, *key;
  key = (uint8_t *) & (ec->working_key);

  DPRINT ("%s\n", __FUNCTION__);
  // ec_set_param (ec); - called in ec_calc_key()
  // do not use mp_get_len() here

  for (i = 0; i < 5; i++)
    {
      memset (key, 0, MP_BYTES);
      // load key bytes from rnd
      rnd_get (key, ec->mp_size);
#if MP_BYTES >= 66
      if (ec->mp_size > 48)
	key[65] &= 1;
#endif
      if (0 == ec_calc_key (&(ec->working_key), pub_key, ec))
	return 0;
    }
  DPRINT ("key fail!\n");
  return 1;
}

uint8_t
ecdsa_sign (uint8_t * message, ecdsa_sig_t * ecsig, struct ec_param *ec)
{
  uint8_t i;
  ec_point_t *R = &(ecsig->signature);

  DPRINT ("%s\n", __FUNCTION__);

// move private key into ecdsa_sig_t structure
  bignum_t *k = &(ec->working_key);
  memcpy (&(ecsig->priv_key), k, sizeof (bignum_t));

  ec_set_param (ec);

  for (i = 0; i < 5; i++)
    {
      // generate key
      if (ec_key_gener (R, ec))
	continue;
// From generated temp public key only X coordinate is used
// as "r" value of result. "s" value is calculated:

// use r= x position of R, e = HASH, dA = private key
// k,R  temp key (private/public), n = field order
// s = (dA * r + e)/k  mod n

      // signature = dA * r + e
      mul_mod (&(R->Y), &(ecsig->priv_key), &(R->X), &ec->order);
      add_mod (&(R->Y), (bignum_t *) message, &ec->order);

      mp_inv_mod (k, k, &ec->order);	// division by k
      mul_mod (&(R->Y), k, &(R->Y), &ec->order);
      if (!mp_is_zero (&(R->Y)))
	return 0;
      DPRINT ("repeating, s=0\n");
    }
  return 1;
}


/***********************************************************************/
//////////////////////////////////////////////////
static void
mp_mul (bigbignum_t * r, bignum_t * b, bignum_t * a)
{
  if
#if MP_BYTES > 48
    (mp_get_len () > 48)
    {
      mp_mul_521 (r, a, b);
    }
  else if
#endif
    (mp_get_len () > 32)
    {
      mp_mul_384 (r, a, b);
    }
  else if (mp_get_len () > 24)
    {
      mp_mul_256 (r, a, b);
    }
  else
    {
      mp_mul_192 (r, a, b);
    }
}

//////////////////////////////////////////////////
#if defined (HAVE_RSA_SQUARE_384) && defined (HAVE_RSA_SQUARE_256) && defined (HAVE_RSA_SQUARE_192)
static void
mp_square (bigbignum_t * r, bignum_t * a)
{
  if
#if MP_BYTES > 48
    (mp_get_len () > 48)
    {
      mp_square_521 (&r->value[0], &a->value[0]);
    }
  else if
#endif
    (mp_get_len () > 32)
    {
      rsa_square_384 (&r->value[0], &a->value[0]);
    }
  else if (mp_get_len () > 24)
    {
      rsa_square_256 (&r->value[0], &a->value[0]);
    }
  else
    {
      rsa_square_192 (&r->value[0], &a->value[0]);
    }
}
#else
#if defined (HAVE_RSA_MUL_384) && defined (HAVE_RSA_MUL_256) && defined (HAVE_RSA_MUL_192)
static void
mp_square (bigbignum_t * r, bignum_t * a)
{
  if
#if MP_BYTES > 48
    (mp_get_len () > 48)
    {
      mp_mul_521 (&r->value[0], &a->value[0], &a->value[0]);
    }
  else if
#endif
    (mp_get_len () > 32)
    {
      rsa_mul_384 (&r->value[0], &a->value[0], &a->value[0]);
    }
  else if (mp_get_len () > 24)
    {
      rsa_mul_256 (&r->value[0], &a->value[0], &a->value[0]);
    }
  else
    {
      rsa_mul_192 (&r->value[0], &a->value[0], &a->value[0]);
    }
}
#else
static void
mp_square (bigbignum_t * r, bignum_t * a)
{
  mp_mul (r, a, a);
}
#endif
#endif
