/*
    ec.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2017 Peter Popovec, popovec.peter@gmail.com

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

    WARNING:

    tested curves (with fast reduction algo)
    nistp192/prime192v1/secp192r1
    nistp256/secp256r1/prime256v1
    secp384r1
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

//    number of bytes for blinding key in ec_mul, (tested for 0 and 4 only)
#define EC_BLIND 4
#include <string.h>
#include <stdint.h>
#include "rnd.h"
#include "ec.h"
#include "bn_lib.h"
#include <stdio.h>

uint8_t
mp_get_len ()
{
  return mod_len;
}

static void
mp_set_len (uint8_t a)
{
  mod_len = a;
}

extern void rsa_mul_384 (uint8_t * r, uint8_t * a, uint8_t * b);
extern void rsa_mul_256 (uint8_t * r, uint8_t * a, uint8_t * b);
extern void rsa_mul_192 (uint8_t * r, uint8_t * a, uint8_t * b);
extern void rsa_square_384 (uint8_t * r, uint8_t * a);
extern void rsa_square_256 (uint8_t * r, uint8_t * a);
extern void rsa_square_192 (uint8_t * r, uint8_t * a);

#ifdef EC_DEBUG
#include <stdio.h>
#define  DPRINT(msg...) fprintf(stderr,msg)
static void __attribute__ ((unused)) hex_print_f (FILE * f, bignum_t * t)
{
  int8_t i;
  uint8_t *T = (void *) t;

  fprintf (f, "0x");
  for (i = mp_get_len () - 1; i >= 0; i--)
    fprintf (f, "%02X", T[i]);
  fprintf (f, "\n");
}
#else
#define DPRINT(msg...)
#endif

typedef struct
{
  uint8_t value[MP_BYTES * 2];
} bigbignum_t;


// functions map ..  FINAL is function that not call any other functions (except memcpy/memset)
//

// ec mathematics (point in projective representation!)
static uint8_t ecisinf (ec_point_t * point);
static void ec_double (ec_point_t * a);
static uint8_t ec_add_ (ec_point_t * a, ec_point_t * b);
static void ec_mul (ec_point_t * point, uint8_t * f);
static void ec_projectify (ec_point_t * r);

//return projective representation to affinite
static uint8_t ec_affinify (ec_point_t * point, struct ec_param *ec);
/**************************************************************************
*                   field mathematics (mod p192)                          *
***************************************************************************/
static void field_sqr (bignum_t * r, bignum_t * a);
static void field_mul (bignum_t * r, bignum_t * a, bignum_t * b);
static void fast192reduction (bignum_t * result, bigbignum_t * bn);
/**************************************************************************
*                       modular arithmetic                               *
***************************************************************************/
static void mul_mod (bignum_t * result, bignum_t * a, bignum_t * b,
		     bignum_t * mod);
/**************************************************************************
*                     basic multiple precision arithmetic                *
***************************************************************************/
uint8_t __attribute__ ((weak)) mp_is_zero (bignum_t * a)
{
  return bn_is_zero (a);
}

uint8_t __attribute__ ((weak)) mp_add (bignum_t * r, bignum_t * a)
{
  return bn_add (r, a);
}

uint8_t
  __attribute__ ((weak)) mp_sub (bignum_t * r, bignum_t * a, bignum_t * b)
{
  return bn_sub (r, a, b);
}

uint8_t __attribute__ ((weak)) mp_cmpGE (bignum_t * c, bignum_t * d)
{
  return bn_cmpGE (c, d);
}

void
  __attribute__ ((weak)) add_mod (bignum_t * r, bignum_t * a, bignum_t * mod)
{
  bn_add_mod (r, a, mod);
}

void
  __attribute__ ((weak)) sub_mod (bignum_t * r, bignum_t * a, bignum_t * mod)
{
  bn_sub_mod (r, a, mod);
}

uint8_t __attribute__ ((weak)) mp_shiftl (bignum_t * r)
{
  return bn_shiftl (r);
}

uint8_t __attribute__ ((weak)) mp_shiftr (bignum_t * r)
{
  return bn_shiftr (r);
}

uint8_t __attribute__ ((weak)) mp_shiftr_c (bignum_t * r, uint8_t carry)
{
  return bn_shiftr_c (r, carry);
}

void __attribute__ ((weak)) mp_mod (bigbignum_t * result, bignum_t * mod)
{
  bn_mod (result, mod);
}

uint8_t __attribute__ ((weak)) mp_inv_mod (bignum_t * result, bignum_t * a, bignum_t * mod)
{
  return bn_inv_mod (result, a, mod);
}

void __attribute__ ((weak))
mp_mul_192 (bigbignum_t * r, bignum_t * a, bignum_t * b)
{
  bn_mul_v (r, a, b, 24);
}

void __attribute__ ((weak))
mp_mul_256 (bigbignum_t * r, bignum_t * a, bignum_t * b)
{
  bn_mul_v (r, a, b, 32);
}

void __attribute__ ((weak))
mp_mul_384 (bigbignum_t * r, bignum_t * a, bignum_t * b)
{
  bn_mul_v (r, a, b, 48);
}


static void mp_mul (bigbignum_t * r, bignum_t * b, bignum_t * a);

static void mp_square (bigbignum_t * r, bignum_t * a);


#define mp_set(r,c) memcpy (r, c, mp_get_len ())
#define mp_clear(r) memset (r, 0, mp_get_len ());


// to fast access prime, A, curve_type .. fill this in any public fcion!
bignum_t *field_prime __attribute__ ((section (".noinit")));
static bignum_t *param_a __attribute__ ((section (".noinit")));
static uint8_t curve_type __attribute__ ((section (".noinit")));

//Change point from affine to projective
static void
ec_projectify (ec_point_t * r)
{
  DPRINT ("%s\n", __FUNCTION__);

  memset (&(r->Z), 0, mp_get_len ());
  r->Z.value[0] = 1;
}

static void
field_add (bignum_t * r, bignum_t * a)
{
  DPRINT ("%s\n", __FUNCTION__);

  add_mod (r, a, field_prime);
}

static void
field_sub (bignum_t * r, bignum_t * a)
{
  DPRINT ("%s\n", __FUNCTION__);

  sub_mod (r, a, field_prime);
}

static void
mul_mod (bignum_t * c, bignum_t * a, bignum_t * b, bignum_t * mod)
{
  bigbignum_t bn;

  DPRINT ("%s\n", __FUNCTION__);

  mp_mul (&bn, a, b);
  mp_mod (&bn, mod);
  memset (c, 0, mp_get_len ());
  memcpy (c, &bn, mp_get_len ());
}

static uint8_t
ecisinf (ec_point_t * point)
{
  return mp_is_zero (&point->Y);
}

#ifndef NIST_ONLY
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
21. s = c0 + k + w1 + w2 + w3 + w4 + w5 + w6 + w7;
22. Return s mod p.
(code below with small optimizations)
*/
static void
secp256k1reduction (bignum_t * result, bigbignum_t * bn)
{
  DPRINT ("%s\n", __FUNCTION__);

  bignum_t w1, k;
  uint8_t *a = (uint8_t *) bn;
  uint16_t acc, k1;

  field_add ((bignum_t *) a, (bignum_t *) (a + 32));

  memset ((uint8_t *) result, 0, 4);
  memcpy ((uint8_t *) result + 4, a + 32, 28);
  field_add ((bignum_t *) a, result);

  memcpy ((uint8_t *) result + 1, a + 32, 31);
  field_add ((bignum_t *) a, result);

  mp_shiftl ((bignum_t *) result);
  field_add (result, (bignum_t *) a);

  memcpy (&w1, a + 32, 32);
  mp_shiftl (&w1);
  mp_shiftl (&w1);
  mp_shiftl (&w1);
  mp_shiftl (&w1);
  field_add (result, &w1);

  mp_shiftl (&w1);
  mp_shiftl (&w1);
  field_add (result, &w1);

  mp_shiftl (&w1);
  field_add (result, &w1);

  acc = bn->value[63];
  k1 = acc >> 4;
  k1 += acc >> 2;
  k1 += (acc >> 1);
  k1 += acc;
  k1 += (acc << 1);
  acc = bn->value[62] >> 7;
  k1 += acc;

// there is enough to calculate 80 bites for k, use 16 bytes
// because mp_add in ASM is designed to use 64 bit in one loop
  mp_set_len (16);

  memset (&w1, 0, 32);
  memcpy (&w1, a + 60, 4);

  memset (&k, 0, 32);
  k.value[0] = k1 & 0xff;
  k.value[1] = (k1 >> 8) & 0xff;
  mp_add (&w1, &k);

  memset (&k, 0, 2);
  memcpy (&k.value[4], &w1, 28);	//32
  mp_add (&k, &w1);
  mp_shiftl (&w1);
  mp_shiftl (&w1);
  mp_shiftl (&w1);
  mp_shiftl (&w1);
  mp_add (&k, &w1);		//4
  mp_shiftl (&w1);
  mp_shiftl (&w1);
  mp_add (&k, &w1);		//6
  mp_shiftl (&w1);
  mp_add (&k, &w1);		//7
  mp_shiftl (&w1);
  mp_add (&k, &w1);		//8
  mp_shiftl (&w1);
  mp_add (&k, &w1);		//9

  mp_set_len (32);		// secp256k1 uses always 32 bytes for number
  field_add (result, &k);
}

#endif

#ifdef HAVE_secp384r1_REDUCTION
extern void fast384reduction (bignum_t * result, bigbignum_t * bn);
#else
static void fast384reduction (bignum_t * result, bigbignum_t * bn);
#endif
#ifndef HAVE_secp384r1_REDUCTION
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
*/
static void
fast384reduction (bignum_t * result, bigbignum_t * bn)
{
  uint8_t *ptr = (void *) bn;
  uint8_t *r = (void *) result;
  uint8_t carry;

  mp_set_len (16);
  // S1(0,A23,A22,A21) || S4(a20) || 0 || S4(A23) || S6(A20)
  memset (r + 7 * 4, 0, 4);	// 0
  memcpy (r + 3 * 4, ptr + 20 * 4, 4 * 4);	// S1(A23..A21)||S4(A20)
  memset (r + 2 * 4, 0, 4);	// 0
  memcpy (r + 1 * 4, ptr + 23 * 4, 4);	//S4(A23)
  memcpy (r + 0 * 4, ptr + 20 * 4, 4);	//S6(A20)
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

: r = t + s1 + s1x + 2 s2 + s3 + s4 - d1 - d2 - d3 - d4
*/

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
  memcpy (ptr_l, ptr_l + 32, 32);
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
  DPRINT ("%s\n", __FUNCTION__);

// use field_add - code is small but fast enough

  // ADD the diagonal parts to T
  field_add ((bignum_t *) bn, (bignum_t *) & bn->value[3 * 8]);
  // generate (0 || A5 || 0) in result
  memset (result, 0, 3 * 8);
  memcpy (&result->value[1 * 8], &bn->value[5 * 8], 8);
  // result = T + diagonal parts +  (0 || A5 || 0) (in result)
  field_add (result, (bignum_t *) bn);
  // A5 copy over A2 (A2 is not needed anymore)
  // this create line (A4 || A3 || A5)
  memcpy (&bn->value[2 * 8], &bn->value[5 * 8], 8);
  field_add (result, (bignum_t *) & bn->value[2 * 8]);

}

static void
field_mul (bignum_t * r, bignum_t * a, bignum_t * b)
{
  bigbignum_t bn;

  DPRINT ("%s\n", __FUNCTION__);

  mp_mul (&bn, a, b);

// known curves/primes:
  if (curve_type == C_PRIME192V1)
    return fast192reduction (r, &bn);
  if (curve_type == C_PRIME256V1)
    return fast256reduction (r, &bn);
#ifdef NIST_ONLY
  return fast384reduction (r, &bn);
#else

  if (curve_type == C_secp384r1)
    return fast384reduction (r, &bn);

  if (curve_type == C_secp256k1)
    return secp256k1reduction (r, &bn);

  mp_mod (&bn, field_prime);
  memcpy (r, &bn, mp_get_len ());

#endif
}

static void
field_sqr (bignum_t * r, bignum_t * a)
{
  bigbignum_t bn;

  DPRINT ("%s\n", __FUNCTION__);

  mp_square (&bn, a);

// known curves/primes:
  if (curve_type == C_PRIME192V1)
    return fast192reduction (r, &bn);
  if (curve_type == C_PRIME256V1)
    return fast256reduction (r, &bn);
#ifdef NIST_ONLY
  return fast384reduction (r, &bn);
#else
  if (curve_type == C_secp384r1)
    return fast384reduction (r, &bn);

  if (curve_type == C_secp256k1)
    return secp256k1reduction (r, &bn);

// any other curves ..
  mp_mod (&bn, field_prime);
  memcpy (r, &bn, mp_get_len ());
#endif
}

//#define field_sqr(r,a) field_mul(r,a,a)

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
  memset (&point->Z, 0, mp_get_len ());
  point->Z.value[0] = 1;
  return 0;
}

//NIST reference implementation .. not working for secp256k1!
//#define NIST_DOUBLE
#ifdef NIST_DOUBLE
#ifndef NIST_ONLY
#error NIST ec_double routine fail for secp256k1
#endif
static __attribute__ ((unused))
     void ec_double (ec_point_t * a)
{
  bignum_t t1, t2, t3, t4, t5;

  DPRINT ("%s\n", __FUNCTION__);

  mp_set (&t1, a->X.value);	//1
  mp_set (&t2, a->Y.value);	//2
  mp_set (&t3, a->Z.value);	//3

  if (mp_is_zero (&(a->Z)))	//4
    {
      mp_set_to_1 (&(a->X));	//5
      mp_set_to_1 (&(a->Y));
      DPRINT ("Not projective point ?\n");
      return;
    }				//6
  field_sqr (&t4, &t3);		//7  t4 = t3^2
  memcpy (&t5, &t1, sizeof (bignum_t));
  field_sub (&t5, &t4);		//8  t5 = t1 - t4
  field_add (&t4, &t1);		//9  t4 = t1 + t4
  field_mul (&t5, &t4, &t5);	//10 t5 = t4 + t5
  //                            //11 t4 = 3*t5
  memcpy (&t4, &t5, sizeof (bignum_t));
  field_add (&t4, &t5);		//   2*t5
  field_add (&t4, &t5);		//   3*t5
  //
  field_mul (&t3, &t3, &t2);	//12 t3 = t3 * t2
  field_add (&t3, &t3);		//13 t3 = t3*2
  field_sqr (&t2, &t2);		//14 t2 = t2^2
  field_mul (&t5, &t1, &t2);	//15 t5 = t1 * &t2
  //                            //16 t5 = 4*t5;
  field_add (&t5, &t5);		//   2x
  field_add (&t5, &t5);		//   4x
  field_sqr (&t1, &t4);		//17 t1 = t4^2
  //                            //18 t1 = t1 - 2*t5
  field_sub (&t1, &t5);
  field_sub (&t1, &t5);
  //
  field_sqr (&t2, &t2);		//19 t2=t2^2
  //                            //20 t2=8*t2
  field_add (&t2, &t2);		//   2x
  field_add (&t2, &t2);		//   4x
  field_add (&t2, &t2);		//   8x
  //
  field_sub (&t5, &t1);		//21 t5 = t5 - t1
  field_mul (&t5, &t4, &t5);	//22
  field_sub (&t5, &t2);		//23

  mp_set (a->X.value, &t1);	//24
  mp_set (a->Y.value, &t5);	//25
  mp_set (a->Z.value, &t3);	//26
}
#else //NIST_DOUBLE

static void
ec_double (ec_point_t * a)
{
  bignum_t S, M, YY, T;

  DPRINT ("%s\n", __FUNCTION__);

  if (ecisinf (a))
    return;
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
#endif //!NIST_DOUBLE

/**************************************************/
#if 0				// NIST ADD
// NIST reference implementation
static uint8_t
ec_add_ (ec_point_t * s, ec_point_t * t)
{
  bignum_t XX, YY, tX, tY, tZZ;

  if (!mp_is_1 (&t->Z))
    {
      field_sqr (&tZZ, &(t->Z));
      field_mul (&(s->X), &(s->X), &tZZ);
      field_mul (&tZZ, &(t->Z), &tZZ);
      field_mul (&(s->Y), &(s->Y), &tZZ);
    }
  else
    field_sqr (&tZZ, &(s->Z));

  field_mul (&tX, &(t->X), &tZZ);
  field_mul (&tZZ, &(s->Z), &tZZ);	// Z^3
  field_mul (&tY, &(t->Y), &tZZ);

// 13
  memcpy (&XX, &(s->X), sizeof (bignum_t));
  field_sub (&XX, &tX);
// 14
  memcpy (&YY, &(s->Y), sizeof (bignum_t));
  field_sub (&(s->Y), &tY);

  if (mp_is_zero (&XX))
    {
      if (mp_is_zero (&(s->Y)))
	return 1;		//signalize double(a) is needed
      else
	{
	  memset (s, 0, sizeof (*s));
	  a->X.value[0] = 1;
	  a->Y.value[0] = 1;
	  return 0;
	}
    }
//22
  field_add (&(s->X), &(s->X));
  field_sub (&(s->X), &XX);
//23
  field_add (&YY, &YY);
  field_sub (&YY, &(s->Y));
//24,25,26
  if (!mp_is_1 (&t->Z))
    field_mul (&(s->Z), &(s->Z), &(t->Z));
  field_mul (&(s->Z), &(s->Z), &XX);	// 27 - final Z

// reuse tZZ ..
  field_sqr (&tZZ, &XX);	// 28
  field_mul (&XX, &XX, &tZZ);	// 29
  field_mul (&tZZ, &(s->X), &tZZ);	// 30
  field_sqr (&(s->X), &(s->Y));	// 31
  field_sub (&(s->X), &tZZ);	// 32   - final X

  field_sub (&tZZ, &(s->X));	// 33
  field_sub (&tZZ, &(s->X));	// 33
  field_mul (&(s->Y), &(s->Y), &tZZ);	// 34
  field_mul (&XX, &YY, &XX);	// 35
  field_sub (&(s->Y), &XX);	// 36
// 37
  if (mp_test_even (&(s->Y)))
    mp_shiftr (&(s->Y));	// Y = Y / 2
  else
    // Y = (Y + p)/2 {do not reduce sum modulo p}
    mp_shiftr_c (&(s->Y), mp_add (&(s->Y), field_prime));
  return 0;
}
#else // NIST ADD
static uint8_t
ec_add_ (ec_point_t * a, ec_point_t * b)
{
  bignum_t u1, u2, s1, s2, t1, t2;

  DPRINT ("%s\n", __FUNCTION__);

  if (ecisinf (b))
    return 0;
  if (ecisinf (a))
    {
      *a = *b;
      return 0;
    }

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

  if (mp_is_zero (&u2))
    {
      if (mp_is_zero (&s2))
	return 1;		//signalize double(a) is needed
      else
	{
	  memset (a, 0, sizeof (*a));
	  a->X.value[0] = 1;
	  a->Y.value[0] = 1;
	  return 0;
	}
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
  return 0;
}

#undef H
#undef R
#endif //!NIST ADD

//ec_full_add (R, S, T ): Set R to S+T . All points projective
static void
ec_full_add (ec_point_t * result, ec_point_t * s, ec_point_t * t)
{

  DPRINT ("%s\n", __FUNCTION__);

  if (mp_is_zero (&(s->Z)))
    {
      memcpy (result, t, sizeof (ec_point_t));
      return;
    }
  memcpy (result, s, sizeof (ec_point_t));
  if (mp_is_zero (&(t->Z)))
    {
      return;
    }
  if (ec_add_ (result, t))
    {
      memcpy (result, s, sizeof (ec_point_t));
      ec_double (result);
    }
}

#if 0

//this is needed by ec_mul by nist ..  do not compile it if not needed
static __attribute__ ((unused))
     void ec_full_sub (ec_point_t * result, ec_point_t * s, ec_point_t * t)
{
  ec_point_t u;

  DPRINT ("%s\n", __FUNCTION__);

  memcpy (&u, t, sizeof (ec_point_t));

  mp_sub (&(u.Y), field_prime, &(u.Y));
  ec_full_add (result, s, &u);
}

#error Do not use this, not working code!
static void
ec_mul_nist (ec_point_t * result, bignum_t * num, ec_point_t * s)
{
  int i, flag;
  bignum_t d3;
  bignum_t d;
  ec_point_t u;

  mp_set (&d, num);
  mp_set (&d3, num);
  mp_add (&d3, &d3);		//2x d
  mp_add (&d3, num);

  if (mp_is_zero (num))
    {
      memset (result, 0, sizeof (*result));
      mp_set_to_1 (&(result->X));
      mp_set_to_1 (&(result->Y));
      return;
    }
  if (mp_is_1 (num))
    {
      mp_set (result, s);
      return;
    }
  if (mp_is_zero (&(s->Z)))
    {
      memset (result, 0, sizeof (*result));
      mp_set_to_1 (&(result->X));
      mp_set_to_1 (&(result->Y));
      return;
    }
  memcpy (result, s, sizeof (ec_point_t));

  for (i = mp_get_len () * 8 - 1; i >= 1; i--)
    {
      ec_double (result);
      flag = 0;
      if ((d3.value[mp_get_len () - 1] & 0x80) == 0x80
	  && ((d.value[mp_get_len () - 1] & 0x80) == 0))
	{
	  ec_full_add (&u, result, s);
	  flag = 1;
	}
      if ((d3.value[mp_get_len () - 1] & 0x80) == 0
	  && ((d.value[mp_get_len () - 1] & 0x80) == 0x80))
	{
	  ec_full_sub (&u, result, s);
	  flag = 1;
	}
      if (flag)
	memcpy (result, &u, sizeof (ec_point_t));
      mp_shiftl (&d);
      mp_shiftl (&d3);
    }
}
#endif

#ifndef EC_BLIND
#define EC_BLIND 0
#endif

#ifndef EC_MUL_WINDOW
#define  EC_MUL_WINDOW 4
#endif

#if EC_MUL_WINDOW == 2
// constant time - do ec_add into false result for zero bit(s) in k
static void
ec_mul (ec_point_t * point, uint8_t * k)
{
  int8_t i;
  uint8_t b, b2, j;
  uint8_t index;

  DPRINT ("%s\n", __FUNCTION__);

  ec_point_t r[2];
  ec_point_t table[4];

  memcpy (&table[1], point, sizeof (ec_point_t));
  memcpy (&table[2], point, sizeof (ec_point_t));
  ec_double (&table[2]);
  ec_full_add (&table[3], &table[2], &table[1]);

  memcpy (&r[1], &table[2], sizeof (ec_point_t));
  memset (&r[0], 0, sizeof (ec_point_t));

  for (i = mp_get_len () - 1 + EC_BLIND; i >= 0; i--)
    {
      b = k[i];
      for (j = 0; j < 4; j++)
	{
	  ec_double (&r[0]);
	  ec_double (&r[0]);
	  b2 = b >> 6;
	  index = (b2 == 0);
	  b2 |= index;
	  ec_full_add (&r[index], &r[index], &table[b2]);
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

  DPRINT ("%s\n", __FUNCTION__);
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
      ec_full_add (&r[index], &r[index], &table[b]);
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

  for (i = mp_get_len () - 1 + EC_BLIND; i >= 0; i--)
    {
      b = k[i];
      for (j = 0; j < 2; j++)
	{
	  ec_double (&r[0]);
	  ec_double (&r[0]);
	  ec_double (&r[0]);
	  ec_double (&r[0]);
	  index = (b & 0xf0) == 0;
	  ec_full_add (&r[index], &r[index], &table[(b >> 4) | index]);
	  b <<= 4;
	}
    }
  memcpy (point, &r[0], sizeof (ec_point_t));
}
#else
#error Unknown EC_MUL_WINDOW
#endif

static void
ec_set_param (struct ec_param *ec)
{
  mp_set_len (ec->mp_size);
  field_prime = &ec->prime;
  param_a = &ec->a;
  curve_type = ec->curve_type;
}

#if EC_BLIND > 0
#if EC_BLIND > 7
#error too many blinding bytes
#endif
static void
  __attribute__ ((noinline)) ec_blind_key (uint8_t * blind_key,
					   bignum_t * order)
{
  uint8_t blind_val[sizeof (bignum_t) * 2];
  uint8_t blind_rnd[sizeof (bignum_t)];
  uint8_t len;

  memset (blind_rnd, 0, sizeof (bignum_t));
  rnd_get (blind_rnd, EC_BLIND);
  blind_rnd[EC_BLIND - 1] &= 0x3f;
  blind_rnd[EC_BLIND - 1] |= 0x20;

  mp_mul ((bigbignum_t *) blind_val, (bignum_t *) blind_rnd, order);

  len = mp_get_len ();
  mp_set_len (len + 8);
  mp_add ((bignum_t *) blind_key, (bignum_t *) blind_val);
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
ec_derive_key (ec_point_t * pub_key, struct ec_param * ec)
{
  DPRINT ("%s\n", __FUNCTION__);
  ec_set_param (ec);

  if (!(ec_is_point_affine (pub_key, ec)))
    return 1;

  return ec_calc_key (&ec->working_key, pub_key, ec);
}


uint8_t
ec_key_gener (ec_point_t * pub_key, struct ec_param * ec)
{
  uint8_t i;

  DPRINT ("%s\n", __FUNCTION__);
  // ec_set_param (ec); - called in ec_calc_key()
  // do not use mp_get_len() here

  for (i = 0; i < 5; i++)
    {
      // load key bytes from rnd
      rnd_get ((uint8_t *) & (ec->working_key), ec->mp_size);

      if (0 == ec_calc_key (&(ec->working_key), pub_key, ec))
	return 0;
    }
  DPRINT ("key fail!\n");
  return 1;
}

uint8_t
ecdsa_sign (uint8_t * message, ecdsa_sig_t * ecsig, struct ec_param * ec)
{
  uint8_t i;
  ec_point_t *R = &(ecsig->signature);

// move private key into ecdsa_sig_t structure
  bignum_t *k = &(ec->working_key);
  memcpy (&(ecsig->priv_key), k, sizeof (bignum_t));

  DPRINT ("%s\n", __FUNCTION__);
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
  if (mp_get_len () > 32)
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
  if (mp_get_len () > 32)
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
  if (mp_get_len () > 32)
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
