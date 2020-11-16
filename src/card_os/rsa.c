/*
    rsa.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2020 Peter Popovec, popovec.peter@gmail.com

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

    montgomery modular arithmetics


Algorithm is based on:
http://www.di-mgt.com.au/crt_rsa.html
and ftp://ftp.rsasecurity.com/pub/pdfs/tr201.pdf

WARNING! it is designed for slow 8 bit CPU with minimal RAM.

Code uses Montgomery exponentiation and Chinese remainder algorithms (CRT).

There are several side channel protections to generally known attacks to RSA
cryptosystem:

- RSA operation is running in constant time, fixed size window (2,4 or 5
  bits) is used in exponentiation.  (Constant time is guaranteed only if code
  is compiled with AVR ASM routines for BN arithmetics)

- Exponent is blinded (24 bit of random data per exponentiation)

- CRT calculation is protected againts Bellcore attack (single error attack)
   (recombination and modulo operation is not protected, but injecting fault
   precisely into this point is very difficult)

Implementation does NOT use message blinding, but due constant time of operation
(no sliding window), it is not possible to use known attacks which could
work due to the absence of a message blinding.

Public exponent is (for now) limited to value 65537.  The single error
checking procedure accepts primes in form 2^n + 1, up to n=255, but only n=16
is hardcoded in code.  Same public exponent 65537 is hardcoded in RSA key
generation routine.

*/
#define DEBUG_RSA
#include "debug.h"

#include <stdint.h>
#include <string.h>
#include "rsa.h"
#include "key.h"
#include "rnd.h"
#include "bn_lib.h"
#include "constants.h"

/////////////////////////////////////////////////////////////////////
// adaptation layer to bn_lib
/////////////////////////////////////////////////////////////////////

// access to global variable also over static functions
static uint8_t
rsa_get_len (void)
{
  return mod_len;
}

static void
rsa_set_len (uint8_t len)
{
  mod_len = len;
}

uint8_t __attribute__((weak)) rsa_add (rsa_num * r, rsa_num * a)
{
  return bn_add (r, a);
}

uint8_t __attribute__((weak))
rsa_add_long (rsa_long_num * r, rsa_long_num * a)
{
  return bn_add_v (r, a, rsa_get_len () * 2, 0);
}

uint8_t __attribute__((weak)) rsa_sub (rsa_num * r, rsa_num * a, rsa_num * b)
{
  return bn_sub (r, a, b);
}

uint8_t
  __attribute__((weak)) mp_add_v (uint8_t * r, uint8_t * a, uint8_t len,
				  uint8_t carry)
{
  return bn_add_v (r, a, len, carry);
}

uint8_t
  __attribute__((weak)) mp_sub_v (uint8_t * r, uint8_t * a, uint8_t * b,
				  uint8_t len)
{
  return bn_sub_v (r, a, b, len);
}

uint8_t __attribute__((weak))
rsa_sub_long (rsa_long_num * r, rsa_long_num * a, rsa_long_num * b)
{
  return bn_sub_v (r, a, b, mod_len * 2);
}

uint8_t __attribute__((weak)) rsa_cmpGE (rsa_num * c, rsa_num * d)
{
  return bn_cmpGE (c, d);
}


uint8_t __attribute__((weak)) rsa_shiftl (rsa_num * r)
{
  return bn_shiftl (r);
}

uint8_t __attribute__((weak)) rsa_shiftr (rsa_num * r)
{
  return bn_shiftr (r);
}

uint8_t __attribute__((weak)) rsa_shiftr_long (rsa_long_num * r)
{
  return bn_shiftr_long (r);
}

void __attribute__((weak)) rsa_mod (rsa_long_num * result, rsa_num * mod)
{
  bn_mod (result, mod);
}

uint8_t
  __attribute__((weak)) rsa_inv_mod (rsa_num * result, rsa_num * a,
				     rsa_num * mod)
{
  return bn_inv_mod (result, a, mod);
}


void
  __attribute__((weak)) rsa_mul_192 (uint8_t * r, uint8_t * a, uint8_t * b);
void
  __attribute__((weak)) rsa_mul_256 (uint8_t * r, uint8_t * a, uint8_t * b);
void
  __attribute__((weak)) rsa_mul_512 (uint8_t * r, uint8_t * a, uint8_t * b);
void
  __attribute__((weak)) rsa_mul_768 (uint8_t * r, uint8_t * a, uint8_t * b);
void
  __attribute__((weak)) rsa_mul_1024 (uint8_t * r, uint8_t * a, uint8_t * b);

void __attribute__((weak)) rsa_square_512 (uint8_t * r, uint8_t * a);

void __attribute__((weak)) rsa_square_768 (uint8_t * r, uint8_t * a);

void __attribute__((weak)) rsa_square_1024 (uint8_t * r, uint8_t * a);

void rsa_inv_mod_N (rsa_half_num * n_, rsa_num * modulus);
//////////////////////////////////////////////////
//  BIG NUMBER ARITHMETIC
//////////////////////////////////////////////////

#ifndef HAVE_RSA_MUL

void __attribute__((weak)) rsa_mul_128 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 16);
}

void __attribute__((weak)) rsa_mul_192 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 24);
}

void __attribute__((weak)) rsa_mul_256 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 32);
}

void __attribute__((weak)) rsa_mul_384 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 48);
}

void __attribute__((weak)) rsa_mul_512 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 64);
}

void __attribute__((weak)) rsa_mul_768 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 96);
}

void
  __attribute__((weak)) rsa_mul_1024 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 128);
}

void __attribute__((weak)) rsa_square_256 (uint8_t * r, uint8_t * a)
{
  rsa_mul_256 (r, a, a);
}

void __attribute__((weak)) rsa_square_384 (uint8_t * r, uint8_t * a)
{
  rsa_mul_384 (r, a, a);
}

void __attribute__((weak)) rsa_square_512 (uint8_t * r, uint8_t * a)
{
  rsa_mul_512 (r, a, a);
}

void __attribute__((weak)) rsa_square_768 (uint8_t * r, uint8_t * a)
{
  rsa_mul_768 (r, a, a);
}

void __attribute__((weak)) rsa_square_1024 (uint8_t * r, uint8_t * a)
{
  rsa_mul_1024 (r, a, a);
}
#endif //HAVE_RSA_MUL
void __attribute__((weak))
rsa_mul_128_mod (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t t[32];

  rsa_mul_128 (t, a, b);
  memcpy (r, t, 16);
}

void __attribute__((weak))
rsa_mul_192_mod (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t t[48];

  rsa_mul_192 (t, a, b);
  memcpy (r, t, 24);
}

void __attribute__((weak))
rsa_mul_256_mod (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t t[64];

  rsa_mul_256 (t, a, b);
  memcpy (r, t, 32);
}

void __attribute__((weak))
rsa_mul_384_mod (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t t[96];

  rsa_mul_384 (t, a, b);
  memcpy (r, t, 48);
}

void __attribute__((weak))
rsa_mul_512_mod (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t t[128];

  rsa_mul_512 (t, a, b);
  memcpy (r, t, 64);
}

static void
rsa_square (rsa_long_num * r, rsa_num * a)
{
#if RSA_BYTES == 64
  if (rsa_get_len () == 32)
    rsa_square_256 (&r->value[0], &a->value[0]);
  else if (rsa_get_len () == 48)
    rsa_square_384 (&r->value[0], &a->value[0]);
  else
    rsa_square_512 (&r->value[0], &a->value[0]);
#elif RSA_BYTES == 96
  if (rsa_get_len () == 32)
    rsa_square_256 (&r->value[0], &a->value[0]);
  else if (rsa_get_len () == 48)
    rsa_square_384 (&r->value[0], &a->value[0]);
  else if (rsa_get_len () == 64)
    rsa_square_512 (&r->value[0], &a->value[0]);
  else
    rsa_square_768 (&r->value[0], &a->value[0]);
#elif RSA_BYTES == 128
  if (rsa_get_len () == 32)
    rsa_square_256 (&r->value[0], &a->value[0]);
  else if (rsa_get_len () == 48)
    rsa_square_384 (&r->value[0], &a->value[0]);
  else if (rsa_get_len () == 64)
    rsa_square_512 (&r->value[0], &a->value[0]);
  else if (rsa_get_len () == 96)
    rsa_square_768 (&r->value[0], &a->value[0]);
  else
    rsa_square_1024 (&r->value[0], &a->value[0]);
#else
#error wrong RSA_BYTES
#endif
}

//static void
void
rsa_mul (rsa_long_num * r, rsa_num * a, rsa_num * b)
{
#if RSA_BYTES == 64
  if (rsa_get_len () == 32)
    rsa_mul_256 (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 48)
    rsa_mul_384 (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_512 (&r->value[0], &a->value[0], &b->value[0]);
#elif RSA_BYTES == 96
  if (rsa_get_len () == 32)
    rsa_mul_256 (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 48)
    rsa_mul_384 (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 64)
    rsa_mul_512 (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_768 (&r->value[0], &a->value[0], &b->value[0]);
#elif RSA_BYTES == 128
  if (rsa_get_len () == 32)
    rsa_mul_256 (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 48)
    rsa_mul_384 (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 64)
    rsa_mul_512 (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 96)
    rsa_mul_768 (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_1024 (&r->value[0], &a->value[0], &b->value[0]);
#else
#error wrong RSA_BYTES
#endif
}

void
rsa_mul_mod_half (rsa_half_num * r, rsa_half_num * a, rsa_half_num * b)
{
#if RSA_BYTES == 64
  if (rsa_get_len () == 32)
    rsa_mul_128_mod (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 48)
    rsa_mul_192_mod (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_256_mod (&r->value[0], &a->value[0], &b->value[0]);
#elif RSA_BYTES == 96
  if (rsa_get_len () == 32)
    rsa_mul_128_mod (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 48)
    rsa_mul_192_mod (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 64)
    rsa_mul_256_mod (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_384_mod (&r->value[0], &a->value[0], &b->value[0]);
#elif RSA_BYTES == 128
  if (rsa_get_len () == 32)
    rsa_mul_128_mod (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 48)
    rsa_mul_192_mod (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 64)
    rsa_mul_256_mod (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 96)
    rsa_mul_384_mod (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_512_mod (&r->value[0], &a->value[0], &b->value[0]);
#else
#error wrong RSA_BYTES
#endif
}

void
rsa_mul_half (rsa_num * r, rsa_half_num * a, rsa_half_num * b)
{
  if (rsa_get_len () == 32)
    rsa_mul_128 (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 48)
    rsa_mul_192 (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 64)
    rsa_mul_256 (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 96)
    rsa_mul_384 (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_512 (&r->value[0], &a->value[0], &b->value[0]);
  return;
}


// reduce "num" (only upper part 1/4 bits -1)
void
partial_barret (rsa_long_num * num, rsa_num * Bc)
{
  uint8_t offset = (rsa_get_len () * 3) / 2;
  uint8_t hsize = rsa_get_len () / 2;
  rsa_num tmp;
  uint8_t carry;

  rsa_mul_half (&tmp, (rsa_half_num *) Bc,
		(rsa_half_num *) (offset + (uint8_t *) num));
  carry = rsa_add ((rsa_num *) num, &tmp);
  memset (&tmp, 0, hsize);

  carry = bn_add_v (rsa_get_len () + (uint8_t *) num, &tmp, hsize, carry);

  rsa_mul_half (&tmp, (rsa_half_num *) (hsize + (uint8_t *) Bc),
		(rsa_half_num *) (offset + (uint8_t *) num));

  carry |= bn_add_v (hsize + (uint8_t *) num, &tmp, rsa_get_len (), 0);

  memset (offset + (uint8_t *) num, 0, hsize);
  num->value[offset] = carry;
}

void
barrett_constant (rsa_num * Bc, rsa_num * modulus)
{
  rsa_long_num tmp;

  memset (&tmp, 0, sizeof (rsa_long_num));
  tmp.value[(rsa_get_len () * 3) / 2] = 1;

  bn_mod_half (&tmp, modulus);
  memcpy (Bc, &tmp, rsa_get_len ());
}

///////////////////////////////////////////////////////


//////////////////////////////////////////////////

// Montgomery multiplication need n_ to reduce product into range 0 .. n-1
// For this, variable r is set as 2^w , r>n. (please read details in montgomery
// multiplication related literature)

// Here calculation of n_ is based on:
// r* r^-1 - n * n_ = 1
// this is same as:
// n_ = (r*(r^-1 mod n)-1)/n or  r - n^ -1 mod r
//
// In next text "modulus" is always "n" from above equation. "r" comes from RSA length.
// Here is modified extended euclidian algo for calculation r - n^ -1 mod r.
// Modulus is always added to TMP variable (not subtracted) and initialized to 0 not 1.

// this version of code generates 1/2 bits of n_, because upper part is not reduced
// by Montgomery reduction. For 256 bits in modulus  r=128, not 256!

// This C version of code is not constant time, but AVR ASM version is constant time.

void
  __attribute__((weak)) rsa_inv_mod_N (rsa_half_num * Mc, rsa_num * modulus)
{
  rsa_half_num tmpnum;
  rsa_half_num *tmp = &tmpnum;
  uint8_t loop = rsa_get_len () / 2;
  uint8_t b_pos = 0, mask = 1;
  rsa_half_num m;
  uint8_t res = 0;
  uint8_t hsize = loop;

  memcpy (&m, modulus, hsize);
  memset (tmp, 0, hsize);

  while (loop)
    {
      if (!(tmp->value[b_pos] & mask))
	{
	  res |= mask;
	  bn_add_v (tmp, &m, hsize, 0);
	}
      bn_shift_L_v (&m, hsize);

      mask <<= 1;
      if (!mask)
	Mc->value[b_pos++] = res, res = 0, mask = 1, loop--;
    }
}

// modular reduction
//---------------------
// upper part is reduced by modified Barrett reduction
// lower part is reduced by Montgomery reduction
// no need to use Karatsuba multiplication (with big overhead)
// only half multiplication is needed (4x) and one
// half truncated multiplication is needed

// return 0/1 (index of t/help1, result is in upper part of rsa_long_num)
uint8_t __attribute__((weak))
monPro0 (rsa_long_num * t, rsa_long_num * help1, rsa_num * n,
	 rsa_half_num * Mc, rsa_num * Bc)
{
  uint8_t carry;

  uint8_t offset = (rsa_get_len () * 3) / 2;
  rsa_half_num *mm = (rsa_half_num *) (offset + (uint8_t *) help1);
  uint8_t hsize = rsa_get_len () / 2;

  // T  = D|C|B|A  (| = concatenation, parts A,B,C,D are 1/2 bit len of modulus)
  // Bc = BcH|BcL (Bc is pecalculated from T 1|0|0|0 mod 'n'
  // Mc = Montgomery constant from  'r - n^-1 mod r', r is  1|0
  // n  = nH|nL - modulus
  // mm = montgomery coefficient, from truncated multiplicatiom of Mc and updted A

  // reduce upper part:
  // update T = B|A + D*BcL (do not change D,C, carry to C is processed later)
  rsa_mul_half ((rsa_num *) help1,
		(rsa_half_num *) Bc,
		(rsa_half_num *) (offset + (uint8_t *) t));

  carry = rsa_add ((rsa_num *) t, (rsa_num *) help1);

  // truncated multiplication Mc * A (A is already updated by BcL)
  // calculate Montgomery part from low bits of partial result
  rsa_mul_mod_half (mm, Mc, (rsa_half_num *) t);

  // update T = B|A + Mp * nL, (do not change D,C, carry to C is processed later)
  rsa_mul_half ((rsa_num *) help1, mm, (rsa_half_num *) n);
  carry += rsa_add ((rsa_num *) t, (rsa_num *) help1);

  // ------------------
  // A is zero (by Montgomery reduction), propagate carry's
  memset (help1, 0, rsa_get_len ());
  help1->value[0] = carry;

  carry = bn_add_v ((rsa_get_len () + (uint8_t *) t), help1, hsize, 0);

  // continue, Mp * nH is added to C|B
  rsa_mul_half ((rsa_num *) help1,
		mm, (rsa_half_num *) (hsize + (uint8_t *) n));


  carry += bn_add_v ((hsize + (uint8_t *) t), help1, rsa_get_len (), 0);

  rsa_mul_half ((rsa_num *) help1, (rsa_half_num *) (hsize + (uint8_t *) Bc),
		(rsa_half_num *) (offset + (uint8_t *) t));

  carry += rsa_add ((rsa_num *) help1, (rsa_num *) (hsize + (uint8_t *) t));

// this code is not perfect constant time, ASM code for atmega128 is
// designed to run this part of code in constant time.
  carry -= rsa_sub ((rsa_num *) t, (rsa_num *) help1, n);
  if (carry == 0xff)
    {
      // correct result in help1, prevent SPA attack
      // (do not subtract  t = help1 - n, this can be detected in power trace)
      rsa_sub ((rsa_num *) t, (rsa_num *) t, n);
      return 0;
    }
  carry -= rsa_sub ((rsa_num *) help1, (rsa_num *) t, n);
  return carry == 0xff ? 1 : 0;
}

////////////////////////////////////////////////////
// square A and do reduction into upper part off result1/2
//                 tmp         result1             result2/A
static uint8_t
monPro_square (rsa_long_num * t, rsa_long_num * tmp,
	       rsa_num * n, rsa_half_num * Mc, rsa_num * Bc)
{
  rsa_square (t, (rsa_num *) tmp);
  return monPro0 (t, tmp, n, Mc, Bc);
}

// muliply B * upper part A, do reduction into upper part of result1/2
//             tmp    B           result1           result2/A
static uint8_t
monPro (rsa_num * b, rsa_long_num * t, rsa_long_num * tmp,
	rsa_num * n, rsa_half_num * Mc, rsa_num * Bc)
{
  rsa_mul (t, (rsa_num *) tmp, b);
  return monPro0 (t, tmp, n, Mc, Bc);
}

// multiply  1*A, do reduction into upper part of result1/2
//                 tmp    result1        result2/A
static uint8_t
monPro_1 (rsa_long_num * t, rsa_long_num * tmp,
	  rsa_num * n, rsa_half_num * Mc, rsa_num * Bc)
{
  // clear upper part of t
  // copy A (A*1)
  memcpy (t, tmp, rsa_get_len ());
  memset (&(t->value[rsa_get_len ()]), 0, rsa_get_len ());
  return monPro0 (t, tmp, n, Mc, Bc);
}

////////////////////////////////////////////////////
// montgomery exponentation (for maximum 255*8 bits!)
#if RSA_BYTES > 255
#error Please check i variable
#endif

/* "best" E_bits for RSA:               numbers of multiplications/ram
Key length      CRT exponentation	Ebits 4	   Ebits 5  Ebits 6
1024 		  512 	                142/1K   >>133/2K<< 148/4k
1536              768                   206/1.5k >>184/3k<< 190/6k
2048             1024                   270/2k     235/4k >>233/8k<<


because ATMEGA 128 RAM is small, 5 bits are used only for 1024 keys,(atmega1284 with 16k RAM can be used with 5 bits )
for 1536 and 2048 only 4 bits..Next code is only for 2 or 4 bites, 5 bits only for devices with 8kB and more ram..
*/
#ifndef E_BITS
#define E_BITS 2
#endif

#if E_BITS != 2 && E_BITS != 4 && E_BITS != 5
#error unsupported E_BITS value
#endif

#if E_BITS == 5
static uint8_t
get_bits5 (rsa_exp_num * exp, uint16_t count)
{
  uint8_t byte, bit;
  uint16_t sample;

  byte = count / 8;
  bit = count & 7;

  sample = exp->value[byte];

  if (bit > 2)
    sample += exp->value[byte + 1] << 8;
  sample >>= bit;

  return sample & 0x1f;
}
#endif

/* x_ is original input number to exponentiate (not in Montgomery format)
   in x_ exponentation result is returned
   test: 0 - no check by public exponent
         1 - test with pub exponent 2^1 + 1 = 3
         16 -                       2^16+1  = 65537
*/
static uint8_t
rsaExpMod_montgomery (rsa_num * x_, rsa_exp_num * exp, rsa_num * modulus,
		      rsa_half_num * Mc, rsa_num * Bc, rsa_long_num t[2],
		      uint16_t count, uint8_t test)
{
  rsa_num M_[1 << E_BITS];
  uint8_t e, j, k, v;
#if E_BITS != 5
  int16_t i;
#endif

#ifdef PREVENT_CRT_SINGLE_ERROR
// save input into check variable
  rsa_num check;
  memcpy (&check, x_, RSA_BYTES);
#endif

// copy:  1  *  r mod MODULUS   and
//       MSG *  r mod MODULUS   into precomputed table

  memcpy (&M_[0], &t[0], RSA_BYTES);
  memcpy (&M_[1], &t[1], RSA_BYTES);

  DPRINT ("Exponenting, exponent length %d\n", count);
  NPRINT ("modulus n = ", modulus, rsa_get_len ());
  NPRINT ("Montgomery constant = ", Mc, rsa_get_len () / 2);
  NPRINT ("1 * r mod n = ", &M_[0], rsa_get_len ());
  NPRINT ("data (message * r mod n)= ", &M_[1], rsa_get_len ());
  NPRINT ("exponent = ", exp, rsa_get_len () + 8);
  NPRINT ("x_ = ", x_, rsa_get_len ());

  // precompute rest of table
  for (j = 2; j < (1 << E_BITS); j++)
    {
      memcpy (&t[1], &M_[1], rsa_get_len ());
      v = monPro (&M_[j - 1], &t[0], &t[1], modulus, Mc, Bc);
      memcpy (&M_[j], &t[v ^ 1], rsa_get_len ());
    }

  memcpy (&t[1], &M_[0], RSA_BYTES);
  v = 0;
// small speed up can be achieved by skipping 1st multiplication
// (load M_[x] into t[1]) but code is then bigger
#if E_BITS == 5
  for (;;)
    {
      count -= E_BITS;
      e = get_bits5 (exp, count);
      v ^= monPro (&M_[e], &t[v], &t[v ^ 1], modulus, Mc, Bc);
      if (count == 0)
	break;
      for (k = 0; k < E_BITS; k++)
	v ^= monPro_square (&t[v], &t[v ^ 1], modulus, Mc, Bc);
    }
#else
  // exponentation..
  i = count / 8;
  for (;;)
    {
      e = exp->value[--i];
      for (j = 0; j < 8; j += E_BITS)
	{
	  v ^=
	    monPro (&M_[e >> (8 - E_BITS)], &t[v],
		    &t[v ^ 1], modulus, Mc, Bc);
	  count -= E_BITS;
	  if (count == 0)
	    goto rsaExpMod_montgomery_ok;

	  for (k = 0; k < E_BITS; k++)
	    v ^= monPro_square (&t[v], &t[v ^ 1], modulus, Mc, Bc);
	  e <<= E_BITS;
	}
    }
rsaExpMod_montgomery_ok:
#endif
#ifdef PREVENT_CRT_SINGLE_ERROR
  if (test)
    {
// Single error check
// save result (not final) to exponent
      memcpy (exp, &t[v ^ 1], RSA_BYTES);

// check result with public exponent
      for (k = 0; k < test; k++)
	v ^= monPro_square (&t[v], &t[v ^ 1], modulus, Mc, Bc);
      v ^= monPro ((rsa_num *) exp, &t[v], &t[v ^ 1], modulus, Mc, Bc);
      v ^= monPro_1 (&t[v], &t[v ^ 1], modulus, Mc, Bc);
// compare
      if (memcmp (&check, &t[v ^ 1], rsa_get_len ()))
	return 1;
// last step is calculated 2x

// return (not final) result back
      memcpy (&t[v ^ 1], exp, RSA_BYTES);
      v ^= monPro_1 (&t[v], &t[v ^ 1], modulus, Mc, Bc);
      memcpy (&check, &t[v ^ 1], rsa_get_len ());
// repeat this step
      memcpy (&t[v ^ 1], exp, RSA_BYTES);
    }
#endif

  v ^= monPro_1 (&t[v], &t[v ^ 1], modulus, Mc, Bc);
  memcpy (x_, &t[v ^ 1], rsa_get_len ());

#ifdef PREVENT_CRT_SINGLE_ERROR
  if (test)
    {
      // final result (multiplication by 1) is calculated 2x,
      // compare to prevent single error in this step
      if (memcmp (&check, x_, rsa_get_len ()))
	return 1;
    }
#endif

  NPRINT ("exponentation result: ", x_, rsa_get_len ());
  return 0;
}

// for 5 bit window there is one more byte accessed after exponent
// enable 1 byte blinding (even when not used)

static uint16_t
  __attribute__((noinline)) rsaExpMod_montgomery_eblind (rsa_long_num t[2],
							 rsa_exp_num * exp,
							 rsa_num * modulus)
{
  uint16_t count;
  uint16_t len = bn_real_bit_len;

#if E_BITS == 5
// 5 bits window
  uint8_t blind;
#ifdef RSA_EXP_BLINDING
#define BLIND_BYTES 4
// extend exponent up to 32 bits, minimum 27
  for (count = 260;; count += 5)
    if (count >= (len + 27))
      break;
  blind = ((uint8_t) (count - len)) - 24;

#else
#define BLIND_BYTES 1
  for (count = 260;; count += 5)
    if (count >= len)
      break;
  blind = count - len;
#endif
#else // E_BITS == 5
// 4/2 bits window
#ifdef RSA_EXP_BLINDING
#define BLIND_BYTES 3
#else
#define BLIND_BYTES 0
#endif
  count = len + BLIND_BYTES * 8;
#endif // E_BITS == 5


#if BLIND_BYTES > 0
// from modulus subtract 1
  memset (&t[1].H, 0, RSA_BYTES);
  t[1].H.value[0] = 1;
  rsa_sub (&t[1].H, modulus, &t[1].H);

// random blinding value
  memset (&t[1].L, 0, RSA_BYTES);
  rnd_get (&t[1].L.value[0], BLIND_BYTES);
#if BLIND_BYTES == 4
  t[1].L.value[3] &= (1 << blind) - 1;
#elif BLIND_BYTES == 1
  t[1].L.value[0] &= (1 << blind) - 1;
#elif BLIND_BYTES != 3
#error Wrong blinding bytes
#endif


// (modulus - 1) * randnom_blinding_number
  rsa_mul (&t[0], &t[1].H, &t[1].L);

  uint8_t s;
  s = rsa_get_len ();
  rsa_set_len (s + 8);		// big number arithmetis allow 64 bit steps in number size..
  rsa_add (&exp->n, &t[0].L);
  rsa_set_len (s);
#endif
  return count;
}

// calculate n', 1 * R mod n, mesg * r mod n,
// do optional exponent blinding

static uint8_t
  __attribute__((noinline)) rsaExpMod_montgomery_init (rsa_long_num t[2],
						       rsa_num * modulus,
						       rsa_half_num * Mc,
						       rsa_num * mesg,
						       uint8_t key)
{
// prepare for exponention (calculate Mc - constant for Montgomery reduction)
#ifndef USE_P_Q_INV
  rsa_inv_mod_N (Mc, modulus);
#else
  // read to t[0] (get_rsa_key_part() may return more data but max RSA_BYTES max)
  if (rsa_get_len () / 2 != get_rsa_key_part (&t[0].value[0], key | 0x20))
    return Re_Q_GET_FAIL_1;
  memcpy (Mc, &t[0].value[0], rsa_get_len () / 2);
#endif

  memset (t, 0, RSA_BYTES * 4);

// 1 * R mod modulus - this is always < modulus
  t[0].value[rsa_get_len () / 2] = 1;
// MSG * R mod  modulus
  memcpy (&t[1].value[rsa_get_len () / 2], mesg, rsa_get_len ());
  bn_mod_half (&t[1], modulus);

  NPRINT ("Exponenting A = ", mesg, rsa_get_len ());
  return 0;
}

// load modulus from file, calculate Bc from modulus or read Bc from file
static uint8_t
rsaGetKeyModulus (rsa_num * modulus, rsa_num * Bc, uint16_t size, uint8_t key)
{
  if (size != get_rsa_key_part (modulus, key))
    {
      DPRINT ("ERROR, unable to get (p) part of key\n");
      return 1;
    }
  if (!(modulus->value[0] & 1))
    {
      DPRINT ("ERROR, rsa prime (p) not odd (%02x)\n", modulus->value[0]);
      return 1;
    }
#ifndef USE_P_Q_INV
  barrett_constant (Bc, modulus);
#else
  if (rsa_get_len () != get_rsa_key_part (Bc, key | 0xF0))
    return 1;
#endif
  return 0;
}

// key file is selected, function reads P,Q, and store modoulus to m
// return 0 if error, sizze of CRT component (128  for 2048 bit key)
uint8_t
rsa_modulus (void *m)
{
  uint16_t size;
  rsa_num p, q;

  size = get_rsa_key_part (&p, KEY_RSA_p);
  if (!size)
    return 0;
  if (size != get_rsa_key_part (&q, KEY_RSA_q))
    return 0;

  bn_set_bitlen (size * 8);
  rsa_mul (m, &p, &q);
  return size;
}

/******************************************************************
*******************************************************************/
/// result = 0 if all ok, or error code
// Warning, code is designed to run in 4kB RAM in atmega 128, most
// variables are reused

uint8_t
rsa_calculate (uint8_t * data, uint8_t * result, uint16_t size)
{
  uint16_t count;
  rsa_exp_num exponent;
  rsa_num *tmp = &exponent.n;

  rsa_long_num t[2];
  rsa_half_num Mc;

#define H (&t[0])
#define TMP1 tmp
#define TMP2 (rsa_num *)(&result[rsa_get_len()])
#define TMP3 (rsa_num *)(&data[rsa_get_len()])

#define M_P (rsa_long_num *)(&result[0])
#define M_Q (rsa_long_num *)(&data[0])

#define M1 (rsa_num *)(&result[0])
#define M2 (rsa_num *)(&data[0])

// some safety checks
  if (data == result)
    {
      DPRINT ("ERROR, rsa input is pointed to same place as output\n");
      return Re_DATA_RESULT_SAME;
    }

  bn_set_bitlen (size * 8);

// duplicate message
  memcpy (result, data, rsa_get_len () * 2);

// calculate message modulo p
// load P and calculate Bc or load Bc from file
  if (rsaGetKeyModulus (TMP1, (rsa_num *) H, size, KEY_RSA_p))
    return Re_P_GET_FAIL_1;

// MSG mod P
  partial_barret (M_P, (rsa_num *) H);
  bn_mod_half (M_P, TMP1);

// calculate message modulo q
// load Q and calculate Bc or load Bc from file
  if (rsaGetKeyModulus (TMP1, TMP2, size, KEY_RSA_q))
    return Re_Q_GET_FAIL_1;

// MSG mod Q
  partial_barret (M_Q, TMP2);
  bn_mod_half (M_Q, TMP1);

// save Q
  memcpy (TMP3, TMP1, RSA_BYTES);

// load exponent
  memset (&exponent, 0, sizeof (rsa_exp_num));
  if (size != get_rsa_key_part (&exponent, KEY_RSA_dQ))
    {
      DPRINT ("ERROR, unable to get (dQ) part of key\n");
      return Re_dQ_1;
    }

  count = rsaExpMod_montgomery_eblind (t, &exponent, TMP3);
// calculate msg * R mod modulus,
// calculate 1 * R mod modulus (or get this from key file),
// calculate n' (or get this from key file)
//#warning, fixed public exponent
  if (rsaExpMod_montgomery_init (t, TMP3, &Mc, M2, KEY_RSA_q))
    return Re_Q_GET_FAIL_1;
//                   mesage,exponent,modulus,Mc,Bc, public exponent (2^16+1)
  if (rsaExpMod_montgomery (M2, &exponent, TMP3, &Mc, TMP2, t, count, 16))
    return Re_Q_Single_Error;

// load P and calculate Bc or load Bc from file
  if (rsaGetKeyModulus (TMP3, TMP2, size, KEY_RSA_p))
    return Re_Q_GET_FAIL_1;

// load exponent
  memset (&exponent, 0, sizeof (rsa_exp_num));
  if (size != get_rsa_key_part (&exponent, KEY_RSA_dP))
    {
      DPRINT ("ERROR, unable to get (dP) part of key\n");
      return Re_dP_1;
    }

  count = rsaExpMod_montgomery_eblind (t, &exponent, TMP3);
// calculate msg * R mod modulus,
// calculate 1 * R mod modulus (or get this from key file),
// calculate n' (or get this from key file)
  if (rsaExpMod_montgomery_init (t, TMP3, &Mc, M1, KEY_RSA_p))
    return Re_P_GET_FAIL_3;
//#warning, fixed public exponent
//                   mesage,exponent,modulus,Mc,Bc, public exponent (2^16+1)
  if (rsaExpMod_montgomery (M1, &exponent, TMP3, &Mc, TMP2, t, count, 16))
    return Re_R_Single_Error;

// prime P is already loaded in TMP3
// Garner's recombination
//  m1 - m2
  bn_sub_mod (M1, M2, TMP3);

// multiply and reduce h = qInv.(m1 - m2) mod p
  if (0 == get_rsa_key_part (TMP1, KEY_RSA_qInv))
    {
      DPRINT ("ERROR, unable to get (qInv) part of key\n");
      return Re_qInv_GET_FAIL_1;
    }
  rsa_mul (H, TMP1, M1);
// do full reduction
  partial_barret (H, TMP2);
  bn_mod_half (H, TMP3);


// calculate M_P= h * q
  if (size != get_rsa_key_part (TMP1, KEY_RSA_q))
    {
      DPRINT ("ERROR, unable to get (q) part of key\n");
      return Re_Q_GET_FAIL_2;
    }
  rsa_mul (M_P, (rsa_num *) H, TMP1);

  memset (TMP3, 0, RSA_BYTES);
  rsa_add_long (M_P, M_Q);

  NPRINT ("final result:\n", M_P, rsa_get_len () * 2);
  return 0;
#undef H
}

#ifdef RSA_GEN_DEBUG
uint8_t debug_rm_count;
#endif

// if some of code is not explained in comments, please check
// openssl-1.0.2j/crypto/bn/bn_prime.c
// because small ram, here two free space pointer comes "t" and "tmp"
static uint8_t __attribute__((noinline))
miller_rabin (rsa_num * n, rsa_long_num t[2], rsa_long_num * tmp)
{
  rsa_exp_num exponent;
  rsa_num *e = &(exponent.n);
  rsa_num *a = &(tmp->L);
  rsa_num *Bc = &(tmp->H);
  rsa_half_num Mc;

  uint8_t i;
  uint16_t count;
  uint16_t d = 0;

  DPRINT ("miller rabin\n");

// clear whole exponent 1st
  memset (&exponent, 0, sizeof (rsa_exp_num));

// exponent = n-1  "n" is always odd, only clear bit 0
  memcpy (e, n, rsa_get_len ());
  e->value[0] &= 0xfe;

// exponent = e * (2 pow (d)), make "e" odd, calculate "d"
  do
    {
      d++, rsa_shiftr (e);
    }
  while ((e->value[0] & 1) == 0);

// precalculate for montgomery...
  rsa_inv_mod_N (&Mc, n);
  barrett_constant (Bc, n);

  NPRINT ("n=", n, rsa_get_len ());
  NPRINT ("Mc=", &Mc, rsa_get_len () / 2);
  NPRINT ("Bc=", Bc, rsa_get_len ());

// calculate number of loops (based on bit len of prime)
// 3 runs for 1024 bit, 6 runs for 512, 12 runs for 256 bit ..
  i = 0, count = bn_real_bit_len;
  while (count <= 3072)
    count += bn_real_bit_len, i++;
#ifdef RSA_GEN_DEBUG
  debug_rm_count = 0;
#endif
  while (i--)
    {
      DPRINT ("miller loop %d\n", i);

      // get random "a" in range <2 .. n-2>
      // minimal "n" is 2^128+1, (rsa key 512) make "a" in range < (2^120)
      memset (a, 0, RSA_BYTES);
      rnd_get ((uint8_t *) a, 15);	// 120 bits
      a->value[0] |= 2;		// minimal value 2

// do not use exponent blinding here ..
#if E_BITS == 5
      for (count = 260;; count += 5)
	if (count >= bn_real_bit_len)
	  break;
#else
      count = bn_real_bit_len;
#endif
      memset (&t[0], 0, RSA_BYTES * 4);
      t[0].value[rsa_get_len () / 2] = 1;

      memcpy (&t[1].value[rsa_get_len () / 2], a, rsa_get_len ());
      partial_barret (&t[1], Bc);
      bn_mod_half (&t[1], n);

//    "a" = "a" pow "e" mod "n"  (n_, t=temp space, count=number of exp. bits)
//    do not check exponentation here (public exponent set to 0)
      rsaExpMod_montgomery (a, &exponent, n, &Mc, Bc, t, count, 0);
#ifdef RSA_GEN_DEBUG
      debug_rm_count++;
#endif
// result must be compared to n-1, n is odd,  n-1 into t[0]...
      memcpy (&t[0], n, RSA_BYTES);
      t[0].value[0] &= 0xfe;

// if exp. result "a"==1, then "n" is candidate for probably prime number
// invert bit 1 in "a" to use bn_test_zero()
      a->value[0] ^= 1;
      if (bn_is_zero (a))
	continue;		// OK, candidate, do next iteration

// keep squaring "a", test "a" pow 2 mod "n"
// a >= n-1  composite (use "d" for this test)
// 1         composite
// n-1       candidate for probably prime

      count = d;

// use goto for this loop ================================================
    mr_squaring_loop:

// return 'a' value back
      a->value[0] ^= 1;

// if result "a"==(n-1) then "n" is candidate for probably prime number
      if (0 == memcmp (a, &t[0], rsa_get_len ()))
	continue;		// OK, candidate, do next iteration
// squaring needed ?
      if (--count == 0)
	return 1;		// definitively composite
// square ..
      rsa_square (&t[1], a);
      partial_barret (&t[1], Bc);
      bn_mod_half (&t[1], n);
      memcpy (a, &t[1], rsa_get_len ());

// test if squared result of exp. "a"==1
// invert bit 1 in "a" to use bn_test_zero()
      a->value[0] ^= 1;
      if (bn_is_zero (a))
	return 1;		// definitively composite

      goto mr_squaring_loop;
// =======================================================================
    }
// probably prime
  return 0;
}

// use GCD to test if n can be divided by small primes
uint8_t __attribute__((weak)) prime_gcd (rsa_num * p)
{
  rsa_num uu, vv;
  rsa_num *v = &vv;
  rsa_num *u = &uu;
  rsa_num *tmp;
  uint8_t ret;
  uint8_t oldlen = rsa_get_len ();

  DPRINT ("prime_gcd\n");

  rsa_set_len (RSA_BYTES);
  memset (v, 0, RSA_BYTES);
  memcpy (v, p, oldlen);
  // product of 1st 130 primes (3*5*7...*733*739)
  memset (u, 0, RSA_BYTES);
  get_constant (u, N_GCD_PRIMES);
// u and v is always odd, and not zero
  for (;;)
    {
      while ((v->value[0] & 1) == 0)
	rsa_shiftr (v);

      if (0 == rsa_cmpGE (v, u))
	{
	  tmp = u;
	  u = v;
	  v = tmp;
	}
      rsa_sub (v, v, u);

      if (bn_is_zero (v))
	break;
    }
// test if U is 1
  u->value[0] ^= 1;
  ret = bn_is_zero (u);
  rsa_set_len (oldlen);
  return ret;
}

// normal random search can be changed to incremental
// undefine PRIME_INC to do incremental search
//#define PRIME_INC

#ifdef RSA_GEN_DEBUG
#ifndef __STDIO_H
#include <stdio.h>
#endif
#endif
// because small ram, here two free space pointer comes "t" and "tmp"
static void __attribute__((noinline))
get_prime (rsa_num * p, rsa_long_num t[2], rsa_long_num * tmp)
{
#ifdef RSA_GEN_DEBUG
  int count_gcd = 0, count_rm = 0;
#endif

  memset (p, 0, RSA_BYTES);
#ifdef PRIME_INC
  rnd_get ((uint8_t *) p, bn_real_byte_len);

  p->value[0] |= 1;		// make number odd
  p->value[bn_real_byte_len - 1] |= 0x80;	// make number big
#endif
  DPRINT ("get_prime\n");
  for (;;)
    {
#ifdef PRIME_INC
      memset (tmp, 0, RSA_BYTES);
      tmp->value[0] = 1;
      rsa_add (p, (rsa_num *) tmp);
#else
      rnd_get ((uint8_t *) p, bn_real_byte_len);

      p->value[0] |= 1;		// make number odd
      p->value[bn_real_byte_len - 1] |= 0x80;	// make number big
#endif
      if (!prime_gcd (p))
	{
#ifdef RSA_GEN_DEBUG
	  count_gcd++;
#endif
	  continue;
	}

//      j++;
      if (!miller_rabin (p, t, tmp))
	break;
#ifdef RSA_GEN_DEBUG
      count_rm += debug_rm_count;
#endif
    }
#ifdef RSA_GEN_DEBUG
  {
    FILE *f;
    int i;
    uint8_t *pr = &p->value[0];

    f = fopen ("rsa_gen_debug.stat", "a");
    if (f != NULL)
      {
	fprintf (f, "gcd %d miller-rabin %d\n0x", count_gcd, count_rm);
	for (i = bn_real_byte_len - 1; i >= 0; i--)
	  fprintf (f, "%02x", pr[i]);
	fprintf (f, "\n");
	fclose (f);
      }
  }
#endif
}


uint8_t
rsa_keygen (uint8_t * message, uint8_t * r, struct rsa_crt_key *key,
	    uint16_t size)
{
  rsa_num *p = (rsa_num *) message;
  rsa_num *q = (rsa_num *) (message + 128);
  rsa_long_num *modulus = (rsa_long_num *) r;
  uint8_t *test, t;
#ifdef RSA_GEN_DEBUG
  int count_too_close = 0, count_too_small = 0;
#endif

  bn_set_bitlen (size / 2);
  for (;;)
    {
      get_prime (p, key->t, modulus);
      get_prime (q, key->t, modulus);

// test P,Q, if P < Q swap P and Q
      if (bn_abs_sub (modulus, p, q))
	bn_swap (p, q);

// test if P is not close to Q (for example for 1024 bit modulus:
// |P - Q| < 2 pow(1024/2 - 100)) - fail

      test = &modulus->value[bn_real_byte_len - 1];
      t = 14;			// over 100 bits
// Not elegant but readable
      do
	{
	  if (*test != 0)
	    goto ok;
	}
      while (--t);
// found over 100 zero bits, |P-Q| si too small, generate new P,Q
#ifdef RSA_GEN_DEBUG
      count_too_close++;
#endif
      continue;
    ok:

// test if key is of desired size (not 1023 but 1024 etc..)
      rsa_mul (modulus, p, q);
      if (!(modulus->value[bn_real_byte_len * 2 - 1] & 0x80))
	{
#ifdef RSA_GEN_DEBUG
	  count_too_small++;
#endif
	  continue;
	}
#ifdef RSA_GEN_DEBUG
      {
	FILE *f;
	f = fopen ("rsa_gen_debug.stat", "a");
	if (f != NULL)
	  {
	    fprintf (f, "close %d small %d\n", count_too_close,
		     count_too_small);
	    fclose (f);
	  }
      }
#endif

// public exponent
//#warning, fixed public exponent
      memset (&(key->d), 0, RSA_BYTES);
      key->d.value[0] = 1;
      key->d.value[2] = 1;
      NPRINT ("P=", p, rsa_get_len ());
      NPRINT ("Q=", q, rsa_get_len ());
      NPRINT ("modulus=", modulus, rsa_get_len () * 2);
      NPRINT ("d=", &key->d, rsa_get_len ());

      //dP = (pub_exp^-1) mod (p-1)
      //dQ = (pub_exp^-1) mod (q-1)
      //qInv = q ^ -1  mod p
      // subtract 1
      p->value[0] &= 0xfe;
      q->value[0] &= 0xfe;

      if (rsa_inv_mod (&(key->dP), &(key->d), p))
	continue;

      if (rsa_inv_mod (&(key->dQ), &(key->d), q))
	continue;
      // add 1 back
      p->value[0] |= 1;
      q->value[0] |= 1;

      if (rsa_inv_mod (&(key->qInv), q, p))
	continue;
      break;
    }

  NPRINT ("dP=", &key->dP, rsa_get_len ());
  NPRINT ("dQ=", &key->dQ, rsa_get_len ());
  NPRINT ("qInv=", &key->qInv, rsa_get_len ());
  return size / 16;
}
