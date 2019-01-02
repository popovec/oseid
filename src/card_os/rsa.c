/*
    rsa.c

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
#ifdef RSA_DEBUG
#include <stdio.h>
#define  DPRINT(msg...) fprintf(stderr,msg)
#else
#define DPRINT(msg...)
#endif

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
rsa_get_len ()
{
  return mod_len;
}

static void
rsa_set_len (uint8_t len)
{
  mod_len = len;
}

uint8_t __attribute__ ((weak)) rsa_add (rsa_num * r, rsa_num * a)
{
  return bn_add (r, a);
}

uint8_t __attribute__ ((weak))
rsa_add_long (rsa_long_num * r, rsa_long_num * a)
{
  return bn_add_v (r, a, rsa_get_len () * 2, 0);
}

uint8_t __attribute__ ((weak)) rsa_sub (rsa_num * r, rsa_num * a, rsa_num * b)
{
  return bn_sub (r, a, b);
}

uint8_t
  __attribute__ ((weak)) mp_add_v (uint8_t * r, uint8_t * a, uint8_t len,
				   uint8_t carry)
{
  return bn_add_v (r, a, len, carry);
}

uint8_t
  __attribute__ ((weak)) mp_sub_v (uint8_t * r, uint8_t * a, uint8_t * b,
				   uint8_t len)
{
  return bn_sub_v (r, a, b, len);
}

uint8_t __attribute__ ((weak))
rsa_sub_long (rsa_long_num * r, rsa_long_num * a, rsa_long_num * b)
{
  return bn_sub_v (r, a, b, mod_len * 2);
}

uint8_t __attribute__ ((weak)) rsa_cmpGE (rsa_num * c, rsa_num * d)
{
  return bn_cmpGE (c, d);
}


uint8_t __attribute__ ((weak)) rsa_shiftl (rsa_num * r)
{
  return bn_shiftl (r);
}

uint8_t __attribute__ ((weak)) rsa_shiftr (rsa_num * r)
{
  return bn_shiftr (r);
}

uint8_t __attribute__ ((weak)) rsa_shiftr_long (rsa_long_num * r)
{
  return bn_shiftr_long (r);
}

void __attribute__ ((weak)) rsa_mod (rsa_long_num * result, rsa_num * mod)
{
  bn_mod (result, mod);
}

uint8_t
  __attribute__ ((weak)) rsa_inv_mod (rsa_num * result, rsa_num * a,
				      rsa_num * mod)
{
  return bn_inv_mod (result, a, mod);
}


void
  __attribute__ ((weak)) rsa_mul_192 (uint8_t * r, uint8_t * a, uint8_t * b);
void
  __attribute__ ((weak)) rsa_mul_256 (uint8_t * r, uint8_t * a, uint8_t * b);
void
  __attribute__ ((weak)) rsa_mul_512 (uint8_t * r, uint8_t * a, uint8_t * b);
void
  __attribute__ ((weak)) rsa_mul_768 (uint8_t * r, uint8_t * a, uint8_t * b);
void
  __attribute__ ((weak)) rsa_mul_1024 (uint8_t * r, uint8_t * a, uint8_t * b);

void __attribute__ ((weak)) rsa_square_512 (uint8_t * r, uint8_t * a);

void __attribute__ ((weak)) rsa_square_768 (uint8_t * r, uint8_t * a);

void __attribute__ ((weak)) rsa_square_1024 (uint8_t * r, uint8_t * a);

void rsa_inv_mod_N (rsa_num * n_, rsa_num * modulus);

// functions for debugging
#ifdef RSA_DEBUG
static void __attribute__ ((unused)) print_rsa_num (rsa_num * r)
{
  uint8_t i;

  DPRINT ("0x");
  for (i = rsa_get_len (); i > 0;)
    DPRINT ("%02X", r->value[--i]);
}

static void __attribute__ ((unused)) print_rsa_exp_num (rsa_exp_num * r)
{
  uint8_t i;

  DPRINT ("0x");
  for (i = rsa_get_len () + 8; i > 0;)
    DPRINT ("%02X", r->value[--i]);
}

static void __attribute__ ((unused)) print_rsa_long_num (rsa_long_num * r)
{
  uint16_t i;

  DPRINT ("0x");
  for (i = rsa_get_len () * 2; i > 0;)
    DPRINT ("%02X", r->value[--i]);
}
#endif
//////////////////////////////////////////////////
//  BIG NUMBER ARITHMETIC
//////////////////////////////////////////////////

#ifndef HAVE_RSA_MUL

void __attribute__ ((weak))
rsa_mul_192 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 24);
}

void __attribute__ ((weak))
rsa_mul_256 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 32);
}

void __attribute__ ((weak))
rsa_mul_384 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 48);
}

void __attribute__ ((weak))
rsa_mul_512 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 64);
}

void __attribute__ ((weak))
rsa_mul_768 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 96);
}

void __attribute__ ((weak))
rsa_mul_1024 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  bn_mul_v (r, a, b, 128);
}

void __attribute__ ((weak)) rsa_square_384 (uint8_t * r, uint8_t * a)
{
  rsa_mul_384 (r, a, a);
}

void __attribute__ ((weak)) rsa_square_512 (uint8_t * r, uint8_t * a)
{
  rsa_mul_512 (r, a, a);
}

void __attribute__ ((weak)) rsa_square_768 (uint8_t * r, uint8_t * a)
{
  rsa_mul_768 (r, a, a);
}

void __attribute__ ((weak)) rsa_square_1024 (uint8_t * r, uint8_t * a)
{
  rsa_mul_1024 (r, a, a);
}
#endif //HAVE_RSA_MUL

void __attribute__ ((weak))
rsa_mul_384_mod (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t t[24];

  rsa_mul_192 (r, a, b + 24);
  memcpy (t, r, 24);

  rsa_mul_192 (r, b, a + 24);
  mp_add_v (t, r, 24, 0);

  rsa_mul_192 (r, a, b);
  mp_add_v (r + 24, t, 24, 0);
}

void __attribute__ ((weak))
rsa_mul_512_mod (uint8_t * r, uint8_t * a, uint8_t * b)
{
#if 1
  uint8_t t[32];

  rsa_mul_256 (r, a, b + 32);
  memcpy (t, r, 32);

  rsa_mul_256 (r, b, a + 32);
  mp_add_v (t, r, 32, 0);

  rsa_mul_256 (r, a, b);
  mp_add_v (r + 32, t, 32, 0);
#else
  uint8_t t[128];
  rsa_mul_512 (t, a, b);
  memcpy (r, t, 64);
#endif
}

void __attribute__ ((weak))
rsa_mul_768_mod (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t t[48];

  rsa_mul_384 (r, a, b + 48);
  memcpy (t, r, 48);

  rsa_mul_384 (r, b, a + 48);
  mp_add_v (t, r, 48, 0);

  rsa_mul_384 (r, a, b);
  mp_add_v (r + 48, t, 48, 0);

}

void __attribute__ ((weak))
rsa_mul_1024_mod (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t t[64];

  rsa_mul_512_mod (t, a, b + 64);

  rsa_mul_512_mod (r, b, a + 64);
  mp_add_v (t, r, 64, 0);

  rsa_mul_512 (r, a, b);
  mp_add_v (r + 64, t, 64, 0);
}


//static void
void
rsa_mul_mod (rsa_num * r, rsa_num * a, rsa_num * b)
{
#if RSA_BYTES == 64
  if (rsa_get_len () == 48)
    rsa_mul_384_mod (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_512_mod (&r->value[0], &a->value[0], &b->value[0]);
#elif RSA_BYTES == 96
  if (rsa_get_len () == 48)
    rsa_mul_384_mod (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 64)
    rsa_mul_512_mod (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_768_mod (&r->value[0], &a->value[0], &b->value[0]);
#elif RSA_BYTES == 128
  if (rsa_get_len () == 48)
    rsa_mul_384_mod (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 64)
    rsa_mul_512_mod (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 96)
    rsa_mul_768_mod (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_1024_mod (&r->value[0], &a->value[0], &b->value[0]);
#else
#error wrong RSA_BYTES
#endif
}

static void
rsa_square (rsa_long_num * r, rsa_num * a)
{
#if RSA_BYTES == 64
  if (rsa_get_len () == 48)
    rsa_square_384 (&r->value[0], &a->value[0]);
  else
    rsa_square_512 (&r->value[0], &a->value[0]);
#elif RSA_BYTES == 96
  if (rsa_get_len () == 48)
    rsa_square_384 (&r->value[0], &a->value[0]);
  else if (rsa_get_len () == 64)
    rsa_square_512 (&r->value[0], &a->value[0]);
  else
    rsa_square_768 (&r->value[0], &a->value[0]);
#elif RSA_BYTES == 128
  if (rsa_get_len () == 48)
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
  if (rsa_get_len () == 48)
    rsa_mul_384 (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_512 (&r->value[0], &a->value[0], &b->value[0]);
#elif RSA_BYTES == 96
  if (rsa_get_len () == 48)
    rsa_mul_384 (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 64)
    rsa_mul_512 (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_768 (&r->value[0], &a->value[0], &b->value[0]);
#elif RSA_BYTES == 128
  if (rsa_get_len () == 48)
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

///////////////////////////////////////////////////////


//////////////////////////////////////////////////

// MONTGOMERY

//////////////////////////////////////////////////

// montgomery multiplication need n_ to reduce product into range 0 .. n-1
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

// This C version of code is not constant time, but AVR ASM version is constant time.
// Two variants of code here, tmp variable rotation or modulus rotation,
// modulus rotation variant can be optimized by table of precalculated rotated moduluses
// (in ASM version)
#if 0				// tmp/modulus rotate variant
void __attribute__ ((weak)) rsa_inv_mod_N (rsa_num * n_, rsa_num * modulus)
{
  rsa_num tmpnum;
  rsa_num *tmp = &tmpnum;
  uint8_t loop = rsa_get_len ();
  uint8_t b_pos = 0, mask = 1;
  uint8_t res = 0;


  memset (tmp, 0, RSA_BYTES);

  while (loop)
    {
      if (!(tmp->value[0] & 1))
	{
	  res |= mask;
	  rsa_add (tmp, modulus);
	}
      rsa_shiftr (tmp);
      mask <<= 1;
      if (!mask)
	n_->value[b_pos++] = res, res = 0, mask = 1, loop--;
    }
}
#else // modulus rotate
void __attribute__ ((weak)) rsa_inv_mod_N (rsa_num * n_, rsa_num * modulus)
{
  rsa_num tmpnum;
  rsa_num *tmp = &tmpnum;
  uint8_t loop = rsa_get_len ();
  uint8_t b_pos = 0, mask = 1;
  rsa_num m;
  uint8_t res = 0;

  memcpy (&m, modulus, RSA_BYTES);
  memset (tmp, 0, RSA_BYTES);

  while (loop)
    {
      if (!(tmp->value[b_pos] & mask))
	{
	  res |= mask;
	  rsa_add (tmp, &m);
	}
      rsa_shiftl (&m);

      mask <<= 1;
      if (!mask)
	n_->value[b_pos++] = res, res = 0, mask = 1, loop--;
    }
}
#endif // table variant

// do montgomery modular reduction on variable 't'
// n = modulus, n0 = n_ (from  r* r^-1 - n * n_ = 1)

// return 0/1 (index of t/help1, result is in upper part of rsa_long_num)
uint8_t __attribute__ ((weak))
monPro0 (rsa_num * a, rsa_long_num * t, rsa_long_num * help1, rsa_num * n,
	 rsa_num * n0)
{
  uint8_t carry;

  rsa_mul_mod (a, (rsa_num *) t, n0);
  rsa_mul (help1, a, n);

  carry = rsa_add_long (help1, t);

  carry ^=
    rsa_sub ((rsa_num *) & t->value[rsa_get_len ()],
	     (rsa_num *) & help1->value[rsa_get_len ()], n);

  return carry ? 0 : 1;
}

////////////////////////////////////////////////////
// square A and do reduction into upper part off result1/2
//                 tmp         result1             result2/A
static uint8_t
monPro_square (rsa_num * a, rsa_long_num * t, rsa_long_num * tmp,
	       rsa_num * n, rsa_num * n0)
{
  rsa_square (t, (rsa_num *) & tmp->value[rsa_get_len ()]);
  return monPro0 (a, t, tmp, n, n0);
}

// muliply B * upper part A, do reduction into upper part of result1/2
//             tmp    B           result1           result2/A
static uint8_t
monPro (rsa_num * a, rsa_num * b, rsa_long_num * t, rsa_long_num * tmp,
	rsa_num * n, rsa_num * n0)
{
  rsa_mul (t, (rsa_num *) & tmp->value[rsa_get_len ()], b);
  return monPro0 (a, t, tmp, n, n0);
}

// multiply  1*A, do reduction into upper part of result1/2
//                 tmp    result1        result2/A
static uint8_t
monPro_1 (rsa_num * a, rsa_long_num * t, rsa_long_num * tmp,
	  rsa_num * n, rsa_num * n0)
{
  // clear upper part of t
  memset (&(t->value[rsa_get_len ()]), 0, rsa_get_len ());
  // copy A (A*1)
  memcpy (t, &tmp->value[rsa_get_len ()], rsa_get_len ());
  return monPro0 (a, t, tmp, n, n0);
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
		      rsa_num * n0, rsa_long_num t[2], uint16_t count,
		      uint8_t test)
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

#ifdef RSA_DEBUG
  DPRINT ("Exponenting, exponent length %d\n", count);
  DPRINT ("modulus n = ");
  print_rsa_num (modulus);
  DPRINT ("\n");
  DPRINT ("((r*(r^-1 mod n))-1)/n = n_ = ");
  print_rsa_num (n0);
  DPRINT ("\n");
  DPRINT ("1 * r mod n = ");
  print_rsa_num (&M_[0]);
  DPRINT ("\n");
  DPRINT ("data (message * r mod n)= ");
  print_rsa_num (&M_[1]);
  DPRINT ("\n");
  DPRINT ("exponent = ");
  print_rsa_exp_num (exp);
  DPRINT ("\n");
  DPRINT ("x_ = ");
  print_rsa_num (x_);
  DPRINT ("\n");
#endif

  // precompute rest of table
  for (j = 2; j < (1 << E_BITS); j++)
    {
      memcpy (&t[1].value[rsa_get_len ()], &M_[1], rsa_get_len ());
      v = monPro (x_, &M_[j - 1], &t[0], &t[1], modulus, n0);
      memcpy (&M_[j], &t[v ^ 1].value[rsa_get_len ()], rsa_get_len ());
    }

  memcpy (&t[1].value[rsa_get_len ()], &M_[0], RSA_BYTES);
  v = 0;
// small speed up can be achieved by skipping 1st multiplication
// (load M_[x] into t[1]) but code is then bigger
#if E_BITS == 5
  for (;;)
    {
      count -= E_BITS;
      e = get_bits5 (exp, count);
      v ^= monPro (x_, &M_[e], &t[v], &t[v ^ 1], modulus, n0);
      if (count == 0)
	break;
      for (k = 0; k < E_BITS; k++)
	v ^= monPro_square (x_, &t[v], &t[v ^ 1], modulus, n0);
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
	    monPro (x_, &M_[e >> (8 - E_BITS)], &t[v],
		    &t[v ^ 1], modulus, n0);
	  count -= E_BITS;
	  if (count == 0)
	    goto rsaExpMod_montgomery_ok;

	  for (k = 0; k < E_BITS; k++)
	    v ^= monPro_square (x_, &t[v], &t[v ^ 1], modulus, n0);
	  e <<= E_BITS;
	}
    }
#endif
rsaExpMod_montgomery_ok:
#ifdef PREVENT_CRT_SINGLE_ERROR
  if (test)
    {
// Single error check
// save result (not final) to exponent
      memcpy (exp, &t[v ^ 1].value[rsa_get_len ()], RSA_BYTES);

// check result with public exponent
      for (k = 0; k < test; k++)
	v ^= monPro_square (x_, &t[v], &t[v ^ 1], modulus, n0);
      v ^= monPro (x_, (rsa_num *) exp, &t[v], &t[v ^ 1], modulus, n0);
      v ^= monPro_1 (x_, &t[v], &t[v ^ 1], modulus, n0);
// compare
      if (memcmp (&check, &t[v ^ 1].value[rsa_get_len ()], rsa_get_len ()))
	return 1;
// last step is calculated 2x

// return (not final) result back
      memcpy (&t[v ^ 1].value[rsa_get_len ()], exp, RSA_BYTES);
      v ^= monPro_1 (x_, &t[v], &t[v ^ 1], modulus, n0);
      memcpy (&check, &t[v ^ 1].value[rsa_get_len ()], rsa_get_len ());
// repeat this step
      memcpy (&t[v ^ 1].value[rsa_get_len ()], exp, RSA_BYTES);
    }
#endif

  v ^= monPro_1 (x_, &t[v], &t[v ^ 1], modulus, n0);
  memcpy (x_, &t[v ^ 1].value[rsa_get_len ()], rsa_get_len ());

#ifdef PREVENT_CRT_SINGLE_ERROR
  if (test)
    {
      // final result (multiplication by 1) is calculated 2x,
      // compare to prevent single error in this step
      if (memcmp (&check, x_, rsa_get_len ()))
	return 1;
    }
#endif

#ifdef RSA_DEBUG
  DPRINT ("exponentation result: ");
  print_rsa_num (x_);
  DPRINT ("\n");
#endif
  return 0;
}

// for 5 bit window there is one more byte accessed after exponent
// enable 1 byte blinding (even when not used)

static uint16_t
  __attribute__ ((noinline)) rsaExpMod_montgomery_eblind (rsa_long_num t[2],
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
  __attribute__ ((noinline)) rsaExpMod_montgomery_init (rsa_long_num t[2],
							rsa_num * modulus,
							rsa_num * modulus_,
							rsa_num * mesg,
							uint8_t key)
{
// prepare for exponention (calculate n')
#ifndef USE_P_Q_INV
  rsa_inv_mod_N (modulus_, modulus);
#else
  if (rsa_get_len () != get_rsa_key_part (modulus_, key | 0x20))
    return Re_Q_GET_FAIL_1;
#endif
  memset (t, 0, RSA_BYTES * 4);


  // here we need (1 * R) mod 'modulus', this can be calculated by rsa_mod ()
  // 'R' is in form 2 pow 'k', usualy minimal 'k' is selected to get 'modulus' < 'R'
  // 'modulus' < 'R' < 2*'modulus', 'R' mod 'modulus' = 'R' - 'modulus'
  // but this is true for bigger 'k' too
  // generally:  2 pow 'k' mod M = 2 pow 'k' - 'M'  mod 'M' - this is enough to get
  // 1*R mod 'modulus' into rsa_get_len() bytes
  // here negation of modulus is used to get 'R' - 'modulus'
  // (negation uses rsa_get_len() to get 'k')
#if 1
  memcpy (&t[0], modulus, RSA_BYTES);
  bn_neg (&t[0]);

#else
  t[0].value[rsa_get_len ()] = 1;
  rsa_mod (&t[0], modulus);
#endif

  memcpy (&t[1].value[rsa_get_len ()], mesg, rsa_get_len ());
  rsa_mod (&t[1], modulus);
#ifdef RSA_DEBUG
  DPRINT ("Exponenting A = ");
  print_rsa_num (mesg);
  DPRINT ("\n");
#endif
  return 0;
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
  if (size != get_rsa_key_part (TMP1, KEY_RSA_p))
    {
      DPRINT ("ERROR, unable to get (p) part of key\n");
      return Re_P_GET_FAIL_1;
    }
  if (!(tmp->value[0] & 1))
    {
      DPRINT ("ERROR, rsa prime (p) not odd (%02x)\n", tmp->value[0]);
      return Re_P_EVEN_1;
    }
  rsa_mod (M_P, TMP1);

// calculate message modulo q
  if (size != get_rsa_key_part (TMP1, KEY_RSA_q))
    {
      DPRINT ("ERROR, unable to get (q) part of key\n");
      return Re_Q_GET_FAIL_1;
    }
  if (!(tmp->value[0] & 1))
    {
      DPRINT ("ERROR, rsa prime (q) not odd (%02x)\n", tmp->value[0]);
      return Re_Q_EVEN_1;
    }
  rsa_mod (M_Q, TMP1);

// save Q
  memcpy (TMP3, TMP1, RSA_BYTES);

  memset (TMP1, 0, sizeof (rsa_exp_num));
  if (size != get_rsa_key_part (TMP1, KEY_RSA_dQ))
    {
      DPRINT ("ERROR, unable to get (dQ) part of key\n");
      return Re_dQ_1;
    }
  count = rsaExpMod_montgomery_eblind (t, &exponent, TMP3);
// calculate msg * R mod modulus,
// calculate 1 * R mod modulus (or get this from key file),
// calculate n' (or get this from key file)
#warning, fixed public exponent
  if (rsaExpMod_montgomery_init (t, TMP3, TMP2, M2, KEY_RSA_q))
    return Re_Q_GET_FAIL_1;
//                   mesage,exponent,modulus,n', public exponent (2^16+1)
  if (rsaExpMod_montgomery (M2, &exponent, TMP3, TMP2, t, count, 16))
    return Re_Q_Single_Error;

  if (size != get_rsa_key_part (TMP3, KEY_RSA_p))
    {
      DPRINT ("ERROR, unable to get (p) part of key\n");
      return Re_P_GET_FAIL_2;
    }

  memset (TMP1, 0, sizeof (rsa_exp_num));
  if (size != get_rsa_key_part (TMP1, KEY_RSA_dP))
    {
      DPRINT ("ERROR, unable to get (dP) part of key\n");
      return Re_dP_1;
    }

  count = rsaExpMod_montgomery_eblind (t, &exponent, TMP3);
// calculate msg * R mod modulus,
// calculate n' (or get this from key file)
  if (rsaExpMod_montgomery_init (t, TMP3, TMP2, M1, KEY_RSA_p))
    return Re_P_GET_FAIL_3;
#warning, fixed public exponent
//                   mesage,exponent,modulus,n', public exponent (2^16+1)
  if (rsaExpMod_montgomery (M1, &exponent, TMP3, TMP2, t, count, 16))
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
  rsa_mod (H, TMP3);

// calculate M_P= h * q
  if (size != get_rsa_key_part (TMP1, KEY_RSA_q))
    {
      DPRINT ("ERROR, unable to get (q) part of key\n");
      return Re_Q_GET_FAIL_2;
    }
  rsa_mul (M_P, (rsa_num *) H, TMP1);

  memset (TMP3, 0, RSA_BYTES);
  rsa_add_long (M_P, M_Q);

#ifdef RSA_DEBUG
  DPRINT ("final result:\n");
  print_rsa_long_num (M_P);
  DPRINT ("\n");
#endif
  return 0;
#undef H
}

// if some of code is not explained in comments, please check
// openssl-1.0.2j/crypto/bn/bn_prime.c
// because small ram, here two free space pointer comes "t" and "tmp"
static uint8_t __attribute__ ((noinline))
miller_rabin (rsa_num * n, rsa_long_num t[2], rsa_long_num * tmp)
{
  rsa_exp_num exponent;
  rsa_num *e = &(exponent.n);
  rsa_num *a = &(tmp->L);
  rsa_num *n_ = &(tmp->H);

  uint8_t i, ret;
  uint16_t count;
  uint16_t d = 0;

  DPRINT ("miller rabin\n");

// assume: n-1 = e * (2 pow (d)),  "exp" is ODD
//         n-1 = e,  p is always odd, only clear bit 0
  memset (e, 0, sizeof (rsa_exp_num));
  memcpy (e, n, rsa_get_len ());
  e->value[0] &= 0xfe;

// make "e" odd  (and calculate d)
  do
    {
      d++, rsa_shiftr (e);
    }
  while ((e->value[0] & 1) == 0);

// precalculate for montgomery...
  rsa_inv_mod_N (n_, n);
#ifdef RSA_DEBUG
  DPRINT ("n=");
  print_rsa_num (n);
  DPRINT ("\n");
  DPRINT ("n_=");
  print_rsa_num (n_);
  DPRINT ("\n");
#endif

// calculate number of loops (based on bit len of prime)
// 3 runs for 1024 bit, 6 runs for 512, 12 runs for 256 bit ..

  i = 0, count = bn_real_bit_len;
  while (count <= 3072)
    count += bn_real_bit_len, i++;

  while (i--)
    {
      DPRINT ("miller loop %d\n", i);

      // get random "a" in range <2 .. n-2> (here minimal 256 bites prime is tested)
      // minimal "n" is 2^128+1, make "a" in range < (2^120)
      memset (a, 0, RSA_BYTES);
      rnd_get ((uint8_t *) a, 15);	// 120 bits
      a->value[0] |= 2;		// minimal value 2

#ifdef RSA_DEBUG
      DPRINT ("a=");
      print_rsa_num (a);
      DPRINT ("\n");
#endif

// do not use exponent blinding here ..
#if E_BITS == 5
      for (count = 260;; count += 5)
	if (count >= bn_real_bit_len)
	  break;
#else
      count = bn_real_bit_len;
#endif

      // TODO 1 * r mod n  can be calculated only once
      // but here t[0] is used in rsaExpMod_montgomery() and
      // no other space is available
      memset (&t[0], 0, RSA_BYTES * 4);
#if 1
      memcpy (&t[0], n, RSA_BYTES);
      bn_neg (&t[0]);
#else
      t[0].value[rsa_get_len ()] = 1;
      rsa_mod (&t[0], n);
#endif

      memcpy (&t[1].value[rsa_get_len ()], a, rsa_get_len ());
      rsa_mod (&t[1], n);

//    "a" = "a" pow "e" mod "n"  (n_, t=temp space, count=number of exp. bits)
//    do not check exponentation here (public exponent set to 0)
      rsaExpMod_montgomery (a, &exponent, n, n_, t, count, 0);

// test if "a"==1 invert bit 1 in "a" to use bn_test_zero()
      a->value[0] ^= 1;
      ret = bn_is_zero (a);
      a->value[0] ^= 1;
      if (ret)
	continue;		// "n" is candidate for probably prime number

// make (n-1) from n, test if "a"==(n-1)
      n->value[0] &= 0xfe;
      ret = memcmp (a, n, rsa_get_len ());
      n->value[0] |= 1;
      if (ret == 0)		// "n" is candidate for probably prime number
	continue;

      count = d;
      while (--count)
	{
	  rsa_square (&t[1], a);
	  rsa_mod (&t[1], n);
	  memcpy (a, &t[1], rsa_get_len ());

// test if "a"==1
// invert bit 1 in "a" to use bn_test_zero()
	  a->value[0] ^= 1;
	  ret = bn_is_zero (a);
	  a->value[0] ^= 1;
	  if (ret)
	    return 1;		// definitively composite

// make (n-1) from n, test if "a"==(n-1)
	  n->value[0] &= 0xfe;
	  ret = memcmp (a, n, rsa_get_len ());
	  n->value[0] |= 1;
	  if (ret == 0)		// "n" is candidate for probably prime number
	    break;
	}
      if (count == 0)
	return 1;		// definitively composite
    }
  return 0;
}

// use GCD to test if n can be divided by small primes
uint8_t __attribute__ ((weak)) prime_gcd (rsa_num * p)
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

// because small ram, here two free space pointer comes "t" and "tmp"
static void __attribute__ ((noinline))
get_prime (rsa_num * p, rsa_long_num t[2], rsa_long_num * tmp)
{
//  int i, j;

  memset (p, 0, RSA_BYTES);
#ifdef PRIME_INC
  rnd_get ((uint8_t *) p, bn_real_byte_len);

  p->value[0] |= 1;		// make number odd
  p->value[bn_real_byte_len - 1] |= 0x80;	// make number big
#endif
  DPRINT ("get_prime\n");
//  for (j = 0, i = 0;; i++)
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
/*
// for tests only
      uint8_t a,b;
      a=prime_gcd (p);
      b=prime_gcd1 (p);
      if(a!=b)
        for(;;);

      asm volatile("nop\n");

      prime_gcd (p);
      asm volatile("nop\n");
*/
      if (!prime_gcd (p))
	continue;
//      j++;
      if (!miller_rabin (p, t, tmp))
	break;
    }
#ifdef RSA_DEBUG
//  DPRINT ("iterations %d miller-rabin %d\n", i, j);
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

      test = (&modulus->value[0]) + bn_real_byte_len;;
      t = 14;			// over 100 bits
// Not elegant but readable
      do
	{
	  if (test != 0)
	    goto ok;
	}
      while (--t);
// found over 100 zero bits, |P-Q| si too small, generate new P,Q
      continue;
    ok:

// test if key is of desired size (not 1023 but 1024 etc..)
      rsa_mul (modulus, p, q);
      if (!(modulus->value[bn_real_byte_len * 2 - 1] & 0x80))
	continue;

// public exponent
#warning, fixed public exponent
      memset (&(key->d), 0, RSA_BYTES);
      key->d.value[0] = 1;
      key->d.value[2] = 1;
#ifdef RSA_DEBUG
      DPRINT ("P=");
      print_rsa_num (p);
      DPRINT ("\n");
      DPRINT ("Q=");
      print_rsa_num (q);
      DPRINT ("\n");
      DPRINT ("modulus=");
      print_rsa_long_num (modulus);
      DPRINT ("\n");
      DPRINT ("d=");
      print_rsa_num (&key->d);
      DPRINT ("\n");
#endif
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

#ifdef RSA_DEBUG
  DPRINT ("dP=");
  print_rsa_num (&key->dP);
  DPRINT ("\n");
  DPRINT ("dQ=");
  print_rsa_num (&key->dQ);
  DPRINT ("\n");
  DPRINT ("qInv=");
  print_rsa_num (&key->qInv);
  DPRINT ("\n");
#endif
  return size / 16;
}
