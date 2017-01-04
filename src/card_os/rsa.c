/*
    rsa.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015,2016 Peter Popovec, popovec.peter@gmail.com

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


Algorhithm is based on:
http://www.di-mgt.com.au/crt_rsa.html
(local copy internet_sources/www.di-mgt.com.au/crt_rsa.html)
and ftp://ftp.rsasecurity.com/pub/pdfs/tr201.pdf
(local copy internet_sources/tr201.pdf)

It uses Montgomery exponentation and Chinese remainder algorithms.

WARNING! it is designed to slow 8 bit CPU!

Implementation does NOT message blinding and exponent blinding! DPA attack isposible.
All operation are designed to run in constant time (only asm version for atmega 128).
SPA attack is prevented by  4 or 2 bits exponentations.





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
// On microcontroler like atmega no dynamic allocation is available (small
// ram, overhead for allocator etc).  all RSA values are stored in two types
// of variables (defined in rsa.h) rsa_num and rsa_long_num.  rsa_num must
// hold same bitlen as RSA modulus (for 2048 bite key 2048 bits = 128 bytes)
// length is defined in RSA_BYTES (check rsa.h)
//
// Arithmetic routines uses only a part of variable, length of actual modulus
// for arithmetic operation can be detected by function rsa_get_len()
// Set of this variable is by function rsa_set_len() (size is 128 for 2048 bits)
//


 // ..................................................
 // big number arithmetics needed for RSA calculation
 // ..................................................
uint8_t mod_len __attribute__ ((section (".noinit")));

uint8_t
rsa_get_len ()
{
  return mod_len;
}

void
rsa_set_len (uint8_t len)
{
  mod_len = len;
}

#ifndef HAVE_RSA_MOD
// calculate remainder(modulus) from long RSA number mod RSA number
// return !=0 if remainder can not be calculated (mod == 0)
static uint8_t rsa_mod (rsa_long_num * result, rsa_num * mod);
#else
extern uint8_t rsa_mod (rsa_long_num * result, rsa_num * mod);
#endif
// add two RSA numbers
#ifndef HAVE_RSA_ADD
static uint8_t rsa_add (rsa_num * r, rsa_num * a, rsa_num * b);
#else
extern uint8_t rsa_add (rsa_num * r, rsa_num * a, rsa_num * b);
#endif

// subtract two RSA numbers
#ifndef HAVE_RSA_SUB
static uint8_t rsa_sub (rsa_num * r, rsa_num * a, rsa_num * b);
#else
extern uint8_t rsa_sub (rsa_num * r, rsa_num * a, rsa_num * b);
#endif

// multiple two RSA numbers to one long RSA number
// size of number from rsa_get_len ()
//#ifndef HAVE_RSA_MUL
//static void rsa_mul (rsa_long_num * r, rsa_num * b, rsa_num * a);
//#else
//extern void rsa_mul (rsa_long_num * r, rsa_num * b, rsa_num * a);

//#endif

#if !defined(HAVE_RSA_MUL_256) && !defined(HAVE_RSA_MUL_512)
static void rsa_mul_256 (uint8_t * r, uint8_t * a, uint8_t * b);
#else
extern void rsa_mul_256 (uint8_t * r, uint8_t * a, uint8_t * b);
#endif

#ifndef HAVE_RSA_MUL_512
static void rsa_mul_512 (uint8_t * r, uint8_t * a, uint8_t * b);
#else
extern void rsa_mul_512 (uint8_t * r, uint8_t * a, uint8_t * b);
#endif

#if RSA_BYTES > 64
#ifndef HAVE_RSA_MUL_768
static void rsa_mul_768 (uint8_t * r, uint8_t * a, uint8_t * b);
#else
extern void rsa_mul_768 (uint8_t * r, uint8_t * a, uint8_t * b);
#endif
#endif

#if RSA_BYTES > 96
#ifndef HAVE_RSA_MUL_1024
static void rsa_mul_1024 (uint8_t * r, uint8_t * a, uint8_t * b);
#else
extern void rsa_mul_1024 (uint8_t * r, uint8_t * a, uint8_t * b);
#endif
#endif


#ifndef HAVE_RSA_SQUARE_512
static void rsa_square_512 (uint8_t * r, uint8_t * a);
#else
extern void rsa_square_512 (uint8_t * r, uint8_t * a);
#endif

#if RSA_BYTES > 64
#ifndef HAVE_RSA_SQUARE_768
static void rsa_square_768 (uint8_t * r, uint8_t * a);
#else
extern void rsa_square_768 (uint8_t * r, uint8_t * a);
#endif
#endif

#if RSA_BYTES > 96
#ifndef HAVE_RSA_SQUARE_1024
static void rsa_square_1024 (uint8_t * r, uint8_t * a);
#else
extern void rsa_square_1024 (uint8_t * r, uint8_t * a);
#endif
#endif

// calculates remaider(modulus)from RSA number * 'r' mod RSA number
// 'r' is 2^ (RSA_BYTES*8+1), for more info read about montgomery
// multiplication literature
#ifndef HAVE_RSA_MOD_R
static void rsa_mod_r (rsa_num * result, rsa_num * mod);
#else
extern void rsa_mod_r (rsa_num * result, rsa_num * mod);
#endif

#ifdef HAVE_RSA_INV_MOD
extern void rsa_inv_mod_full (rsa_num * n_, rsa_num * modulus);
#else
static void rsa_inv_mod_full (rsa_num * n_, rsa_num * modulus);
#endif
#ifdef HAVE_RSA_SHIFTL5
extern uint8_t rsa_shiftl5 (rsa_num * exp);
#endif
//..........................................
//  MONTOMERY routines
//..........................................
// basic montgomery product routine (just reduction)
#ifndef USE_N0
#define USE_N0 0
#endif
#if USE_N0 != 8 && USE_N0 != 16 && USE_N0 != 32 && USE_N0 != 0
#error please set USE_N0 to 0,8,16 or 32
#endif
#if USE_N0 == 0
#define n0_t rsa_num *
#elif USE_N0 == 8
#define n0_t uint8_t
#elif USE_N0 == 16
#define n0_t uint16_t
#else
#define n0_t uint32_t
#endif

#if USE_N0 != 0
#error This version of code uses new api to call monPro0, reprogram monPro0!
#endif

#ifndef HAVE_MON_PRO0
static uint8_t
monPro0 (rsa_num * a, rsa_long_num * t, rsa_long_num * help1, rsa_num * n,
	 n0_t n0);
#else
extern uint8_t
monPro0 (rsa_num * a, rsa_long_num * t, rsa_long_num * help1, rsa_num * n,
	 n0_t n0);
#endif

// calculate n0 for montgomery reduction in monPro0
//static n0_t modInverse (n0_t x);


// functions for debugging
#ifdef RSA_DEBUG
static void __attribute__ ((unused)) print_rsa_num (rsa_num * r)
{
  uint8_t i;

  printf ("\n0x");
  for (i = rsa_get_len (); i > 0;)
    printf ("%02X", r->value[--i]);
}

static void __attribute__ ((unused)) print_rsa_long_num (rsa_long_num * r)
{
  uint16_t i;

  printf ("\n0x");
  for (i = rsa_get_len () * 2; i > 0;)
    printf ("%02X", r->value[--i]);
}

#endif
//////////////////////////////////////////////////
//  BIG NUMBER ARITHMETIC
//////////////////////////////////////////////////
///////////////////////////////////////////////////////
// generic multiple precision add
static uint8_t
mp_add_v (uint8_t * r, uint8_t * a, uint8_t * b, uint8_t len, uint8_t carry)
{
  int16_t pA, pB, Res;

  do
    {
      pA = *a++;
      pB = *b++;
      Res = pA + pB + carry;

      *r++ = Res & 255;
      carry = (Res >> 8) & 1;
    }
  while (--len != 0);
  return carry;
}

#ifndef HAVE_RSA_ADD
// fixed len add for normal rsa number
static uint8_t
rsa_add (rsa_num * r, rsa_num * a, rsa_num * b)
{
  return mp_add_v (&r->value[0], &a->value[0], &b->value[0], rsa_get_len (),
		   0);
}
#endif
#ifndef HAVE_RSA_ADD_LONG
// fixed len add for long rsa number
static uint8_t
rsa_add_long (rsa_long_num * r, rsa_long_num * a, rsa_long_num * b)
{
  return mp_add_v (&r->value[0], &a->value[0], &b->value[0],
		   rsa_get_len () * 2, 0);
}

#endif
///////////////////////////////////////////////////////
#if (!defined(HAVE_RSA_SUB) \
  || !defined(HAVE_RSA_SUB_LONG) \
  || !defined(HAVE_RSA_MOD) \
  || !defined(HAVE_RSA_MUL_256) \
  || !defined(HAVE_RSA_MUL_512) \
  || (!defined(HAVE_RSA_MUL_1024) && RSA_BYTES>96) )

static uint8_t
mp_sub_v (uint8_t * r, uint8_t * a, uint8_t * b, uint8_t len)
{
  uint8_t carry;
  int16_t pA, pB, Res;

  carry = 0;
  do
    {
      pA = *a++;
      pB = *b++;;
      Res = pA - pB - carry;

      *r++ = Res & 255;
      carry = (Res >> 8) & 1;
    }
  while (--len != 0);
  return carry;
}
#endif
// fixed len sub for normal rsa number
#ifndef HAVE_RSA_SUB
#define NEED_MP_SUB_V
static uint8_t
rsa_sub (rsa_num * r, rsa_num * a, rsa_num * b)
{
  return mp_sub_v (&r->value[0], &a->value[0], &b->value[0], rsa_get_len ());
}
#endif
#if !defined(HAVE_RSA_SUB_LONG)
#define NEED_MP_SUB_V
static uint8_t
rsa_sub_long (rsa_long_num * r, rsa_long_num * a, rsa_long_num * b)
{
  return mp_sub_v (&r->value[0], &a->value[0], &b->value[0],
		   rsa_get_len () * 2);
}
#endif
///////////////////////////////////////////////////////
#if  !defined (HAVE_RSA_MOD) || !defined(HAVE_RSA_MOD_R) || E_BITS==5
static uint8_t
mp_shiftl_v (uint8_t * r, uint8_t len)
{
  uint8_t carry;
  int16_t Res;

  carry = 0;
  do
    {
      Res = *r << 1;
      Res |= carry;
      carry = (Res >> 8) & 1;
      *r++ = Res & 255;
    }
  while (--len != 0);
  return carry;
}

static uint8_t
rsa_shiftl (rsa_num * r)
{
  return mp_shiftl_v (&r->value[0], rsa_get_len ());
}

#endif
//////////////////////////////////////////////////
//helper for rsa_mod
#if !defined(HAVE_RSA_MOD) || (USE_N0 == 0 && (!defined(HAVE_MON_PRO0) || !defined(HAVE_RSA_INV_MOD)))
static uint8_t
mp_shiftr_v (uint8_t * r, uint8_t len)
{
  uint8_t carry, c2;
  int16_t Res;

  len--;
  r += len;
  len++;

  carry = 0;
  do
    {
      Res = *r;
      c2 = Res & 1;
      Res = Res >> 1;
      Res |= carry;
      carry = c2 << 7;
      *r-- = Res;

    }
  while (--len != 0);
  return carry;

}
#endif
#ifndef HAVE_RSA_SHIFTR_LONG
static uint8_t
rsa_shiftr_long (rsa_long_num * r)
{
  return mp_shiftr_v (&r->value[0], rsa_get_len () * 2);
}
#endif
#if !defined(HAVE_RSA_MOD)
//////////////////////////////////////////////////
// "result" = "result" mod "mod"
// operates on full modulus length (256 bytes for 2048 RSA)
static uint8_t
rsa_mod (rsa_long_num * result, rsa_num * mod)
{
  rsa_long_num tmp;
  rsa_long_num helper;

  rsa_long_num *tmp_result[2];

// check below..
#if 0
  rsa_num *n;
  uint8_t len = rsa_get_len () * 2 - 1;
#endif
  uint16_t i;
  uint8_t index;


  memset ((uint8_t *) (&tmp), 0, rsa_get_len ());
  memcpy ((uint8_t *) (&tmp) + rsa_get_len (), mod, rsa_get_len ());

  i = rsa_get_len () * 8;

// this part of code is not needed, we are interested only for integer part of remainder
#if 0
  n = (rsa_num *) ((uint8_t *) & tmp + rsa_get_len ());
  while (!(tmp.value[len] & 0x80))
    {
      rsa_shiftl (n);
      i++;
      // test for mod==0 - not perfect, but working ..
      if (i == 0)
	return 1;
    }
#endif
// get pointers for posible results
  tmp_result[0] = result;
  tmp_result[1] = &helper;
// first calculate result - tmp, - init index at 0
  index = 0;

  for (i++; i > 0; i--)
    {
      // subtract from result, if this generates carry
      // (result < tmp), switch to unchanged result
      if (!rsa_sub_long
	  (tmp_result[(~index) & 1], tmp_result[index & 1], &tmp))
	index++;
      rsa_shiftr_long (&tmp);
    }

  memcpy (result, &tmp_result[index & 1]->value[0], RSA_BYTES * 2);

  return 0;
}
#endif
///////////////////////////////////////////////////////
#ifndef HAVE_RSA_MUL

#if (!defined(HAVE_RSA_MUL_256) && !defined(HAVE_RSA_MUL_512)) \
 || (!defined(HAVE_RSA_MUL_1024) && RSA_BYTES>96)
// helpers
static void
mp_com_v (uint8_t * r, uint8_t len)
{
  uint8_t i;
  uint8_t *p;
  uint8_t c;
  uint16_t res;

  i = len;
  p = r;

  while (i--)
    {
      *p ^= 255;
      p++;
    }

  i = len;
  p = r;
  res = *p + 1;
  *p = res & 255;
  c = res >> 8;
  p++;

  while (--i)
    {
      res = *p + c;
      *p = res & 255;
      p++;
      c = res >> 8;
    }
}

// add +127 -128 ..
static void
mp_prop_carry (uint8_t * r, int16_t prop, uint8_t len)
{
  uint16_t res;
  uint8_t c1, c2;

  c1 = prop & 255;
  c2 = prop >> 8;

  while (len)
    {
      res = *r + c1 + c2;
      *r = res & 0xff;
      c1 = res >> 8;
      r++;
      len--;
    }
}
#endif

#if !defined(HAVE_RSA_MUL_512) && !defined(HAVE_RSA_MUL_256)
// Tested on atmega, karatsuba at this level is slower that
// simple multiplication
static void
rsa_mul_128 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t i, j, c;
  uint8_t a_;
  uint16_t res;

  memset (r, 0, 32);

  for (i = 0; i < 16; i++)
    {
      c = 0;
      a_ = a[i];

      for (j = 0; j < 16; j++)
	{
	  res = a_ * b[j];
	  res += r[i + j];
	  res += c;

	  c = res >> 8;
	  r[i + j] = res & 255;
	}
      r[i + 16] = c;
    }
}

static void
rsa_mul_192 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t i, j, c;
  uint8_t a_;
  uint16_t res;

  memset (r, 0, 48);

  for (i = 0; i < 24; i++)
    {
      c = 0;
      a_ = a[i];

      for (j = 0; j < 24; j++)
	{
	  res = a_ * b[j];
	  res += r[i + j];
	  res += c;

	  c = res >> 8;
	  r[i + j] = res & 255;
	}
      r[i + 24] = c;
    }
}

#define DO_1 16
#define DO_2 32
static void
rsa_mul_256 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t s1, s2;
  int8_t c, c2;

  struct ld
  {
    uint8_t l_up[DO_1];
    uint8_t m[DO_2];
  } ld;

  s1 = mp_sub_v (r, a, a + DO_1, DO_1);
  s2 = mp_sub_v (r + DO_1, b, b + DO_1, DO_1);

  if (s1)
    mp_com_v (r, DO_1);
  if (s2)
    mp_com_v (r + DO_1, DO_1);

  rsa_mul_128 (ld.m, r, r + DO_1);

  rsa_mul_128 (r, a, b);
  rsa_mul_128 (r + DO_2, a + DO_1, b + DO_1);

  memcpy (ld.l_up, r + DO_1, DO_1);

  c = mp_add_v (r + DO_1, r + DO_1, r + DO_2, DO_2, 0);

  c2 = mp_add_v (r + DO_1, r + DO_1, r, DO_1, 0);
  c2 = mp_add_v (r + DO_2, r + DO_2, ld.l_up, DO_1, c2);

  c += c2;

  if (s1 != s2)
    {
      c += mp_add_v (r + DO_1, r + DO_1, ld.m, DO_2, 0);
      // c= 0,1,2
    }
  else
    {
      c = c - mp_sub_v (r + DO_1, r + DO_1, ld.m, DO_2);
      //c = -1 0 1
    }
  mp_prop_carry (r + DO_1 + DO_2, c, DO_1);
}

#undef DO_1
#undef DO_2
#endif
#ifndef HAVE_RSA_MUL_512
#define DO_1 32
#define DO_2 64
static void
rsa_mul_512 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t s1, s2;
  int8_t c, c2;

  struct ld
  {
    uint8_t l_up[DO_1];
    uint8_t m[DO_2];
  } ld;

  s1 = mp_sub_v (r, a, a + DO_1, DO_1);
  s2 = mp_sub_v (r + DO_1, b, b + DO_1, DO_1);

  if (s1)
    mp_com_v (r, DO_1);
  if (s2)
    mp_com_v (r + DO_1, DO_1);

  rsa_mul_256 (ld.m, r, r + DO_1);

  rsa_mul_256 (r, a, b);
  rsa_mul_256 (r + DO_2, a + DO_1, b + DO_1);

  memcpy (ld.l_up, r + DO_1, DO_1);

  c = mp_add_v (r + DO_1, r + DO_1, r + DO_2, DO_2, 0);

  c2 = mp_add_v (r + DO_1, r + DO_1, r, DO_1, 0);
  c2 = mp_add_v (r + DO_2, r + DO_2, ld.l_up, DO_1, c2);

  c += c2;

  if (s1 != s2)
    {
      c += mp_add_v (r + DO_1, r + DO_1, ld.m, DO_2, 0);
      // c= 0,1,2
    }
  else
    {
      c = c - mp_sub_v (r + DO_1, r + DO_1, ld.m, DO_2);
      //c = -1 0 1
    }
  mp_prop_carry (r + DO_1 + DO_2, c, DO_1);
}

#undef DO_1
#undef DO_2
#endif

#if RSA_BYTES > 64
#ifndef HAVE_RSA_MUL_768
#define DO_1 24
#define DO_2 48
static void
rsa_mul_384 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t s1, s2;
  int8_t c, c2;

  struct ld
  {
    uint8_t l_up[DO_1];
    uint8_t m[DO_2];
  } ld;

  s1 = mp_sub_v (r, a, a + DO_1, DO_1);
  s2 = mp_sub_v (r + DO_1, b, b + DO_1, DO_1);

  if (s1)
    mp_com_v (r, DO_1);
  if (s2)
    mp_com_v (r + DO_1, DO_1);

  rsa_mul_192 (ld.m, r, r + DO_1);

  rsa_mul_192 (r, a, b);
  rsa_mul_192 (r + DO_2, a + DO_1, b + DO_1);

  memcpy (ld.l_up, r + DO_1, DO_1);

  c = mp_add_v (r + DO_1, r + DO_1, r + DO_2, DO_2, 0);

  c2 = mp_add_v (r + DO_1, r + DO_1, r, DO_1, 0);
  c2 = mp_add_v (r + DO_2, r + DO_2, ld.l_up, DO_1, c2);

  c += c2;

  if (s1 != s2)
    {
      c += mp_add_v (r + DO_1, r + DO_1, ld.m, DO_2, 0);
      // c= 0,1,2
    }
  else
    {
      c = c - mp_sub_v (r + DO_1, r + DO_1, ld.m, DO_2);
      //c = -1 0 1
    }
  mp_prop_carry (r + DO_1 + DO_2, c, DO_1);
}

#undef DO_1
#undef DO_2
#define DO_1 48
#define DO_2 96
static void
rsa_mul_768 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t s1, s2;
  int8_t c, c2;

  struct ld
  {
    uint8_t l_up[DO_1];
    uint8_t m[DO_2];
  } ld;

  s1 = mp_sub_v (r, a, a + DO_1, DO_1);
  s2 = mp_sub_v (r + DO_1, b, b + DO_1, DO_1);

  if (s1)
    mp_com_v (r, DO_1);
  if (s2)
    mp_com_v (r + DO_1, DO_1);

  rsa_mul_384 (ld.m, r, r + DO_1);

  rsa_mul_384 (r, a, b);
  rsa_mul_384 (r + DO_2, a + DO_1, b + DO_1);

  memcpy (ld.l_up, r + DO_1, DO_1);

  c = mp_add_v (r + DO_1, r + DO_1, r + DO_2, DO_2, 0);

  c2 = mp_add_v (r + DO_1, r + DO_1, r, DO_1, 0);
  c2 = mp_add_v (r + DO_2, r + DO_2, ld.l_up, DO_1, c2);

  c += c2;

  if (s1 != s2)
    {
      c += mp_add_v (r + DO_1, r + DO_1, ld.m, DO_2, 0);
      // c= 0,1,2
    }
  else
    {
      c = c - mp_sub_v (r + DO_1, r + DO_1, ld.m, DO_2);
      //c = -1 0 1
    }
  mp_prop_carry (r + DO_1 + DO_2, c, DO_1);

}

#undef DO_1
#undef DO_2


#endif
#endif
#if RSA_BYTES > 96
#ifndef HAVE_RSA_MUL_1024
#define DO_1 64
#define DO_2 128
static void
rsa_mul_1024 (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t s1, s2;
  int8_t c, c2;

  struct ld
  {
    uint8_t l_up[DO_1];
    uint8_t m[DO_2];
  } ld;

  s1 = mp_sub_v (r, a, a + DO_1, DO_1);
  s2 = mp_sub_v (r + DO_1, b, b + DO_1, DO_1);

  if (s1)
    mp_com_v (r, DO_1);
  if (s2)
    mp_com_v (r + DO_1, DO_1);

  rsa_mul_512 (ld.m, r, r + DO_1);

  rsa_mul_512 (r, a, b);
  rsa_mul_512 (r + DO_2, a + DO_1, b + DO_1);

  memcpy (ld.l_up, r + DO_1, DO_1);

  c = mp_add_v (r + DO_1, r + DO_1, r + DO_2, DO_2, 0);

  c2 = mp_add_v (r + DO_1, r + DO_1, r, DO_1, 0);
  c2 = mp_add_v (r + DO_2, r + DO_2, ld.l_up, DO_1, c2);

  c += c2;

  if (s1 != s2)
    {
      c += mp_add_v (r + DO_1, r + DO_1, ld.m, DO_2, 0);
      // c= 0,1,2
    }
  else
    {
      c = c - mp_sub_v (r + DO_1, r + DO_1, ld.m, DO_2);
      //c = -1 0 1
    }
  mp_prop_carry (r + DO_1 + DO_2, c, DO_1);

}

#undef DO_1
#undef DO_2
#endif
#endif
/// falback fcions
#ifndef HAVE_RSA_MUL_512_MOD
static void
rsa_mul_512_mod (uint8_t * r, uint8_t * a, uint8_t * b)
{
#if 1
  uint8_t t[32];

  rsa_mul_256 (r, a, b + 32);
  memcpy (t, r, 32);

  rsa_mul_256 (r, b, a + 32);
  mp_add_v (t, t, r, 32, 0);

  rsa_mul_256 (r, a, b);
  mp_add_v (r + 32, r + 32, t, 32, 0);
#else
  uint8_t t[128];
  rsa_mul_512 (t, a, b);
  memcpy (r, t, 64);
#endif
}
#else
void rsa_mul_512_mod (uint8_t * r, uint8_t * a, uint8_t * b);
#endif
#if RSA_BYTES >64
#ifndef HAVE_RSA_MUL_768_MOD
static void rsa_mul_1024_mod (uint8_t * r, uint8_t * a, uint8_t * b);
static void
rsa_mul_768_mod (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t t[48];

  rsa_mul_384 (r, a, b + 48);
  memcpy (t, r, 48);

  rsa_mul_384 (r, b, a + 48);
  mp_add_v (t, t, r, 48, 0);

  rsa_mul_384 (r, a, b);
  mp_add_v (r + 48, r + 48, t, 48, 0);

}
#else
void rsa_mul_768_mod (uint8_t * r, uint8_t * a, uint8_t * b);
#endif
#endif
#if RSA_BYTES > 96
#ifndef HAVE_RSA_MUL_1024_MOD
static void
rsa_mul_1024_mod (uint8_t * r, uint8_t * a, uint8_t * b)
{
  uint8_t t[64];

  rsa_mul_512_mod (t, a, b + 64);

  rsa_mul_512_mod (r, b, a + 64);
  mp_add_v (t, t, r, 64, 0);

  rsa_mul_512 (r, a, b);
  mp_add_v (r + 64, r + 64, t, 64, 0);
}
#endif
#endif
#ifndef HAVE_RSA_SQUARE_512
static void
rsa_square_512 (uint8_t * r, uint8_t * a)
{
  rsa_mul_512 (r, a, a);
}
#endif
#if RSA_BYTES >64
#ifndef HAVE_RSA_SQUARE_768
static void
rsa_square_768 (uint8_t * r, uint8_t * a)
{
  rsa_mul_768 (r, a, a);
}
#endif
#endif
#if RSA_BYTES > 96
#ifndef HAVE_RSA_SQUARE_1024
static void
rsa_square_1024 (uint8_t * r, uint8_t * a)
{
  rsa_mul_1024 (r, a, a);
}
#endif
#endif

//static void
void
rsa_mul_mod (rsa_num * r, rsa_num * a, rsa_num * b)
{
#if RSA_BYTES == 64
  rsa_mul_512_mod (&r->value[0], &a->value[0], &b->value[0]);
#elif RSA_BYTES == 96
  if (rsa_get_len () == 64)
    rsa_mul_512_mod (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_768_mod (&r->value[0], &a->value[0], &b->value[0]);
#elif RSA_BYTES == 128
  if (rsa_get_len () == 64)
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
  rsa_square_512 (&r->value[0], &a->value[0]);
#elif RSA_BYTES == 96
  if (rsa_get_len () == 64)
    rsa_square_512 (&r->value[0], &a->value[0]);
  else
    rsa_square_768 (&r->value[0], &a->value[0]);
#elif RSA_BYTES == 128
  if (rsa_get_len () == 64)
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
  rsa_mul_512 (&r->value[0], &a->value[0], &b->value[0]);
#elif RSA_BYTES == 96
  if (rsa_get_len () == 64)
    rsa_mul_512 (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_768 (&r->value[0], &a->value[0], &b->value[0]);
#elif RSA_BYTES == 128
  if (rsa_get_len () == 64)
    rsa_mul_512 (&r->value[0], &a->value[0], &b->value[0]);
  else if (rsa_get_len () == 96)
    rsa_mul_768 (&r->value[0], &a->value[0], &b->value[0]);
  else
    rsa_mul_1024 (&r->value[0], &a->value[0], &b->value[0]);
#else
#error wrong RSA_BYTES
#endif
}

#endif
///////////////////////////////////////////////////////


//////////////////////////////////////////////////

// MONTGOMERY

//////////////////////////////////////////////////
#ifndef HAVE_RSA_MOD_R
// Montgomery helper fcion
// calculates  result = result * r mod n
// r = 1<<(RSA_BYTES * 8 + 1)
static void
rsa_mod_r (rsa_num * result, rsa_num * mod)
{
  uint16_t i;
  uint8_t c1 = 0, c2;
  rsa_num tmp;
  rsa_num *active[2];
  uint8_t j = 0;

  active[0] = result;
  active[1] = &tmp;

  i = rsa_get_len () * 8;
  for (;;)
    {
      c2 = rsa_sub (active[(~j) & 1], active[j & 1], mod);
      if (0 == (c1 ^ c2))
	j++;
      if (!i)
	break;
      i--;
      c1 = rsa_shiftl (active[j & 1]);
    }
  memcpy (result, active[j & 1], rsa_get_len ());
}
#endif
//////////////////////////////////////////////////

#if !defined(HAVE_RSA_INV_MOD) && USE_N0 == 0
static uint8_t
rsa_num_test_even (rsa_num * r)
{
  return 1 ^ (r->value[0] & 1);
}

static uint8_t
rsa_shiftr (rsa_num * r)
{
  return mp_shiftr_v (&r->value[0], rsa_get_len ());
}

// calculate mod inverse for k^-1  mod n,  k is in form 2^w
// Warning, this function is not constant time!

static void
rsa_inv_mod (rsa_num * n_, rsa_num * n)
{
  rsa_num zero;
  uint8_t carry, j;
  uint16_t i;

  memset (&zero, 0, RSA_BYTES);
  memset (n_, 0, RSA_BYTES);
  n_->value[0] = 1;

  j = rsa_get_len ();
  for (i = j * 8; i > 0; i--)
    {
      if (rsa_num_test_even (n_))
	{
	  // constant time ..
	  // n_ = (n_ + 0)/ 2
	  carry = rsa_add (n_, n_, &zero);
	  rsa_shiftr (n_);
	  if (carry)
	    n_->value[j - 1] |= 0x80;
	}
      else
	{
	  // n_ = (n_ + p)/2
	  carry = rsa_add (n_, n_, n);
	  rsa_shiftr (n_);
	  if (carry)
	    n_->value[j - 1] |= 0x80;
	}
    }
  return;
}

/*
 montgomery reduction  need n'
 to calculate n', folowing method is used:

 r * r^(-1) - n * n' = 1

 in this code R is selected to  2 ^((RSA_NUM<<8)+1)

 r^(-1) is calculated, then n'  is calculated by

 (r*r^(-1) -1)/n = n'

 operands assigments:
           modulus = r
           n_ = n'
*/

static void
rsa_inv_mod_full (rsa_num * n_, rsa_num * modulus)
{
  rsa_num r0_;
  rsa_num r1_;

  rsa_num *help[2];
  uint8_t c1, c2;

  uint8_t index;
  uint16_t i;
  uint8_t j;
  uint8_t result_byte;
  uint8_t carry;


  // calculate r^-1 mod modulus, r is 2 ^((RSA_NUM<<8)+1)
  rsa_inv_mod (&r0_, modulus);

// subtract 1 

  memset (&r1_, 0, rsa_get_len ());
  r1_.value[0] = 1;
  rsa_sub (&r0_, &r0_, &r1_);

// create copy
//  memcpy (&r1_, &r0_, rsa_get_len ());

// divide
  result_byte = 1;		// catch this bit in carry to get final byte
  help[0] = &r0_;
  help[1] = &r1_;

  index = 0;
  j = rsa_get_len () - 1;
  for (i = 0; i < rsa_get_len () * 8; i++)
    {
      c1 = rsa_shiftl (help[index & 1]);
      help[index & 1]->value[0] |= 1;

      c2 = rsa_sub (help[(index + 1) & 1], help[index & 1], modulus);
      index += (c2 == c1);
      // catch carry (C does not support CARRY bit :-\ )
      carry = result_byte & 0x80;
      result_byte <<= 1;
      result_byte |= (c2 == c1);

      if (carry)
	{
	  n_->value[j] = result_byte;
	  result_byte = 1;	// catch this bit in carry to get final byte
	  j--;
	}
    }
}
#endif // HAVE_RSA_INV_MOD

#ifndef HAVE_MON_PRO0
#if USE_N0 == 0

static uint8_t
monPro0 (rsa_num * a, rsa_long_num * t, rsa_long_num * help1, rsa_num * n,
	 n0_t n0)
{
  uint8_t carry;

  rsa_mul_mod (a, (rsa_num *) t, n0);
  rsa_mul (help1, a, n);

  carry = rsa_add_long (help1, t, help1);

  carry ^=
    rsa_sub ((rsa_num *) & t->value[rsa_get_len ()],
	     (rsa_num *) & help1->value[rsa_get_len ()], n);

  return carry ? 1 : 0;
}


#elif USE_N0 != 8
#error no support for non 8 bit N0 in default code
#else

#if 1				// new algo 1  old algo = 0
//#define MASK_VAR (((1<<(USE_N0-1))<<1)|1)
static void
monPro0 (rsa_num * a, rsa_long_num * t, rsa_num * n, n0_t n0)
{
  uint8_t i, j;
  uint16_t res, c;

  n0_t m;
  n0_t *ptr_t = (n0_t *) t, *backup_t;
  n0_t *ptr_n;
  i = rsa_get_len () * 8 / USE_N0;
  do
    {
      c = 0;
      res = (*ptr_t * n0);
      m = res;			// & MASK_VAR;
      ptr_n = (n0_t *) n;
      backup_t = ptr_t;
      j = rsa_get_len () * 8 / USE_N0;
      do
	{
	  res = *ptr_n * m;
	  res += *ptr_t;
	  res += c;
	  c = res >> USE_N0;
	  *ptr_t = res;		// & MASK_VAR;
	  ptr_t++;
	  ptr_n++;
	}
      while (--j);
      j = i;
      do
	{
	  res = *ptr_t + c;
	  c = res >> USE_N0;
	  *ptr_t = res;		// & MASK_VAR;
	  ptr_t++;
	}
      while (--j);
      ptr_t = backup_t;
      ptr_t++;
    }
  while (--i);

// precalculate a - n into lower part of t, update c from this subtract operation
// copy correct result to "a"
  {
    uint8_t len = rsa_get_len ();
    c |= (1 -
	  rsa_sub ((rsa_num *) & t->value[0], (rsa_num *) & t->value[len],
		   n));
    if (!c)
      memcpy (a, (rsa_num *) & t->value[len], len);
    else
      memcpy (a, (rsa_num *) & t->value[0], len);
  }
}
#else //old algo
static void
monPro0 (rsa_num * a, rsa_long_num * t, rsa_num * n, n0_t n0)
{
  uint8_t m;
  uint16_t i;
  uint16_t j;
  uint16_t res;
  uint8_t c = 0;
  uint8_t len = rsa_get_len ();

  // reduction ..  
  for (i = 0; i < len; i++)
    {
      c = 0;
      res = (t->value[i] * n0);
      m = res & 255;
      for (j = 0; j < len; j++)
	{
	  res = m * n->value[j];
	  res += t->value[i + j];
	  res += c;
	  c = res >> 8;
	  t->value[i + j] = res & 255;
	}
      // propagate carry
      for (j = i + len; j < 2 * len; j++)
	{
	  res = t->value[j] + c;
	  c = res >> 8;
	  t->value[j] = res & 255;
	}
    }
// result "a" in upper bytes of "t",// "t" can hawe one more bite in c

// divide by r (r is always 2^(RSA_BYTES*8+1))
// a is upper part of t

// precalculate a - n into lower part of t, update c from this subtract operation
// copy correct result to "a"

  c |=
    (1 - rsa_sub ((rsa_num *) & t->value[0], (rsa_num *) & t->value[len], n));

  if (!c)
    memcpy (a, (rsa_num *) & t->value[rsa_get_len ()], rsa_get_len ());
  else
    memcpy (a, (rsa_num *) & t->value[0], rsa_get_len ());
}

#endif // old algo
#endif // 8 bit monpro
#endif // have monpro
////////////////////////////////////////////////////
static uint8_t
monPro_square (rsa_num * a, rsa_long_num * t, rsa_long_num * tmp,
	       rsa_num * n, n0_t n0)
{
  rsa_square (t, (rsa_num *) & tmp->value[rsa_get_len ()]);
  return monPro0 (a, t, tmp, n, n0);
}

static uint8_t
monPro (rsa_num * a, rsa_num * b, rsa_long_num * t, rsa_long_num * tmp,
	rsa_num * n, n0_t n0)
{
  rsa_mul (t, (rsa_num *) & tmp->value[rsa_get_len ()], b);
  return monPro0 (a, t, tmp, n, n0);
}

static uint8_t
monPro_1 (rsa_num * a, rsa_long_num * t, rsa_long_num * tmp, rsa_num * n,
	  n0_t n0)
{
  // clear upper part of t
  memset (&(t->value[rsa_get_len ()]), 0, rsa_get_len ());
  // copy a (a*1)
  memcpy (t, &tmp->value[rsa_get_len ()], rsa_get_len ());

  // calculate product
  return monPro0 (a, t, tmp, n, n0);
}

////////////////////////////////////////////////////
// calculate n0 for modified montgomery multiplication
// based on ftp://ftp.rsasecurity.com/pub/pdfs/tr201.pdf page 60
// function modInverse. Implementation for 8bit CPU:
// #define n0_t uint8_t of for 16 bit define uint16_t
// this is working for max 32 bit on avr-gcc
#if USE_N0 <= 32 && USE_N0 != 0
n0_t
modInverse (n0_t x)
{
  n0_t x_mul1;
  n0_t x_mul2;
  n0_t y;
  n0_t p;
  x = (~x) + 1;
  y = 1;
  x_mul1 = 2;
  x_mul2 = 3;
  while (x_mul1 != 0)
    {
      p = x * y;
      p = p & x_mul2;
      x_mul2 = (x_mul1 << 1) | 1;
      if (p > x_mul1)
	y += x_mul1;
      x_mul1 <<= 1;
    }
  return y;
}
#endif
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


because ATMEGA 128 RAM is small, 5 bits are used only for 1024 keys,(atmega1284 with 8k ram can be used with 5 bits )
for 1536 and 2048 only 4 bits..Next code is only for 2 or 4 bites, 5 bits only for devices with 8kB and more ram..
*/
#ifndef E_BITS
#define E_BITS 2
#endif

#if E_BITS != 2 && E_BITS != 4 && E_BITS != 5
#error unsupported E_BITS value
#endif
// return in exp!
static void
rsaExpMod_montgomery (rsa_num * x_, rsa_num * exp, rsa_num * modulus,
		      rsa_num * n0)
{
  rsa_num M_[1 << E_BITS];
  rsa_long_num t[2];

  uint8_t e, j, k, v;
  int16_t i;
  uint16_t count;

  memcpy (&M_[1], x_, rsa_get_len ());
#ifdef RSA_DEBUG
  printf ("Exponenting\ndata = ");
  print_rsa_num (&M_[1]);
  printf ("\n");
  printf ("exponent = ");
  print_rsa_num (exp);
  printf ("\n");
  printf ("modulus = ");
  print_rsa_num (modulus);
  printf ("\n");
#endif

  // calculate 1*r mod modulus
  memset (x_, 0, rsa_get_len ());
  x_->value[0] = 1;
  rsa_mod_r (x_, modulus);
  memcpy (&M_[0], x_, rsa_get_len ());

  // calculate message * r mod modulus
  rsa_mod_r (&M_[1], modulus);

  // calculate constants
  for (j = 2; j < (1 << E_BITS); j++)
    memcpy (&M_[j], &M_[1], rsa_get_len ());

  for (j = 2; j < (1 << E_BITS); j++)
    {
      memcpy (&t[1].value[rsa_get_len ()], &M_[j], rsa_get_len ());
      v = monPro (&M_[j], &M_[j - 1], &t[0], &t[1], modulus, n0);
      memcpy (&M_[j], &t[v].value[rsa_get_len ()], rsa_get_len ());
    }

#ifdef RSA_DEBUG
  printf ("n0=");
  print_rsa_num (n0);
  printf ("\n");
  printf ("1 * r mod n = ");
  print_rsa_num (x_);
  printf ("\n");
  printf ("message * r mod n = ");
  print_rsa_num (&M_[1]);
  printf ("\n");
#endif

  memcpy (&t[1].value[rsa_get_len ()], x_, RSA_BYTES);
  v = 0;

  // exponentation..
  i = rsa_get_len ();

#if E_BITS == 5
  e = exp->value[i - 1];
  if (i == 64)
    {
      count = 515;
      e >>= 6;
      e &= 3;
      rsa_shiftl (exp);
      rsa_shiftl (exp);
    }
  else if (i == 96)
    {
      count = 770;
      e >>= 5;
      rsa_shiftl (exp);
      rsa_shiftl (exp);
      rsa_shiftl (exp);
    }
  else
    {
      count = 1025;
      e >>= 4;
      rsa_shiftl (exp);
      rsa_shiftl (exp);
      rsa_shiftl (exp);
      rsa_shiftl (exp);
    }

  for (;;)
    {
      v += monPro (x_, &M_[e], &t[v & 1], &t[(v + 1) & 1], modulus, n0);
      v++;
      count -= E_BITS;
      if (count == 0)
	{
	  v += monPro_1 (x_, &t[v & 1], &t[(v + 1) & 1], modulus, n0);
	  memcpy (x_, &t[v & 1].value[rsa_get_len ()], rsa_get_len ());

#ifdef RSA_DEBUG
	  printf ("exponentation result");
	  print_rsa_num (x_);
	  printf ("\n");
#endif
	  return;
	}
      for (k = 0; k < E_BITS; k++)
	{
	  v += monPro_square (x_, &t[v & 1], &t[(v + 1) & 1], modulus, n0);
	  v++;
	}
      e = exp->value[i - 1];
      e >>= 3;
      e &= 0x1f;
#ifndef HAVE_RSA_SHIFTL5
      rsa_shiftl (exp);
      rsa_shiftl (exp);
      rsa_shiftl (exp);
      rsa_shiftl (exp);
      rsa_shiftl (exp);
#else
      rsa_shiftl5 (exp);
#endif
    }
#else
  count = i * 8;
  for (;;)
    {
      e = exp->value[--i];
      for (j = 0; j < 8; j += E_BITS)
	{
	  v +=
	    monPro (x_, &M_[e >> (8 - E_BITS)], &t[v & 1],
		    &t[(v + 1) & 1], modulus, n0);
	  v++;
	  count -= E_BITS;
	  if (count == 0)
	    {
	      v += monPro_1 (x_, &t[v & 1], &t[(v + 1) & 1], modulus, n0);
	      memcpy (x_, &t[v & 1].value[rsa_get_len ()], rsa_get_len ());

#ifdef RSA_DEBUG
	      printf ("exponentation result");
	      print_rsa_num (x_);
	      printf ("\n");
#endif
	      return;
	    }
	  for (k = 0; k < E_BITS; k++)
	    {
	      v +=
		monPro_square (x_, &t[v & 1], &t[(v + 1) & 1], modulus, n0);
	      v++;
	    }
	  e <<= E_BITS;
	}
    }
#endif
}

/******************************************************************
Minimalize memory usage:

already allocated (before rsa_calculate() call)

256 byte data
256 byte result

(RSA_BYTES = 128)
struct RSA
  128  p
  128  q
  128  dP
  128  dQ
  128 qInv
----------------------------------------- 1152 bytes sum = 1152

result = data mod P
data   = data mod Q

data and result - we need only lower 128 bytes, combine two 128 bytes
value into one 256 variable ("result") and get "data" free;

Reuse "data" as "t" variable (used as result for rsa_mul in monPro)

Exponentation:
Input 128 byte, modulus (128 bytes), private exponent (128 bytes)
Allocate 16*128 table
----------------------------------------- 2048 bytes  sum = 3200

rsa_mul then call rsa_mul_1024 ----------- 128 bytes
             call rsa_mul_512  -------------64 bytes
             call rsa_mul_256  -------------58 bytes

new API:
rsa->data  - input message 		256
rsa->result                		256

load q  into TMP1
calculate data mod q to "result_high"

load p  into TMP1                       128
calculate data mod p to "result_low"

load dP  into "data_low"
calculate n_  "data_high"

call exponentation with: 
     message       exponent    n_         modulus  
    "result_low", "data_low", "data_high", TMP1
// output to "result_low"    
{
allocate 16x 128 bytes                  2048

mul/square message to get temp result    256

in mul/square (1024 bites) max                 300

reduction:
allocate buffer to get result of monPro multiplication
                                         256
mul                                            300                                         
           
}

load q into  TMP1
load dP  into "data_low"
calculate n_  "data_high"

call exponentation with: 
     message       exponent    n_         modulus  
    "result_high", "data_low", "data_high", TMP1
// output to "result_high"    
{



}

subtract "result_low" - "result_high" into TMP1 
to get m12
at this moment "result_low" can be reused

load qInv into "result_low"
multiply "result_low" * m12 into "data"
load "p" into "result_low"

reduce data by "result_low" to get "data_low" = "h"
move "h" into TMP1

load q into "result_low"
multiply q,h into "data"

add "result_high" to "data"

copy "data" to "result"


*******************************************************************/
/// result = 0 if all ok, or error code


uint8_t
rsa_calculate (uint8_t * data, uint8_t * result, uint16_t size)
{

  rsa_num tmp;
#define TMP1 &tmp
#define TMP2 (rsa_num *)(&result[rsa_get_len()])
#define TMP3 (rsa_num *)(&data[rsa_get_len()])

#define M_P (rsa_long_num *)(&result[0])
#define M_Q (rsa_long_num *)(&data[0])
#define DATA M_Q
#define M_MOD_P (rsa_num *)(&result[0])
#define M_MOD_Q (rsa_num *)(&data[0])
#define M1 M_MOD_P
#define M2 M_MOD_Q

// some safety checks
  if (data == result)
    {
      DPRINT ("ERROR, rsa input is pointed to same place as output\n");
      return Re_DATA_RESULT_SAME;
    }
  if (size <= 64)
    rsa_set_len (64);
  if (size > 96)
    rsa_set_len (128);
  else if (size > 64)
    rsa_set_len (96);

// duplicate message
  memcpy (result, data, rsa_get_len () * 2);

// calculate message modulo p
  memset (TMP1, 0, RSA_BYTES);
  if (size != get_rsa_key_part (TMP1, KEY_RSA_p))
    {
      DPRINT ("ERROR, unable to get (p) part of key\n");
      return Re_P_GET_FAIL_1;
    }
  if (!(tmp.value[0] & 1))
    {
      DPRINT ("ERROR, rsa prime (p) not odd (%02x)\n", tmp.value[0]);
      return Re_P_EVEN_1;
    }
  if (rsa_mod (M_P, TMP1))
    {
      DPRINT ("P is zero ? (rsa_mod)\n");
      return Re_P_MOD_1;
    }

// calculate message modulo q
  memset (TMP1, 0, RSA_BYTES);
  if (size != get_rsa_key_part (TMP1, KEY_RSA_q))
    {
      DPRINT ("ERROR, unable to get (q) part of key\n");
      return Re_Q_GET_FAIL_1;
    }
  if (!(tmp.value[0] & 1))
    {
      DPRINT ("ERROR, rsa prime (p) not odd\n");
      return Re_Q_EVEN_1;
    }
  if (rsa_mod (M_Q, TMP1))
    {
      DPRINT ("Q is zero? \n");
      return Re_Q_MOD_1;
    }
// prepare for exponention (calculate n')
  rsa_inv_mod_full (TMP2, TMP1);

  memset (TMP3, 0, RSA_BYTES);
  if (size != get_rsa_key_part (TMP3, KEY_RSA_dQ))
    {
      DPRINT ("ERROR, unable to get (dQ) part of key\n");
      return Re_dQ_1;
    }
  //                        mesage,exponent,modulus,n'
  rsaExpMod_montgomery (M2, TMP3, TMP1, TMP2);

  memset (TMP1, 0, RSA_BYTES);
  if (size != get_rsa_key_part (TMP1, KEY_RSA_p))
    {
      DPRINT ("ERROR, unable to get (p) part of key\n");
      return Re_P_GET_FAIL_2;
    }
  rsa_inv_mod_full (TMP2, TMP1);

  memset (TMP3, 0, RSA_BYTES);
  if (size != get_rsa_key_part (TMP3, KEY_RSA_dP))
    {
      DPRINT ("ERROR, unable to get (dP) part of key\n");
      return Re_dP_1;
    }

  rsaExpMod_montgomery (M1, TMP3, TMP1, TMP2);

  memset (TMP3, 0, RSA_BYTES);
  if (size != get_rsa_key_part (TMP3, KEY_RSA_p))
    {
      DPRINT ("ERROR, unable to get (p) part of key\n");
      return Re_P_GET_FAIL_3;
    }
  {
    uint8_t carry;

    //keep  constant time
    carry = rsa_sub (TMP2, M1, M2);
    rsa_add (TMP3, TMP3, TMP2);
    if (carry)
      memcpy (TMP1, TMP3, RSA_BYTES);
    else
      memcpy (TMP1, TMP2, RSA_BYTES);
  }

// multiply and reduce qInv.(m1 - m2)

  memset (TMP3, 0, RSA_BYTES);
  if (0 == get_rsa_key_part (TMP3, KEY_RSA_qInv))
    {
      DPRINT ("ERROR, unable to get (qInv) part of key\n");
      return Re_qInv_GET_FAIL_1;
    }
  rsa_mul (M_P, TMP3, TMP1);

  memset (TMP3, 0, RSA_BYTES);
  if (size != get_rsa_key_part (TMP3, KEY_RSA_p))
    {
      DPRINT ("ERROR, unable to get (p) part of key\n");
      return Re_P_GET_FAIL_4;
    }
  rsa_mod (M_P, TMP3);

  memcpy (TMP3, M1, RSA_BYTES);

  memset (TMP1, 0, RSA_BYTES);
  if (size != get_rsa_key_part (TMP1, KEY_RSA_q))
    {
      DPRINT ("ERROR, unable to get (q) part of key\n");
      return Re_Q_GET_FAIL_2;
    }
  rsa_mul (M_P, TMP3, TMP1);

// prepare zero for propagating carry
  memset (TMP1, 0, RSA_BYTES);
  // calculate final m =  m2 + (h*q)
  tmp.value[0] = rsa_add (M1, M1, M2);

  // propagate carry to upper bits of 'm'
  rsa_add (TMP2, TMP2, TMP1);

#ifdef RSA_DEBUG
  printf ("final result:\n");
  print_rsa_long_num (M_P);
  printf ("\n");
#endif
  return 0;
}
