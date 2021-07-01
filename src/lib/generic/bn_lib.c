/*
    bn_lib.c

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
    
    big number arithmetics 
    
    All functions are "generic", able to run on 8 bit CPU.  It is assumed,
    all these functions are in ASM for target architecture, therefore all
    functions are weak.  Use this code only for debug/test purposes, or if 
    target architecture does not have optimized functions.

    lot of routines use rsa_getlen() to get actual length of big number    
    please  use only 8 bytes steps in bn length (ASM optimized routines uses
    step in length 64 bits)

   please write this code for you platform in ASM/C to prevent side channel 
   attack (timing.. ), this code must run in constant time
    

*/
#include <stdint.h>
#include <string.h>
#include <alloca.h>

#define __BN_LIB_SELF__


#define DEBUG_BN_MATH
#include "debug.h"

//#warning rename to bn_bytes..
uint8_t mod_len __attribute__((section (".noinit")));	// global variable - number of significant bytes for BN operation
uint16_t bn_real_bit_len __attribute__((section (".noinit")));	// global variable - number of bits  for opreation (this number * 8)>=mod_len
uint8_t bn_real_byte_len __attribute__((section (".noinit")));

#include "bn_lib.h"

uint8_t
bn_set_bitlen (uint16_t blen)
{
  uint8_t len = blen / 8;

  bn_real_byte_len = len;
  bn_real_bit_len = blen;

  if (len <= 32)
    len = 32;
  else if (len <= 48)
    len = 48;
  else if (len <= 64)
    len = 64;
  else if (len <= 96)
    len = 96;
  else
    len = 128;

  mod_len = len;
  return len;
}

void
bn_swap (void *a, void *b)
{
  uint8_t i = mod_len;
  uint8_t *a1, *b1;
  uint8_t tmp;
  a1 = (uint8_t *) a;
  b1 = (uint8_t *) b;
  while (i--)
    {
      tmp = *a1;
      *(a1++) = *b1;
      *(b1++) = tmp;
    }
}


uint8_t __attribute__((weak)) bn_is_zero (void *k)
{
  uint8_t j = 0, ret;
  uint8_t len = mod_len;
  uint8_t *val = (uint8_t *) k;

  do
    {
      j |= *val;
      val++;
    }
  while (--len);

  ret = (j == 0);
  return ret;
}

uint8_t __attribute__((weak)) bn_neg (void *a)
{
  uint8_t carry;
  uint16_t pA, Res;
  uint8_t len = mod_len;
  uint8_t i = 0;
  uint8_t *A = (uint8_t *) a;;

  carry = 0;
  do
    {
      pA = A[i];
      Res = 0 - pA - carry;
      A[i] = Res & 255;
      carry = (Res >> 8) & 1;
      i++;
    }
  while (--len);
  return carry;
}



uint8_t
  __attribute__((weak)) bn_add_v (void *r, void *a, uint8_t len,
				  uint8_t carry)
{
  uint8_t *A, *R;
  uint8_t i = 0;
  int16_t pA, pB, Res;

  A = (uint8_t *) a;
  R = (uint8_t *) r;

  carry = carry ? 1 : 0;
  do
    {
      pA = A[i];
      pB = R[i];
      Res = pA + pB + carry;

      R[i] = Res & 255;
      carry = (Res >> 8) & 1;
      i++;
    }
  while (--len);
  return carry;
}

uint8_t __attribute__((weak)) bn_add (void *r, void *a)
{
  return bn_add_v (r, a, mod_len, 0);
}

/////////////////////////////////////////////////////////////////////
uint8_t __attribute__((weak))
bn_sub_v (void *r, void *a, void *b, uint8_t len)
{
  uint8_t *A, *B, *R;
  uint8_t carry;
  uint8_t i = 0;
  int16_t pA, pB, Res;

  A = (uint8_t *) a;
  B = (uint8_t *) b;
  R = (uint8_t *) r;

  carry = 0;
  do
    {
      pA = A[i];
      pB = B[i];
      Res = pA - pB - carry;

      R[i] = Res & 255;
      carry = (Res >> 8) & 1;
      i++;
    }
  while (--len);
  return carry;
}

uint8_t __attribute__((weak)) bn_sub (void *r, void *a, void *b)
{
  return bn_sub_v (r, a, b, mod_len);
}

uint8_t __attribute__((weak)) bn_sub_long (void *r, void *a, void *b)
{
  return bn_sub_v (r, a, b, mod_len * 2);
}

/////////////////////////////////////////////////////////////////////
// return  1  if c >= d
uint8_t __attribute__((weak)) bn_cmpGE (void *c, void *d)
{
  uint8_t *C = (uint8_t *) c;
  uint8_t *D = (uint8_t *) d;
  uint8_t i = mod_len;

  do
    {
      i--;
      if (C[i] > D[i])
	return 1;
      if (C[i] < D[i])
	return 0;
    }
  while (i);
  return 1;
}

/////////////////////////////////////////////////////////////////////
void __attribute__((weak)) bn_sub_mod (void *r, void *a, void *mod)
{
  uint8_t carry;

  carry = bn_sub (r, r, a);
  if (carry)
    bn_add (r, mod);
}

void __attribute__((weak)) bn_add_mod (void *r, void *a, void *mod)
{
  uint8_t carry;

  carry = bn_add (r, a);
  if (carry)
    bn_sub (r, r, mod);
  else if (bn_cmpGE (r, mod))
    bn_sub (r, r, mod);
}

/////////////////////////////////////////////////////////////////////
uint8_t __attribute__((weak)) bn_shift_L_v (void *r, uint8_t len)
{
  uint8_t carry = 0;
  uint16_t Res;
  uint8_t *R = (uint8_t *) r;

  do
    {
      Res = *R << 1;
      Res |= carry;
      carry = (Res >> 8) & 1;
      *R = Res & 255;
      R++;
    }
  while (--len);
  return carry;
}

uint8_t __attribute__((weak)) bn_shiftl (void *r)
{
  return bn_shift_L_v (r, mod_len);
}

//////////////////////////////////////////////////////////////////////////////////
uint8_t
  __attribute__((weak)) bn_shift_R_v_c (void *r, uint8_t len, uint8_t carry)
{
  uint16_t Res;
  uint8_t *R = (uint8_t *) r;
  uint8_t c2;

  carry = carry ? 0x80 : 0;
  R += (uint8_t) (len - 1);
  do
    {
      Res = *R;
      c2 = Res & 1;
      Res = Res >> 1;
      Res |= carry;
      carry = c2 << 7;
      *R = Res;
      R--;
    }
  while (--len);
  return c2;
}

uint8_t __attribute__((weak)) bn_shift_R_v_signed (void *r, uint8_t len)
{
  uint8_t sign;
  uint8_t *tmp = (uint8_t *) r;

  sign = tmp[len - 1] & 0x80;
  return bn_shift_R_v_c (r, len, sign);
}

uint8_t __attribute__((weak)) bn_shift_R_signed (void *r)
{
 return bn_shift_R_v_signed (r, mod_len);
}
uint8_t __attribute__((weak)) bn_shiftr (void *r)
{
  return bn_shift_R_v_c (r, mod_len, 0);
}

uint8_t __attribute__((weak)) bn_shiftr_c (void *r, uint8_t carry)
{
  return bn_shift_R_v_c (r, mod_len, carry);
}

uint8_t __attribute__((weak)) bn_shiftr_long (void *r)
{
  return bn_shift_R_v_c (r, mod_len * 2, 0);
}


/////////////////////////////////////////////////////////////////////
void __attribute__((weak)) bn_mul_v (void *R, void *A, void *B, uint8_t len)
{
  uint8_t i, j, c;
  uint8_t a_;
  uint16_t res;
  uint8_t *r = (uint8_t *) R;
  uint8_t *a = (uint8_t *) A;
  uint8_t *b = (uint8_t *) B;

  memset (r, 0, 2 * len);

  for (i = 0; i < len; i++)
    {
      c = 0;
      a_ = a[i];

      for (j = 0; j < len; j++)
	{
	  res = a_ * b[j];
	  res += r[i + j];
	  res += c;

	  c = res >> 8;
	  r[i + j] = res & 255;
	}
      r[i + len] = c;
    }
}


/////////////////////////////////////////////////////////////////////
#include <alloca.h>

// reduce 'result' by modulus 'mod', assume, modulus hogest bit is sero!
void __attribute__((weak)) bn_mod_half (void *result, void *mod)
{
  uint8_t *tmp;
  uint8_t *helper;
  uint8_t *tmp_result[2];
  uint16_t i;
  uint8_t index;

  tmp = alloca (mod_len * 2);
  helper = alloca (mod_len * 2);


  memset (tmp, 0, mod_len * 2);	// 1+3/4 * mod_len bytes is sufficient
  memcpy (tmp + mod_len / 2, mod, mod_len);
  bn_shift_L_v (tmp, mod_len * 2);	// 1+ 3/4 mod_len bytes is sufficient

  i = 1 + mod_len * 8 / 2;	// half operand + 1 bit

// get pointers for posible results
  tmp_result[0] = result;
  tmp_result[1] = helper;
// first calculate result - tmp, - init index at 0

  index = 0;
  do
    {
      // subtract from result, if this generates carry
      // (result < tmp), switch to unchanged result

      // TODO 1 + 3/4 bytes is enough
      if (!bn_sub_long (tmp_result[(~index) & 1], tmp_result[index & 1], tmp))
	index++;
      bn_shiftr_long (tmp);
    }
  while (i--);

  memcpy (result, tmp_result[index & 1], mod_len);
  return;
}


void __attribute__((weak)) bn_mod (void *result, void *mod)
{
  uint8_t *tmp;
  uint8_t *helper;
  uint8_t *tmp_result[2];

// check below..
#if 0
  rsa_num *n;
  uint8_t len = mod_len * 2 - 1;
#endif
  uint16_t i;
  uint8_t index;

  tmp = alloca (mod_len * 2);
  helper = alloca (mod_len * 2);


  memset (tmp, 0, mod_len);
  memcpy (tmp + mod_len, mod, mod_len);

  i = mod_len * 8;

// this part of code is not needed, modulus higest bit is alwais set
// but this code is not universal. ZERO in modulus is not checked too.
#if 0
#error not used code, if needed, please correct this code
  n = (rsa_num *) ((uint8_t *) & tmp + rsa_get_len ());
  while (!(tmp.value[len] & 0x80))
    {
      bn_shiftl (n);
      i++;
      // test for mod==0 - not perfect, but working ..
      if (i == 0)
	return;
    }
#endif
// get pointers for posible results
  tmp_result[0] = result;
  tmp_result[1] = helper;
// first calculate result - tmp, - init index at 0
  index = 0;

  do
    {
      // subtract from result, if this generates carry
      // (result < tmp), switch to unchanged result
      if (!bn_sub_long (tmp_result[(~index) & 1], tmp_result[index & 1], tmp))
	index++;
      bn_shiftr_long (tmp);

    }
  while (i--);

  memcpy (result, tmp_result[index & 1], mod_len);

  return;
}

/////////////////////////////////////////////////////////////////////
#if 1				// please check code below for odd modulus only

// set r = a^(-1) (mod m) this function can handle odd and even motulus, if
// inversion does not exist return from this fcion is 1 otherwise 0.
//
// Function is based on extended euclidian algo, original NIST algo (seems
// to be this is first published by Knuth) is usable only for odd modulus
// (because eliminates ones in number by division by 2 - right rotation.
// (if modulus is even, there is no way to add modulus to odd number to
// create even number that can be divided without remainder)
//
// This algo eliminates bits by aligning u/v higest bits - similar to binary
// euclidian algo or non restoring division.  Code is designed to be run on
// AVR or other 8 bit CPUs but ASM version is recomended (because code speed
// and size)

uint8_t __attribute__((weak)) bn_abs_sub (void *r, void *a, void *b)
{
#if 0
  if (bn_cmpGE (a, b))
    {
      bn_sub (r, a, b);
      return 0;
    }
  else
    {
      bn_sub (r, b, a);
      return 1;
    }
#else
  if (bn_sub (r, a, b))
    {
      bn_neg (r);
      return 1;
    }
  return 0;
#endif
}

//static uint16_t
uint16_t __attribute__((weak)) bn_count_bits (void *n)
{
  uint8_t val;
  uint8_t byte = mod_len;
  uint8_t *a = (uint8_t *) n;

  uint16_t ret;
  for (;;)
    {
      val = a[--byte];
      if (val)
	break;
      if (byte == 0)
	return 0;
    }

  ret = byte * 8;
  while (val)
    {
      ret++;
      val >>= 1;
    }
  return ret;
}

// 0 - inversion exists
// 1 - no inversion exists
uint8_t __attribute__((weak)) bn_inv_mod (void *result, void *a, void *m)
{
  uint8_t bn_len = mod_len;

  uint8_t *u;
  uint8_t *v;
  uint8_t *r;
  uint8_t *s;
  uint16_t bsize_U, bsize_V, V_off;
  int16_t rot;

  // we need track both signs (U,V) because U sign is used to determine the result sign
  uint8_t sU = 0, sV = 0;

  // one of A or M must be odd (or both)
  if (((*(uint8_t *)a | *(uint8_t*)m) & 1) == 0)
    return 1;

// matrix:
// u,v in range 0 to modulus-1
// r,s in range -(modulus/2) to (modulus/2)

  u = alloca (4 * bn_len);
  memcpy (u, a, bn_len);

  v = (u + bn_len);
  memcpy (v, m, bn_len);

  r = (v + bn_len);
  s = (r + bn_len);

  // clear help variables
  memset (r, 0, 2 * bn_len);

  // init 'r'
  *r = 1;

  // clear result (do not clear result before 'a' is copied to 'u'!)
  // (the result can be in the same memory location as the operand)
  memset (result, 0, bn_len);

  // swap r, s,  and  u, v
  if (bn_cmpGE (u, v))
    {
      uint8_t *tmp;
      tmp = r, r = s, s = tmp;
      tmp = u, u = v, v = tmp;
    }

  V_off = 0;

  bsize_V = bn_count_bits (v);

  // if V is 1 or 0  result is 0 or 1..
  if (bsize_V < 2)
    {
      *((uint8_t *) result) = bsize_V;
      return 0;
    }

  for (;;)
    {
      bsize_U = bn_count_bits (u);

      rot = bsize_U - bsize_V;

      if (rot < 0)
	{
	  bsize_V = bsize_U;
	  if (bsize_V == 0)
	    return 1;		// no inversion
	  if (bsize_V == 1)
	    break;		// inversion found
	  // clear offset of s,v
	  while (V_off--)
	    {
	      bn_shift_R_signed (s);
	      bn_shiftr (v);
	    }
	  // swap u,v, r,s, sU,sV
	  {
	    uint8_t *tmp;
	    tmp = r, r = s, s = tmp;
	    tmp = u, u = v, v = tmp;
	  }
	  {
	    uint8_t tmp;
	    tmp = sU, sU = sV, sV = tmp;
	  }
	  rot = -rot;
	  {
	    V_off = rot;
	    while (rot--)
	      {
		bn_shiftl (s);
		bn_shiftl (v);
	      }
	  }
	}
      else
	{
	  uint16_t tmp = V_off - rot;

	  V_off = rot;
	  while (tmp--)
	    {
	      bn_shift_R_signed (s);
	      bn_shiftr (v);
	    }
	}
      if (sU ^ sV)
	bn_add (r, s);
      else
	bn_sub (r, r, s);

      sU ^= bn_abs_sub (u, u, v);
    }

  // r is in range -(modulus/2) to (modulus/2)
  // use 'U' sign to correct 'R'
  if (sU)
    bn_neg (r);

  memcpy (result, r, bn_len);
  // for negative result do correction
  if (r[bn_len - 1] & 0x80)	// if (r < 0)
    {
      bn_add (result, m);
      return 0;
    }
  // if 'a' was bigger that 'm' we need to correct one more correction
  if (bn_cmpGE (r, m))
    bn_sub (result, result, m);

  return 0;
}
#else
//return true if r is even

static uint8_t
bn_test_even (void *n)
{
  uint8_t *v = (uint8_t *) n;

  return 1 ^ (*v & 1);
}


//return true if k is 1
static uint8_t
bn_is_1 (void *n)
{
  uint8_t *k = (uint8_t *) n;
  uint8_t j, ret, len = mod_len - 1;

  j = *k ^ 1;
  while (len--)
    {
      k++;
      j |= *k;
    }
  ret = (j == 0);
  return ret;
}

//set r = c^(-1) (mod p)

// based on NIST, working only for odd modulus (usable in ECC code for prime
// or order as "p").  Even modulus is not checked here, code can run into
// never ending loop. This code fail for not coprime numbers too.
#error Do not use this code, this code fail for RSA key calculation (because even modulus)

uint8_t __attribute__((weak)) bn_inv_mod (void *r, void *c, void *p)
{
  uint8_t carry;
  uint8_t *u, *v, *x1, *x2;

  u = alloca (mod_len);
  v = alloca (mod_len);
  x1 = alloca (mod_len);
  x2 = alloca (mod_len);

  memcpy (u, c, mod_len);
  memcpy (v, p, mod_len);
  memset (x2, 0, mod_len);
  memset (x1, 0, mod_len);
  *x1 = 1;

  for (;;)
    {
      if (bn_is_1 (u))
	{
	  memcpy (r, x1, mod_len);
	  return 0;
	}
      if (bn_is_1 (v))
	{
	  memcpy (r, x2, mod_len);
	  return 0;
	}


      while (bn_test_even (u))
	{
	  bn_shiftr (u);	// u = u / 2
	  if (bn_test_even (x1))
	    {
	      bn_shiftr (x1);	// x1 = x1 / 2
	    }
	  else
	    {
	      // x1 = (x1 + p)/2 {do not reduce sum modulo p}
	      carry = bn_add (x1, p);
	      bn_shiftr_c (x1, carry);
	    }
	}

      while (bn_test_even (v))
	{
	  bn_shiftr (v);	// v = v/2
	  if (bn_test_even (x2))
	    {
	      bn_shiftr (x2);	// x1 = x2 / 2
	    }
	  else
	    {
	      // x2 = (x2 + p)/2 {do not reduce sum modulo p}
	      carry = bn_add (x2, p);
	      bn_shiftr_c (x2, carry);
	    }
	}

      if (bn_cmpGE (u, v) > 0)
	{
	  bn_sub_mod (u, v, p);
	  bn_sub_mod (x1, x2, p);
	}
      else
	{
	  bn_sub_mod (v, u, p);
	  bn_sub_mod (x2, x1, p);
	}
    }
}
#endif
