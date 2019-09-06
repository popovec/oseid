/*
    aes.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2017-2019 Peter Popovec, popovec.peter@gmail.com

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

    AES(128,192,256) enc/dec routines (designed for 8 bit CPU)

This version of AES is designed for minimal flash space.  The design of the
algorithm does not make the speed as important for this code. Key is
expanded in RAM, SBOX and INV SBOX is calculated in RAM.

Please check AVR ASM version  - code size below 600 bytes

*/
#include <stdint.h>
#include <string.h>
#include "aes.h"

#define KEY (ta)
#define SBOX (ta+256)
#define IBOX (ta+256+256)
#define ALOG (ta)
#define LOG (ta+256)

/***************************************************
base fcions for "state" manipulation
*/
static uint8_t
rj_xtime (uint8_t x)
{
  uint8_t c = 0;

  if (x & 0x80)
    c = 0x1b;

  return (x << 1) ^ c;
}

static void
  __attribute__ ((noinline)) aes_subBytes (uint8_t * state, uint8_t * ta)
{
  uint8_t i;

  for (i = 0; i < 16; i++)
    state[i] = SBOX[state[i]];
}

static void
  __attribute__ ((noinline)) aes_subBytes_inv (uint8_t * state, uint8_t * ta)
{
  uint8_t i;

  for (i = 0; i < 16; i++)
    state[i] = IBOX[state[i]];
}

static void __attribute__ ((noinline)) aes_shiftRowsEnd (uint8_t * state)
{
  uint8_t tmp;

  tmp = state[2];
  state[2] = state[10];
  state[10] = tmp;

  tmp = state[6];
  state[6] = state[14];
  state[14] = tmp;
}

static void __attribute__ ((noinline)) aes_shiftRows (uint8_t * state)
{
  uint8_t tmp;

  tmp = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = tmp;

  tmp = state[3];
  state[3] = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = tmp;

  aes_shiftRowsEnd (state);
}

static void __attribute__ ((noinline)) aes_shiftRows_inv (uint8_t * state)
{
  uint8_t tmp;

  tmp = state[1];
  state[1] = state[13];
  state[13] = state[9];
  state[9] = state[5];
  state[5] = tmp;

  tmp = state[3];
  state[3] = state[7];
  state[7] = state[11];
  state[11] = state[15];
  state[15] = tmp;

  aes_shiftRowsEnd (state);
}

static void __attribute__ ((noinline)) aes_mixColumns (uint8_t * state)
{
  uint8_t i, a, b, c, d, e;

  for (i = 0; i < 16; i += 4)
    {
      a = state[i + 0];
      b = state[i + 1];
      c = state[i + 2];
      d = state[i + 3];
      e = a ^ b ^ c ^ d;
      state[i + 0] ^= e ^ rj_xtime (a ^ b);
      state[i + 1] ^= e ^ rj_xtime (b ^ c);
      state[i + 2] ^= e ^ rj_xtime (c ^ d);
      state[i + 3] ^= e ^ rj_xtime (d ^ a);
    }
}

static void __attribute__ ((noinline)) aes_mixColumns_inv (uint8_t * state)
{
  uint8_t i, a, b, c, d, e, x, y, z;

  for (i = 0; i < 16; i += 4)
    {
      a = state[i + 0];
      b = state[i + 1];
      c = state[i + 2];
      d = state[i + 3];
      e = a ^ b ^ c ^ d;
      z = rj_xtime (e);
      x = e ^ rj_xtime (rj_xtime (z ^ a ^ c));
      y = e ^ rj_xtime (rj_xtime (z ^ b ^ d));
      state[i + 0] ^= x ^ rj_xtime (a ^ b);
      state[i + 1] ^= y ^ rj_xtime (b ^ c);
      state[i + 2] ^= x ^ rj_xtime (c ^ d);
      state[i + 3] ^= y ^ rj_xtime (d ^ a);
    }
}

static void
addEKey (uint8_t * state, uint8_t * key)
{
  uint8_t i;
  for (i = 0; i < 16; i++)
    state[i] ^= key[i];
}

/***************************************************
  Key expansion to RAM, SBOX and SBOX inv calculation
*/
static void
ek (uint8_t * key, uint8_t keysize, uint8_t * ta)
{
  uint8_t rc = 1, j;
  uint8_t *k = KEY;
  uint8_t i, l;

  memcpy (k, key, keysize);
  // 14 rounds = 224 bytes - 32 = 192 bytes

  for (j = 0; j < 193; j += keysize)
    {
      memcpy (k + keysize, k, keysize);
      k += keysize;
      l = keysize - 4;
      // rotate 8 bit ..
      k[0] ^= SBOX[k[l + 1]] ^ rc;
      k[1] ^= SBOX[k[l + 2]];
      k[2] ^= SBOX[k[l + 3]];
      k[3] ^= SBOX[k[l + 0]];
      l = 13;
      if (keysize == 24)
	l = 21;

      for (i = 0; --l; i++)
	k[i + 4] ^= k[i];

      if (keysize == 32)
	{
	  for (i = 12; i < 28; i++)
	    {
	      if (i < 16)
		l = SBOX[k[i]];
	      else
		l = k[i];
	      k[i + 4] ^= l;
	    }
	}
      rc = rj_xtime (rc);
    }
}

static uint8_t
sbox_helper (uint8_t r)
{
  uint8_t tmp;

  tmp = r;
  tmp = (uint8_t) (tmp << 1) | (tmp >> 7), r ^= tmp;
  tmp = (uint8_t) (tmp << 1) | (tmp >> 7), r ^= tmp;
  tmp = (uint8_t) (tmp << 1) | (tmp >> 7), r ^= tmp;
  tmp = (uint8_t) (tmp << 1) | (tmp >> 7), r ^= tmp;
  return r;
}

static uint8_t
aes_init (uint8_t * key, uint8_t keysize, uint8_t * ta)
{
  uint8_t i, t, tt;

// calculate ALOG and LOG table
  i = 0;
  t = 1;
  do
    {
      ALOG[i] = t;
      LOG[t] = i;
      tt = t;
      t <<= 1;
      if (0x80 & tt)
	t ^= 0x1b;
      t ^= tt;
      i++;
    }
  while (i != 0);
// calculate gf_mulinv, sbox and inverse sbox
  t = 0;
  do
    {
      t = sbox_helper (t);
      t ^= 0x63;

      IBOX[t] = i;
      SBOX[i++] = t;
      t = LOG[i];
      t ^= 0xff;
      t = ALOG[t];
    }
  while (i != 0);

  ek (key, keysize, ta);

  return (keysize / 4) + 6;
}

/***************************************************
 generic  call
*/
void __attribute__ ((weak))
aes_run (uint8_t * buf, uint8_t * key, uint8_t keysize, uint8_t mode)
{
  uint8_t ta[2400];
  uint8_t rounds;
  uint8_t *kkey = KEY;

  rounds = aes_init (key, keysize, ta);
  if (mode)
    {
      // decrypt
      kkey += rounds * 16;

      addEKey (buf, kkey);
      kkey -= 16;

      aes_shiftRows_inv (buf);
      aes_subBytes_inv (buf, ta);

      for (; --rounds;)
	{
	  addEKey (buf, kkey);
	  kkey -= 16;

	  aes_mixColumns_inv (buf);
	  aes_shiftRows_inv (buf);
	  aes_subBytes_inv (buf, ta);
	}
      addEKey (buf, kkey);
    }
  else
    {
      // encrypt
      addEKey (buf, kkey);
      kkey += 16;

      for (; --rounds;)
	{
	  aes_subBytes (buf, ta);
	  aes_shiftRows (buf);
	  aes_mixColumns (buf);

	  addEKey (buf, kkey);
	  kkey += 16;
	}
      aes_subBytes (buf, ta);
      aes_shiftRows (buf);
      addEKey (buf, kkey);
    }
}
