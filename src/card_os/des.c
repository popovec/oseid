/*
    des.c

    DES cipher implementation

    This is designed to be a part of OsEID (Open source Electronic ID)
    https:/oseid.sourceforge.io

    Copyright (C) 2017-2020 Peter Popovec, popovec.peter@gmail.com

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

    DES cipher implementation
    -------------------------

    Code is designed to be small (for 8 bit microcontrolers), minimal
    RAM usage, minimal FLASH usage (on 8 bit AVR 1296 bytes, speed
    about 177300 instruction for DES encrypt/decrypt, 3DES version 1346
    bytes). Please check des.S AVR implementation of this code.

    Code is modified, does not use standard permutations as described by DES
    original (NIST) description.

    Message expansion (E), Permuted choice 1 (PC-1) and Permuted choice 2
    (PC-2) are merged into one 56 bit long message expansion.  This expanded
    message is directly XORed by plain key.  S-box adresses are selected from
    result of XOR operation by table.  S-boxes are merged to one table (256
    bytes).

    Initial and inverse initial permutation is done by procedures. Key
    expansion is in procedure too. Only permutation (P) is unchanged.

*/
#include <string.h>
#include <stdint.h>
#include "des.h"

// KEY and DATA can be converted to DES format by permutation table or by
// procedures. It depends on architecture, which one is faster.
// Code size will also be affected. Select what is better.

//#define KEY_PERMUTATION
//#define MSG_PERMUTATION
#define DES3

#ifdef __AVR__
#define GCC_VERSION (__GNUC__ * 10000 \
               + __GNUC_MINOR__ * 100 \
                 + __GNUC_PATCHLEVEL__)

#if GCC_VERSION < 40700
#error Your GCC is too old
#endif
//Linker is responsible to link ASM version if exists
//#warning Do not use this code, use ASM version
#define TAB_TYPE const __flash uint8_t
#ifdef KEY_PERMUTATION
#warning Please undefine KEY_PERMUTATION, code is smaller
#endif
#ifdef MSG_PERMUTATION
#warning Please undefine MSG_PERMUTATION, code is smaller
#endif
#else
#define TAB_TYPE  uint8_t
#endif


/* *INDENT-OFF* */
// not used key bits marked by /**/
static TAB_TYPE message_perm[] = {	//
  5,      0,     0,/**/ 0,     9, 15,  0,/**/ 7,
  12,     2,    24,     8,    14,  6, 15,     0,/**/
  11,    11,     1,     3,    13,  4, 23,     4,

  3, 10, 12,     0,/**/       29, 19,  0,/**/ 27,

  23,    18,    26,    31,    31, 20, 28,     17,
  16,     0,/**/27,     8,    19, 30,  0,/**/ 21,
  25,     0,/**/28,    16,     7, 22, 20,     24
};				//


static TAB_TYPE S_box_address_perm[] = {
  0, 0, 23,  0, 13,  7, 19, 10,
  0, 0,  3, 18,  9, 24, 14, 21,
  0, 0, 26, 20, 12,  5, 16,  1,
  0, 0, 11,  4, 25, 17, 22,  8,

  0, 0, 37, 47, 53, 32, 29, 43,
  0, 0, 51, 39, 33, 44, 36, 54,
  0, 0, 50, 28, 45, 35, 31, 40,
  0, 0, 55, 48, 34, 42, 52, 38,
};

#ifdef KEY_PERMUTATION
static TAB_TYPE initial_key_permutation[] = {
  5, 13, 21, 29, 37, 45, 53, 61,
  6, 14, 22, 30, 38, 46, 54, 62,
  7, 15, 23, 31, 39, 47, 55, 63,

  36, 44, 52, 60, 4, 12, 20, 28,

  3, 11, 19, 27, 35, 43, 51, 59,
  2, 10, 18, 26, 34, 42, 50, 58,
  1,  9, 17, 25, 33, 41, 49, 57,
};
#endif
#ifdef MSG_PERMUTATION
static TAB_TYPE initial_message_permutation[] = {
  6, 14, 22, 30, 38, 46, 54, 62,
  4, 12, 20, 28, 36, 44, 52, 60,
  2, 10, 18, 26, 34, 42, 50, 58,
  0,  8, 16, 24, 32, 40, 48, 56,
  7, 15, 23, 31, 39, 47, 55, 63,
  5, 13, 21, 29, 37, 45, 53, 61,
  3, 11, 19, 27, 35, 43, 51, 59,
  1,  9, 17, 25, 33, 41, 49, 57,
};

static TAB_TYPE final_message_permutation[] = {
  56, 24, 48, 16, 40,  8, 32, 0,
  57, 25, 49, 17, 41,  9, 33, 1,
  58, 26, 50, 18, 42, 10, 34, 2,
  59, 27, 51, 19, 43, 11, 35, 3,
  60, 28, 52, 20, 44, 12, 36, 4,
  61, 29, 53, 21, 45, 13, 37, 5,
  62, 30, 54, 22, 46, 14, 38, 6,
  63, 31, 55, 23, 47, 15, 39, 7,
};
#endif
static TAB_TYPE S_box[] = {		//
  0xef, 0xa7, 0x2c, 0x4d, 0x41, 0x0d, 0xc1, 0xb2,
  0xd8, 0x9e, 0x4a, 0x28, 0x1e, 0xe3, 0x1f, 0xe4,
  0x26, 0x60, 0x79, 0xf6, 0xfb, 0x36, 0xa2, 0x0f,
  0xb3, 0xf9, 0xb6, 0x8b, 0x84, 0x5a, 0x68, 0xd1,

  0x39, 0x11, 0x80, 0x3a, 0xa7, 0xd2, 0x5d, 0xc9,
  0x62, 0xc8, 0x33, 0x93, 0xcd, 0x75, 0xf4, 0x7e,
  0x5c, 0xbb, 0xde, 0x55, 0x90, 0x4c, 0x07, 0xa0,
  0x05, 0x24, 0xe5, 0x6c, 0x7a, 0x8f, 0x9b, 0x17,

  0x03, 0xdd, 0xea, 0xd1, 0xfd, 0x78, 0xbf, 0x0f,
  0x74, 0x0b, 0x24, 0xbd, 0x47, 0x95, 0xc2, 0x78,
  0xef, 0x36, 0x47, 0x4a, 0x22, 0x4f, 0x7c, 0x93,
  0xd8, 0x60, 0xd9, 0x17, 0x1e, 0xa3, 0x15, 0xa4,

  0xac, 0x24, 0x56, 0xec, 0x60, 0x87, 0x01, 0x35,
  0xc1, 0x52, 0xfd, 0x56, 0xba, 0xec, 0xae, 0xcb,
  0x96, 0xc1, 0x30, 0x20, 0x59, 0xba, 0x9b, 0xfe,
  0x3b, 0xfe, 0x83, 0x89, 0x85, 0x19, 0x68, 0x62,

  0x40, 0xda, 0x49, 0x17, 0x1e, 0x66, 0x2e, 0x4b,
  0xe7, 0x49, 0x1f, 0xb4, 0x8b, 0x90, 0xb5, 0xd1,
  0xda, 0x8c, 0xa2, 0xc9, 0x64, 0xfb, 0xd8, 0x3c,
  0x2d, 0x37, 0x7c, 0x7e, 0xb1, 0x0d, 0x83, 0xe2,

  0xf5, 0xbf, 0xf7, 0xa0, 0xc8, 0x11, 0x90, 0xf6,
  0x9c, 0x23, 0xc4, 0x6a, 0x76, 0xce, 0x5a, 0x8d,
  0x39, 0x55, 0x61, 0x0f, 0xa3, 0xa2, 0x3d, 0x53,
  0x52, 0xe8, 0x0b, 0x95, 0x0f, 0x74, 0xe6, 0x28,

  0xfd, 0x13, 0xb4, 0x62, 0xc8, 0xaf, 0x83, 0xb1,
  0x8a, 0xd0, 0xc2, 0xde, 0x21, 0x06, 0x7c, 0x87,
  0x43, 0x6a, 0x19, 0x14, 0x9f, 0x91, 0xe5, 0x4a,
  0x14, 0x8d, 0x2f, 0xa8, 0x72, 0x78, 0xda, 0x7d,

  0x5b, 0x49, 0x6b, 0x9f, 0xb6, 0xf4, 0xfe, 0x5c,
  0x37, 0xe5, 0x01, 0x09, 0xec, 0x3b, 0x97, 0xf0,
  0xa0, 0xbc, 0xa6, 0xe3, 0x05, 0x57, 0x40, 0x25,
  0x6e, 0x22, 0x58, 0x36, 0xd9, 0xce, 0x3d, 0xcb,
};
static TAB_TYPE right_sub_message_permutation[] = {	//
  23, 28, 12, 27, 19, 20,  1,  8,
  14, 25, 22,  3, 30, 17,  9,  7,
  15,  5, 29, 24, 10, 16,  0,  6,
  31,  4, 13, 18,  2, 26, 11, 21,
};
/* *INDENT-ON* */

// this is very simple implementation not usable in production code, use for test only
// or rewrite for your architecture in ASM!
// #warning Do not use this rotations in production code, write rotations code for your arch
// for avr-gcc is better if this function is non static
void
rotate_key_l (uint8_t * key)
{
  uint8_t carry, tmp;
  uint8_t i;
  carry = 0;

  for (i = 0; i < 7; i++)
    {
      tmp = key[i];
      key[i] = (tmp << 1) | carry;
      carry = tmp >> 7;
    }
  tmp = key[3];
  key[0] |= (tmp & 0x10) >> 4;
  key[3] = (tmp & 0xef) | carry << 4;
}

static void
rotate_key_r (uint8_t * key)
{
  uint8_t carry, tmp;
  int8_t i;
  carry = 0;

  for (i = 6; i >= 0; i--)
    {
      tmp = key[i];
      key[i] = (tmp >> 1) | carry;
      carry = tmp << 7;
    }
  tmp = key[3];
  key[6] |= (tmp & 8) << 4;
  key[3] = (tmp & 0xf7) | (carry >> 4);
}

static uint8_t
permute1 (TAB_TYPE ** table, uint8_t * from)
{
  uint8_t i;
  uint8_t shift_size;
  uint8_t byte;
  uint8_t to = 0;

  for (i = 0; i < 8; i++)
    {
      shift_size = **table;
      (*table)++;
      byte = from[(shift_size) >> 3];
      byte >>= ((shift_size) & 7);
      byte &= 1;
      to |= byte << (i & 7);
    }
  return to;
}


static void
permute (uint8_t count, TAB_TYPE * table, uint8_t * from, uint8_t * to)
{
  while (count--)
    *(to++) = permute1 (&table, from);
}

#ifndef KEY_PERMUTATION
static void
des_key_perm (uint8_t * from, uint8_t * to)
{
  uint8_t i, j;
  uint8_t tmp, tmp0 = 0;

  for (j = 0; j < 7; j++)
    {
      for (i = 0; i < 8; i++)
	{
	  tmp = *(from);

	  tmp0 >>= 1;

	  if (tmp & 0x80)
	    tmp0 |= 0x80;
	  tmp <<= 1;

	  *(from) = tmp;
	  from++;
	}
      from -= 8;

      to[j] = tmp0;
    }

  i = to[0];
  to[0] = to[2];
  to[2] = i;
  // swap ..
  to[3] = to[3] >> 4 | to[3] << 4;
}
#endif
#ifndef MSG_PERMUTATION
static void
des_iip (uint8_t * from, uint8_t * to)
//  final_message_permutation (inverse initial permutation)
{
  uint8_t i;
  uint8_t mask = 1;
  uint8_t tmp = 0;
  do
    {
      for (i = 0; i < 4; i++)
	{
	  tmp <<= 2;
	  if (*(from + 4) & mask)
	    tmp |= 1;
	  if (*(from++) & mask)
	    tmp |= 2;
	}
      mask <<= 1;
      *to++ = tmp;
      from -= 4;
    }
  while (mask);
}

static void
des_ip (uint8_t * from, uint8_t * to)	//  initial permutation
{
  uint8_t i, j;
  uint8_t tmp, tmp0 = 0, tmp1 = 0;

  for (j = 0; j < 4; j++)
    {
      for (i = 0; i < 8; i++)
	{
	  tmp = *(from + 7);

	  // in ASM rol, rol ... no cond..
	  tmp1 <<= 1;
	  if (tmp & 0x80)
	    tmp1 |= 1;

	  tmp <<= 1;
	  tmp0 <<= 1;
	  if (tmp & 0x80)
	    tmp0 |= 1;

	  tmp <<= 1;
	  *(from + 7) = tmp;
	  from--;
	}
      from += 8;

      *(to + 4) = tmp1;
      *(to) = tmp0;
      to++;
    }
}
#endif

void __attribute__ ((weak))
des_run (uint8_t * data, uint8_t * main_key, uint8_t mode)
{
  uint16_t ss;
  uint8_t i, k;
  uint8_t L[8];
#define R (L+4)
  uint8_t key[7];
  uint8_t tmp_buffer[8];	// warning, 8 bytes, not 7!
  uint8_t s_addr[8];

#ifdef DES3
  if (mode > 12)
    main_key += 16;

des3_run:
#endif

#ifdef MSG_PERMUTATION
  permute (8, initial_message_permutation, data, L);
#else
  des_ip (data, L);
#endif

#ifdef KEY_PERMUTATION
  permute (7, initial_key_permutation, main_key, key);
#else
  memcpy (tmp_buffer, main_key, 8);
  des_key_perm (tmp_buffer, key);
#endif

  if (mode & 2)
    rotate_key_l (key);

  ss = 0x7efc;			// shift_size

  for (k = 0; k < 16; k++)
    {

      i = ss & 1;
      do
	{
	  if (mode & 2)
	    rotate_key_r (key);
	  else
	    rotate_key_l (key);
	}
      while (i--);
      ss >>= 1;

// message is expanded to 64 bits to match bits in part KC,KD
      permute (7, message_perm, R, tmp_buffer);

// XOR key and expanded message
      for (i = 0; i < 7; i++)
	tmp_buffer[i] ^= key[i];

// calculate S-box addresses
      permute (8, S_box_address_perm, tmp_buffer, s_addr);

      for (i = 0; i < 8; i++)
	s_addr[i] &= 0xfc;

// load s-box
      tmp_buffer[0] = S_box[s_addr[0]] & 0xf0;
      tmp_buffer[0] |= S_box[s_addr[1]] & 0xf;
      tmp_buffer[1] = S_box[1 + s_addr[2]] & 0xf0;
      tmp_buffer[1] |= S_box[1 + s_addr[3]] & 0xf;
      tmp_buffer[2] = S_box[2 + s_addr[4]] & 0xf0;
      tmp_buffer[2] |= S_box[2 + s_addr[5]] & 0xf;
      tmp_buffer[3] = S_box[3 + s_addr[6]] & 0xf0;
      tmp_buffer[3] |= S_box[3 + s_addr[7]] & 0xf;

      memcpy (tmp_buffer + 4, R, 4);
      permute (4, right_sub_message_permutation, tmp_buffer, R);

      for (i = 0; i < 4; i++)
	R[i] ^= L[i];
      memcpy (L, tmp_buffer + 4, 4);
    }

#ifdef MSG_PERMUTATION
  permute (8, final_message_permutation, L, data);
#else
  des_iip (L, data);
#endif

#ifdef DES3
  main_key += 8;
  if ((mode & 1))
    main_key -= 16;
  mode -= 6;
  if (mode < 15)
    goto des3_run;
#endif
}

#if ENABLE_DES56
void __attribute__ ((weak)) des_56to64 (uint8_t * key)
{
  uint8_t k[8];

  k[0] = key[0] & 0xfe;
  k[1] = ((key[0] << 8 | key[1]) >> 1) & 0xfe;
  k[2] = ((key[1] << 8 | key[2]) >> 2) & 0xfe;
  k[3] = ((key[2] << 8 | key[3]) >> 3) & 0xfe;
  k[4] = ((key[3] << 8 | key[4]) >> 4) & 0xfe;
  k[5] = ((key[4] << 8 | key[5]) >> 5) & 0xfe;
  k[6] = ((key[5] << 8 | key[6]) >> 6) & 0xfe;
  k[7] = ((key[6] << 8 | key[7]) >> 7) & 0xfe;

  memcpy (key, k, 8);
}
#endif