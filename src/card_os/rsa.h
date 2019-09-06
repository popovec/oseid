/*
    rsa.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015,2017-2018 Peter Popovec, popovec.peter@gmail.com

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

    RSA algo header file

*/

// RSA_BYTES - size of variable for RSA calculation.
//
// 128 bytes for 2048 RSA modulus (128*8=1024 bits, this is enough for CRT algo for 2048 RSA key)
// 96 bytes for RSA 1536
// 64 bytes for RSA 1024

#ifndef RSA_BYTES
#error RSA_BYTES undefined
#endif

#if RSA_BYTES != 64 && RSA_BYTES != 96 && RSA_BYTES != 128
#error only fixed size RSA_BYTES are supported (64,96,128)
#endif
#ifndef __RSA_H__
#define __RSA_H__

#ifndef __ASSEMBLER__
typedef struct rsa_num
{
  uint8_t value[RSA_BYTES];	//128bytes for 2048 RSA modulus + reserve for carry
} rsa_num;

typedef struct rsa_half_num
{
  uint8_t value[RSA_BYTES/2];
} rsa_half_num;

// allow use rsa_long_num as two rsa_num
typedef struct rsa_long_num
{
  union
  {
    uint8_t value[RSA_BYTES * 2];	//for multiplication result ..
    struct
    {
      rsa_num L;
      rsa_num H;
    };
  };
} rsa_long_num;

typedef struct rsa_exp_num
{
  union
  {
    uint8_t value[RSA_BYTES + 8];	// always allow 8 bytes! big number arithmetic operates with number length in 64 bit steps
    rsa_num n;
  };
} rsa_exp_num;

// structure is reused for intermediate results
// in Chinese remainder algorithms
/*
struct rsa
{
  rsa_num dP;            // m1 here .. from c^dP mod p
  rsa_num dQ;            // m2 here .. from c^dQ mod q
  rsa_num p;
  rsa_num q;
  rsa_num qInv;          // h here .. from qInv.(m1 - m2) mod p
  // pointers for input and output, must address minimal 2*RSA_BYTES memory!
  // WARN, must point different places!
  rsa_long_num *data;	 // message/cyphertext
  rsa_long_num *result;	 // result after sign/decrypt
  uint8_t bytes;	 // size of rsa_num in bytes
};
*/
// 0 all ok, 1 error

// this struct is used for RSA key generate function
struct rsa_crt_key
{
  union
  {
    rsa_long_num t[2];
    struct
    {
      rsa_num dP;
      rsa_num dQ;
      rsa_num qInv;
      rsa_num d;		// public exponent
    };
  };
};



uint8_t rsa_calculate (uint8_t * data, uint8_t * result, uint16_t size);
uint8_t rsa_keygen (uint8_t * message, uint8_t * r, struct rsa_crt_key *key, uint16_t size);
uint8_t rsa_modulus(void *m);

#ifdef USE_P_Q_INV
void rsa_inv_mod_N (rsa_half_num * n_, rsa_num * modulus);
void rsa_mod (rsa_long_num * result, rsa_num * mod);
void barrett_constant(rsa_num * Bc, rsa_num * modulus);
#endif
#endif

// do not use different error codes for normal code
// this save about 50 bytes of flash in AVR
#if 0
// error codes (for debug)
#define Re_DATA_RESULT_SAME 	230
#define Re_P_GET_FAIL_1		231
#define Re_P_EVEN_1		232
#define Re_P_MOD_1		233
#define Re_Q_GET_FAIL_1         234
#define Re_Q_EVEN_1             235
#define Re_Q_MOD_1		236
#define Re_dP_1			237
#define Re_dQ_1			238
#define Re_P_GET_FAIL_2		239
#define Re_P_GET_FAIL_3		240
#define Re_P_GET_FAIL_4		241
#define Re_qInv_GET_FAIL_1	242
#define Re_Q_GET_FAIL_2		243
#define Re_R_Single_Error	244
#define Re_Q_Single_Error	245
#else
// error codes (normal)
#define Re_DATA_RESULT_SAME 	1
#define Re_P_GET_FAIL_1		1
#define Re_P_EVEN_1		1
#define Re_P_MOD_1		1
#define Re_Q_GET_FAIL_1         1
#define Re_Q_EVEN_1             1
#define Re_Q_MOD_1		1
#define Re_dP_1			1
#define Re_dQ_1			1
#define Re_P_GET_FAIL_2		1
#define Re_P_GET_FAIL_3		1
#define Re_P_GET_FAIL_4		1
#define Re_qInv_GET_FAIL_1	1
#define Re_Q_GET_FAIL_2		1
#define Re_R_Single_Error	1
#define Re_Q_Single_Error	1
#endif

#endif

