/*
    rsa.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015 Peter Popovec, popovec.peter@gmail.com

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

    montgomery modular arithmetics header file

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

#ifndef __ASSEMBLER__
typedef struct rsa_num
{
  uint8_t value[RSA_BYTES]; //128bytes for 2048 RSA modulus + reserve for carry
} rsa_num;

typedef struct rsa_long_num
{
  uint8_t value[RSA_BYTES * 2];     //for multiplication result ..
} rsa_long_num;


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
uint8_t rsa_calculate (uint8_t * data, uint8_t * result, uint16_t size);
#endif

// error codes
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
