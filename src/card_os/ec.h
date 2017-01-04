/*
    ec.c

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


*/
#ifndef CS_EC_H
#define CS_EC_H
#define MP_BYTES 48

#ifndef __ASSEMBLER__

typedef struct
{
  uint8_t value[MP_BYTES];
} bignum_t;

typedef struct
{
  bignum_t X;
  bignum_t Y;
  bignum_t Z;
} ec_point_t;

typedef struct
{
  bignum_t R;
  bignum_t S;

  bignum_t *message;		//message to sign (padded to 32 bytes)

} ecdsa_sig_t;

// curve types, bit 7 and 6 used to encode special A value
// (this is used to select optimized algo for calculation)
// for A=0  set bit 7
// for A=-3 set bit 6

#define C_PRIME192V1 (1 | 0x40)
#define C_PRIME256V1 (2 | 0x40)
#define C_secp384r1  (3 | 0x40)
#define C_secp256k1  (4 | 0x80)

struct ec_param
{
  bignum_t prime;
  bignum_t order;
  bignum_t Gx;
  bignum_t Gy;
#ifndef NIST_ONLY
  bignum_t a;			// not needed, NIST curves A=-3 ..
#endif
  bignum_t private_key;
  bignum_t *r;
  bignum_t *s;

  uint8_t curve_type;		// curve type (to select beeter algo and fast reduction algo)
  uint8_t mp_size;		// arithmetics size (max 48 bytes)
};


#endif

uint8_t ec_key_gener (bignum_t * k, ec_point_t * pub_key,
		      struct ec_param *ec);
uint8_t ecdsa_sign (ecdsa_sig_t * ecsig, struct ec_param *ec);
uint8_t ec_check_key (bignum_t * k, ec_point_t * pub_key,
		      struct ec_param *ec);
#endif
