/*
    key.h

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

    key file constants definitions
*/

// types of KEY for fs_read_key/fs_write_key
// (used low 5 bites, in upper bits reserved for flags)

#define KEY_OID		1
//EC key parts
#define KEY_EC_PRIVATE	2
#define KEY_EC_PUBLIC	3

// RSA key parts
// public exponent
#define KEY_RSA_EXP_PUB	0x81

// CRT components
#define KEY_RSA_p	0x83
#define KEY_RSA_q	0x84
#ifdef USE_P_Q_INV
// inverse of p and q
#define KEY_RSA_p_	0xb3
#define KEY_RSA_q_	0xb4
#endif
#define KEY_RSA_dP	0x85
#define KEY_RSA_dQ	0x86
#define KEY_RSA_qInv	0x87
// modulus (for get data fcion.. not for CRT)
#define KEY_RSA_MOD	0x80
// parts for 2048 key
#define KEY_RSA_MOD_p1	0x88
#define KEY_RSA_MOD_p2	0x89

// not CRT parts private exponent full
#define KEY_RSA_EXP	0x82
// parts for 2048 key
#define KEY_RSA_EXP_p1	0x8a
#define KEY_RSA_EXP_p2	0x8b


//AES, DES - not used, 0xa0 comes from APDU directly
#define KEY_AES_DES  0xa0

// mask for key "generated"
#define KEY_GENERATE	0x40

#define KEY_FREE_SPACE 0xff

#define RSA_KEY_EF	0x11
#define EC1_KEY_EF	0x22
#define EC2_KEY_EF	0x23
#define DES_KEY_EF	0x19
#define AES_KEY_EF	0x29


uint8_t get_rsa_key_part (void *here, uint8_t id);
