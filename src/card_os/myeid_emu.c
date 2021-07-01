/*
    myeid_emu.c

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
*/
/* 1.1.2021 coding style is changed to "linux" all new code is indented by
indent -linux -l100
*/
/** @file
 *  @brief Emulation of MyEID functions
 */
/*
 Function are based on documentation from:
 https://webservices.aventra.fi/wordpress/wp-content/downloads/MyEID_PKI_JavaCard_Applet_Reference_Manual_2-1-4.pdf
 https://webservices.aventra.fi/wordpress/wp-content/downloads/MyEID%20PKI%20JavaCard%20Applet%20Reference%20Manual%202-3-0.pdf

 Some functions are derived from opensc sources https://github.com/OpenSC/OpenSC - card-myeid.c

 Code is designed to be small (to fit into AVR flash).

 It is assumed, all functions can access 5 bytes of message in message buffer.
 Caller is responsible to fill this data in message correctly.
*/

#define DEBUG_MyEID_EMU
#include "debug.h"

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <alloca.h>
#include "card_io.h"
#include "ec.h"
#include "iso7816.h"
#include "myeid_emu.h"
#include "fs.h"
#include "key.h"
#include "rsa.h"
#include "des.h"
#include "aes.h"
#include "constants.h"
#include "bn_lib.h"

#define M_CLASS message[0]
#define M_CMD message[1]
#define M_P1 message[2]
#define M_P2 message[3]
#define M_P3 message[4]

#if RSA_BYTES > 128
#error RSA_BYTES over 128, for atmega only 256 byte buffers are reserved!
#endif

#ifndef I_VECTOR_MAX
#define I_VECTOR_MAX 16
#endif
static uint8_t sec_env_reference_algo __attribute__((section(".noinit")));
static uint16_t key_file_uuid __attribute__((section(".noinit")));
static uint16_t target_file_uuid __attribute__((section(".noinit")));
static uint8_t i_vector_tmp[I_VECTOR_MAX]
    __attribute__((section(".noinit")));
static uint8_t i_vector[I_VECTOR_MAX] __attribute__((section(".noinit")));
static uint8_t i_vector_len __attribute__((section(".noinit")));

// bits 0,1 = template in environment (depend on ISO7816-8, manage secutiry env, P2 (P2>>1)&3
#define SENV_TEMPL_CT 0
#define SENV_TEMPL_AT 2
#define SENV_TEMPL_DST 3
#define SENV_TEMPL_MASK 3

// mask for encipher operation
#define SENV_ENCIPHER    0x04
// mask for valid file reference
#define SENV_FILE_REF    0x10
// mask for valir reference algo
#define SENV_REF_ALGO    0x20
// mask for valid init vector
#define SENV_INIT_VECTOR 0x40
// mask for valid  target ID
#define SENV_TARGET_ID 	 0x80

uint8_t sec_env_valid __attribute__((section(".noinit")));

////////////////////////////////////////////////////////////////////////////////////
//  base helpers

static void reverse_string(uint8_t * p, uint16_t len)
{
	uint8_t *t, tmp;

	t = p + len - 1;
	len /= 2;
	while (len--) {
		tmp = *p;
		*p = *t;
		*t = tmp;
		t--;
		p++;
	}
}

static void reverse_copy(uint8_t * d, uint8_t * s, uint16_t len)
{
	s += len - 1;
	while (len--) {
		*d = *s;
		s--;
		d++;
	}
}

////////////////////////////////////////////////////////////////////////////////////
//  base helpers for key manipulation/checks
//

// 0xffff = error
static uint16_t get_key_file_uuid(uint16_t id)
{
	uint16_t old_uuid;
	uint16_t uuid;

	old_uuid = fs_get_selected_uuid();
	if (S0x6100 != fs_select_ef(id, NULL))
		return 0xffff;
	uuid = fs_get_selected_uuid();
	fs_select_uuid(old_uuid, NULL);
	return uuid;
}

static uint8_t check_ec_key_file(uint16_t size, uint8_t type)
{
#ifndef NIST_ONLY
	if (type == EC2_KEY_EF)
		if (size == 256)
			return 0;
#endif
	if (type == EC1_KEY_EF) {
		if (size == 192)
			return 0;
#if MP_BYTES >= 32
		if (size == 256)
			return 0;
#endif
#if MP_BYTES >=48
		if (size == 384)
			return 0;
#endif
#if MP_BYTES >=66
		if (size == 521)
			return 0;
#endif
	}
	return 1;
}

#ifdef USE_P_Q_INV
static uint8_t key_preproces(uint8_t * kpart, uint8_t m_size)
{
	struct {
		uint8_t type;
		uint8_t size;
		union {
			rsa_num t1;
			rsa_half_num hn;
		};
	} tmp;

	uint16_t ret;

	ret = fs_key_write_part(kpart);
	if (ret != S_RET_OK)
		return ret;

	DPRINT("calculating inverse of p/q size=%d\n", m_size);

	m_size = bn_set_bitlen(m_size * 8);
	tmp.type = 0x20 | kpart[0];
	tmp.size = m_size / 2;

	rsa_inv_mod_N(&tmp.hn, (rsa_num *) (kpart + 2));

	ret = fs_key_write_part(&tmp.type);
	if (ret != S_RET_OK)
		return ret;

	tmp.type |= 0x30;
	tmp.size = m_size;
	barrett_constant(&tmp.t1, (rsa_num *) (kpart + 2));
	return fs_key_write_part(&tmp.type);
}
#endif

static uint8_t check_rsa_key_size(uint16_t size)
{
	// allow only 512,768,1024,1536 and 2048 bit key
	// this limitation is alredy in opensc (card-myeid.c)
	// new reduction method is not designed/tested
	// with arbitrary key size.
	if (size == 768)
		return 0;
	if (size & 0x1ff)
		return 1;
	if (size < 512)
		return 1;
	if (size > 2048)
		return 1;
	return 0;
}

// target pointer must allow store RSA_BYTES of bytes
uint8_t get_rsa_key_part(void *here, uint8_t id)
{
	uint16_t part_size;
	uint8_t *key = here;

	memset(key, 0, RSA_BYTES);
	part_size = fs_key_read_part(NULL, id);
	if (part_size > RSA_BYTES)
		return 0;
	fs_key_read_part(key, id);
	return part_size;
}

// do sign/decrypt with selected key, return 0 if error,
// or len of returned message (based on key size).
// input length of message, message, result after sign/decrypt
// WARNING, message and result buffers must hold 256 bytes!
// flag 0 - raw data, must match key size
// flag 1 - add OID of SHA1 before message, then add padding..
// flag 2 - add padding only (type 01), SHA1 digest is in message
static uint16_t rsa_raw(uint16_t len, uint8_t * message, uint8_t * result, uint8_t flag)
{
	uint16_t part_size;
	uint8_t ret;

	DPRINT("message first byte 0x%02x size %d\n", *message, len);

	reverse_string(message, len);	// number from message
	if (len < RSA_BYTES)
		memset(message + len, 0, RSA_BYTES * 2 - len);

	HPRINT("reversed mesage =\n", message, RSA_BYTES * 2);

	// test if key match data size
	part_size = fs_key_read_part(NULL, KEY_RSA_p);
	part_size *= 2;		// calculate message size

	DPRINT("key modulus: %d, message len: %d flag: %d\n", part_size, len, flag);
	if (flag == 0) {
		if (len != part_size)
			return 0;
	}
	if (flag == 1) {
		DPRINT("adding SHA1 OID to message\n");
// this test is not needed, minimal key modulus is 512 bit
/*
      if (len + 15 > part_size)
	return 0;
*/
		// SHA1 need 20 bytes len message exact
		if (len != 20)
			return 0;
		// add sha1 oid before message
		get_constant(message + len, N_PSHA1_prefix);

		reverse_string(message + len, 15);
		flag = 2;
		len += 15;

		HPRINT("reversed mesage with SHA1 OID=\n", message, RSA_BYTES * 2);
	}
	if (flag == 2) {
		DPRINT("adding padding type 1 size of modulus %d, message size %d\n",
		       part_size, len);
// add padding- type 1 (00 01 [FF .. FF] 00 .. minimal 8 bytes 0xff
// MyEID manual 2.1.4:  Size of the DigestInfo must not exceed 40% of the RSA key modulus length.
		if (len + 11 > part_size)
			return 0;
		message[len] = 0;
		len++;
		while (len < part_size)
			message[len++] = 0xff;
		message[part_size - 1] = 0x00;
		message[part_size - 2] = 0x01;
		flag = 0;
	}
	// check unknown padding
	if (flag != 0)
		return 0;

	HPRINT("mesage\n", message, RSA_BYTES * 2);

	DPRINT("calculating RSA\n");
	ret = rsa_calculate(message, result, len / 2);

	if (ret) {
// prevent sensitive data
		DPRINT("RSA fail clearing buffers\n");
		memset(message, 0, 256);
		memset(result, 0, 256);
		return 0;
	}
	DPRINT("RSA ok, reversing\n");
	reverse_string(result, part_size);
	DPRINT("return size %d\n", part_size);
	return part_size;
}

// for NIST curves and for secp256k1 A is not needed
// Special values of A (A=0, A=-3) are indicated in the c->curve_type
// (A and B is needed for ECDH operation to check if point is on curve)

// size 24/32/48 for ecc 192,256/384 bis, id 0 get key from selected file and use
// key size to setup ec parameters
static uint8_t prepare_ec_param(struct ec_param *c, ec_point_t * p, uint8_t size)
{
	uint16_t ret;
	uint8_t var_C;

	memset(c, 0, sizeof(struct ec_param));

	// ACL and file existence is checked in fs_key_read, return value can be used to select
	// 192/256/384 key algo

	if (size == 0) {
		ret = fs_key_read_part(NULL, KEY_EC_PRIVATE);
		if (ret > MP_BYTES)
			return 0;
		// c->working_key size is MP_BYTES, not overrun...
		// coverity[overrun-buffer-val]
		if (ret != fs_key_read_part((uint8_t *) & c->working_key, KEY_EC_PRIVATE))
			return 0;
	} else
		ret = size;

#ifndef NIST_ONLY
	if (fs_get_file_type() == EC2_KEY_EF) {
		var_C = C_SECP256K1 | C_SECP256K1_MASK;
	} else
#endif
	{
		if (ret == 24) {
			var_C = C_P192V1 | C_P192V1_MASK;
		}
#if MP_BYTES >= 32
		else if (ret == 32) {
			var_C = C_P256V1 | C_P256V1_MASK;
		}
#endif
#if MP_BYTES >= 48
		else if (ret == 48) {
			var_C = C_SECP384R1 | C_SECP384R1_MASK;
		}
#endif
#if MP_BYTES >= 66
		else if (ret == 66) {
			var_C = C_SECP521R1 | C_SECP521R1_MASK;
		}
#endif
		else
			return 0;
	}
	c->curve_type = var_C;
	var_C &= 0x3f;
	if (p) {
		memset(p, 0, sizeof(ec_point_t));
		get_constant((uint8_t *) & (p->X), var_C + 5);
		get_constant((uint8_t *) & (p->Y), var_C + 6);
	}
	get_constant(&c->prime, var_C + 1);
	get_constant(&c->order, var_C + 2);
	get_constant(&c->a, var_C + 3);
	get_constant(&c->b, var_C + 4);

	reverse_string((uint8_t *) & c->working_key, ret);
	c->mp_size = ret;

	return ret;
}

static uint8_t add_num_to_seq(uint8_t * here, uint8_t * num, uint8_t size)
{
	uint8_t ret = size;

	reverse_string(num, size);

	*(here++) = 2;
	*here = size;
	if (*num & 0x80) {
		*(here++) = size + 1;
		ret++;
		*here = 0;
	}
	memcpy(here + 1, num, size);
	return ret + 2;
}

// return error code if fail, or response if ok
static uint8_t sign_ec_raw(uint8_t * message, struct iso7816_response *r, uint16_t size)
{
#if MP_BYTES > 48
	ecdsa_sig_t *e = alloca(sizeof(ecdsa_sig_t));
	struct ec_param *c = alloca(sizeof(struct ec_param));
#else
// reuse "message" buffer for ecdsa_sig_t (warning, this is really only for max 48 bytes in bignum_t)
	ecdsa_sig_t *e = (ecdsa_sig_t *) (message + sizeof(bignum_t));
// reuse result buffer for ec_param structure
	struct ec_param *c = (struct ec_param *)r->data;
#endif
	uint16_t ret;

	DPRINT("%s\n", __FUNCTION__);

	// prepare Ec constant, use size based on key  (key from selected file)
	// generator point into e->signature
	ret = prepare_ec_param(c, &e->signature, 0);
	if (ret == 0) {
		DPRINT("Error, unable to get EC parameters/key\n");
		return S0x6985;
	}

	if (ret < size)
		return S0x6700;	// Incorrect length

	// message to number
	reverse_string(message, size);

	// pad message to match key length

	if (size < sizeof(bignum_t))
		memset(message + size, 0, sizeof(bignum_t) - size);
	HPRINT("mesage =\n", message, ret);
	HPRINT("working key:\n", c->working_key.value, ret);
	HPRINT("prime:\n", c->prime.value, ret);
	HPRINT("a:\n", c->a.value, ret);
	HPRINT("b:\n", c->b.value, ret);
	HPRINT("order:\n", c->order.value, ret);
	DPRINT("size: %d\n", c->mp_size);
	DPRINT("type: %d\n", c->curve_type);

	DPRINT("SIGN ...\n");
	if (ecdsa_sign(message, e, c)) {
		DPRINT("SIGN FAIL\n");
		return S0x6985;
	}
	DPRINT("SIGN OK, generating response\n");
	HPRINT("SIGNATURE R:\n", e->R.value, ret);
	HPRINT("SIGNATURE S:\n", e->S.value, ret);

// Generate object 1.2.840.10045.4.1  with r and s value

	uint8_t *here;
	uint8_t skip, skip0;

	DPRINT("size=%d\n", c->mp_size);

// sequence 0x30, LEN, 0x02, R, 0x02, S
// there is simplification for calculating LEN that generates invalid DER (valid BER) for 61 bytes R/S value:

// 0x30, LEN      , 2  ,R[61],2,  S[61]  = 126
// 0x30, LEN      , 2,0,R[61],2,  S[61]  = 127
// 0x30, LEN      , 2,0,R[61],2,0,S[61]  = 127
// 0x30, 0x81,LEN , 2,0,R[61],2,0,S[61]  = 129

// for LEN = 126 / 127  LEN is coded as 0x81 0x7e / 0x81 0x7f correct coding is 0x7e / 0x7f
// This simplification is no problem for OsEID, here only  24,32,48, or 66 bytes are used

	r->data[0] = 0x30;
	skip0 = 2;

#if MP_BYTES > 60
	if (c->mp_size > 60) {
		r->data[1] = 0x81;
		skip0 = 3;
	}
#endif
	here = r->data + skip0;
	skip = add_num_to_seq(here, e->R.value, c->mp_size);
	here += skip;
	skip += add_num_to_seq(here, e->S.value, c->mp_size);

	r->data[skip0 - 1] = skip;

	skip += skip0;
	RESP_READY(skip);
}

uint8_t security_env_set_reset(uint8_t * message, __attribute__((unused))
			       struct iso7816_response *r)
{
	uint16_t tagval;
	uint8_t xlen, *data;;
	uint8_t tag;
	uint8_t taglen;
	uint8_t s_env = 0;

// invalidate sec env
	sec_env_valid = 0;

// this is used to initialize sec_env_valid after reboot
	if (message == NULL)
		return 0;

	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	DPRINT("sec env operation: %1x ", M_P1 & 15);
	DPRINT("%s", (M_P1 & 15) == 1 ? "set" : "");
	DPRINT("%s", (M_P1 & 15) == 2 ? "store" : "");
	DPRINT("%s", (M_P1 & 15) == 3 ? "restore" : "");
	DPRINT("%s", (M_P1 & 15) == 4 ? "erase" : "");
	DPRINT("\n");

	// X3h = restore, FXh = all sec env (for sec messaging and for enciph/deciph)
	if (M_P1 == 0xf3) {
		DPRINT("%s, Restore security environment %02X\n", __FUNCTION__, M_P2);
		if (M_P3 != 0 || M_P2 != 0) {
			DPRINT("%s lc/le not 0 ? \n", __FUNCTION__);
			return S0x6a87;	// len inconsistent with P1
		}
		return (S_RET_OK);
	}
/*
Key wrap/unwrap
00 22 41 B8 1D
                80 01 8A
                81 02 4D 01
                83 02 4D 02
                87 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
*/
// OsEID sec environment templates by P2 value:

//           P1           P2
// DECIPHER 0x41          0xB8 = Confidentiality Template (CT)
// SIGN     0x41          0xB6 = Digital Signature Template (DST)
// UNWRAP   0x41          0xB8 = Confidentiality Template (CT)
// ECDH     0x41          0xA4 = Authentication Template (AT)
// WRAP     0x81          0xB8 = Confidentiality Template (CT)
// ENCIPHER 0x81          0xB8 = Confidentiality Template (CT)

// OsEID does not use templates:
// 0xA6 = Key Agreement Template (KAT)
// 0xAA = Hash-code Template (HT)
// 0xB4 = Cryptographic Checksum Template (CCT)

// TEMPLATE:
// MyEID manual 2.1.4 specifies nibbles for algorhithm reference, below combinations from opensc driver
// 0x80 = 1 byte algo reference:
//                              0x00 for normal RSA/AES, 0x0A for RSA or AES WRAP/UNWRAP operation
//                              0x02 pad data (PKCS#1) before operation
//                              0x04 for EC operations (ECDSA/ECDH)
//                              0x0A WRAP/UNWRAP operation (with RSA or AES)
//                              0x12 insert OID of SHA1 before data, then do PKCS#1 padding
//                              0x80 perform PKCS#7 padding (for AES)
//                              0x8A wrap/unwrap and pkcs#7 padding op
// from MyEID manual 2.1.4:
//                              0xX0 - compute signature/decipher
//                              0xX1 - RFU
//                              0xX2 - pad data to match modulus/ remove padding PKCS#1 v1.5
//                              0xX3 - RFU
//                              0xX4 - ECDSA/ECDH
//                              0x0X - no hash algo
//                              0x1X - add SHA1 digest before message
//                              0x2X - 0x6X RFU - add digest before message (RIMEMP160, SHA224, SHA256, SHA384, SHA512)
//  added in 2.3.0 ref man:
//                              0x8X - Symmetric operations: PKCS#7 padding
//                              0xXA - Key wrapping or unwrapping
// 0x81 = 2 byte file reference
// 0x83 = 1 byte key reference in file (always 0 for MyEID/OsEID) (symetric keys)
// 0x83 = 2 byte target key file reference for wrap/unwrap  (from opensc..)
// 0x84 = 1 byte key reference in file (always 0 for MyEID/OsEID) (asym keys)
// 0x87 = 8/16 bytes ? initialization vector
// tags used .. for EC  operations   : 0x80, 0x81, 0x84
//              for RSA operations   : 0x80, 0x81, 0x84
//              for RSA + WRAP/UNWRAP: 0x80, 0x81, 0x84, 0x87
//              for AES + WRAP/UNWRAP: 0x80, 0x81, 0x83?/0x84?, 0x87
//              for AES/DES          : 0x80, 0x81, 0x83/0x84?, 0x87
// thanks to hhonkanen, tag 0x83 is necessary for symmetric operations!

/* Example sequence of APDUs for AEs encipher/decipher: (tested on MyEID)
file 4d04 - AES key:
IV vector size must match cypher (DES8 bytes AES 16 bytes) MSO operation ends OK but PSO
fails with 69 85 : Command not allowed. Conditions of use not satisfied.
For wrong size of PSO (not 8 or 16 bytes.. ) 67 00 : Wrong length.
Encipher (ECB)
echo "00 A4 00 00 00"|scriptor -p T=1
echo "00 A4 00 00 02 50 15"|scriptor
echo "00 A4 00 00 02 4d 04"|scriptor
echo "00 20 00 01 08 31 31 31 31 31 31 31 31"|scriptor
echo "00 22 81 b8 1C 80 01 00 81 02 4d 04 83 01 00 87 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"|scriptor
echo "00 2a 84 80 10 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 00"|scriptor
Decipher (ECB):
echo "00 A4 00 00 00"|scriptor -p T=1
echo "00 A4 00 00 02 50 15"|scriptor
echo "00 A4 00 00 02 4d 04"|scriptor
echo "00 20 00 01 08 31 31 31 31 31 31 31 31"|scriptor
echo "00 22 41 b8 1c 80 01 00 81 02 4d 04 83 01 00 87 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "|scriptor
echo "00 2a 80 84 10 AA E0 06 A6 28 AB 33 21 CD 46 0D 43 C1 71 EA 4F 00"|scriptor

AES/DES  tag 0x80, value 0x80 - pkcs#7 padding
*/

#if 0
// MyEID manual 2.1.4: P1 must be set to 0xA4 for ECDH, but opensc 0.17 set
// this to 0x41 and P2 is set to 0xA4 ..  allow A4 here too
// this violates ISO (A4 = erase sec env for sec messaging an verification..)
// (this seems to be a typo error in MyEID manual, A4 is for auth teplate..)
	if (M_P1 == 0xA4) {
		M_P1 = 0x41;
		M_P2 = 0xA4;
	}
#endif
// ISO: bit 0x80 = decipher, sign, unwrap etc..  operation with private key
// ISO: bit 0x40 = encripher, wrap ..
// allow only set sec env. (only bits bits 7,6 and 0 are allowed)

// for LC==0  this function fails in code below

// encipher operation
	if (M_P1 == 0x81) {
		// allowed template CT only!
		if (M_P2 != 0xb8)
			return S0x6985;	//    Conditions not satisfied
		s_env |= SENV_ENCIPHER;
		DPRINT("encipher requested, s_env=%02x\n", s_env);
	} else if (M_P1 == 0x41) {
		switch (M_P2) {
			// check teplate type
		case 0xB8:
		case 0xB6:
		case 0xA4:
			s_env |= (M_P2 >> 1) & 3;
			DPRINT("decipher requested, s_env=%02x\n", s_env);
			break;
			// unknown template
			return S0x6985;	//    Conditions not satisfied
		}
	} else
		return S0x6a81;	//Function not supported // change to wrong arg ?

	// Empty or concatenation of Control Reference Data Objects (CRDO)
	xlen = M_P3;
	data = message + 5;
	for (;;) {
		if (!(xlen--))
			break;
		tag = *(data++);
		if (tag == 0 || tag == 0xff)
			continue;
		if (!(xlen--))
			break;
		taglen = *(data++);
		if (taglen > 16)
			return S0x6984;	//maximal tag size is 16 (init vector)
		if (xlen < taglen)	// not enough data in buffer (to match taglen)
			return S0x6984;	//invalid data
		tagval = *data;
		if (taglen == 2)
			tagval = (tagval << 8) | *(data + 1);
		switch (tag) {
		case 0x80:
			if (taglen != 1)
				return S0x6a81;	//Function not supported      // change to wrong arg ?
			DPRINT("reference algo=%02x\n", tagval);
			switch (tagval) {
			case 0x00:	// no hash, raw data in paket, len must match key modulus
			case 0x02:	// data must be padded to match key modulus
			case 0x12:	// SHA1 ...
			case 0x04:	// ECDSA (DATA in RAW format)
			case 0x0A:	// WRAP/UNWRAP
			case 0x80:	// remove/add PKCS#7 padding
			case 0x8A:	// WRAP/UNWRAP (PKCS#7 padding)
				break;
			default:
				return S0x6a81;	//Function not supported // change to wrong arg ?
			}
			sec_env_reference_algo = tagval;	//=[D;// *data;
			s_env |= SENV_REF_ALGO;
			DPRINT("ref algo defined s_env=%02x\n", s_env);
			break;
		case 0x81:
			if (taglen != 2)
				return S0x6a81;	//Function not supported      // change to wrong arg ?
			DPRINT("KEY file ID=%04x\n", tagval);
			key_file_uuid = get_key_file_uuid(tagval);
			if (key_file_uuid == 0xffff)
				return S0x6a88;	//    Reference data not found
			s_env |= SENV_FILE_REF;
			DPRINT("added file reference s_env=%02x\n", s_env);

			break;
		case 0x83:	// MyEID requeres this for AES!
		case 0x84:
			if (taglen == 2)	// TARGET FILE ID (for UNWRAP)
			{
				DPRINT("target file ID=%04x\n", tagval);
				target_file_uuid = get_key_file_uuid(tagval);
				if (target_file_uuid == 0xffff)
					return S0x6a88;	//    Reference data not found
				s_env |= SENV_TARGET_ID;
				DPRINT("added target file reference s_env=%02x\n", s_env);
			} else if (taglen == 1) {
				DPRINT("reference for key=%d\n", *data);
				if (*data != 0) {
					// MyEID support only one key per file, then this reference must be 0
					return S0x6a81;	//Function not supported // change to wrong arg ?
				}
			} else
				return S0x6a81;	//Function not supported // change to wrong arg ?
			break;
		case 0x87:
			// maximal taglen 16 is already checked
			i_vector_len = taglen;
			memcpy(i_vector, data, taglen);
			s_env |= SENV_INIT_VECTOR;
			break;
		default:
			return S0x6a80;	// incorrect parameters in the data field / wrong data
		}
		xlen -= taglen;
		data += taglen;
	}
	// minimum template - reference algo and file
	if ((s_env & (SENV_FILE_REF | SENV_REF_ALGO))
	    != (SENV_FILE_REF | SENV_REF_ALGO)) {
		DPRINT("not all env variables present = %02x\n", s_env);
		return S0x6a81;	//Function not supported // change to wrong arg ?
	}
	DPRINT("Final s_env=%02x\n", s_env);
	sec_env_valid = s_env;
	return S_RET_OK;
}

static uint8_t security_operation_rsa_ec_sign(struct iso7816_response *r)
{
	uint8_t flag;
	uint16_t size = r->Nc;

// is security enviroment set to sign ?
	if ((sec_env_valid &
	     (SENV_TEMPL_MASK | SENV_ENCIPHER | SENV_FILE_REF | SENV_REF_ALGO)) !=
	    (SENV_TEMPL_DST | SENV_FILE_REF | SENV_REF_ALGO)) {
		DPRINT("invalid sec env - no DTS teplate or encipher defined (%02x)\n",
		       sec_env_valid);
		DPRINT("sec env %02x\n", sec_env_valid);
		DPRINT("mask %02x\n",
		       SENV_TEMPL_MASK | SENV_ENCIPHER | SENV_FILE_REF | SENV_REF_ALGO);
		DPRINT("To:  %02x\n", SENV_TEMPL_DST | SENV_FILE_REF | SENV_REF_ALGO);
		return S0x6985;	//    Conditions not satisfied
	}
	if (!r->Nc)
		return S0x6700;
	DPRINT("sec environment %0x2 valid sign algo = 0x%02x, message len %d\n",
	       sec_env_valid, sec_env_reference_algo, size);

	// Wait for full APDU if chaining is active
	if (r->chaining_state & APDU_CHAIN_RUNNING) {
		DPRINT("APDU chaining is active, waiting more data\n");
		return S_RET_OK;
	}
	// this is  long operation, start sending NULL
	card_io_start_null();

// SIGN operation posible values for reference algo: 0,2,4,0x12
	if (sec_env_reference_algo == 4) {
		DPRINT("RAW-ECDSA-PKCS algo %02x\n", sec_env_reference_algo);
		// in buffer RAW data to be signed
		return sign_ec_raw(r->input + 5, r, size);
	} else if (sec_env_reference_algo == 2) {
		DPRINT("Digest Info data in paket\n");
		flag = 2;
	} else if (sec_env_reference_algo == 0x12) {
		DPRINT("SHA1 message in buffer\n");
		flag = 1;
	} else if (sec_env_reference_algo == 0) {
		DPRINT("RAW message in buffer\n");
		flag = 0;
	} else
		return S0x6985;	//    Conditions not satisfied

	size = rsa_raw(size, r->input + 5, r->data, flag);
//  DPRINT ("RSA calculation %s, returning APDU\n", size ? "OK":"FAIL");
	if (size != 0) {
		DPRINT("RSA sign OK\n");
		RESP_READY(size);
	}
	return S0x6985;		//    Conditions not satisfied
}

/*!
  @brief Helper function for des_aes_cipher()

  @param[in,out] data

  @par Global variables
  @param[in] i_vector_tmp		initialization vector
  @param[in] i_vector_len		size of IV
 */
static void apply_iv(uint8_t * data)
{
	uint8_t i;

	for (i = 0; i < i_vector_len; i++)
		data[i] ^= i_vector_tmp[i];
}

/*!
  @brief run AES or DES in CBC mode

  ECB is posible, but the length of the data must correspond to the block size.

  Padding is added/removed only if reference algorithm request for
  this, and chaining flag is not set.

  @par Environment
  Key used for operation is acquired by fs_key_read_part() function.
  Caller is responsible to select proper file.

  @param[in]  r->data		data to be encoded
  @param[out] r->data		encoded result
  @param[in]  r->Nc		size
  @param[in]  r->input[0]	APDU chaining flag
  @param[in]  mode   		0 = encipher, any other value decipher

  @note
  (r->input+5 contain same data as r->data - card_os/iso7816.c)

  @par Global variables
  @param[in] sec_env_reference_algo	bit 7 - add/remove pkcs#7 padding
  @param[in] i_vector			initialization vector
  @param[in] i_vector_len		size of IV

  @par Side effects
  @param[out] i_vector_tmp		initialized by i_vector

  @return SW code
  @retval S0x6985 - command not satisfied - wrong padding detected - decipher
  @retval S0x6700 - wrong length - unable to append padding (encipher)
  @retval S0x6985 - conditions not satisfied - unable to read key file, AC not correct etc.
  @retval S0x6981 - incorect file type - unable to read correct key from file, blank file etc.

  @note incorect size for AES key is not handled (no error code), result of operation is incorrect

 */
static uint8_t des_aes_cipher(struct iso7816_response *r, uint8_t mode)
{
	uint8_t type;
	uint8_t ksize;
	uint8_t bsize;
	uint16_t offset;
	uint16_t iv[I_VECTOR_MAX];
	uint8_t flag = 0;
	uint8_t padd_len;
	uint8_t last_block_padding;
	uint8_t *p = r->data;
	uint8_t *data = r->input;
	uint16_t size = r->Nc;

	DPRINT("%s mode %s chain state %d\n", __FUNCTION__,
	       mode ? "decipher" : "encipher", r->chaining_state);

	if (r->chaining_state <= APDU_CHAIN_START) {
		DPRINT("setting up temporary IV vector\n");
		memcpy(i_vector_tmp, i_vector, i_vector_len);
	}
	// padding remove/add only for last block and only if reference algo request this..
	last_block_padding = sec_env_reference_algo & 0x80;

	if (data[0] & 0x10)
		last_block_padding = 0;

	// there is over 256 bytes free in data, fs_key_read_part() return at max 256 bytes
	ksize = fs_key_read_part(data, 0xa0);

	// 0 - wrong file, no data in key file, or no PIN verified...
	if (!ksize)
		return S0x6985;	//    Conditions not satisfied

	type = fs_get_file_type();
	DPRINT("key type =%02x size=%d\n", type, size);
	if (type == DES_KEY_EF) {
		bsize = 8;

		if (mode)
			flag |= DES_DECRYPTION_MODE;

#if ENABLE_DES56
// allow use 7 or 8 bytes as DES key
		if (ksize == 7) {
			des_56to64(data);
			ksize = 8;
		}
#endif
		if (ksize == 16) {
			memcpy(data, data + 16, 8);
			flag = DES_3DES;
		} else if (ksize == 24)
			flag = DES_3DES;
		else if (ksize != 8)
			return S0x6981;	//incorect file type
	} else if (type == AES_KEY_EF) {
		bsize = 16;
		// do not check exact key sizes (32,24,16), AES is running
		// with wrong keysize (1.15,16..23,25..31) but fails in
		// decipher/encipher. This alow us to save FLASH space.
		if (ksize > 32)
			return S0x6981;	//incorect file type
/*
      switch (ksize)
	{
	case 16:
	case 24:
	case 32:
	  break;
	default:
	  return S0x6981;	//incorect file type
	}
*/
	} else
		return S0x6981;	//incorect file type

	padd_len = (size & (bsize - 1));
	if (mode == 0 && last_block_padding) {
		// encipher, and pkcs#7 padding is requested
		DPRINT("PKCS#7 padding in encypher mode\n");
		padd_len = bsize - padd_len;
		if (APDU_RESP_LEN < size + padd_len)
			return S0x6700;
		memset(p + size, padd_len, padd_len);
		size += padd_len;
		padd_len = 0;
	}
	// data size must match multiple of block size
	if (padd_len)
		return S0x6700;	//Incorrect length

	for (offset = size; offset; offset -= bsize, p += bsize) {
		if (mode == 0)
			apply_iv(p);
		else
			memcpy(iv, p, bsize);

		if (type == AES_KEY_EF)
			aes_run(p, data, ksize, mode);
		else
			des_run(p, data, flag);

		if (mode == 0)
			memcpy(i_vector_tmp, p, bsize);
		else {
			apply_iv(p);
			memcpy(i_vector_tmp, iv, bsize);
		}
	}

// pkcs#7 padding remove
	if (mode != 0 && last_block_padding) {
		uint8_t b;

		padd_len = *(p - 1);
		if (padd_len == 0 || padd_len > bsize)
			return S0x6985;	// command not satisfied
		b = padd_len;
		do {
			size--;
			if (*(--p) != b)
				return S0x6985;	// command not satisfied
		}
		while (--padd_len);
	}
	RESP_READY(size);
}

static uint8_t decipher(struct iso7816_response *r)
{
	uint8_t ret;
	uint16_t size;
	uint8_t padding, p2;
	uint8_t *message = r->input;

	DPRINT("%s\n", __FUNCTION__);

// check key type, if DES/AES key is selected
	ret = fs_get_file_type();
	if (ret == DES_KEY_EF || ret == AES_KEY_EF) {
		// 0x86 is not allowed for symmetric cyphers
		if (M_P2 != 0x84)
			return S0x6a86;	//Incorrect parameters P1-P2

		DPRINT("return decrypted data, cla = %02x\n", r->input[0]);
		ret = des_aes_cipher(r, 1 /*DECRYPTION_MODE */ );
		return ret;
	}
	// only RSA key can be used to decipher (ASE/DES already checked)
	if (ret != RSA_KEY_EF)
		return S0x6985;	// command not satisfied

	// Wait for full APDU if chaining is active
	if (r->chaining_state & APDU_CHAIN_RUNNING) {
		DPRINT("APDU chaining is active, waiting more data\n");
		return S_RET_OK;
	}
// RSA decipher - P2 0x84 CT in data field, 0x86 padding + CT in data field
// P2 is already checked, (0x84 or 0x86 ) in security_operation()
	size = r->Nc;
	p2 = M_P2;
	message += 5;

// P2 is checked in security_operation(), allowed values:
// P2: 0x84 data field contains encrypted data
// P2: 0x86 data field contain padding indicator

	if (p2 == 0x86) {
// APDU chaining is inactive or at last state
		padding = *(message++);
		DPRINT("message contain padding indicator %02x, size=%d\n", padding, size - 1);

// message points to APDU data field (raw, no padding indicator)
// size = data size of APDU (inclusie padding indicator)
// padding:    0 - data block, no more blocks
//          0x81 - one more block comming
//          0x82 - last block
//
		if (padding == 0x81) {
			// check 2nd padding indicator
			if (r->tmp_len) {
				uint8_t *p = message + r->tmp_len - 1;
				if (*(p) != 0x82) {
					DPRINT("Unable to find 2nd padding inicator %02x\n", *p);
					return S0x6a86;	//Incorrect parameters P1-P2
				}
				// reduce size (skip 2nd padding indicator)
				size--;
				memcpy(p, r->data + r->tmp_len + 1, size - r->tmp_len);
			} else {
				DPRINT("1st part of message, emulating APDU chain\n");
				r->chaining_state = APDU_CHAIN_ACTIVE;
				r->chaining_ins = 0x2a;
				r->chain_len = size;
				return S_RET_OK;
			}
		} else if (padding != 0) {
			DPRINT("Unkonwn padding indicator %02x\n", padding);
			return S0x6984;
		}
		// reduce size (skip 1st padding indicator)
		size--;
	}
	DPRINT("All data available (%d bytes), running security OP\n", size);
	// ok all data concatenated, do real OP

// RSA decrypt, and optional padding remove
	card_io_start_null();
	size = rsa_raw(size, message, r->data, 0);

	if (size == 0) {
		DPRINT("decrypt fail\n");
		return S0x6985;	// command not satisfied
	}
// 0x0a UNWRAP, 0x02 decipher, in both cases remove PKCS#1 padding
	if ((sec_env_reference_algo & 2) == 2) {
		// return error for not correct padding
		// allowed padding is: 00 || 02 || random data[8+] || 00 || real data
		DPRINT("requested padding remove operation, (message len %d)\n", size);
		if (r->data[0] == 0 && r->data[1] == 2 && size > 11) {
			uint8_t *padd = r->data + 2;
			uint16_t s = size - 3;

			for (; s > 0; s--, padd++)
				if (*padd == 0) {
					if (padd < r->data + 10) {
						DPRINT
						    ("Wrong padding, below 8 bytes of random data\n");
						return S0x6985;	// command not satisfied
					}
					memcpy(r->data, padd + 1, s);
					size = s;
					DPRINT("padding removed, (message len %d)\n", size);
					break;
				}
			if (!s) {
				DPRINT("Wrong padding, no 0x00 found after random padding data\n");
				return S0x6985;	// command not satisfied
			}
		} else {
			DPRINT("Unknown padding, %02x %02x,\n", r->data[0], r->data[1]);
			return S0x6985;	// command not satisfied
		}
	}
	HPRINT("return mesage =\n", r->data, size);
	RESP_READY(size);
}

static uint8_t security_operation_encrypt(struct iso7816_response *r)
{
	uint16_t uuid = fs_get_selected_uuid();	// save uuid of key file
	uint8_t type;
	DPRINT("%s\n", __FUNCTION__);

	if ((sec_env_valid &
	     (SENV_TEMPL_MASK | SENV_ENCIPHER | SENV_FILE_REF | SENV_REF_ALGO)) !=
	    (SENV_TEMPL_CT | SENV_ENCIPHER | SENV_FILE_REF | SENV_REF_ALGO)) {
		DPRINT("security env not valid\n");
		return S0x6985;	//    Conditions not satisfied
	}
	// key wrap (only DES/AES for now)
	if (r->Nc == 0) {
		if ((sec_env_valid & SENV_TARGET_ID) == 0)
			return S0x6700;	// wrong length

		DPRINT("WRAP key %x\n", target_file_uuid);
		// chain is not active if r->Nc > 0
		fs_select_uuid(target_file_uuid, NULL);
		// test if key file is extractable
		// (we do not need to select key file back)
		if (!(fs_get_file_proflag() & 0x0008))
			return S0x6985;	// Conditions not satisfied
		// check type
		type = fs_get_file_type();
		switch (type) {
			// load key from file
		case AES_KEY_EF:
		case DES_KEY_EF:
			// maximal part size is < 256, we have enough space in r->data
			r->Nc = fs_key_read_part(r->data, 0xa0);
			// test key part (key file is wrong/blank)
			if (r->Nc)
				break;
			// fall through
		default:
			return S0x6985;	// Conditions not satisfied
		}
	}
	// select key back
	fs_select_uuid(uuid, NULL);
	DPRINT("return encrypted data, cla = %02x\n", r->input[0]);
	return des_aes_cipher(r, 0);
}

static uint8_t security_operation_decrypt(struct iso7816_response *r)
{
	uint8_t ret;

	DPRINT("%s\n", __FUNCTION__);

	if ((sec_env_valid & (SENV_ENCIPHER | SENV_FILE_REF | SENV_REF_ALGO))
	    == (SENV_ENCIPHER | SENV_FILE_REF | SENV_REF_ALGO)) {
		DPRINT("sec environment %02x valid sign algo = 0x%02x\n",
		       sec_env_valid, sec_env_reference_algo);
		DPRINT("security env not valid\n");
		return S0x6985;	//    Conditions not satisfied
	}
	if (!r->Nc)
		return S0x6700;
	ret = decipher(r);
	// for Unwrap operation write data to file
	if (ret == S0x6100 && sec_env_valid & SENV_TARGET_ID
	    && (!(r->chaining_state & APDU_CHAIN_RUNNING))) {
		uint8_t type;
		uint8_t *keydata;

		DPRINT("storing decrypted data to target file\n");

		fs_select_uuid(target_file_uuid, NULL);
		type = fs_get_file_type();
		// TODO better checking of key sizes  etc...
		if ((type == 0x41 || type == DES_KEY_EF || type == AES_KEY_EF)
		    && r->len16 < 254) {
			memcpy(r->input + 5, r->data, r->len16);
			// copy data, experimental, how is stored data in original MyEID card?
			keydata = r->input + 3;
			keydata[0] = 0xa0;	// TAG
			keydata[1] = r->len16 & 0xff;	// LEN

			HPRINT("data for file: \n", keydata, r->len16 + 2);

			// TODO error checking
			if (type == 0x41)
				fs_update_binary(keydata + 1, 0);	// do not store TAG, LEN
			else
				fs_key_write_part(keydata);
		} else
			ret = S0x6985;	//    Conditions not satisfied
	}
	return ret;
}

/*
$ pkcs15-init --generate-key rsa/1024 --user-consent 1 --auth-id 1 --pin 11111111 --label UC1
FCI ..  85 02 11 00 - deauth PIN1
//$ pkcs15-init --generate-key rsa/1024 --user-consent 0 --auth-id 1 --pin 11111111 --label UC0
FCI ... 85 02 01 00 - no deauth
*/

static void select_back_and_deauth(uint16_t uuid)
{
	uint8_t auth_id;

	auth_id = (fs_get_file_proflag() >> 12);
	// if here is 0, do not call fs_deauth() - it would deauth all PINs
	if (auth_id)
		fs_deauth(auth_id);

	fs_select_uuid(uuid, NULL);	// select back old file
}

//APDU: 00 86 00 00 35
// Dynamic auth template:
// (tag)7C (ASN1 coded len)33
// (tag)85 (ASN1 coded len)31
// (uncompress indicator)04
//  public key
//    47 57 75 41 68 74 24 FE B1 55 55 27 06 52 90 2D 62 84 B5 C2 FF 1B 12 9E
//    CD EE D7 47 58 FB 45 F1 E8 8B 72 E3 C7 9E 80 F0 CC 3D 18 D7 4C 05 CD 31

// here r->data is used as input and point for ecdh
// in first part (0..109) = data for exdh operation (copied from message)
// rest 110-254 ec_point_t

#define L_ECDH_OFFSET 110
uint8_t myeid_ecdh_derive(uint8_t * message, struct iso7816_response *r)
{
#if MP_BYTES > 48
	struct ec_param *ec = alloca(sizeof(struct ec_param));
	ec_point_t *derived_key = alloca(sizeof(ec_point_t));
	memset(derived_key, 0, sizeof(ec_point_t));
#else
	// reuse result buffer for ec_param structure
	struct ec_param *ec = (struct ec_param *)message;
	ec_point_t *derived_key = (ec_point_t *) (r->data + L_ECDH_OFFSET);
#endif

	uint8_t ret, dret;
	uint8_t t_len, *t;
	uint8_t tg, tl;
	uint16_t uuid;

	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	if (M_P1 != 0 || M_P2 != 0)
		return S0x6a86;	//Incorrect parameters P1-P2

// is security enviroment set to derive ?
	if ((sec_env_valid & (SENV_TEMPL_MASK | SENV_ENCIPHER)) != SENV_TEMPL_AT) {
		DPRINT("invalid sec env\n");
		return S0x6985;	//    Conditions not satisfied
	}
// security operation always need data
	if (M_P3 == 0)
		return S0x6984;	//invalid data
#if  MP_BYTES <= 48
	if (M_P3 > L_ECDH_OFFSET)
		return S0x6700;	//Incorrect length
#endif

// check minimal LC: 0x7c LEN TAG ..  or 0x7x 0x81 LEN
	if (M_P3 < 3)
		return S0x6984;	// Invalid data

	t = r->data;
// message is reused as ec_param structure (for MP_BYTES <= 48)
	memcpy(t, message + 5, M_P3);

	uint8_t dlen = M_P3;
// check rest of APDU
	if (*t++ != 0x7c)	// Dynamic autentification template
		return S0x6984;	// Invalid data

// parse ASN1 LEN value (0-255)
	t_len = *t++;
	if (t_len & 0x80) {
		dlen--;
		if (t_len != 0x81)
			return S0x6984;	// Invalid data (ASN1 length > 255)
		t_len = *t++;
	}

	if (t_len != dlen - 2)	// check length of template
		return S0x6984;	// Invalid data

	while (t_len > 1) {
		tg = *t++;
		// parse ASN1 LEN value (0-255)
		tl = *t++;
		if (tl & 0x80) {
			t_len--;
			if (tl != 0x81)
				return S0x6984;	// Invalid data (ASN1 length >255)
			tl = *t++;
		}
		t_len -= 2;

		if (t_len < tl) {
			DPRINT("Wrong length of tag  %02x lenght %d (in buffer only %d)\n",
			       tg, tl, t_len);
			return S0x6984;	// Invalid data
		}
		if (tg == 0x85) {
			if (*t++ != 0x04)	// unexpanded point indicator
				return S0x6984;	// Invalid data
			if (tl != t_len)
				return S0x6984;	// Invalid data
			t_len--;
			break;
		} else if (tg == 0x80) {
			t += tl;
			t_len -= tl;
		} else {
			DPRINT("Unknown tag %02x\n", tg);
			return S0x6984;	// Invalid data
		}
	}
	// prepare Ec constant, use size based on key  (key from selected file)
	ret = prepare_ec_param(ec, NULL, 0);
	if (ret == 0) {
		DPRINT("Error, unable to get EC parameters/key\n");
		return S0x6985;	//    Conditions not satisfied
	}
	if (ret * 2 != t_len) {
		DPRINT
		    ("Incorrect length of point data %d, selected file need %d bytes\n",
		     t_len, ret * 2);
		return S0x6984;	// Invalid data
	}
	reverse_copy((uint8_t *) & (derived_key->X), t, ec->mp_size);
	reverse_copy((uint8_t *) & (derived_key->Y), t + ret, ec->mp_size);

	uuid = fs_get_selected_uuid();	// save old selected file
	fs_select_uuid(key_file_uuid, NULL);
	// this is  long operation, start sending NULL
	card_io_start_null();

	dret = ec_derive_key(derived_key, ec);

	select_back_and_deauth(uuid);

	if (dret)
		return S0x6985;	//    Conditions not satisfied

	reverse_copy(r->data, (uint8_t *) derived_key, ret);
	RESP_READY(ret);
}

uint8_t security_operation(uint8_t * message, struct iso7816_response *r)
{
	uint16_t uuid;
	uint8_t op, ret_data;
	uint8_t ret;

	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

/*
  check P1, P2, convert P1,P2 to two variables:
  op /SIGN 0x9E/ENCIPHER 0x84/DECIPHER 0/
  ret_data 0x80/0 (return data/save data to file)
  or raise error Incorrect parameters P1-P2
SIGNATURE: 9E 9A
ENCIPHER:  84 00 || 84 80
DECIPHER:  00 84 || 80 84 || 00 86 || 80 86
*/
	op = M_P1;
	ret_data = M_P2;
	// sign
	if (op == 0x9E && ret_data == 0x9A)
		ret_data = 0x80;
	// encipher
	else if (op == 0x84) ;
	// decipher
	else if (ret_data == 0x84 || ret_data == 0x86) {
		ret_data = op;
		op = 0;
	} else
		return S0x6a86;	// Incorrect parameters P1-P2

	// result into file (0x00) or return result (0x80)
	if (ret_data & 0x7f)
		return S0x6a86;	// Incorrect parameters P1-P2

	uuid = fs_get_selected_uuid();	// save old selected file
	fs_select_uuid(key_file_uuid, NULL);
	switch (op) {
	case 0x9e:
		ret = security_operation_rsa_ec_sign(r);
		break;
	case 0x84:
		ret = security_operation_encrypt(r);
		break;
	case 0:
		// for UNWRAP operation - only SW is returned, clear Ne
		if (!ret_data)
			r->Ne = 0;
		ret = security_operation_decrypt(r);
		break;
	default:
		ret = S0x6a86;	// Incorrect parameters P1-P2
	}
	select_back_and_deauth(uuid);
	return ret;
}

static __attribute__((noinline))
uint8_t myeid_generate_rsa_key(uint8_t * message, struct iso7816_response *r)
{
	uint16_t k_size;
	uint16_t ret, err;
	struct rsa_crt_key key;
// check user suplied data (if any)
	if (M_P3) {

		// private RSA exponent in APDU (MyEID allow only 3 or 65537)
		// in data field sequence can be found:

		// 0x30 0x03 0x02 0x01 0x03           - public exponent = 3
		// 0x30 0x05 0x02 0x03 0x01 0x00 0x01 - public exponent = 65537
		//           ^^^^ is public exponent tag, but opensc uses 0x81 here

// lot of stupid tests .. TODO do normal ASN parsing
		if (M_P3 != 7)
			return S0x6984;	//invalid data
		if (message[5] != 0x30)
			return S0x6984;	//invalid data

// Workaround ..
		if (message[7] != 0x81 && message[7] != 2)
			return S0x6984;	//invalid data

// allow only matching lengths..
		if (message[6] != 5)
			return S0x6984;	//invalid data
// test for 65537 ..
		if (message[8] != 3)
			return S0x6984;	//invalid data

		if (message[9] != 1)
			return S0x6984;	//invalid data
		if (message[10] != 0)
			return S0x6984;	//invalid data
		if (message[11] != 1)
			return S0x6984;	//invalid data
	}
// user data are checked to public exponent 65537, even user does not specify
// public exponent, for now always 65537 public exponent is used

// key size is checked in rsa_keygen()
	k_size = fs_get_file_size();
	if (check_rsa_key_size(k_size))
		return S0x6981;	//icorrect file type

	card_io_start_null();
	// return: dP, dQ, qInv and d in  struct rsa_crt_key
	//         P,Q                in message
	//         modulus            in r->data
	ret = rsa_keygen(message + 4, r->data, &key, k_size);

	if (ret == 0)
		return S0x6a82;	// file not found ..
// save key parts into file
#ifndef USE_P_Q_INV
	message[2] = KEY_RSA_p | KEY_GENERATE;
	message[3] = ret;
	err = fs_key_write_part(message + 2);
	if (err != S_RET_OK) {
		DPRINT("Unable to write KEY_RSA_p\n");
		return err;
	}

	message[128 + 2] = KEY_RSA_q | KEY_GENERATE;
	message[128 + 3] = ret;
	err = fs_key_write_part(message + 128 + 2);
	if (err != S_RET_OK) {
		DPRINT("Unable to write KEY_RSA_q\n");
		return err;
	}
#else
	message[2] = KEY_RSA_p | KEY_GENERATE;
	message[3] = ret;
	err = key_preproces(message + 2, ret);
	if (err != S_RET_OK) {
		DPRINT("Unable to write KEY_RSA_p and precalc data\n");
		return err;
	}

	message[128 + 2] = KEY_RSA_q | KEY_GENERATE;
	message[128 + 3] = ret;
	err = key_preproces(message + 128 + 2, ret);
	if (err != S_RET_OK) {
		DPRINT("Unable to write KEY_RSA_q and precalc data\n");
		return err;
	}
#endif
	memcpy(message + 4, (uint8_t *) & key.dP, ret);	//dP
	message[2] = KEY_RSA_dP | KEY_GENERATE;
	err = fs_key_write_part(message + 2);
	if (err != S_RET_OK) {
		DPRINT("Unable to write KEY_RSA_dP\n");
		return err;
	}

	memcpy(message + 4, (uint8_t *) & key.dQ, ret);	//dQ
	message[2] = KEY_RSA_dQ | KEY_GENERATE;
	err = fs_key_write_part(message + 2);
	if (err != S_RET_OK) {
		DPRINT("Unable to write KEY_RSA_dQ\n");
		return err;
	}

	memcpy(message + 4, (uint8_t *) & key.qInv, ret);	//qInv
	message[2] = KEY_RSA_qInv | KEY_GENERATE;
	err = fs_key_write_part(message + 2);
	if (err != S_RET_OK) {
		DPRINT("Unable to write KEY_RSA_qInv\n");
		return err;
	}
	// Fixed public exponent 65537
	message[2] = KEY_RSA_EXP_PUB;
	message[3] = 3;
	message[4] = 1;
	message[5] = 0;
	message[6] = 1;
	err = fs_key_write_part(message + 2);
	if (err != S_RET_OK) {
		DPRINT("Unable to write public exponent to file\n");
		return err;
	}

/*
Return plain modulus, tested on MyEID 3.3.3, RSA key 1024:

Outgoing APDU (12 bytes):
00 46 00 00 07 30 05 81 03 01 00 01
Incoming APDU (130 bytes):
B8 80 9E 31 7D 91 CC 7D 30 66 FB 9C 93 DB FD F0
92 6B B0 60 77 52 89 50 CF 03 F1 1F 24 C9 C1 3B
72 15 9B E5 17 66 5F 75 47 87 FC 2B 0D CD 44 15
B2 6E 0E 2E 87 AC 2C 91 28 E5 A2 AB 6A 6E 64 50
7E 44 76 C6 FD AA 35 5B B1 05 73 BB 47 6D 1C DB
CE 63 8B C4 19 CE 2A 04 3E 33 20 B1 C8 65 BE 47
C6 70 B0 7F E7 0A AA 5D 7E 22 42 C5 9C 92 77 E9
96 64 D9 AF 8A 38 22 D3 86 64 3C 5C D2 14 78 9D
90 00

pkcs15-tool --read-public-key:

00000000  30 81 9f 30 0d 06 09 2a  86 48 86 f7 0d 01 01 01  |0..0...*.H......|
00000010  05 00 03 81 8d 00 30 81  89 02 81 81 00 b8 80 9e  |......0.........|
00000020  31 7d 91 cc 7d 30 66 fb  9c 93 db fd f0 92 6b b0  |1}..}0f.......k.|
00000030  60 77 52 89 50 cf 03 f1  1f 24 c9 c1 3b 72 15 9b  |`wR.P....$..;r..|
00000040  e5 17 66 5f 75 47 87 fc  2b 0d cd 44 15 b2 6e 0e  |..f_uG..+..D..n.|
00000050  2e 87 ac 2c 91 28 e5 a2  ab 6a 6e 64 50 7e 44 76  |...,.(...jndP~Dv|
00000060  c6 fd aa 35 5b b1 05 73  bb 47 6d 1c db ce 63 8b  |...5[..s.Gm...c.|
00000070  c4 19 ce 2a 04 3e 33 20  b1 c8 65 be 47 c6 70 b0  |...*.>3 ..e.G.p.|
00000080  7f e7 0a aa 5d 7e 22 42  c5 9c 92 77 e9 96 64 d9  |....]~"B...w..d.|
00000090  af 8a 38 22 d3 86 64 3c  5c d2 14 78 9d 02 03 01  |..8"..d<\..x....|
000000a0  00 01                                             |..|
000000a2
*/
	reverse_string(r->data, ret * 2);
	RESP_READY(ret * 2);
}

static uint8_t ec_read_public_key(struct iso7816_response *r, uint8_t tag)
{
/*
Return seq:
TAG 0x__len__ _public_key_
return size = 2 + _public_key_size_
opensc add to this data OID of prime192v1 or prime256v1 curve.
Use public key with "uncompressed" indicator (byte 04 at start)
(size 49 for prime192v1 or size 65 for prime256v1)
*/
	uint8_t ret;
	uint8_t *here = r->data;
	uint8_t add = 2;

	*here = tag;
	here++;
// check size
	ret = fs_key_read_part(NULL, KEY_EC_PUBLIC);
	DPRINT("Public key len %d\n", ret);
	if (ret == 0)
		return S0x6985;	// conditions not satisfaied

	if (ret > 128) {
		*here = 0x81;
		here++;
		add++;
	}
	*here = ret;
	here++;
	// maximum 2*66 + header < 256 - no overrun
	// coverity[overrun-buffer-val]
	ret = fs_key_read_part(here, KEY_EC_PUBLIC);
	if (ret == 0)
		return S0x6985;	// conditions not satisfaied
	RESP_READY(ret + add);
}

// generate key, file is already selected,
// key type/size can be determined only from file size/file type
// file type 0x11:
// file size 0x0800 = 2048 RSA key
// file size 0x0400 = 1024 RSA key
// file size 0x0200 = 512 RSA key
// file type 0x22 NIST curves
// file size 0x0209 = 521 EC key secp521r1
// file size 0x0180 = 384 EC key secp384r1
// file size 0x0100 = 256 EC key prime256v1
// file size 0x00C0 = 192 EC key prime192v1
// OsEID special, file type 0x23:
// file size 0x0100 = secp256k1 key file
uint8_t myeid_generate_key(uint8_t * message, struct iso7816_response *r)
{
	uint16_t k_size;
	uint16_t ret;
	uint8_t type;

	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	if (M_P1 != 0 || M_P2 != 0)
		return S0x6a86;	//Incorrect parameters P1-P2

	type = fs_get_file_type();
	// check file type
	if (type == RSA_KEY_EF)
		return myeid_generate_rsa_key(message, r);

// EC key generation is requested.., for now no user data are allowed
	if (M_P3)
		return S0x6985;	//    Conditions not satisfied

	uint8_t size;

	struct pub_key {
		ec_point_t key;
		uint8_t type;
		uint8_t size;
		uint8_t ui;	// for 0x04 = indicate uncompressed key
		uint8_t key_bytes[2 * sizeof(bignum_t)];
	};

	// reuse r->data and message for ec param structure and fo pub_key structure
#if MP_BYTES > 96
#error MP_BYTES over 96, check all reused RAM spaces
#endif
	struct pub_key *pub_key = (struct pub_key *)r->data;
#if MP_BYTES > 48
	struct ec_param *c = alloca(sizeof(struct ec_param));
#else
	struct ec_param *c = (struct ec_param *)(message);
#endif
// get key size (from file size) - 192, 256, 384, 521 bits
// also check key file type (0x22, 0x23)
	k_size = fs_get_file_size();
	if (check_ec_key_file(k_size, type))
		return S0x6985;	//    Conditions not satisfied

	card_io_start_null();

	DPRINT("Generating key, selected file 0x%04x, key size %d bits\n",
	       fs_get_selected(), k_size);

	if (0 == prepare_ec_param(c, &(pub_key->key), (k_size + 7) / 8)) {
		DPRINT("Wrong EC parameteres\n");
		return S0x6985;	//    Conditions not satisfied
	}
	if (ec_key_gener(&(pub_key->key), c)) {
		DPRINT("Key wrong\n");
		return S0x6985;	//    Conditions not satisfied
	}
	// reverse key
	reverse_string((uint8_t *) & (c->working_key), c->mp_size);

	reverse_copy((uint8_t *) & (pub_key->key_bytes),
		     (uint8_t *) & (pub_key->key.X), c->mp_size);
	reverse_copy(c->mp_size + (uint8_t *) & (pub_key->key_bytes),
		     (uint8_t *) & (pub_key->key.Y), c->mp_size);

	// function for write key inspect size of key and checks ACL ..
	// (based on actually selected file)

	c->curve_type = KEY_EC_PRIVATE | KEY_GENERATE;
	size = c->mp_size;
	// warning, this depend on struct ec_param entries
	ret = fs_key_write_part((uint8_t *) & (c->curve_type));
	if (ret != S_RET_OK)
		return ret;

	// store public key with 0x04 uncompressed indicator
	size = size * 2 + 1;
	pub_key->type = KEY_EC_PUBLIC | KEY_GENERATE;
	pub_key->size = size;
	pub_key->ui = 4;

	ret = fs_key_write_part((uint8_t *) (pub_key) + offsetof(struct pub_key, type));
	if (ret != S_RET_OK)
		return ret;
	return ec_read_public_key(r, 0x86);
}

static uint8_t ecc_param(uint8_t v, uint8_t * response, struct iso7816_response *r)
{
	struct ec_param c;
	ec_point_t p;
	uint8_t len;

	len = prepare_ec_param(&c, &p, 0);
	if (!len)
		return S0x6a88;	//Referenced data (data objects) not found

	switch (v) {
	case 0x81:
		memcpy(response, &c.prime, len);
		break;
	case 0x82:
		memcpy(response, &c.a, len);
		break;
	case 0x83:
		memcpy(response, &c.b, len);
		break;
	case 0x84:
		memcpy(response, &p.Y, len);
		memcpy(response + len, &p.X, len);
		len *= 2;
		break;
	case 0x85:
		memcpy(response, &c.order, len);
		break;
	}
	reverse_string(response, len);
	RESP_READY(len);
}

/*

get/put data emulation of MYEID card

*/
uint8_t myeid_get_data(uint8_t * message, struct iso7816_response *r)
{
	uint16_t ret;
	uint8_t *response = r->data;

	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	if (M_P1 != 1)
		return S0x6a88;	//Referenced data (data objects) not found

	if ((M_P2 & 0xb0) == 0xb0)
		return fs_return_pin_info(M_P2 & 0x0f, r);

	if (M_P2 >= 0x81 && M_P2 <= 0x85)
		return ecc_param(M_P2, response, r);

	switch (M_P2) {
	case 0xa0:
		get_constant(response, N_CARD_ID);
#ifdef HW_SERIAL_NUMBER
		get_HW_serial_number(response + 8);
#endif
		RESP_READY(20);
	case 0xa1:
	case 0xa2:
	case 0xa3:
	case 0xa4:
	case 0xa5:
	case 0xa6:
		return fs_list_files(M_P2, r);
	case 0xaa:
		get_constant(response, N_CARD_CAP_ID);
		RESP_READY(11);
	case 0xac:
		ret = fs_get_access_condition();
		response[0] = ret >> 8;
		response[1] = ret & 0xff;
		RESP_READY(2);
	case 0:
		// info data for key
// 6 bytes
// 0x9200 - CRT algo identifier
// 0xMMMM - bits of modulus
// 0xEEEE - size of publix exponent
		response[0] = 0x92;
		response[1] = 0;
		ret = fs_key_read_part(NULL, KEY_RSA_EXP_PUB);
		DPRINT("ret=%d\n", ret);
		if (!ret)
			return S0x6a88;	//Referenced data (data objects) not found
		// TODO here for 65537 24 bit is calculated, but 17 bits is enough
		ret = ret * 8;
		response[2] = ret >> 8;
		response[3] = ret & 0xff;
		ret = fs_key_read_part(NULL, KEY_RSA_p);
		DPRINT("ret=%d\n", ret);
		if (!ret)
			return S0x6a88;	//Referenced data (data objects) not found
		ret = ret * 16;
		response[4] = ret >> 8;
		response[5] = ret & 0xff;
		RESP_READY(6);
	case 1:
		// return modulus
#if RSA_BYTES > 128
#error posible overflow in response buffer
#endif
		ret = rsa_modulus(response);
		if (!ret)
			return S0x6a88;	//Referenced data (data objects) not found
		ret *= 2;
		reverse_string(response, ret);
		RESP_READY(ret);
	case 2:
		// public exponent
		ret = fs_key_read_part(response, KEY_RSA_EXP_PUB);
		if (!ret)
			return S0x6a88;	//Referenced data (data objects) not found
		RESP_READY(ret);

//read public key
	case 0x86:
		{
			DPRINT("Reading public EC key\n");
			return ec_read_public_key(r, 0x30);	//0x30 = TAG sequence
		}
	default:
		return S0x6a88;	//Referenced data (data objects) not found
	}
}

static uint8_t myeid_upload_ec_key(uint8_t * message, uint16_t size)
{
	DPRINT("%s %02x %02x %02x\n", __FUNCTION__, M_P1, M_P2, M_P3);
	uint8_t key_bytes = (size + 7) / 8;
	// EC key private key upload
	if (M_P2 == 0x87)
		message[3] = KEY_EC_PRIVATE;
	else if (M_P2 == 0x86) {
		// public key - two numbers and uncompressed indicator
		key_bytes = 2 * key_bytes + 1;
		message[3] = KEY_EC_PUBLIC;
		// check uncompressed indicator
		if (message[5] != 4)
			return S0x6985;	//    Conditions not satisfied
	} else
		return S0x6a86;	// Incorrect parameters P1-P2
	if (key_bytes != M_P3)
		return S0x6700;	// Incorrect length
	card_io_start_null();
	return fs_key_write_part(message + 3);
}

static uint8_t myeid_upload_rsa_key(uint8_t * message, uint16_t size)
{
	uint16_t test_size;
	uint8_t m_size = M_P3;

	DPRINT("uloading key type %02x\n", M_P2);

	// key part may start with 0x00 and M_P3 is incremented by one (65 bytes for 1024 key)
	if ((m_size & 1) && (M_P2 != 0x81)) {
		DPRINT("M_P3 is odd, message[5] = 0x%02x\n", message[5]);
		if (message[5] != 0)
			return S0x6985;	//    Conditions not satisfied
		m_size--;
		message[5] = m_size;
		message[4] = message[3];
		message++;
	}

	switch (M_P2) {
// private exponent is not needed for CRT
// modulus is not needed, card calculates modulus from P and Q
	case KEY_RSA_MOD_p1:
	case KEY_RSA_MOD_p2:
	case KEY_RSA_EXP_p1:
	case KEY_RSA_EXP_p2:
	case KEY_RSA_EXP:
	case KEY_RSA_MOD:
		return S_RET_OK;
	case KEY_RSA_p:
	case KEY_RSA_q:
	case KEY_RSA_dP:
	case KEY_RSA_dQ:
	case KEY_RSA_qInv:
		test_size = 16 * m_size;
		break;
	case KEY_RSA_EXP_PUB:
// allow any size of public exponet, if this size does not fit in key file, this fail in fs_key_write_part ()
		test_size = size;
		break;
	default:
		return S0x6985;	//    Conditions not satisfied
	}
	if (size != test_size) {
		DPRINT("write size, key file %d size of part %d\n", size, m_size);
		return S0x6700;	//Incorrect length
	}
	card_io_start_null();

	reverse_string(message + 5, m_size);
#ifdef USE_P_Q_INV
	// calculate n_
	if (M_P2 == KEY_RSA_p || M_P2 == KEY_RSA_q)
		return key_preproces(message + 3, m_size);
#endif
	return fs_key_write_part(message + 3);
}

static uint8_t myeid_upload_keys(uint8_t * message)
{
	uint16_t k_size;
	uint8_t type;

	DPRINT("%s \n", __FUNCTION__);
// key upload, file is already selected,

	k_size = fs_get_file_size();
	if (!k_size)
		return S0x6a82;	//file not found

// EC key is stored to file with type 0x22, RSA to type 0x11
// AES 0x29, DES 0x19

	type = fs_get_file_type();
	DPRINT("Key size %d, type=0x%02x\n", k_size, type);

// DES, AES key
	if (type == DES_KEY_EF) {
#if ENABLE_DES56
		if (k_size != 56 && k_size != 64 && k_size != 128 && k_size != 192)
#else
		if (k_size != 64 && k_size != 128 && k_size != 192)
#endif
			return S0x6700;	//Incorrect length
		return fs_key_write_part(message + 3);
	}
	if (type == AES_KEY_EF) {
		if (k_size != 128 && k_size != 192 && k_size != 256)
			return S0x6700;	//Incorrect length
		return fs_key_write_part(message + 3);
	}
	// file type is checked in check_ec_key_file(),
	// size and key part type is checked in myeid_upload_ec_key()
	if (0 == check_ec_key_file(k_size, type))
		return myeid_upload_ec_key(message, k_size);

	// size and key part type is checked in myeid_upload_rsa_key()
	if (type == RSA_KEY_EF)
		if (0 == check_rsa_key_size(k_size))
			return myeid_upload_rsa_key(message, k_size);

	return S0x6981;		//icorrect file type
}

uint8_t myeid_put_data(uint8_t * message, __attribute__((unused))
		       struct iso7816_response *r)
{
	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	if (M_P1 != 1)
		return S0x6a86;	// incorrect P1/P2
	//initialize applet
	if (M_P2 == 0xe0) {
		// MyEID difference - MyEID accept only 8 bytes here, OsEID accept 0-255 bytes here,
		// For LC=5, DF 5015 is not created (MyEID always create DF 5015)
		DPRINT
		    ("P3=%d, Filesystem size %d, MF ACL=%02X%02X%02X 5015 ACL=%02X%02X%02X\n",
		     M_P3, message[5] * 256 + message[6], message[7], message[8],
		     message[9], message[10], message[11], message[12]);
		// this is  long operation, start sending NULL
		card_io_start_null();
		return fs_erase_card(message + 4);
	}
	//initialize PIN
	if (M_P2 > 0 && M_P2 < 15) {
		if (M_P3 < 0x10 || M_P3 > (16 + 7 + 24))
			return S0x6700;	//Incorrect length
		DPRINT("initialization of PIN %d\n", M_P2);
		return fs_initialize_pin(message + 3);
	}
	// Upload keys, Nc > 0 (checked in APDU parser)

	if ((M_P2 >= 0x80 && M_P2 <= 0x8B) || (M_P2 == 0xA0))
		return myeid_upload_keys(message);

	return S0x6a81;		//Function not supported
}

uint8_t myeid_activate_applet( __attribute__((unused)) uint8_t * message, __attribute__((unused))
			      struct iso7816_response *r)
{
	//TOTO check applet name
	fs_set_lifecycle();
	return (S_RET_OK);
}
