/*
    iso7816.c

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

    iso 7816  command parser

*/
/*
 Coding style is adjusted to generate small code on AVR (avr-gcc).  AVR does
 not provide instructions for addressing with offset and a base, passing
 arguments as pointer to one structure generates bigger code as passing more
 arguments.
*/
/* 1.1.2021 coding style is changed to "linux" all new code is indented by
indent -linux -l100
*/

#define DEBUG_ISO7816
#include "debug.h"

#if !defined(PROTOCOL_T0) && !defined(PROTOCOL_T1)
#define PROTOCOL_T1
#define PROTOCOL_T0
#endif

#include <stdint.h>
#include <string.h>

#include "rnd.h"
#include "iso7816.h"
#include "fs.h"
#include "myeid_emu.h"
#include "card_io.h"
#ifdef CARD_TESTS
#include "mem_device.h"
#endif

#define M_CLASS message[0]
#define M_CMD message[1]
#define M_P1 message[2]
#define M_P2 message[3]
// same position two names, use Nc if P3 is really Nc
#define M_P3 message[4]
#define M_Nc message[4]

#ifndef T1_IFS
#define T1_IFS 254
#endif

struct iso7816_response iso_response __attribute__((section(".noinit")));

#ifdef T1_TRANSPORT
#include "T1_transport.c"
// disable inlining (to save RAM)
static void __attribute__((noinline)) card_io_tx1(uint8_t * message, uint16_t ret)
{
	uint8_t t_buffer[5 + T1_IFS];

	T1_parser(&t1, t_buffer, 0, message, ret);
}
#endif

static void return_status(uint8_t status)
{
	// reuse P1,P2 as buffer for status (optionaly for protocol T0 use INS as procedure byte)
	uint8_t *message = iso_response.input + 2;
	uint16_t Ne, Na;
	uint16_t ret = 2;

	Ne = iso_response.Ne;
	if (Ne == 0)
		iso_response.len16 = 0;
	Na = iso_response.len16;

// stop sending NULL bytes
	card_io_stop_null();

	message[0] = 0x60 | (status >> 4);
	message[1] = 0;

	switch (status) {
		// here low byte defaults to 0
	case S_RET_OK:
		message[0] = 0x90;
		break;
	case S0x6700:
	case S0x6b00:
	case S0x6d00:
	case S0x6e00:
	case S0x6f00:
		// error code, stop APDU chaining if running
		iso_response.chaining_state = APDU_CHAIN_INACTIVE;
		break;
	case S0x6100:		// low byte - how many bytes are still available
#ifdef PROTOCOL_T0
		// if chaining is running drop already parsed APDU
		iso_response.chain_len = 0;
		DPRINT("remaining bytes in buffer %d\n", Na);
		// message[1] is already 0
		if (Na < 256)
			message[1] = Na;
		// for T0 return SW, for T1 return data, then SW
		if (iso_response.protocol == 0)
			break;
#endif
		// fall through
	case S_RET_GET_RESPONSE:
		// if chaining is running drop already parsed APDU
		iso_response.chain_len = 0;
		DPRINT("returning APDU with data, %d bytes available, Ne=%d\n", Na, Ne);
		// Ne: maximum number of bytes expected in the response data field
		// Na: exact number of available data bytes

		// ISO77816 allow us to send fewer bytes as requested by Ne
		// OsEID specific, return max 256 bytes, and signalize remaining bytes
		// if needed (for short/extended APDU)
		if (Ne > 256)
			Ne = 256;
		if (Ne > Na)
			Ne = Na;
		memcpy(message, iso_response.data, Ne);
		// calculate how many data is now in buffer
		Na -= Ne;
		if (Na == 0) {
			//mark data already sended
			message[Ne] = 0x90;
			message[Ne + 1] = 0;
		} else {
			message[Ne] = 0x61;
			if (Na <= 255)
				message[Ne + 1] = Na;
			else
				message[Ne + 1] = 0;
			memcpy(iso_response.data, iso_response.data + Ne, Na);
		}
		iso_response.len16 = Na;
		DPRINT("sending response\n");
		ret = Ne + 2;
#ifdef PROTOCOL_T0
// send response APDU (for protocol 0 prepend procedure byte "message" is pointer to P1..)
		if (iso_response.protocol == 0) {
			ret++;
			message--;
		}
#endif
		break;

		// for all other codes low byte defaults to 0x8X,
		// except for codef 0x63XX, here low byte defaults 0xCX
	default:
		// error code, stop APDU chaining if running
		iso_response.chaining_state = APDU_CHAIN_INACTIVE;

		if ((status & 0xf0) == 0x30) {
			// 63
			message[1] = 0xc0 | (status & 0xf);
		} else {
			// (60), 62,64,65,66,68,69,6a
			message[1] = 0x80 | (status & 0xf);
		}
	}

// return response ADPU and status to reader
#ifdef T1_TRANSPORT
	if (iso_response.protocol == 0)
		card_io_tx(message, ret);
	else
		card_io_tx1(message, ret);
#else
	card_io_tx(message, ret);
#endif
	return;
}

static uint8_t iso7816_get_response(uint8_t * message, struct iso7816_response *r)
{
	DPRINT("%s %02x %02x %02X %d\n", __FUNCTION__, M_P1, M_P2, M_P3, r->Ne);
	if (M_P1 != 0 || M_P2 != 0) {
		DPRINT("incorrect p1,p2\n");
		return S0x6a86;	//incorrect P1,P2
	}
	if (r->len16 == 0) {
		DPRINT("data already returned / no data to return \n");
		return S0x6985;	//Failure: Not allowed - no data to response
	}
	return S_RET_GET_RESPONSE;
}

static uint8_t iso7816_verify(uint8_t * message, __attribute__((unused))
			      struct iso7816_response *r)
{
	DPRINT("%s %02x %02x %02X\n", __FUNCTION__, M_P1, M_P2, M_P3);

	if (M_P1 != 0)
		return S0x6a86;	// Incorrect parameters P1-P2

	// TODO latest ISO7816-4 (2013?) if P1=0xff deauth of pin P2

	return fs_verify_pin(message + 3);
}

static uint8_t iso7816_get_challenge(uint8_t * message, struct iso7816_response *r)
{
	uint8_t rlen;

	DPRINT("%s %02x %02x %02X\n", __FUNCTION__, M_P1, M_P2, M_P3);

// TODO if P1 == 2 challange for authentification ..
	if (M_P1 != 0 || M_P2 != 0)
		return S0x6a86;	//incorrect P1,P2

// Ne > 256 is handled in APDU parser  -> Ne = 256, in this case 0
	rlen = r->Ne & 0xff;
	if (rlen == 0)
		return S0x6f00;	//no particular diagnostic (same response as from MyEID 3.3.3)
	rnd_get(r->data, rlen);
	r->len16 = rlen;
	return S0x6100;
}

static uint8_t iso7816_select_file(uint8_t * message, struct iso7816_response *r)
{
// read command parameters..
	DPRINT("select\n");

	// in all case P2 must be 0 (return FCI) except 0x0c (do not return any template)
	if (M_P2 == 0x0c)
		r->Ne = 0;
	else if (M_P2 != 0)
		return S0x6a86;	//Incorrect parameters P1-P2

	if (!M_Nc) {
// ISO special case, select MF if P1,P2 == 00 00 and data field is empty
		if (M_P1 == 0 && M_P2 == 0) {
			return fs_select_mf(r);
		}
		if (M_P1 == 3) {
			return fs_select_parent(r);
		}
		return S0x6700;	//incorrect data len
	}
// select by path ..
	if ((M_P1 & 0xfe) == 8) {
		if (M_Nc < 2)
			return S0x6a87;	// len inconsistent with P1
		if (M_Nc & 1)
			return S0x6a87;	// len inconsistent with P1
		if (M_P1 & 1)
			return fs_select_by_path_from_df(message + 4, r);
		else
			return fs_select_by_path_from_mf(message + 4, r);
	}
// select by DF name (all names must be unique)
	if (M_P1 == 4) {
		if (M_Nc < 1 || M_Nc > 16)
			return S0x6a87;	// len inconsistent with P1
		else
// send len and name as first arg, select by name, position by P2
			return fs_select_by_name(message + 4, r);
	}
// rest commands  in all case LC must be 2
	if (M_Nc != 2) {
		return S0x6a87;	// len inconsistent with P1
	}
// select EF/DF by id .. (match M_P1 in range 0..2)
	uint16_t id = (message[5] << 8) | message[6];

	DPRINT("message ID %04x\n", id);
	if (M_P1 == 0) {
// ISO - if P1,P2 == 00 00 and data field is empty (already checked few lines above)
// or equal to 3f00 select MF
		if (M_P2 == 0 && id == 0x3f00)
			return fs_select_mf(r);
		else
			return fs_select_0(id, r);
	}
	if (M_P1 == 1)
		return fs_select_df(id, r);
	if (M_P1 == 2)
		return fs_select_ef(id, r);

// P1/P2 out of range
	return S0x6a86;		//Incorrect parameters P1-P2
}

static uint8_t iso7816_read_binary(uint8_t * message, struct iso7816_response *r)
{
	DPRINT("%s P1: %02x P2: %02x LC: %02x\n", __FUNCTION__, M_P1, M_P2, M_P3);

	if (M_P1 & 0x80)
		return S0x6a86;	//Incorrect parameters P1-P2 - better alt. function not supported ?

	// Ne from iso_response ..
	return fs_read_binary((M_P1 << 8) | M_P2, r);
}

static uint8_t iso7816_update_binary(uint8_t * message, __attribute__((unused))
				     struct iso7816_response *r)
{
	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	if (M_P1 & 0x80)
		return S0x6a86;	//Incorrect parameters P1-P2 - better alt. function not supported ?

	// Nc is not 0, checked in parser
	return fs_update_binary(message + 4, (M_P1 << 8) | M_P2);
}

static uint8_t iso7816_erase_binary(uint8_t * message, __attribute__((unused))
				    struct iso7816_response *r)
{

	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

// TODO: end of erased area can be specified in data field (LC=2)
// data field then contain address of 1st unerased byte in file
// do not add this function for now (due limited flash size)

//  uint16_t end = 0x7fff;
	uint16_t start;

	start = (M_P1 << 8) | M_P2;
#if 0
	if (M_Nc == 2)
		end = (message[5] << 8) | message[6];
#endif
	if ((start /*|end */ ) & 0x8000) {
		return S0x6a86;	//Incorrect parameters P1-P2
	}
	return fs_erase_binary(start /*, end */ );
}

static uint8_t iso7816_delete_file(uint8_t * message, __attribute__((unused))
				   struct iso7816_response *r)
{
	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	if (M_P1 | M_P2)
		return S0x6a86;	//Incorrect parameters P1-P2

// TODO, LC==2, data field contain file ID to be deleted (From ETSI TS 102 222 V4.2.0 (2005-10))
// Nc is not 0, checked in parser
	return fs_delete_file();
}

static uint8_t iso7816_create_file(uint8_t * message, __attribute__((unused))
				   struct iso7816_response *r)
{
	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	if (M_P1 != 0 || M_P2 != 0)
		return S0x6a86;	//Incorrect parameters P1-P2

	// Nc is not 0, checked in parser
	return fs_create_file(message + 4);
}

static uint8_t change_reference_data(uint8_t * message, __attribute__((unused))
				     struct iso7816_response *r)
{
	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);
	if (M_P1 != 0) {
		return S0x6a86;	// Incorrect parameters P1-P2
	}
	// Nc is not 0, checked in parser
	return fs_change_pin(message + 3);
}

static uint8_t reset_retry_counter(uint8_t * message, __attribute__((unused))
				   struct iso7816_response *r)
{
	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	if (M_P1 != 0) {
		return S0x6a86;	// Incorrect parameters P1-P2
	}
	// Nc is not 0, checked in parser
	return fs_reset_retry_count(message + 3);
}

static uint8_t deauthenticate(uint8_t * message, __attribute__((unused))
			      struct iso7816_response *r)
{

	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

// M_P3 /Nc is 0 (checked in parser)

	uint8_t pin = M_P2;

	if (M_P1 == 0) {
		if (M_P2 > 14)
			return S0x6a86;	// Incorrect parameters P1-P2
	} else if (M_P1 == 0xa0)	// deauth admin state
	{
		if (M_P2 != 0)
			return S0x6a86;	// Incorrect parameters P1-P2
		pin = M_P1;
	} else if (M_P1 == 0xb0)	// deauth global unblocker
	{
		if (M_P2 != 0)
			return S0x6a86;	// Incorrect parameters P1-P2
		pin = M_P1;
	} else {
		return S0x6a86;	// Incorrect parameters P1-P2
	}

	fs_deauth(pin);
	return S_RET_OK;
}

static uint8_t w_fs_key_change_type(uint8_t * message, __attribute__((unused))
				    struct iso7816_response *r)
{
	// Nc > 0, Ne == 0 - checked in parser
	// test P1, P2 for zero
	if (M_P1 | M_P2) {
		DPRINT("%s incorrect P1, P2\n", __FUNCTION__);
		return S0x6a86;	//incorrect P1,P2
	}
	return (fs_key_change_type());
}

// P3 is Ne in T0 protocol
#define ATTR_T0_P3NE 0x10
// T0 protocol can not handle Le for CASE 4, use this flag to set Ne=256
#define ATTR_T0_Le_present 0x20
// if command allow use of Nc > 255 .. (P3 can be used as Nc only if this flag is not set)
// this flag also allow use of Ne > 256 for extended APDU, Ne is clamped to 256 if this flag
// is not set. This is not an extended APDU flag, APDU chaining can generate Nc > 255.
#define APDU_LONG  0x80
// if set, Nc/Ne can not be zero
#define APDU_Nc 0x01
#define APDU_Ne 0x02
// INS need zero in Nc (no DATA field in APDU)
#define APDU_Lc_empty 0x04
// INS need zero in Ne (does not return any data)
#define APDU_Le_empty 0x08

struct f_table {
	uint8_t attr;
	uint8_t ins;
	 uint8_t(*func) (uint8_t * message, struct iso7816_response * r);
};
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#ifdef __AVR__
static const struct f_table __flash cla00[] = {
#else
static struct f_table cla00[] = {
#endif
	{APDU_Lc_empty, 0x0e, iso7816_erase_binary},	// iso7816-4/7.2.7  Ne = 0, Nc 0 (in future 0 or 2, end of erased data in data field)
	{APDU_Le_empty, 0x20, iso7816_verify},	// iso7816-4/7.5.6  Ne = 0
	{APDU_Le_empty, 0x22, security_env_set_reset},	// iso7816-4/7.5,11 Ne = 0
	{APDU_Nc | APDU_Le_empty, 0x24, change_reference_data},	// iso7816-4/7.5.7  Ne = 0
	{ATTR_T0_Le_present | APDU_LONG, 0x2a, security_operation},	// iso7816-8....???, Nc = 0 for wrap operation,
	{APDU_Nc | APDU_Le_empty, 0x2c, reset_retry_counter},	// iso7816-4/7.5.10 Ne = 0
	{APDU_Lc_empty | APDU_Le_empty, 0x2e, deauthenticate},	// MyEID doc
	{APDU_Le_empty, 0x44, myeid_activate_applet},	// MyEID doc
	{ATTR_T0_Le_present, 0x46, myeid_generate_key},	// iso7816-8
	{APDU_Ne | APDU_Lc_empty | ATTR_T0_P3NE, 0x84, iso7816_get_challenge},	//iso7816-4/7.5.3 Nc = 0
	{ATTR_T0_Le_present | APDU_Nc, 0x86, myeid_ecdh_derive},
	// Nc 0..255, Ne 1..256
	{ATTR_T0_Le_present, 0xa4, iso7816_select_file},
	{APDU_Ne | APDU_Lc_empty | ATTR_T0_P3NE, 0xb0, iso7816_read_binary},	// iso7816-4/7.2.3 Nc = 0,  Nc > 0 for 0xb1
	{APDU_Ne | APDU_Lc_empty | ATTR_T0_P3NE, 0xc0, iso7816_get_response},	// iso7816-4/7.6.2 Nc = 0
	//{0, 0xc2, iso7816_envelope},
	{APDU_Ne | APDU_Lc_empty | ATTR_T0_P3NE, 0xca, myeid_get_data},	// iso7816-4/7.4.2 Nc = 0, Nc > 0 for 0xcb...
	{APDU_Nc | APDU_Le_empty, 0xd6, iso7816_update_binary},	// iso7816-4/7.2.5 Ne = 0, Nc 1..255
	{APDU_Nc | APDU_Le_empty | APDU_LONG, 0xda, myeid_put_data},	// iso7816-4/7.4.3 Ne = 0, Nc 1..256 (extended APDU)
	{APDU_Nc | APDU_Le_empty, 0xe0, iso7816_create_file},	// Nc 1..255  Ne 0
	{APDU_Le_empty, 0xe4, iso7816_delete_file},	// Nc 0, Ne 0 / Nc 2, Ne 0 in future (ID in data field)
	{0xff}
};

#ifdef __AVR__
static const struct f_table __flash cla80[] = {
#else
static struct f_table cla80[] = {
#endif
	{APDU_Nc | ATTR_T0_Le_present | APDU_LONG, 0x2a, security_operation},	// iso7816-8....???
	{APDU_Nc | APDU_Le_empty, 0xda, w_fs_key_change_type},	// proprietary ..
	{0xff}
};

#pragma GCC diagnostic pop

static uint8_t parse_apdu(uint16_t input_len)
{
	uint8_t *message = &iso_response.input[0];
	struct iso7816_response *r = &iso_response;
	uint8_t cla = message[0];
	uint8_t ins = message[1];
	uint8_t Lc;
	uint16_t Nc, Ne;
	uint8_t ret;
	uint8_t offset = 5;

#ifdef PROTOCOL_T1
	if (input_len < 4)
		return S0x6700;
#endif
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
	if (r->protocol == 0)
#endif
#ifdef PROTOCOL_T0
		if (input_len != 5)
			return S0x6700;
#endif
	// PTS is handled in io layer, here is already available:
	// 5 bytes for protocol 0
	// 4 or more bytes for protocol 1

	// invalidate response buffer in case if no "get_response" call
	// do this for any CLA

	if (ins != 0xc0)
		r->len16 = 0;

	// MyEID driver in OpenSC uses CLA 0xA0 for DELETE FILE
	// adapt to CLA 0 - as specified in MyEID reference manual
	if (cla == 0xa0 && ins == 0xe4)
		cla = 0;

#ifdef __AVR__
	const __flash struct f_table *c;
#else
	const struct f_table *c;
#endif
	switch (cla) {
// chaining allowed only for CLA 0, this also prevents change of CLA inside chain
// there is of course way to start chain with 0x10 and end chain with 0x80, this
// violates ISO but class 0x80 is proprietary...
	case 0:
	case 0x10:
		c = &cla00[0];
		break;
	case 0x80:
		c = &cla80[0];
		break;
	default:
		return S0x6e00;	// CLA not supported
	}

	DPRINT("searching INS %02x\n", ins);
	for (;; c++) {
		if (c->attr == 0xff)
			return S0x6d00;	// CLA ok but INS not programmed or invalid
		if (c->ins == ins)
			break;
	}

	DPRINT("input len = %d\n", input_len);
	// defaults for Nc and Ne (CASE 1 APDU, T1 protocol)
	Nc = 0;
	Ne = 0;
#ifdef PROTOCOL_T1
	if (input_len == 4) {
		DPRINT("T1 CASE 1S\n");
		// fix P3
		message[4] = 0;
	} else
#endif				// T1
	{
		// P3 is present, use it as Lc/Le
		Lc = M_P3;
		if (Lc) {
#ifdef PROTOCOL_T0
			if (r->protocol == 0) {
				// use INS to determine CASE 2S or CASE 3S/4S
				if (ATTR_T0_P3NE & c->attr) {
					// do not send procedure byte here!
					DPRINT("T0 CASE 2S Ne in range 1..255\n");
					Ne = Lc;
				} else {
					DPRINT("T0 CASE 3S/4S reading DATA field %d bytes\n", Lc);;
					// INS is used as procedure byte ISO7816-3/10.3.3
					card_io_tx(message + 1, 1);
					// Lc is < 256, buffer is large enough
					if (Lc != card_io_rx(message + 5, Lc))
						return S0x6700;	// wrong length
					// Le is not awailable, use INS attribute to set Ne
					if (c->attr & ATTR_T0_Le_present)
						Ne = 256;
					Nc = Lc;
				}
			}
#endif				// T0
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
			else
#endif
#ifdef PROTOCOL_T1
			{
				// protocol 1, P3 > 0
				if (input_len == 5) {
					DPRINT("T1 CASE 2S\n");
					Ne = Lc;
				} else if (Lc + 5 == input_len) {
					DPRINT("T1 CASE 3S\n");
					Nc = Lc;
				} else if (Lc + 6 == input_len) {
					DPRINT("T1 CASE 4S\n");
					Nc = Lc;
					Ne = message[input_len - 1];
					if (Ne == 0)
						Ne = 256;
				} else {
					DPRINT
					    ("APDU (short), protocol T1, input length %d, Lc=%d\n",
					     input_len, Lc);
					return S0x6700;	// wrong length
				}
			}
#endif				// T1
		} else {
			// P3 present, and is zero, T0 or T1
			if (input_len == 5) {
				//CASE 2S
				DPRINT("T0/1 CASE 2S, Ne=256\n");
				Ne = 256;
			}
#ifdef PROTOCOL_T1
			// Protocol T1, len > 5
			else {
				uint16_t LcExtended;

				// extended cases 2E,3E,4E
				if (input_len < 7) {
					DPRINT
					    ("Protocol T1, extended case APDU, length below 7 (%d)\n",
					     input_len);
					return S0x6700;	// wrong length
				}
				LcExtended = message[5] << 8 | message[6];
				if (!LcExtended) {
					// case 2E or fail
					if (input_len == 7) {
						DPRINT("T1 CASE 2E, Le=0 (65535)\n");
						Ne = 65535;
					} else {
						DPRINT("T1, Nc=0 for CASE 3E/4E\n");
						return S0x6700;	// wrong length
					}
				} else {
					// Lc(Le) > 0, check Le field and corresponding APDU length
					if (input_len == 7) {
						DPRINT("T1 CASE 2E\n");
						Ne = LcExtended;
					} else {
						// we need to move APDU data form message+7 to message+5
						// here only offset of data is incremented, move is done below
						offset += 2;
						Nc = LcExtended;

						if (input_len == 9 + Nc) {
							DPRINT("T1 CASE 4E\n");
							Ne = message[input_len - 2] << 8 |
							    message[input_len - 1];
							// warning 65536 here, but Ne is only 16 bites long (not real limit)
							if (Ne == 0)
								Ne = 65535;
						} else if (input_len == 7 + Nc) {
							DPRINT("T1 CASE 3E\n");
						} else {
							DPRINT
							    ("T1, wrong APDU length for cases 3E/4E\n");
							return S0x6700;	// wrong length
						}
					}
				}
			}
#endif				//  PROTOCOL_T1
		}
	}
// APDU chaining
//===============
// errors are handled in return_status() - chain is terminated
	if (r->chaining_state & APDU_CHAIN_RUNNING) {
		DPRINT("APDU chaining: running\n");
		r->chaining_state = APDU_CHAIN_ACTIVE;
// this may violate the ISO 7816, but this code allow us to insert GET RESPONSE inside
// running chain to read intermediate results
		if (ins == 0xc0) {
			DPRINT("APDU chaining: GET RESPONSE inserted in chain\n");
			if (Nc) {
				DPRINT("APDU chaining: Nc in GET RESPONSE\n");
				return S0x6883;	// expected last command of chain
			}
			// if GET RESPONSE ends with error, chain is terminated
		} else {
			if (r->chaining_ins != ins) {

				DPRINT("APDU chaining: INS changed %02x %02x\n",
				       r->chaining_ins, ins);
				return S0x6883;	// expected last command of chain
			}
			// chaining is allowed only for CASE 3S/E 4S/E
			// check Nc field, if zero, this is CASE 1,2S/E
			if (!Nc) {
				DPRINT("APDU chaining: no data in APDU?\n");
				return S0x6700;	// wrong length
			}
			if (cla & 0x10) {
				DPRINT("APDU chaining: continuing\n");
			} else {
				DPRINT("APDU chaining: last APDU in chain\n");
				r->chaining_state = APDU_CHAIN_LAST;
			}
		}
	} else {
		r->chain_len = 0;	// no chaining active, clear chain_len
		r->chaining_state = APDU_CHAIN_INACTIVE;
		if (cla & 0x10) {
			DPRINT("APDU chaining: start\n");
			// chaining is allowed only for CASE 3S/E 4S/E
			// check Nc field, if zero, this is CASE 1,2S/E
			if (!Nc) {
				DPRINT("APDU chaining: no data in APDU?\n");
				return S0x6700;	// wrong length
			}
			// TODO save P1,P2
			r->chaining_ins = ins;
			r->chaining_state = APDU_CHAIN_START;
		} else {
			DPRINT("APDU chaining: not active\n");
		}
	}
// APDU chaining END
// =================
	// concatenate this APDU with previous APDU (if chain is not running chain_len = 0)
	// then only this single APDU is in APDU input buffer
	// this does not affect GET_RESPONSE, because always Nc is 0
	// and this does not affect chaning, because chained ADPU has Nc > 0
	if (Nc) {
		if (r->chain_len + Nc > APDU_RESP_LEN) {
			DPRINT("No space in buffer\n");
			return S0x6700;	// wrong length
		}
		// offset is set to 5 or 7 (extended APDU)
		memcpy(r->data + r->chain_len, message + offset, Nc);
		// r->tmp_len point to last APDU part in chain..
		r->tmp_len = r->chain_len;
		r->chain_len += Nc;
		Nc = r->chain_len;
		HPRINT("APDU data:", r->data, Nc);
		memcpy(message + 5, r->data, Nc);
	}
// P3 is fixed below (for APDUs where Nc < 256)
// message+5 is always position of data, functions can use Ne, Nc  or P3 if P3 !=0  (P3 is then Nc 1..255)
// if function does not have APDU_LONG flag:
// if function does not accept Nc > 255, return error 0x6700
// if function does not accept Ne > 256, change Ne to 256  (TODO flag for this..)
// P3 is always Lc (not Le!!)
	if (!(c->attr & APDU_LONG)) {
		if (Nc > 255) {
			DPRINT("INS does not allow Nc > 255 (Nc=%d)\n", Nc);
			return S0x6700;	// wrong length
		}
		message[4] = Nc;
		if (Ne > 256) {
			DPRINT("INS does not allow Ne > 256, (Ne=%d) clamping Ne to 256\n", Ne);
			Ne = 256;
		}
	}
// INS does not allow Ne or need Ne
	if (Ne) {
		// Ne set
		if ((c->attr & APDU_Le_empty) && r->protocol == 1) {
			DPRINT("INS does not allow Le field\n");
			return S0x6700;	// wrong length
		}
	} else {
		// Ne = 0
		if (c->attr & APDU_Ne) {
			DPRINT("INS does not allow empty Le\n");
			return S0x6700;	// wrong length
		}
	}

// INS does not allow Nc or need Nc
	if (Nc) {
		// Nc set
		if (c->attr & APDU_Lc_empty) {
			DPRINT("INS does not allow Lc field\n");
			return S0x6700;	// wrong length
		}
	} else {
		// Nc = 0
		if (c->attr & APDU_Nc) {
			DPRINT("INS does not allow empty Lc\n");
			return S0x6700;	// wrong length
		}
	}

	DPRINT("Running command 0x%02X P3=%d Nc=%d Ne=%d\n", ins, M_P3, Nc, Ne);
	r->Nc = Nc;
	r->Ne = Ne;
/*
command uses iso7816_response as input/output
input:
	iso7816_response.input[in]		command APDU (innclusive header)
	iso7816_response.data[in,out]		command APDU (without header), place for response APDU
	iso7816_response.len16[out]		how many bytes are stored in response buffer
	iso7816_response.protocol	  	0/1 T0/T1
	iso7816_response.input[4]		Nc (0..255), for function with flag APDU_LONG iso7816_response.Nc must be used
	iso7816_response.Nc[in]			Nc in range 0.. up to APDU_CMD_LEN - 5 = 256,	0 Lc not present
	iso7816_response.Ne[in]			Ne in range 0.. 65535,       			0 Le not present

	if command generates data, data are stored into iso_response.data,
	iso_response.len16 represent number of returned data bytes (up to APDU_RESP_LEN)
	SW must be set to S0x6100

	If APDU chaining is active, command may or may not proceed input buffer.
	(this is handled in the return_status() function)
	- If command return 0x9000 status, the APDU data remain unchanged in
	  iso7816_response.data. Next APDU is then concatenated with this saved part.
	- If command return data (SW 0x61xx, r->len16 > 0), iso7816_response.data
          contain a response. APDU chain can continue but next APDU is not concatenated
          with already sprocessed APDU. The GET_RESPONSE can be inserted into chain
          to retrieve data.
	- If comand return any another return code, APDU chaining is interrupted.
*/

	ret = ((c->func) (message, r));
	DPRINT("command return code %02x\n", ret);
	return ret;
}

static uint16_t __attribute__((noinline)) card_poll_(void)
{
	uint16_t len;
#ifdef T1_TRANSPORT
	uint8_t t_buffer[T1_MIN_FRAME + T1_IFS];
#define RXBUF t_buffer
#else
#define	RXBUF iso_response.input
#endif

	len = card_io_rx(RXBUF, sizeof(RXBUF));
	// for parity error, PPS frame error: len = 0
	if (!len)
		return 0;

#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
	// check pps class, io layer is responsinble to check pps
	// (inclusive PPS1 - allowed only T0 and T1 protocol)

	if (RXBUF[0] == 0xff) {

#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
		iso_response.protocol = RXBUF[1] & 1;
#ifdef T1_TRANSPORT
		if (iso_response.protocol == 1)
			T1_INIT();
#endif				// T1_TRANSPORT
		// accept PPS
		card_io_tx(RXBUF, len);
#endif				// defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
		DPRINT("PPS protocol %d\n", iso_response.protocol);
		return 0;
	}

#endif				//TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE

#ifdef T1_TRANSPORT
	if (iso_response.protocol == 0)
		memcpy(iso_response.input, t_buffer, len);
	else
		len = T1_parser(&t1, t_buffer, len, iso_response.input, APDU_CMD_LEN);
#endif
	return len;
}

void card_poll(void)
{
	uint16_t len;
	for (;;) {
		len = card_poll_();
		DPRINT("protocol %d\n", iso_response.protocol);
		if (len)
			return_status(parse_apdu(len));
	}
}

void response_clear(void)
{
	iso_response.len16 = 0;
	// clear chaining, chain_len is cleared insipe APDU parsing code
	iso_response.chaining_state = APDU_CHAIN_INACTIVE;
#ifdef PROTOCOL_T0
	iso_response.protocol = 0;
#else
// T0 protocol support disabled
	iso_response.protocol = 1;
#endif
}
