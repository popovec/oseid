/*
    iso7816.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2020 Peter Popovec, popovec.peter@gmail.com

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

#define DEBUG_ISO7816
#include "debug.h"

#define PROTOCOL_T1

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

struct iso7816_response iso_response __attribute__((section (".noinit")));

uint8_t
resp_ready (struct iso7816_response *r, uint16_t len)
{
  r->len16 = len;
  r->flag = R_NO_DATA;

  if (r->Ne == 0)
    return S_RET_OK;

  r->flag = R_RESP_READY;
  if (r->Ne >= len)
    return S0x6100;
  else
    return S0x6c00;
}

static void
return_status (uint8_t status)
{
  // reuse P1,P2 as buffer for status
  uint8_t *message = iso_response.input + 2;
  uint16_t Ne, Na;

  Na = iso_response.len16;

// stop sending NULL bytes
  card_io_stop_null ();

  message[0] = 0x60 | (status >> 4);
  message[1] = 0;

  // protocol 1 - return data, protocol 0 only signalize data available
  if (iso_response.protocol == 1 && status == S0x6100)
    status = S_RET_GET_RESPONSE;

  switch (status)
    {
      // here low byte defaults to 0
    case S_RET_OK:
      message[0] = 0x90;
      break;
    case S0x6700:
    case S0x6b00:
    case S0x6d00:
    case S0x6e00:
    case S0x6f00:
      break;
    case S0x6c00:
    case S0x6100:		// low byte - how many bytes are still available
      DPRINT ("remaining bytes in buffer %d\n", Na);
      // message[1] is already 0
      if (Na < 256)
	message[1] = Na;
      break;
    case S_RET_GET_RESPONSE:
      Ne = iso_response.Ne;
      DPRINT ("returning APDU with data, %d bytes available, Ne=%d\n",
	      Na, Ne);
      // Ne: maximum number of bytes expected in the response data field
      // Na: exact number of available data bytes

      // ISO77816 allow us to send fewer bytes as requested by Ne
      // OsEID specific, return max 256 bytes, and signalize remaining bytes
      // if needed (for short/extended APDU)

      if (Ne > 256)
	Ne = 256;
      if (Ne > Na)
	Ne = Na;
      // reuse INS as procedure byte
      memcpy (iso_response.input + 2, iso_response.data, Ne);
      // calculate how many data is now in buffer
      Na -= Ne;
      iso_response.len16 = Na;
      if (Na == 0)
	{
	  //mark data already sended
	  iso_response.flag = R_NO_DATA;
	  iso_response.input[Ne + 2] = 0x90;
	  iso_response.input[Ne + 3] = 0;
	}
      else
	{
	  memcpy (iso_response.data, iso_response.data + Ne, Na);
	  iso_response.input[Ne + 2] = 0x61;
	  iso_response.input[Ne + 3] = Na;
	  if (Na & 0xff00)
	    iso_response.input[Ne + 3] = 0;
	  else
	    iso_response.input[Ne + 3] = Na;
	}
      DPRINT ("sending response\n");
// send response APDU (for protocol 0 prepend procedure byte)
      if (iso_response.protocol == 1)
	card_io_tx (iso_response.input + 2, Ne + 2);
      else
	card_io_tx (iso_response.input + 1, Ne + 3);
      return;

      // for all other codes low byte defaults to 0x8X,
      // except for codef 0x63XX, here low byte defaults 0xCX
    default:
      if ((status & 0xf0) == 0x30)
	{
	  // 63
	  message[1] = 0xc0 | (status & 0xf);
	}
      else
	{
	  // (60), 62,64,65,66,68,69,6a
	  message[1] = 0x80 | (status & 0xf);
	}
    }

// return status to reader
  card_io_tx (message, 2);
}


static uint8_t
iso7816_get_response (void)
{
  uint8_t *message = iso_response.input;

  DPRINT ("%s %02x %02x %02X %d\n", __FUNCTION__, M_P1, M_P2, M_P3,
	  iso_response.Ne);
  if (M_P1 != 0 || M_P2 != 0)
    {
      DPRINT ("incorrect p1,p2\n");
      return S0x6a86;		//incorrect P1,P2
    }
  if (iso_response.flag != R_RESP_READY || iso_response.len16 == 0)
    {
      DPRINT ("data already returned / no data to return \n");
      return S0x6985;		//Failure: Not allowed - no data to response
    }
  return S_RET_GET_RESPONSE;
}

#ifdef C_ENVELOPE
static uint8_t
iso7816_envelope (void)
{
  uint8_t *message = iso_response.input;
  uint16_t size = M_Nc;

  DPRINT ("%s %02x %02x %02X\n", __FUNCTION__, M_P1, M_P2, M_P3);
  if (M_P1 != 0 || M_P2 != 0)
    {
      DPRINT ("incorrect p1,p2\n");
      return S0x6a86;		//incorrect P1,P2
    }
  // data field is present, concatenate data into temp buffer
  if (size)
    {
      if (iso_response.flag != R_ENVELOPE)
	{
	  iso_response.flag = R_ENVELOPE;
	  iso_response.tmp_len = 0;
	}
      // check if enough space in buffer
      if (((uint16_t) size + iso_response.tmp_len) > 256)
	{
	  DPRINT ("Message over 256 bytes ?\n");
	  iso_response.flag = R_NO_DATA;
	  return S0x6700;	// incorect length
	}
      memcpy (iso_response.data + iso_response.tmp_len, message, size);
      iso_response.tmp_len += size;
    }
  else
    {
      // T0 protocol, mark envelope chain end
      iso_response.flag = R_TMP;
    }
  return S_RET_OK;
}
#endif

static uint8_t
iso7816_verify (void)
{
  uint8_t *message = iso_response.input;

  DPRINT ("%s %02x %02x %02X\n", __FUNCTION__, M_P1, M_P2, M_P3);

  if (M_P1 != 0)
    return S0x6a86;		// Incorrect parameters P1-P2

  // TODO latest ISO7816-4 (2013?) if P1=0xff deauth of pin P2

  return fs_verify_pin (message + 3);
}

static uint8_t
iso7816_get_challenge (void)
{
  uint8_t *message = iso_response.input;
  uint8_t rlen;

  DPRINT ("%s %02x %02x %02X\n", __FUNCTION__, M_P1, M_P2, M_P3);

// TODO if P1 == 2 challange for authentification ..
  if (M_P1 != 0 || M_P2 != 0)
    return S0x6a86;		//incorrect P1,P2

// Ne > 256 is handled in APDU parser  -> Ne = 256, in this case 0
  rlen = iso_response.Ne & 0xff;
  if (rlen == 0)
    return S0x6f00;		//no particular diagnostic (same response as from MyEID 3.3.3)
  rnd_get (iso_response.data, rlen);
  iso_response.len16 = rlen;
  iso_response.flag = R_RESP_READY;
  return S0x6100;
}


static uint8_t
iso7816_select_file (void)
{
  uint8_t *message = iso_response.input;

//read command parameters..
  DPRINT ("select\n");

  // in all case P2 must be 0 (return FCI) except 0x0c (do not return any template)
  if (M_P2 == 0x0c)
    iso_response.Ne = 0;
  else if (M_P2 != 0)
    return S0x6a86;		//Incorrect parameters P1-P2

  if (!M_Nc)
    {
// ISO special case, select MF if P1,P2 == 00 00 and data field is empty
      if (M_P1 == 0 && M_P2 == 0)
	{
	  return fs_select_mf (&iso_response);
	}
      if (M_P1 == 3)
	{
	  return fs_select_parent (&iso_response);
	}
      return S0x6700;		//incorrect data len
    }

//select by path ..
  if ((M_P1 & 0xfe) == 8)
    {
      if (M_Nc < 2)
	return S0x6a87;		// len inconsistent with P1
      if (M_Nc & 1)
	return S0x6a87;		// len inconsistent with P1
      if (M_P1 & 1)
	return fs_select_by_path_from_df (message + 4, &iso_response);
      else
	return fs_select_by_path_from_mf (message + 4, &iso_response);
    }

//select by DF name (all names must be unique)
  if (M_P1 == 4)
    {
      if (M_Nc < 1 || M_Nc > 16)
	return S0x6a87;		// len inconsistent with P1
      else
	//send len and name as first arg
	return fs_select_by_name (message + 4, &iso_response);	//select by name, position by P2
    }
// rest commands  in all case LC must be 2
  if (M_Nc != 2)
    {
      return S0x6a87;		// len inconsistent with P1
    }

// select EF/DF by id .. (match M_P1 in range 0..2)
  uint16_t id = (message[5] << 8) | message[6];

  DPRINT ("message ID %04x\n", id);
  if (M_P1 == 0)
    {
      // ISO - if P1,P2 == 00 00 and data field is empty (already checked few rows up) od equal to 3f00 select MF
      if (M_P2 == 0 && id == 0x3f00)
	return fs_select_mf (&iso_response);
      else
	return fs_select_0 (id, &iso_response);
    }
  if (M_P1 == 1)
    return fs_select_df (id, &iso_response);
  if (M_P1 == 2)
    return fs_select_ef (id, &iso_response);

// P1/P2 out of range
  return S0x6a86;		//Incorrect parameters P1-P2
}

static uint8_t
iso7816_read_binary (void)
{
  uint8_t *message = iso_response.input;

  DPRINT ("%s P1: %02x P2: %02x LC: %02x\n", __FUNCTION__, M_P1, M_P2, M_P3);

  if (M_P1 > 0x80)
    return S0x6a86;		//Incorrect parameters P1-P2    -better alt  function not supported ?

  // Ne from iso_response ..
  return fs_read_binary ((M_P1 << 8) | M_P2, &iso_response);
}

static uint8_t
iso7816_update_binary (void)
{
  uint8_t *message = iso_response.input;

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 > 0x80)
    return S0x6a86;		//Incorrect parameters P1-P2 -better alt  function not supported ?

  // Nc is not 0, checked in parser
  return fs_update_binary (message + 4, (M_P1 << 8) | M_P2);
}


static uint8_t
iso7816_erase_binary (void)
{
  uint8_t *message = iso_response.input;

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

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
  if ((start /*|end */ ) & 0x8000)
    {
      return S0x6a86;		//Incorrect parameters P1-P2
    }
  return fs_erase_binary (start /*, end */ );
}

static uint8_t
iso7816_delete_file (void)
{
  uint8_t *message = iso_response.input;

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 | M_P2)
    return S0x6a86;		//Incorrect parameters P1-P2

  // TODO, LC==2, data field contain file ID to be deleted (From ETSI TS 102 222 V4.2.0 (2005-10))
  // Nc is not 0, checked in parser

  return fs_delete_file ();
}

static uint8_t
iso7816_create_file (void)
{
  uint8_t *message = iso_response.input;

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 != 0 || M_P2 != 0)
    return S0x6a86;		//Incorrect parameters P1-P2

  // Nc is not 0, checked in parser
  return fs_create_file (message + 4);
}

static uint8_t
change_reference_data (void)
{
  uint8_t *message = iso_response.input;

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);
  if (M_P1 != 0)
    {
      return S0x6a86;		// Incorrect parameters P1-P2
    }
  // Nc is not 0, checked in parser
  return fs_change_pin (message + 3);
}

static uint8_t
reset_retry_counter (void)
{
  uint8_t *message = iso_response.input;

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 != 0)
    {
      return S0x6a86;		// Incorrect parameters P1-P2
    }
  // Nc is not 0, checked in parser
  return fs_reset_retry_count (message + 3);
}

static uint8_t
deauthenticate (void)
{
  uint8_t *message = iso_response.input;

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

// M_P3 /Nc is 0 (checked in parser)

  uint8_t pin = M_P2;

  if (M_P1 == 0)
    {
      if (M_P2 > 14)
	return S0x6a86;		// Incorrect parameters P1-P2
    }
  else if (M_P1 == 0xa0)	// deauth admin state
    {
      if (M_P2 != 0)
	return S0x6a86;		// Incorrect parameters P1-P2
      pin = M_P1;
    }
  else if (M_P1 == 0xb0)	// deauth global unblocker
    {
      if (M_P2 != 0)
	return S0x6a86;		// Incorrect parameters P1-P2
      pin = M_P1;
    }
  else
    {
      return S0x6a86;		// Incorrect parameters P1-P2
    }

  fs_deauth (pin);
  return S_RET_OK;
}

static uint8_t
w_security_env_set_reset (void)
{
  return (security_env_set_reset (iso_response.input));
}

static uint8_t
w_security_operation (void)
{
  return (security_operation (iso_response.input, &iso_response));
}

static uint8_t
w_myeid_activate_applet (void)
{
  return (myeid_activate_applet (iso_response.input));
}

static uint8_t
w_myeid_generate_key (void)
{
  return (myeid_generate_key (iso_response.input, &iso_response));
}

static uint8_t
w_myeid_ecdh_derive (void)
{
  return (myeid_ecdh_derive (iso_response.input, &iso_response));
}

static uint8_t
w_myeid_get_data (void)
{
  return (myeid_get_data (iso_response.input, &iso_response));
}

static uint8_t
w_myeid_put_data (void)
{
  return (myeid_put_data (iso_response.input, &iso_response));
}

static uint8_t
w_fs_key_change_type (void)
{
  // Nc ==0, Ne ==0 - checked in parser
  uint8_t *message = iso_response.input;
  if (M_P1 != 0 || M_P2 != 0)
    {
      DPRINT ("%s incorrect P1, P2\n", __FUNCTION__);
      return S0x6a86;		//incorrect P1,P2
    }
  return (fs_key_change_type ());
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

struct f_table
{
  uint8_t attr;
  uint8_t ins;
    uint8_t (*func) (void);
};
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#ifdef __AVR__
static const struct f_table __flash cla00[] = {
#else
static struct f_table cla00[] = {
#endif
  {APDU_Lc_empty, 0x0e, iso7816_erase_binary},	// iso7816-4/7.2.7  Ne = 0, Nc 0 (in future 0 or 2, end of erased data in data field)
  {APDU_Le_empty, 0x20, iso7816_verify},	// iso7816-4/7.5.6  Ne = 0
  {APDU_Le_empty, 0x22, w_security_env_set_reset},	// iso7816-4/7.5,11 Ne = 0
  {APDU_Nc | APDU_Le_empty, 0x24, change_reference_data},	// iso7816-4/7.5.7  Ne = 0
// allow Nc 0 if other  transport (envelope) is allowed
  {APDU_Nc | ATTR_T0_Le_present | APDU_LONG, 0x2a, w_security_operation},	// iso7816-8....???
  {APDU_Nc | APDU_Le_empty, 0x2c, reset_retry_counter},	// iso7816-4/7.5.10 Ne = 0
  {APDU_Lc_empty | APDU_Le_empty, 0x2e, deauthenticate},	// MyEID doc
  {APDU_Le_empty, 0x44, w_myeid_activate_applet},	// MyEID doc
  {ATTR_T0_Le_present, 0x46, w_myeid_generate_key},	// iso7816-8
  {APDU_Ne | APDU_Lc_empty | ATTR_T0_P3NE, 0x84, iso7816_get_challenge},	//iso7816-4/7.5.3 Nc = 0
  {ATTR_T0_Le_present | APDU_Nc, 0x86, w_myeid_ecdh_derive},
// Nc 0..255, Ne 1..256
  {ATTR_T0_Le_present, 0xa4, iso7816_select_file},
  {APDU_Ne | APDU_Lc_empty | ATTR_T0_P3NE, 0xb0, iso7816_read_binary},	// iso7816-4/7.2.3 Nc = 0,  Nc > 0 for 0xb1
  {APDU_Ne | APDU_Lc_empty | ATTR_T0_P3NE, 0xc0, iso7816_get_response},	// iso7816-4/7.6.2 Nc = 0
//{0, 0xc2, iso7816_envelope},
  {APDU_Ne | APDU_Lc_empty | ATTR_T0_P3NE, 0xca, w_myeid_get_data},	// iso7816-4/7.4.2 Nc = 0, Nc > 0 for 0xcb...
  {APDU_Nc | APDU_Le_empty, 0xd6, iso7816_update_binary},	// iso7816-4/7.2.5 Ne = 0, Nc 1..255
  {APDU_Nc | APDU_Le_empty | APDU_LONG, 0xda, w_myeid_put_data},	// iso7816-4/7.4.3 Ne = 0, Nc 1..256 (extended APDU)
  {APDU_Nc | APDU_Le_empty, 0xe0, iso7816_create_file},	// Nc 1..255  Ne 0
  {APDU_Le_empty, 0xe4, iso7816_delete_file},	// Nc 0, Ne 0 / Nc 2, Ne 0 in future (ID in data field)
  {0xff}
};

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#ifdef __AVR__
static const struct f_table __flash cla80[] = {
#else
static struct f_table cla80[] = {
#endif
  {APDU_Nc | ATTR_T0_Le_present | APDU_LONG, 0x2a, w_security_operation},	// iso7816-8....???
  {APDU_Nc | APDU_Le_empty, 0xda, w_fs_key_change_type},	// proprietary ..
  {0xff}
};




static uint8_t
parse_apdu (uint16_t input_len)
{
  uint8_t *message = &iso_response.input[0];
  struct iso7816_response *r = &iso_response;
  uint8_t cla = message[0];
  uint8_t ins = message[1];
  uint8_t Lc;
  uint16_t Nc, Ne;

  // PTS is handled in io layer, here is already available:
  // 5 bytes for protocol 0
  // 4 or more bytes for protocol 1

  // invalidate response buffer in case if no "get_response" call
  // do this for any CLA

  if (ins != 0xc0)
    if (r->flag == R_RESP_READY)
      r->flag = R_NO_DATA;

  // MyEID driver in OpenSC uses CLA 0xA0 for DELETE FILE
  // adapt to CLA 0 - as specified in MyEID reference manual
  if (cla == 0xa0 && ins == 0xe4)
    cla = 0;

#ifdef __AVR__
  const __flash struct f_table *c;
#else
  const struct f_table *c;
#endif
  switch (cla)
    {
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
      return S0x6e00;		// CLA not supported
    }

  DPRINT ("searching INS %02x\n", ins);
  for (;; c++)
    {
      if (c->attr == 0xff)
	return S0x6d00;		// CLA ok but INS not programmed or invalid
      if (c->ins == ins)
	break;
    }

  DPRINT ("input len = %d\n", input_len);
  // defaults for Nc and Ne (CASE 1 APDU, T1 protocol)
  Nc = 0;
  Ne = 0;
  if (input_len == 4)
    {
      DPRINT ("T1 CASE 1S\n");
      // fix P3
      message[4] = 0;
    }
  else
    {
      // P3 is present, use it as Lc/Le
      Lc = M_P3;
      if (Lc)
	{
	  if (r->protocol == 0)
	    {
	      // use INS to determine CASE 2S or CASE 3S/4S
	      if (ATTR_T0_P3NE & c->attr)
		{
		  // do not send procedure byte here!
		  DPRINT ("T0 CASE 2S Ne in range 1..255\n");
		  Ne = Lc;
		}
	      else
		{
		  DPRINT ("T0 CASE 3S/4S reading DATA field %d bytes\n", Lc);;
		  // INS is used as procedure byte ISO7816-3/10.3.3
		  card_io_tx (message + 1, 1);
		  if (Lc != card_io_rx (message + 5, Lc))
		    return S0x6984;	//invalid data
		  // Le is not awailable, use INS attribute to set Ne
		  if (c->attr & ATTR_T0_Le_present)
		    Ne = 256;
		  Nc = Lc;
		}
	    }
#ifdef PROTOCOL_T1
	  else			// protocol 1, P3 > 0
	    {
	      if (input_len == 5)
		{
		  DPRINT ("T1 CASE 2S\n");
		  Ne = Lc;
		}
	      else if (Lc + 5 == input_len)
		{
		  DPRINT ("T1 CASE 3S\n");
		  Nc = Lc;
		}
	      else if (Lc + 6 == input_len)
		{
		  DPRINT ("T1 CASE 4S\n");
		  Nc = Lc;
		  Ne = message[input_len - 1];
		  if (Ne == 0)
		    Ne = 256;
		}
	      else
		{
		  DPRINT
		    ("APDU (short), protocol T1, input length %d, Lc=%d\n",
		     input_len, Lc);
		  return S0x6700;	// wrong length
		}
	    }
#endif
	}
      else			// P3 = 0
	{
	  // P3 present, and is zero, T0 or T1
	  if (input_len == 5)
	    {
	      //CASE 2S
	      DPRINT ("T0/1 CASE 2S, Ne=256\n");
	      Ne = 256;
	    }
#ifdef PROTOCOL_T1
	  // Protocol T1, len > 5
	  else
	    {
	      uint16_t LcExtended;

	      // extended cases 2E,3E,4E
	      if (input_len < 7)
		{
		  DPRINT
		    ("Protocol T1, extended case APDU, length below 7 (%d)\n",
		     input_len);
		  return S0x6700;	// wrong length
		}
	      LcExtended = message[5] << 8 | message[6];
	      if (!LcExtended)
		{
		  // case 2E or fail
		  if (input_len == 7)
		    {
		      DPRINT ("T1 CASE 2E, Le=0 (65535)\n");
		      Ne = 65535;
		    }
		  else
		    {
		      DPRINT ("T1, Nc=0 for CASE 3E/4E\n");
		      return S0x6700;	// wrong length
		    }
		}
	      else
		{
		  // Lc(Le) > 0, check Le field and corresponding APDU length
		  if (input_len == 7)
		    {
		      DPRINT ("T1 CASE 2E\n");
		      Ne = LcExtended;
		    }
		  else
		    {
		      // data always at message+5, overwrite extended (already parsed) Lc field
		      memmove (message + 5, message + 7, input_len - 7);
		      Nc = LcExtended;

		      if (input_len == 9 + Nc)
			{
			  DPRINT ("T1 CASE 4E\n");
			  Ne =
			    message[input_len - 2] << 8 | message[input_len -
								  1];
			  // warning 65536 here, but Ne is only 16 bites long (not real limit)
			  if (Ne == 0)
			    Ne = 65535;
			}
		      else if (input_len == 7 + Nc)
			{
			  DPRINT ("T1 CASE 3E\n");
			}
		      else
			{
			  DPRINT ("T1, wrong APDU length for cases 3E/4E\n");
			  return S0x6700;	// wrong length
			}
		    }
		}
	    }
#endif //  PROTOCOL_T1
	}
    }

// handle APDU chaining (bit 7 is already checked - is 0)
// INS 0 is not udes in OsEId card and is not described in ISO7816 .. use  0 here for chaining
  if (cla & 0x10)
    {
      DPRINT ("APDU chaining: requested\n");
      // chaining is allowed only for CASE 3S/E 4S/E
      // check Nc field, if zero, this is CASE 1,2S/E
      if (!Nc)
	{
	  DPRINT ("APDU chaining: no data in APDU?\n");
	  iso_response.chaining_active = 0;
	  return S0x6700;	// wrong length
	}
      if (iso_response.chaining_active == 0)
	{
	  DPRINT ("APDU chaining: start\n");
	  // TODO save P1,P2
	  iso_response.tmp_len = 0;
	  iso_response.chaining_active = ins;
	}
      else
	{
	  DPRINT ("APDU chaining: running\n");
	  // TODO check P1,P2
	  if (iso_response.chaining_active != ins)
	    {
	      DPRINT ("APDU chaining: INS changed %02x %02x\n",
		      iso_response.chaining_active, ins);
	      iso_response.chaining_active = 0;
	      return S0x6883;	// expected last command of chain
	    }
	}
      // check if there is space in temp buffer
      if (iso_response.tmp_len + Nc > APDU_RESP_LEN)
	{
	  iso_response.chaining_active = 0;
	  return S0x6700;	// wrong length
	}
      // copy data into temp buffer
      memcpy (iso_response.data + iso_response.tmp_len, message + 5, Nc);
      iso_response.tmp_len += Nc;
      return S_RET_OK;
    }
  else
    {
      if (iso_response.chaining_active != 0)
	{
	  DPRINT ("APDU chaining: last APDU\n");
	  iso_response.chaining_active = 0;
	  if (Nc)
	    {
	      // check if there is space in temp buffer
	      if (iso_response.tmp_len + Nc > APDU_RESP_LEN)
		{
		  return S0x6700;	// wrong length
		}
	      // copy data into temp buffer
	      memcpy (iso_response.data + iso_response.tmp_len,
		      message + 5, Nc);
	      iso_response.tmp_len += Nc;
	    }
	  else
	    {
	      DPRINT ("APDU chaining: no data in APDU?\n");
	      return S0x6700;	// wrong length
	    }
	  // OK whole APDU in iso_response.data
	  // Ne is already set
	  Nc = iso_response.tmp_len;
	  memcpy (message + 5, iso_response.data, Nc);
	  // P3 is fixed below (for APDUs where Nc < 256)
	}
    }

// message+5 is always position of data, functions can use Ne, Nc  or P3 if P3 !=0  (P3 is then Nc 1..255)
// if function does not have APDU_LONG flag:
// if function does not accept Nc > 255, return error 0x6700
// if function does not accept Ne > 256, change Ne to 256  (TODO flag for this..)
// P3 is always Lc (not Le!!)
  if (!(c->attr & APDU_LONG))
    {
      if (Nc > 255)
	{
	  DPRINT ("INS does not allow Nc > 255 (Nc=%d)\n", Nc);
	  return S0x6700;	// wrong length
	}
      message[4] = Nc;
      if (Ne > 256)
	{
	  DPRINT ("INS does not allow Ne > 256, (Ne=%d) clamping Ne to 256\n",
		  Ne);
	  Ne = 256;
	}
    }

// INS does not allow Ne or need Ne
  if (Ne)
    {
      // Ne set
      if ((c->attr & APDU_Le_empty) && r->protocol == 1)
	{
	  DPRINT ("INS does not allow Le field\n");
	  return (S0x6700);	// wrong length
	}
    }
  else
    {
      // Ne = 0
      if (c->attr & APDU_Ne)
	{
	  DPRINT ("INS does not allow empty Le\n");
	  return S0x6700;	// wrong length
	}
    }

// INS does not allow Nc or need Nc
  if (Nc)
    {
      // Nc set
      if (c->attr & APDU_Lc_empty)
	{
	  DPRINT ("INS does not allow Lc field\n");
	  return S0x6700;	// wrong length
	}
    }
  else
    {
      // Nc = 0
      if (c->attr & APDU_Nc)
	{
	  DPRINT ("INS does not allow empty Lc\n");
	  return S0x6700;	// wrong length
	}
    }

  DPRINT ("Running command 0x%02X P3=%d Nc=%d Ne=%d\n", ins, M_P3, Nc, Ne);
  r->Nc = Nc;
  r->Ne = Ne;
/*
command uses iso7816_response as input/output
input:
	iso7816_response.input			command APDU
	iso7816_response.protocol	  	0/1 T0/T1
	iso7816_response.input[4]		Nc (0..255), for function with flag APDU_LONG iso7816_response.Nc must be used
	iso7816_response.input[5....]           Nc bytes of DATA field
	iso7816_response.Nc			Nc in range 0.. up to 257   0 Lc not present
	iso7816_response.Ne			Ne in range 0.. 65535       0 Le not present

	if command generates data, data are stored into iso_response.data,
	iso_response.flag  is set to R_RESP_READY and
	iso_response.len16 represent number of returned data bytes (up to APDU_RESP_LEN)
	SW must be set to S0x6100
*/

  return ((c->func) ());
}


void
card_poll (void)
{
  uint16_t len;

  len = card_io_rx (iso_response.input, APDU_CMD_LEN);
  // test if 5 bytes is received (header for protocol T0) or 4 or more bytes for protocol T1
  if (len == 5 || len >= 0x8004)
    {
      iso_response.protocol = len >> 15;
      DPRINT ("received protocol %d\n", iso_response.protocol);
      len &= 0x7fff;
      return_status (parse_apdu (len));
    }
}

void
response_clear (void)
{
  iso_response.flag = R_NO_DATA;
  // clear chaining
  iso_response.chaining_active = 0;
}
