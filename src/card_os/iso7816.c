/*
    iso7816.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2017 Peter Popovec, popovec.peter@gmail.com

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

#ifdef DEBUG
#include <stdio.h>
#define  DPRINT(msg...) fprintf(stderr,msg)
#else
#define DPRINT(msg...)
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
#define M_LC message[4]

struct iso7816_response iso_response __attribute__ ((section (".noinit")));

static void
return_status (uint16_t status)
{
  uint8_t message[3];

  message[0] = status >> 8;;
  message[1] = status & 0xff;

// stop sending NULL bytes
  card_io_stop_null ();
// return status to reader
  card_io_tx (message, 2);
}

//confirm command
// use command value, in INS = VPP inactive, all remaining data bytes are transferred subsequently
// alternatives:
// INS+1 VPP active, all remaining data bytes are transferred subsequently
// INS negated: VPP inactive, Next data byte is transferred subsequently.
// INS+1 negated VPP is active. Next data byte is transferred subsequently.
// In year 2006 standard ISO 7816 changed the definition of Vpp pad. Vpp is not used
// anymore. Confirm only by INS. (Now odd commands are allowed too).

void
confirm_command (uint8_t * message)
{
  //reuse message buffer to send response
  card_io_tx (message + 1, 1);
}

//read command data into message
uint8_t
read_command_data (uint8_t * message)
{
  uint8_t len = M_LC;

  return (len != card_io_rx (message + 5, len));
}


static void
iso7816_get_response (uint8_t * message)
{
  uint16_t s1, s2;

  DPRINT ("%s %02x %02x %02X\n", __FUNCTION__, M_P1, M_P2, M_LC);
  if (M_P1 != 0 || M_P2 != 0)
    {
      DPRINT ("incorrect p1,p2\n");
      return_status (0x6a86);	//incorrect P1,P2
      return;
    }
  if (iso_response.flag != R_RESP_READY)
    {
      DPRINT ("data already returned / no data to return \n");
      return_status (0x6985);	//Failure: Not allowed - no data to response
      return;
    }
  s1 = M_LC;
  s2 = iso_response.len;
  if (s1 == 0)
    s1 = 256;
  if (s2 == 0)
    s2 = 256;

  // not enough data in buffer ?
  if (s1 > s2)			//correction of length
    {
      DPRINT ("reserved data %d !=  received data %d\n",
	      iso_response.len, message[4]);
      return_status ((0x6c << 8) | iso_response.len);
      return;
    }

  // send message (only data requested by reader)
  confirm_command (message);
  card_io_tx ((uint8_t *) & iso_response.data, s1 & 255);
  // calculate how many data is now in buffer
  s2 -= s1;
  if (s2 == 0)
    {
      //mark data already sended
      iso_response.flag = R_NO_DATA;
    }
  else
    {
      uint8_t *start;
      uint8_t *rest;
      start = iso_response.data;
      rest = start + s1;
      while (s1)
	{
	  *start = *rest;
	  start++;
	  rest++;
	  s1--;
	}
    }
  iso_response.len = s2 & 255;
  if (iso_response.len)
    return_status (0x6100 | iso_response.len);
  else
    return_status (0x9000);
}



static void
iso7816_verify (uint8_t * message)
{
  DPRINT ("%s %02x %02x %02X\n", __FUNCTION__, M_P1, M_P2, M_LC);

  if (M_P1 != 0)
    {
      return_status (0x6a86);	// Incorrect parameters P1-P2
      return;
    }
  if (M_LC)
    {
      confirm_command (message);
      if (read_command_data (message))
	{
	  return_status (0x6984);	//invalid data
	  return;
	}
    }
  return_status (fs_verify_pin (message + 3));
}

static void
iso7816_get_challenge (uint8_t * message)
{
  uint8_t rlen;

  DPRINT ("%s %02x %02x %02X\n", __FUNCTION__, M_P1, M_P2, M_LC);

// TODO if P1 == 2 challange for authentification ..
  if (M_P1 != 0 || M_P2 != 0)
    {
      return_status (0x6a86);	//incorrect P1,P2
      return;
    }
  rlen = M_LC;
  if (rlen > 8)
    {
      return_status (0x6700);	//incorrect data len
      return;
    }
  if (rlen == 0)
    rlen = 8;
  while (rnd_get (iso_response.data, rlen));
  iso_response.len = rlen;
  iso_response.flag = R_RESP_READY;
  return_status ((0x61 << 8) | rlen);
}


static void
return_status_s (uint16_t status, uint8_t rewrite)
{
  if (rewrite)
    if ((status & 0xff00) == 0x6100)
      return return_status (0x9000);
  return_status (status);
}

static void
iso7816_select_file (uint8_t * message)
{
  uint8_t s = 0;
//read command parameters..
  DPRINT ("select\n");
  // in all case P2 must be 0 (return FCI)!

  if (M_P2 == 0x0c)
    s = 1;
  else if (M_P2 != 0)
    {
      return_status (0x6A86);	//Incorrect parameters P1-P2
      return;
    }

  if (!M_LC)
    {
// ISO special case, select MF if P1,P2 == 00 00 and data field is empty
      if (M_P1 == 0 && M_P2 == 0)
	{
	  return_status_s (fs_select_mf (&iso_response), s);
	  return;
	}
      if (M_P1 == 3)
	{
	  return_status_s (fs_select_parent (&iso_response), s);
	  return;
	}
      return_status (0x6700);	//incorrect data len
      return;
    }
  //read rest of apdu
  confirm_command (message);
  if (read_command_data (message))
    {
      return_status (0x6984);	//invalid data
      return;
    }

//select by path ..
  if ((M_P1 & 0xfe) == 8)
    {
      if (M_LC < 2)
	return_status (0x6A87);	// len inconsistent with P1
      if (M_LC & 1)
	return_status (0x6A87);	// len inconsistent with P1
      if (M_P1 & 1)
	return_status_s (fs_select_by_path_from_df
			 (message + 4, &iso_response), s);
      else
	return_status_s (fs_select_by_path_from_mf
			 (message + 4, &iso_response), s);
      return;
    }

//select by DF name (all names must be unique)
  if (M_P1 == 4)
    {
      if (M_LC < 1 || M_LC > 16)
	return_status (0x6A87);	// len inconsistent with P1
      else
	//send len and name as first arg
	return_status_s (fs_select_by_name (message + 4, &iso_response), s);	//select by name, position by P2
      return;
    }
// rest commands  in all case LC must be 2
  if (M_LC != 2)
    {
      return_status (0x6A87);	// len inconsistent with P1
      return;
    }

//select EF/DF by id .. 
  if (M_P1 < 3)
    {
      uint16_t id;

      id = (message[5] << 8) | message[6];
      DPRINT ("message ID %04x\n", id);
      if (M_P1 == 0)
	{
	  // ISO - if P1,P2 == 00 00 and data field is empty (already checked few rows up) od equal to 3f00 select MF
	  if (M_P2 == 0 && id == 0x3f00)
	    return_status_s (fs_select_mf (&iso_response), s);
	  else
	    return_status_s (fs_select_0 (id, &iso_response), s);
	}
      if (M_P1 == 1)
	return_status_s (fs_select_df (id, &iso_response), s);
      if (M_P1 == 2)
	return_status_s (fs_select_ef (id, &iso_response), s);

      return;
    }

  return_status (0x6A86);	//Incorrect parameters P1-P2
}

static void
iso7816_read_binary (uint8_t * message)
{
  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);
  if (M_P1 > 0x80)
    {
      return_status (0x6A86);	//Incorrect parameters P1-P2    -better alt  function not supported ?
      return;
    }
  if (!M_LC)
    {
      return_status (0x6700);	//Incorrect length
      return;
    }
  return_status (fs_read_binary ((M_P1 << 8) | M_P2, M_LC, &iso_response));
}

static void
iso7816_update_binary (uint8_t * message)
{
  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);
  if (M_P1 > 0x80)
    {
      return_status (0x6A86);	//Incorrect parameters P1-P2 -better alt  function not supported ?
      return;
    }
  if (!M_LC)
    {
      return_status (0x6700);	//Incorrect length
      return;
    }
  //read rest of apdu
  confirm_command (message);
  if (read_command_data (message))
    {
      return_status (0x6984);	//invalid data
      return;
    }

  return_status (fs_update_binary (message + 4, (M_P1 << 8) | M_P2));
}

static void
iso7816_erase_binary (uint8_t * message)
{
  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);
  if (M_P1 > 0x80)
    {
      return_status (0x6A86);	//Incorrect parameters P1-P2 -better alt  function not supported ?
      return;
    }
  if (M_LC)
    {
      return_status (0x6700);	//Incorrect length
      return;
    }

  return_status (fs_erase_binary ((M_P1 << 8) | M_P2));
}

static void
iso7816_delete_file (uint8_t * message)
{
  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);
  if (M_P1 | M_P2)
    {
      return_status (0x6A86);	//Incorrect parameters P1-P2
      return;
    }
  if (M_LC)
    {
      return_status (0x6700);	//Incorrect length
      return;
    }

  return_status (fs_delete_file ());
}

static void
iso7816_create_file (uint8_t * message)
{
  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 != 0 || M_P2 != 0)
    {
      return_status (0x6A86);	//Incorrect parameters P1-P2    
      return;
    }
  if (M_LC == 0)
    {
      return_status (0x6700);	//Incorrect length
      return;
    }
  //read rest of apdu
  confirm_command (message);
  if (read_command_data (message))
    {
      return_status (0x6984);	//invalid data
      return;
    }

  return_status (fs_create_file (message + 4));
}

static void
change_reference_data (uint8_t * message)
{
  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);
  if (M_P1 != 0)
    {
      return_status (0x6a86);	// Incorrect parameters P1-P2 
      return;
    }
  // correct is only value 16, this is checked in fs_change_pin()
  if (M_LC == 0)
    {
      return_status (0x6700);	//Incorrect length
      return;
    }
  //read rest of apdu
  confirm_command (message);
  if (read_command_data (message))
    {
      return_status (0x6984);	//invalid data
      return;
    }

  return_status (fs_change_pin (message + 3));
}

static void
reset_retry_counter (uint8_t * message)
{
  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 != 0)
    {
      return_status (0x6a86);	// Incorrect parameters P1-P2
      return;
    }

  if (M_LC == 0)
    {
      return_status (0x6700);	//Incorrect length
      return;
    }
  //read rest of apdu
  confirm_command (message);
  if (read_command_data (message))
    {
      return_status (0x6984);	//invalid data
      return;
    }

  return_status (fs_reset_retry_count (message + 3));
}


static void
deauthenticate (uint8_t * message)
{
  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 != 0)
    {
      return_status (0x6a86);	// Incorrect parameters P1-P2
      return;
    }
  if (M_P2 > 14)
    {
      return_status (0x6a86);	// Incorrect parameters P1-P2
      return;
    }
  if (M_LC != 0)
    {
      return_status (0x6700);	//Incorrect length
      return;
    }

  fs_deauth (M_P2);
  return_status (0x9000);
}


static void
command_class_A0 (uint8_t * message)
{
  if (message[1] == 0xe4)
    {
      iso7816_delete_file (message);
      return;
    }
  return_status (0x6f00);	//no particular diagnostic
}

static void
command_class_normal (uint8_t * message)
{
  // invalidate response buffer in case if no "get_response" call
  if (message[1] != 0xc0)
    if (iso_response.flag == R_RESP_READY)
      iso_response.flag = R_NO_DATA;

  switch (message[1])
    {
    case 0x0e:			// erase binary .. fill file with 0xff from offset (P1,P2) to end of file
      iso7816_erase_binary (message);
      return;
    case 0x20:
      iso7816_verify (message);
      return;
    case 0x22:
      return_status (security_env_set_reset (message, &iso_response));
      return;
    case 0x24:
      change_reference_data (message);	//pin change
      return;
    case 0x2a:
      {
	uint16_t ret;
	// only upload first part of RSA decrypt data end with 0x9000,
	// in all other return codes reset PINs,
	ret = (security_operation (message, &iso_response));
	if (ret != 0x9000)
	  fs_reset_security ();
	return_status (ret);
      }
      return;
    case 0x2c:
      reset_retry_counter (message);
      return;
    case 0x2e:
      deauthenticate (message);
      return;
    case 0x44:
      return_status (myeid_activate_applet (message));
      return;
    case 0x46:
      return_status (myeid_generate_key (message));
      return;
    case 0x84:
      iso7816_get_challenge (message);
      return;
    case 0x86:
      return_status (myeid_ecdh_derive (message, &iso_response));
      return;

    case 0xa4:
      iso7816_select_file (message);
      return;
    case 0xb0:
      iso7816_read_binary (message);
      return;
    case 0xc0:
      iso7816_get_response (message);
      return;
    case 0xca:
      return_status (myeid_get_data (message, &iso_response));
      return;

    case 0xd6:
      iso7816_update_binary (message);
      return;

    case 0xda:
      return_status (myeid_put_data (message, &iso_response));
      return;

    case 0xe0:
      iso7816_create_file (message);
      return;
    case 0xe4:
      iso7816_delete_file (message);
      return;
    }
  return_status (0x6f00);	//no particular diagnostic
}

static void
command_class_default (uint8_t * message)
{
  return_status (0x6e00);
}


#ifndef NIST_ONLY
static void
command_class_prop (uint8_t * message)
{
  switch (message[1])
    {
    case 0xda:			// put data - prop command (change key file type to 0x23)
      if (M_P1 != 0 || M_P2 != 0 || M_LC != 0)
	{
	  DPRINT ("incorrect p1,p2\n");
	  return_status (0x6a86);	//incorrect P1,P2
	  return;
	}
      return_status (fs_key_change_type ());
      return;
    default:
      return_status (0x6f00);	//no particular diagnostic
    }
}
#endif


#define C_CLASS_PTS 0xff
#ifndef NIST_ONLY
#define C_CLASS_PROP 0x80
#endif
#define C_CLASS_ACTIVE 0x0
#define C_CLASS_A0 0xA0

//return positive number (how many characters need to be read from 
static void
parse_T0 (uint8_t * message)
{
// PTS is handled in io layer

// all implemented functions needs 5 bytes (CLA, INS, P1, P2, LC/LE)
  if (iso_response.input_len < 5)
    return_status (0x6f00);	//no particular diagnostic

  switch (M_CLASS)
    {
    case C_CLASS_ACTIVE:
      return command_class_normal (message);
    case C_CLASS_A0:
      return command_class_A0 (message);
#ifndef NIST_ONLY
//proprietary!
    case C_CLASS_PROP:
      return command_class_prop (message);
#endif
    default:
      DPRINT ("CLASS OTHER\n");
      return command_class_default (message);
    }
}

void
card_poll ()
{
  uint8_t len;

  len = card_io_rx (iso_response.input, 255);
  if (len)
    {
      iso_response.input_len = len;
      parse_T0 (iso_response.input);
    }
}

void
response_clear (void)
{
  iso_response.flag = R_NO_DATA;
}
