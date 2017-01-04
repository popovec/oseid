/*
    myeid_emu.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015,2016 Peter Popovec, popovec.peter@gmail.com

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

    Emulation of MyEID functions

*/
/*
 Function are based on documentation from: 
 http://aventra.fi/pdf/MyEID%20PKI%20JavaCard%20Applet%20Reference%20Manual%201-7-7.pdf
 (local copy internet_sources/MyEID PKI JavaCard Applet Reference Manual 1-7-7.pdf)
 
 Some functions are derived from opensc sources https://github.com/OpenSC/OpenSC - card-myeid.c
 
*/

#ifdef DEBUG
#include <stdio.h>
#define  DPRINT(msg...) fprintf(stderr,msg)
#else
#define DPRINT(msg...)
#endif


#include <stdint.h>
#include <string.h>
#include "card_io.h"
#include "ec.h"
#include "iso7816.h"
#include "myeid_emu.h"
#include "fs.h"
#include "key.h"
#include "rsa.h"
#include "constants.h"

#define M_CLASS message[0]
#define M_CMD message[1]
#define M_P1 message[2]
#define M_P2 message[3]
#define M_LC message[4]

#if RSA_BYTES > 128
#error RSA_BYTES over 128, for atmega only 256 byte buffers are reserved!
#endif

uint8_t sign_algo __attribute__ ((section (".noinit")));
uint16_t key_file_id __attribute__ ((section (".noinit")));
uint8_t sec_env_valid __attribute__ ((section (".noinit")));	//0xB6 - valid for  sign, 0XB8 valid for decrypt


static void
reverse_string (uint8_t * p, uint16_t len)
{
  uint8_t *t, tmp;

  t = p + len - 1;
  len /= 2;
  while (len--)
    {
      tmp = *p;
      *p = *t;
      *t = tmp;
      t--;
      p++;
    }
}

static void
reverse_copy (uint8_t * d, uint8_t * s, uint16_t len)
{
  s += len - 1;
  while (len--)
    {
      *d = *s;
      s--;
      d++;
    }
}

// target pointer must allow store RSA_BYTES of bytes
uint8_t
get_rsa_key_part (void *here, uint8_t id)
{
  uint16_t part_size;
  uint8_t *key = here;

  part_size = fs_key_read_part (key, id);
  reverse_string (key, part_size);
  if (part_size > 255)
    part_size = 0;
  return part_size;
}

// do sign/decrypt with selected key, return 0 if error, 
// or len of returned message (based on key size). 
// input length of message, message, result after sign/decrypt
// WARNING, message and result buffers must hold 256 bytes!
// flag 0 - raw data, must match key size
// flag 1 - add OID of SHA1 before message, then add padding.. 
// flag 2 - add padding only (type 01), SHA1 digest is in message
static uint16_t
rsa_raw (uint16_t len, uint8_t * message, uint8_t * result, uint8_t flag)
{
  uint16_t part_size;
  uint8_t ret;

  DPRINT ("message first byte 0x%02x size %d\n", *message, len);

  reverse_string (message, len);	// number from message
  if (len < RSA_BYTES)
    memset (message + len, 0, RSA_BYTES * 2 - len);
#ifdef DEBUG
  {
    int i, j;
    DPRINT ("reversed mesage =\n");
    for (j = 0; j < RSA_BYTES * 2; j += 32)
      {
	for (i = 0; i < 32; i++)
	  DPRINT ("%02X ", message[i + j]);
	DPRINT ("\n");
      }
  }
#endif
  // test if key match data size
  part_size = fs_key_read_part (NULL, KEY_RSA_p);
  part_size *= 2;		// calculate message size

  DPRINT ("key modulus: %d, message len: %d flag: %d\n", part_size, len,
	  flag);
  if (flag == 0)
    {
      if (len != part_size)
	return 0;
    }
  if (flag == 1)
    {
      DPRINT ("adding SHA1 OID to message\n");
// this test is not needed, minimal key modulus is 512 bit
/*
      if (len + 15 > part_size)
	return 0;
*/
      // SHA1 need 20 bytes len message exact
      if (len != 20)
	return 0;
      // add sha1 oid before message
      if (0 == get_constant (message + len, N_PSHA1_prefix))
	return 0;
      reverse_string (message + len, 15);
      flag = 2;
      len += 15;
#ifdef DEBUG
      {
	int i, j;
	DPRINT ("reversed mesage with SHA1 OID=\n");
	for (j = 0; j < RSA_BYTES * 2; j += 32)
	  {
	    for (i = 0; i < 32; i++)
	      DPRINT ("%02X ", message[i + j]);
	    DPRINT ("\n");
	  }
      }
#endif
    }
  if (flag == 2)
    {
      DPRINT ("adding padding type 1 size of modulus %d, message size %d\n",
	      part_size, len);
// add padding- type 1 (00 01 [FF .. FF] 00 .. minimal 8 bytes 0xff
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

#ifdef DEBUG
  {
    int i, j;
    DPRINT ("mesage =\n");
    for (j = 0; j < RSA_BYTES * 2; j += 32)
      {
	for (i = 0; i < 32; i++)
	  DPRINT ("%02X ", message[i + j]);
	DPRINT ("\n");
      }
  }
#endif

  DPRINT ("calculating RSA\n");
  ret = rsa_calculate (message, result, len / 2);

  if (ret)
    {
// prevent sensitive data
      DPRINT ("RSA fail clearing buffers\n");
      memset (message, 0, 256);
      memset (result, 0, 256);
      return 0;
    }
  DPRINT ("RSA ok, reversing\n");
  reverse_string (result, part_size);
  DPRINT ("return size %d\n", part_size);
  return part_size;
}

// size 24/32/48 for ecc 192,256/384 bis, id 0 get key from selected file and use
// key size to setup ec parameters
static uint8_t
prepare_ec_param (struct ec_param *c, uint8_t size)
{
  uint16_t ret;

  memset (c, 0, sizeof (struct ec_param));
  // ACL and file existence is checked in fs_key_read, return value can be used to select
  // 192/256/384 key algo

  if (size == 0)
    ret = fs_key_read_part ((uint8_t *) & c->private_key, KEY_EC_PRIVATE);
  else
    ret = size;
  if (ret == 24)
    {
      c->mp_size = 24;
      get_constant (&c->prime, N_P192V1_prime);
      get_constant (&c->order, N_P192V1_order);
      get_constant (&c->Gx, N_P192V1_Gx);
      get_constant (&c->Gy, N_P192V1_Gy);
      c->curve_type = C_PRIME192V1;
    }
  else if (ret == 32)
    {
#ifndef NIST_ONLY
// Experimental only!
      if (fs_get_file_type () != 0x22)
	{
	  c->mp_size = 32;
	  get_constant (&c->prime, N_SECP256K1_prime);
	  get_constant (&c->order, N_SECP256K1_order);
	  get_constant (&c->Gx, N_SECP256K1_Gx);
	  get_constant (&c->Gy, N_SECP256K1_Gy);
	  // for NIST curves and for secp256k1 A is not needed
	  // Special values of A are indicated in the c->curve_type
	  // get_constant (&c->a, N_SECP256K1_a);
	  c->curve_type = C_secp256k1;
	}
      else
	{
#endif
	  c->mp_size = 32;
	  get_constant (&c->prime, N_P256V1_prime);
	  get_constant (&c->order, N_P256V1_order);
	  get_constant (&c->Gx, N_P256V1_Gx);
	  get_constant (&c->Gy, N_P256V1_Gy);
	  c->curve_type = C_PRIME256V1;
#ifndef NIST_ONLY
	}
#endif
    }
  else if (ret == 48)
    {
      c->mp_size = 48;
      get_constant (&c->prime, N_P384V1_prime);
      get_constant (&c->order, N_P384V1_order);
      get_constant (&c->Gx, N_P384V1_Gx);
      get_constant (&c->Gy, N_P384V1_Gy);
      c->curve_type = C_secp384r1;
    }

  else
    return 0;

  reverse_string ((uint8_t *) & c->private_key, ret);
  return ret;
}

/*
apdu for raw ec sign .. ?
>> 00 2a 9e 9a xx 
  
security_operation 9e 9a

*/
// return 0 if fail, or size of response if ok
static uint8_t
sign_ec_raw (uint8_t * message, struct iso7816_response *r)
{
//message -  first byte len, rest  data
  ecdsa_sig_t e;
  uint16_t off;
  uint16_t ret;
  struct ec_param c;

  DPRINT ("%s\n", __FUNCTION__);

  // message to number
  reverse_string (message + 1, message[0]);

  // prepare Ec constant, use size based on key  (key from selected file)
  ret = prepare_ec_param (&c, 0);
  if (ret == 0)
    {
      DPRINT ("Error, unable to get EC parameters/key\n");
      return 0;
    }

  off = message[0];
  message++;
  // pad message to match key length
  if (ret < off)
    off = ret;
  if (off < sizeof (bignum_t))
    memset (message + off, 0, sizeof (bignum_t) - off);

#ifdef DEBUG
  {
    int i;
    DPRINT ("mesage =\n");
    for (i = 0; i < 32; i++)
      DPRINT ("%02X ", message[i]);
    DPRINT ("\n");
  }
#endif

  e.message = (bignum_t *) (message);

  DPRINT ("SIGN ...\n");
  if (ecdsa_sign (&e, &c))
    {
      DPRINT ("SIGN FAIL\n");
      return 0;
    }
  DPRINT ("SIGN OK, generating response\n");
//  reverse_string(e.R.value,c.mp_size);
//  reverse_string(e.S.value,c.mp_size);

// Generate object 1.2.840.10045.4.1  with r and s value

  r->data[0] = 0x30;
  r->data[1] = 2 * (c.mp_size + 2);
  off = 3;
  r->data[2] = 2;

  if (e.R.value[c.mp_size - 1] & 0x80)
//    if (e.R.value[0] & 0x80)
    {
      r->data[1] += 1;
      r->data[off] = c.mp_size + 1;
      off++;
      r->data[off] = 0;
      off++;
    }
  else
    {
      r->data[off] = c.mp_size;
      off++;
    }
  reverse_copy (r->data + off, e.R.value, c.mp_size);
//  memcpy(r->data + off, e.R.value, c.mp_size);
//  reverse_string(r->data + off,c.mp_size);
  off += c.mp_size;
  r->data[off++] = 2;

  if (e.S.value[c.mp_size - 1] & 0x80)
//  if (e.S.value[0] & 0x80)
    {
      r->data[1] += 1;
      r->data[off] = c.mp_size + 1;
      off++;
      r->data[off] = 0;
      off++;
    }
  else
    {
      r->data[off] = c.mp_size;
      off++;
    }
  reverse_copy (r->data + off, e.S.value, c.mp_size);
//   memcpy(r->data + off, e.S.value, c.mp_size);
//  reverse_string(r->data + off,c.mp_size);
  r->flag = R_RESP_READY;
  r->len = off + c.mp_size;
  return r->len;
}


uint16_t
security_env_set_reset (uint8_t * message, uint8_t len,
			struct iso7816_response * r)
{

  uint16_t i;
  uint8_t tag;
  uint8_t taglen;
  uint8_t flag = 0;

// invalidate sec env
  sec_env_valid = 0;

// this is used to initialize sec_env_valid after reboot
  if (message == 0)
    return 0;

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 == 0xf3)
    {
      DPRINT ("%s, Restore security environment %02X\n", __FUNCTION__, M_P2);
      if (M_LC != 0)
	{
	  DPRINT ("%s lc/le not 0 ? \n", __FUNCTION__);
	  return 0x6A87;	// len inconsistent with P1
	}
      return (0x9000);		//Function not supported
    }

/*
APDU for set env:
00 22 41 b6 0a 
    80 01 02 81 02 4b 01 84 01 00

reference algo = 02
file id = 0x4b01
key reference 0
*/

  if (M_P1 == 0x41)
    {
      DPRINT ("set security env\n");
      if (M_P2 != 0xb6 && M_P2 != 0xb8)
	{
	  DPRINT ("Unknown byte P2 = %02x\n", M_P2);
	  return 0x6A81;	//Function not supported
	}
      if (M_LC)
	{
	  //read rest of apdu
	  confirm_command (message);
	  if (read_command_data (message))
	    return 0x6984;	//invalid data
	}

      if (M_P2 == 0xb6)
	DPRINT ("attributes of DST in data field = SIGN operation\n");
      else
	DPRINT ("attributes of CT in data field =  DECIPHER operation\n");


      //Empty or concatenation of Objects (CRDO)
      for (i = 0; i < M_LC; i += taglen)
	{
	  tag = message[5 + i];
	  i++;
	  taglen = message[5 + i];
	  i++;
	  if (tag == 0x80)
	    {
	      flag |= 1;
	      if (taglen != 1)
		return 0x6A81;	//Function not supported      // change to wrong arg ? 
	      DPRINT ("reference algo=%02x\n", message[5 + i]);
	      switch (message[5 + i])
		{
		case 0x00:	// no hash, raw data in paket, len must match key modulus
		case 0x02:	// data must be padded to match key modulus    
		case 0x12:	// SHA1 ...
		case 0x04:	// ECDSA (DATA in RAW format)
		  break;
		default:
		  return 0x6A81;	//Function not supported // change to wrong arg ?  
		}
	      sign_algo = message[5 + i];
	    }
	  if (tag == 0x81)
	    {
	      flag |= 2;
	      if (taglen != 2)
		return 0x6A81;	//Function not supported      // change to wrong arg ? 
	      DPRINT ("private key file id=%02x%02X\n", message[5 + i],
		      message[5 + i + 1]);
	      key_file_id = message[5 + i] << 8 | message[5 + i + 1];
	    }
	  if (tag == 0x84)
	    {
	      flag |= 4;
	      if (taglen != 1)
		return 0x6A81;	//Function not supported      // change to wrong arg ? 
	      DPRINT ("reference for key=%d\n", message[5 + i]);
	      if (message[5 + i] != 0)
		{
		  // MyEID support only one key per file, then this reference must be 0
		  return 0x6A81;	//Function not supported // change to wrong arg ?
		}
	    }
	  if (flag == 7)
	    {
	      sec_env_valid = M_P2;
	      return 0x9000;
	    }
	}
      return 0x6A81;		//Function not supported // change to wrong arg ?
    }
  return 0x6A81;		//Function not supported
}

static uint16_t
security_operation_rsa_ec_sign (uint8_t * message, uint8_t len,
				struct iso7816_response *r)
{
  uint8_t flag = 0xff;
  if (M_LC == 0)
    return 0x6700;		//Incorrect length

  //read rest of apdu
  confirm_command (message);
  if (read_command_data (message))
    return 0x6984;		//invalid data

// is security enviroment set to sign ?
  if (sec_env_valid != 0xb6)
    {
      DPRINT ("invalid sec env\n");
      return 0x6985;		//    Conditions not satisfied
    }
// compare if selected file is same as file id from sec env
  if (fs_get_selected () != key_file_id)
    {
      DPRINT ("file selected not same as in sec env\n");
      return 0x6985;		//    Conditions not satisfied
    }

  DPRINT ("%d %d %d\n", sec_env_valid, sign_algo, message[4]);
  if (sign_algo == 4)
    {
      DPRINT ("RAW-ECDSA-PKCS algo %02x\n", sign_algo);
      // this is  long operation, start sending NULL
      card_io_start_null ();
      // in buffer RAW data to be signed
      if (sign_ec_raw (message + 4, r))
	return ((0x61 << 8) | r->len);
      return 0x6985;		//    Conditions not satisfied
    }

  if (sign_algo == 2)
    {
      DPRINT ("Digest Info data in paket\n");
      flag = 2;
    }
  if (sign_algo == 0x12)
    {
      DPRINT ("SHA1 message in buffer\n");
      flag = 1;
    }
  if (sign_algo == 0)
    {
      DPRINT ("RAW message in buffer\n");
      flag = 0;
    }
  if (flag != 0xff)
    {
      uint16_t size;

      // move message to buffer start (rsa_calculate need 2x RSA_BYTES buffer)
      size = M_LC;
      memmove (message, message + 5, size);
      // this is  long operation, start sending NULL
      card_io_start_null ();
      size = rsa_raw (size, message, r->data, flag);

//  DPRINT ("RSA calculation %s, returning APDU\n", size ? "OK":"FAIL");
      if (size != 0)
	{
	  if (size == 256)
	    r->len = 0;
	  else
	    r->len = size & 255;
	  r->flag = R_RESP_READY;
	  DPRINT ("RSA sign OK\n");
	  return ((0x61 << 8) | r->len);
	}
      else
	{
	  return 0x6985;	//    Conditions not satisfied  
	}
    }

  DPRINT ("sec environment %s valid sign algo = 0x%02x, message len %d\n",
	  sec_env_valid == 0 ? "in" : "", sign_algo, message[4]);
  DPRINT ("TODO .. this is unsupported now\n");
  return 0x6A81;		//Function not supported
}

static uint16_t
security_operation_rsa_decrypt (uint8_t * message, uint8_t len,
				struct iso7816_response *r)
{
  uint16_t size;

  if (sec_env_valid != 0xb8)
    {
      return 0x6985;		//    Conditions not satisfied 
    }
  DPRINT ("return decrypted data\n");
  DPRINT ("sec environment %s valid sign algo = 0x%02x\n",
	  sec_env_valid == 0 ? "in" : "", sign_algo);

  // myeid doc - M_LC must be 0x81, but this
  // is valid only for 1024 bit key,
  // check only if M_LC is over 511 bits ..
  if (M_LC < 0x41)
    {
      return 0x6700;		//Incorrect length
    }
  //read rest of apdu
  confirm_command (message);
  if (read_command_data (message))
    return 0x6984;		//invalid data

  if (message[5] == 0x81)
    {
      DPRINT ("First part of data to decypt, saving into temp buffer\n");
      r->len = M_LC - 1;
      // copy data into temp buffer
      memcpy (r->data, message + 6, M_LC - 1);
      r->flag = R_TMP;
      return 0x9000;
    }
  else if (message[5] == 0x82)
    {
      DPRINT ("Second part of data to decrypt\n");
      if (r->flag != R_TMP)
	{
	  DPRINT ("First part of data missing\n");
	  return 0x6984;	// Invalid data
	}
      r->flag = R_NO_DATA;
      size = r->len;
      // append data into temp buffer
      // memcpy (r->data + size, message + 6, size);
      memcpy (r->data + size, message + 6, M_LC);
      size += M_LC;
      size--;
      // move data from emp buffe rinto message buffer
      memcpy (message, r->data, size);
#ifdef DEBUG
      {
	int i, j;
	DPRINT ("mesage to decrypt sum=%d\n", size);
	for (j = 0; j < 256; j += 32)
	  {
	    for (i = 0; i < 32; i++)
	      DPRINT ("%02X ", r->data[i + j]);
	    DPRINT ("\n");
	  }
      }
#endif
      // this is  long operation, start sending NULL
      card_io_start_null ();
      size = rsa_raw (size, message, r->data, 0);
    }
  else if (message[5] == 0)
    {
      // move message to buffer start (rsa_calculate need 2x RSA_BYTES buffer)
      size = M_LC - 1;
      memmove (message, message + 6, size);
      DPRINT ("Data to decrypt\n");
      // this is  long operation, start sending NULL
      card_io_start_null ();
      size = rsa_raw (size, message, r->data, 0);
    }
  else
    {
      DPRINT ("Unknown padding for decrypt data\n");
      return 0x6984;		// Invalid data
    }

  if (size != 0)
    {
      if (sign_algo == 2)
	{
#warning what is correct to do ? raise error or return data "as is" ?
	  // on wrong padding data are returned "as is"
	  DPRINT ("requested padding remove operation, (message len %d)\n",
		  size);
	  if (r->data[0] == 0 && r->data[1] == 2 && size > 11)
	    {
	      // allowed padding is 00 02 ... random data .. 0  real data

	      uint8_t *padd = r->data + 2;
	      uint16_t s = size - 3;

	      for (; s > 0; s--, padd++)
		if (*padd == 0)
		  {
		    if (padd < r->data + 12)
		      break;
		    padd++;
		    memcpy (r->data, padd, s);
		    size = s;
		    DPRINT ("padding removed, (message len %d)\n", size);
		    break;
		  }
	      // TODO, DPRINT.. if padding was not removed (no 00 found)
	    }
	  else
	    DPRINT ("Unknown padding, %02x %02x,\n", r->data[0], r->data[1]);
	}

      if (size == 256)
	r->len = 0;
      else
	r->len = size & 255;

      r->flag = R_RESP_READY;

#ifdef DEBUG
      {
	int i, j;
	DPRINT ("return mesage =\n");
	for (j = 0; j < 140; j += 32)
	  {
	    for (i = 0; i < 32; i++)
	      DPRINT ("%02X ", r->data[i + j]);
	    DPRINT ("\n");
	  }
      }
#endif
      return ((0x61 << 8) | r->len);
    }
  return 0x6985;		//    Conditions not satisfied
}

uint16_t
security_operation (uint8_t * message, uint8_t len,
		    struct iso7816_response * r)
{

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  // 0x9E = return digital signature
  // 0x9A = data in APDU = source for digital signature
  if (M_P1 == 0x9E && M_P2 == 0x9A)
    return security_operation_rsa_ec_sign (message, len, r);

  // decipher operation 
  if (M_P1 == 0x80 && M_P2 == 0x86)
    return security_operation_rsa_decrypt (message, len, r);

//  return 0x6A81;      //Function not supported
  return 0x6A86;		//Incorrect parameters P1-P2
}

uint16_t
myeid_generate_key (uint8_t * message, uint8_t len)
{

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 != 0 || M_P2 != 0)
    return 0x6A86;		//Incorrect parameters P1-P2

  if (M_LC)
    {
      // private RSA exponent in APDU (MyEID allow only 3 or 65537)
      // Sequence 0x30, size 0x05, 0x81 ..
      // 0x30 0x05 0x81  then size and data: 0x01 0x03 = exponent 3
      // 0x30 0x07 0x81  then size and data: 0x03 0x01 0x00 0x01 (65537)
      // OsEID does not need this, RSA key generation is not supported
      //
      // opensc 0.16.0 seems to be have a error, exponent 65537 is send with wrong length:
      // 0x30 0x05 0x81 0x03 0x01 0x00 0x01

      // read rest of apdu
      confirm_command (message);
      if (read_command_data (message))
	return 0x6984;		//invalid data
    }
// EC keys, no data in APDU
  if (M_LC == 0)
    {
      uint16_t k_size;

      struct private_key
      {
	uint8_t type;
	uint8_t size;
	bignum_t key;
      } private_key;

      struct pub_key
      {
	uint8_t type;
	uint8_t size;
	uint8_t ui;		// for 0x04 = indicate uncompressed key
	uint8_t key_bytes[2 * sizeof (bignum_t)];
	ec_point_t key;

// next value is for avr-gcc, code is smaller with this aligment
//      uint8_t align[181];
      }
      pub_key;

      struct ec_param c;

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
      k_size = fs_get_file_size ();
      if (k_size == 0xffff)
	return 0x6a82;		//file not found

      if (fs_get_file_type () != 0x22)
	return 0x6985;		//    Conditions not satisfied
// get key size (from file size), now only EC keys are supported (192 and 256 bits)
      if (k_size != 384 && k_size != 256 && k_size != 192)
	return 0x6985;		//    Conditions not satisfied

      card_io_start_null ();

      DPRINT ("Generating key, selected file 0x%04x, key size %d bits\n",
	      fs_get_selected (), k_size);

      if (0 == prepare_ec_param (&c, k_size / 8))
	{
	  DPRINT ("Wrong EC parameteres\n");
	  return 0x6985;	//    Conditions not satisfied
	}
      if (ec_key_gener (&private_key.key, &pub_key.key, &c))
	{
	  DPRINT ("Key wrong\n");
	  return 0x6985;	//    Conditions not satisfied
	}

      // reverse key
      reverse_string ((uint8_t *) & private_key.key, c.mp_size);
      reverse_copy ((uint8_t *) & pub_key.key_bytes,
		    (uint8_t *) & pub_key.key.X, c.mp_size);
      reverse_copy (c.mp_size + (uint8_t *) & pub_key.key_bytes,
		    (uint8_t *) & pub_key.key.Y, c.mp_size);
      // function for write key inspect size of key and checks ACL ..
      // (based on actually selected file)

      private_key.type = KEY_EC_PRIVATE | KEY_GENERATE;
      private_key.size = c.mp_size;

      uint16_t ret = fs_key_write_part ((uint8_t *) & private_key);

      if (ret != 0x9000)
	return ret;

      // store public key with 0x04 uncompressed indicator 
      pub_key.type = KEY_EC_PUBLIC | KEY_GENERATE;
      pub_key.size = c.mp_size * 2 + 1;
      pub_key.ui = 4;

      return fs_key_write_part ((uint8_t *) & pub_key);
    }
  return 0x6985;		//    Conditions not satisfied
}

/*

get/put data emulation of MYEID card

*/
uint16_t
myeid_get_data (uint8_t * message, uint8_t len, struct iso7816_response * r)
{
  uint16_t ret;

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 != 1)
    return 0x6a88;		//Referenced data (data objects) not found

  switch (M_P2)
    {
    case 0xa0:
      get_constant (r->data, N_CARD_ID);
      r->len = 20;
      r->flag = R_RESP_READY;
      return (0x6114);
    case 0xa1:
    case 0xa2:
    case 0xa3:
      return fs_list_files ((M_P2 - 0xa1), r);
    case 0:
      // info data for key
// 6 bytes
// 0x9200 - CRT algo identifier
// 0xMMMM - bits of modulus
// 0xEEEE - size of publix exponent
      r->data[0] = 0x92;
      r->data[1] = 0;
      ret = fs_key_read_part (NULL, KEY_RSA_EXP_PUB);
      DPRINT ("ret=%d\n", ret);
      if (!ret)
	return 0x6a88;		//Referenced data (data objects) not found
      ret = ret * 8;
      r->data[2] = ret >> 8;
      r->data[3] = ret & 0xff;
      ret = fs_key_read_part (NULL, KEY_RSA_p);
      DPRINT ("ret=%d\n", ret);
      if (!ret)
	return 0x6a88;		//Referenced data (data objects) not found
      ret = ret * 16;
      r->data[4] = ret >> 8;
      r->data[5] = ret & 0xff;
      r->len = 6;
      r->flag = R_RESP_READY;
      return 0x6106;		// 6 bytes
    case 1:
      // modulus
      ret = fs_key_read_part (r->data, KEY_RSA_MOD);
      DPRINT ("ret1=%d\n", ret);
      if (!ret)
	{
	  uint16_t len;

	  ret = fs_key_read_part (r->data, KEY_RSA_MOD_p1);
	  DPRINT ("ret2=%d\n", ret);

	  if (!ret)
	    return 0x6a88;	//Referenced data (data objects) not found
// fs_key_read_part return maximum RSA_BYTES
#if RSA_BYTES > 128
#error posible overflow in response buffer
#endif
	  len = ret;
	  ret = fs_key_read_part (r->data + ret, KEY_RSA_MOD_p2);
	  DPRINT ("ret3=%d\n", ret);
	  if (!ret)
	    return 0x6a88;	//Referenced data (data objects) not found
	  ret += len;
	  if (ret == 256)
	    ret = 0;
	}
      r->len = ret;
      r->flag = R_RESP_READY;
      return 0x6100 | ret;

    case 2:
      // public exponent
      ret = fs_key_read_part (r->data, KEY_RSA_EXP_PUB);
      DPRINT ("ret_p=%d\n", ret);
      if (!ret)
	return 0x6a88;		//Referenced data (data objects) not found
      r->len = ret;
      r->flag = R_RESP_READY;
      return 0x6100 | ret;

//read public key
    case 0x86:
      {
	uint16_t ret;

	DPRINT ("Reading public EC key\n");
/*
Return seq:
0x30 0x__len__ _public_key_
return size = 2 + _public_key_size_
opensc add to this data OID of prime192v1 or prime256v1 curve. 
Use public key with "uncompressed" indicator (byte 04 at start)
(size 49 for prime192v1 or size 65 for prime256v1)
*/
	// read public key (insert offset for seq 0x30, len)
	//
	ret = fs_key_read_part (r->data + 2, KEY_EC_PUBLIC);
	DPRINT ("Public key len %d\n", ret);
	if (ret == 0)
	  return 0x6985;	// conditions not satisfaied
	//correct first two bytes in response
	r->data[0] = 0x30;
	r->data[1] = ret + 2;
	r->flag = R_RESP_READY;
	r->len = ret + 2;
	return ((0x61 << 8) | (ret + 2));
      }
    default:
      return 0x6a88;		//Referenced data (data objects) not found
    }
}

static uint16_t
myeid_upload_ec_key (uint8_t * message, uint8_t len)
{
  DPRINT ("%s %02x %02x %02x\n", __FUNCTION__, M_P1, M_P2, M_LC);

//  message[5] = message[4];
  // EC key private key upload
  if (M_P2 == 0x87)
    message[3] = KEY_EC_PRIVATE;
  else if (M_P2 == 0x86)
    message[3] = KEY_EC_PUBLIC;
  else
    return 0x6985;		//    Conditions not satisfied

  card_io_start_null ();
  return fs_key_write_part (message + 3);
}


static uint16_t
myeid_upload_rsa_key (uint8_t * message, uint8_t len, uint16_t size)
{
  uint16_t test_size;
  uint8_t m_size = M_LC;

  DPRINT ("uloading key type %02x\n", M_P2);

  // key part may start with 0x00 and M_LC is incremented by one (65 bytes for 1024 key)
  if ((m_size & 1) && (M_P2 != 0x81))
    {
      DPRINT ("M_LC is odd, message[5] = 0x%02x\n", message[5]);
      if (message[5] != 0)
	return 0x6985;		//    Conditions not satisfied
      m_size--;
      message[5] = m_size;
      message[4] = message[3];
      message++;
    }

  switch (M_P2)
    {
    case KEY_RSA_p:
    case KEY_RSA_q:
    case KEY_RSA_dP:
    case KEY_RSA_dQ:
    case KEY_RSA_qInv:

    case KEY_RSA_MOD_p1:
    case KEY_RSA_MOD_p2:
      test_size = 16 * m_size;
      break;
    case KEY_RSA_MOD:
      test_size = 8 * m_size;
      break;
    case KEY_RSA_EXP_PUB:
      test_size = size;
      break;
    case KEY_RSA_EXP:
    case KEY_RSA_EXP_p1:
    case KEY_RSA_EXP_p2:
      DPRINT ("RSA KEY private exponent part 2 for 2048 .. \n");
      DPRINT ("private exponent unsuported, use CRT keys\n");
      return 0x6985;		//    Conditions not satisfied
    default:
      return 0x6985;		//    Conditions not satisfied
    }
// proceed checked types ..    
  if (test_size > RSA_BYTES * 16)
    {
      DPRINT ("RSA_BYTES  %d does not allow key len %d\n", RSA_BYTES,
	      test_size);
      return 0x6985;		//    Conditions not satisfied
    }
  if (size != test_size)
    {
      DPRINT ("write size, key file %d size of part %d\n", size, m_size);
      return 0x6985;		//    Conditions not satisfied
    }
  card_io_start_null ();
  return fs_key_write_part (message + 3);
}


static uint16_t
myeid_upload_keys (uint8_t * message, uint8_t len)
{
  uint16_t k_size;
  uint8_t type;

  DPRINT ("%s \n", __FUNCTION__);
// key upload, file is already selected,
// key type/size can be determined only from file size
// file size 0x0800 = 2048 RSA key
// file size 0x0400 = 1024 RSA key
// file size 0x0200 = 512 RSA key
// file size 0x0209 = 521 EC key
// file size 0x0180 = 384 EC key
// file size 0x0100 = 256 EC key
// file size 0x00C0 = 192 EC key

  k_size = fs_get_file_size ();
  if (!k_size)
    return 0x6a82;		//file not found

// EC key is stored to file with type 0x22, RSA to type 0x11

  type = fs_get_file_type ();
  DPRINT ("Key size %d, type=0x%02x\n", k_size, type);

#ifndef NIST_ONLY
  if (type == 0x23 && k_size == 0x0100)
    return myeid_upload_ec_key (message, len);
#endif
  if (type == 0x22)
    {
      if (k_size == 0x00c0 || k_size == 0x0100 || k_size == 0x0180
	  || k_size == 0x0209)
	return myeid_upload_ec_key (message, len);
    }
  if (type == 0x11)
    {
      if (k_size >= 0x0200 && k_size <= 0x0800)
	return myeid_upload_rsa_key (message, len, k_size);
    }
  return 0x6981;		//icorrect file type
}

uint16_t
myeid_put_data (uint8_t * message, uint8_t len, struct iso7816_response * r)
{
  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_LC)
    {
      //read rest of apdu
      confirm_command (message);
      if (read_command_data (message))
	return 0x6984;		//invalid data
    }

  if (M_P1 != 1)
    return 0x6a88;		//Referenced data (data objects) not found
  if (M_P2 == 0xe0)
    {				//initialize applet
      if (M_LC != 8)
	return 0x6700;		//Incorrect length
      DPRINT
	("Filesystem size %d, MF ACL=%02X%02X%02X 5015 ACL=%02X%02X%02X\n",
	 message[5] * 256 + message[6], message[7], message[8], message[9],
	 message[10], message[11], message[12]);
      // this is  long operation, start sending NULL
      card_io_start_null ();

      return fs_erase_card (message + 7);
    }
  if (M_P2 > 0 && M_P2 < 15)
    {
      if (M_LC < 0x10 || M_LC > 0x13)
	return 0x6700;		//Incorrect length
      DPRINT ("initialization of PIN %d\n", M_P2);
      return fs_initialize_pin (message + 3);
    }
  // Upload keys
  if (M_P2 >= 0x80 && M_P2 <= 0x8B)
    return myeid_upload_keys (message, len);

  return 0x6A81;		//Function not supported
}


uint16_t
myeid_activate_applet (uint8_t * message, uint8_t len)
{
  if (M_LC)
    {
      //read rest of apdu
      confirm_command (message);
      if (read_command_data (message))
	return 0x6984;		//invalid data
    }
  //TOTO check applet name   
  fs_set_lifecycle ();
  return (0x9000);
}
