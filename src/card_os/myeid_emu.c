/*
    myeid_emu.c

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

    Emulation of MyEID functions

*/
/*
 Function are based on documentation from:
 http://aventra.fi/pdf/MyEID%20PKI%20JavaCard%20Applet%20Reference%20Manual%201-7-7.pdf
 (local copy internet_sources/MyEID PKI JavaCard Applet Reference Manual 1-7-7.pdf)

 Some functions are derived from opensc sources https://github.com/OpenSC/OpenSC - card-myeid.c

 It is assumed, all functions can access 5 bytes of message in message buffer.
 Caller is responsible to fill this data in message correctly.


*/

#ifdef DEBUG
#include <stdio.h>
#define  DPRINT(msg...) fprintf(stderr,msg)
#else
#define DPRINT(msg...)
#endif


#include <stdint.h>
#include <string.h>
#include <stddef.h>
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
#define M_LC message[4]

#if RSA_BYTES > 128
#error RSA_BYTES over 128, for atmega only 256 byte buffers are reserved!
#endif

uint8_t sign_algo __attribute__ ((section (".noinit")));
uint16_t key_file_id __attribute__ ((section (".noinit")));

// bits 0..3  operation
// bits 4..7  flags
#define SENV_SIGN 1
#define SENV_DECRYPT 2
#define SENV_ENCRYPT 3
#define SENV_ECDH    4

#define SENV_INIT_VECTOR 0x80
#define SENV_OP_MASK  15

uint8_t sec_env_valid __attribute__ ((section (".noinit")));

static uint8_t __attribute__ ((noinline))
resp_ready (struct iso7816_response *r, uint8_t len)
{
  r->flag = R_RESP_READY;
  r->len = len;
  return S0x6100;
}

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

  part_size = fs_key_read_part (NULL, id);
  if (part_size > RSA_BYTES)
    return 0;
  fs_key_read_part (key, id);
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

// for NIST curves and for secp256k1 A is not needed
// Special values of A (A=0, A=-3) are indicated in the c->curve_type
// (A and B is needed for ECDH operation to check if point is on curve)

// size 24/32/48 for ecc 192,256/384 bis, id 0 get key from selected file and use
// key size to setup ec parameters
static uint8_t
prepare_ec_param (struct ec_param *c, ec_point_t * p, uint8_t size)
{
  uint16_t ret;
  uint8_t var_Gx, var_Gy, var_A, var_B, var_PRIME, var_ORDER, var_TYPE;


  memset (c, 0, sizeof (struct ec_param));
  // ACL and file existence is checked in fs_key_read, return value can be used to select
  // 192/256/384 key algo

  if (size == 0)
    ret = fs_key_read_part ((uint8_t *) & c->working_key, KEY_EC_PRIVATE);
  else
    ret = size;

#ifndef NIST_ONLY
  if (fs_get_file_type () == 0x23)
    {
      var_Gx = N_SECP256K1_Gx;
      var_Gy = N_SECP256K1_Gy;
      var_A = N_SECP256K1_a;
      var_B = N_SECP256K1_b;
      var_PRIME = N_SECP256K1_prime;
      var_ORDER = N_SECP256K1_order;
      var_TYPE = C_secp256k1;
    }
  else
#endif
    {
      if (ret == 24)
	{
	  var_Gx = N_P192V1_Gx;
	  var_Gy = N_P192V1_Gy;
	  var_A = N_P192V1_a;
	  var_B = N_P192V1_b;
	  var_PRIME = N_P192V1_prime;
	  var_ORDER = N_P192V1_order;
	  var_TYPE = C_PRIME192V1;
	}
      else if (ret == 32)
	{
	  var_Gx = N_P256V1_Gx;
	  var_Gy = N_P256V1_Gy;
	  var_A = N_P256V1_a;
	  var_B = N_P256V1_b;
	  var_PRIME = N_P256V1_prime;
	  var_ORDER = N_P256V1_order;
	  var_TYPE = C_PRIME256V1;
	}
      else if (ret == 48)
	{
	  var_Gx = N_P384V1_Gx;
	  var_Gy = N_P384V1_Gy;
	  var_A = N_P384V1_a;
	  var_B = N_P384V1_b;
	  var_PRIME = N_P384V1_prime;
	  var_ORDER = N_P384V1_order;
	  var_TYPE = C_secp384r1;
	}
      else
	return 0;
    }
  if (p)
    {
      get_constant ((uint8_t *) & (p->X), var_Gx);
      get_constant ((uint8_t *) & (p->Y), var_Gy);
    }
  get_constant (&c->prime, var_PRIME);
  get_constant (&c->order, var_ORDER);
  get_constant (&c->a, var_A);
  get_constant (&c->b, var_B);
  c->curve_type = var_TYPE;

  reverse_string ((uint8_t *) & c->working_key, ret);
  c->mp_size = ret;
  return ret;
}


static uint8_t
add_num_to_seq (uint8_t * here, uint8_t * num, uint8_t size)
{
  uint8_t ret = size;

  reverse_string (num, size);

  *(here++) = 2;
  *here = size;
  if (*num & 0x80)
    {
      *(here++) = size + 1;
      ret++;
      *here = 0;
    }
  memcpy (here + 1, num, size);
  return ret + 2;
}

// return 0 if fail, or size of response if ok
static uint8_t
sign_ec_raw (uint8_t * message, struct iso7816_response *r)
{
//message -  first byte len, rest  data

// reuse "message" buffer for ecdsa_sig_t (warning, this is realy only for max 48 bytes in bignum_t)
  ecdsa_sig_t *e = (ecdsa_sig_t *) (message + 1 + sizeof (bignum_t));
// reuse result buffer for ec_param structure
  struct ec_param *c = (struct ec_param *) r->data;
  uint16_t off;
  uint16_t ret;

  DPRINT ("%s\n", __FUNCTION__);

  // message to number
  reverse_string (message + 1, message[0]);

  // prepare Ec constant, use size based on key  (key from selected file)
  // generator point into e->signature
  ret = prepare_ec_param (c, &e->signature, 0);
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

  DPRINT ("SIGN ...\n");
  if (ecdsa_sign (message, e, c))
    {
      DPRINT ("SIGN FAIL\n");
      return 0;
    }
  DPRINT ("SIGN OK, generating response\n");

// Generate object 1.2.840.10045.4.1  with r and s value

  uint8_t *here;
  uint8_t skip;

  here = r->data + 2;
  skip = add_num_to_seq (here, e->R.value, c->mp_size);
  here += skip;
  skip += add_num_to_seq (here, e->S.value, c->mp_size);

  r->data[0] = 0x30;
  r->data[1] = skip;
  skip += 2;

  r->flag = R_RESP_READY;
  r->len = skip;
  return skip;
}


uint8_t
security_env_set_reset (uint8_t * message, struct iso7816_response * r)
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
	  return S0x6a87;	// len inconsistent with P1
	}
      return (S_RET_OK);	//Function not supported
    }
// MyEID manual 2.1.4: P1 must be set to 0xA4 for ECDH, but opensc 0.17 set
// this to 0x41 and P2 is set to 0xA4 ..  allow A4 here too
  if (M_P1 == 0xA4)
    {
      M_P1 = 0x41;
      M_P2 = 0xA4;
    }
  if (M_P1 == 0x41 || M_P1 == 0x81)
    {
      DPRINT ("set security env\n");
      if (M_LC)
	{
	  //read rest of apdu
	  confirm_command (message);
	  if (read_command_data (message))
	    return S0x6984;	//invalid data
	}

      if (M_P2 == 0xb6)
	{
	  DPRINT ("attributes of DST in data field = SIGN operation\n");
	  sec_env_valid = SENV_SIGN;
	}
      else if (M_P2 == 0xb8)
	{
	  DPRINT
	    ("attributes of CT in data field =  DECIPHER/ENCIPHER operation\n");
	  if (M_P1 == 0x81)
	    sec_env_valid = SENV_ENCRYPT;
	  else
	    sec_env_valid = SENV_DECRYPT;
	}
      else if (M_P2 == 0xa4)
	{
	  DPRINT ("authentication/key agreement\n");
	  sec_env_valid = SENV_ECDH;
	}
      else
	{
	  DPRINT ("Unknown byte P2 = %02x\n", M_P2);
	  return S0x6a81;	//Function not supported
	}
      // Empty or concatenation of Control Reference Data Objects (CRDO)
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
		return S0x6a81;	//Function not supported      // change to wrong arg ?
	      DPRINT ("reference algo=%02x\n", message[5 + i]);
	      switch (message[5 + i])
		{
		case 0x00:	// no hash, raw data in paket, len must match key modulus
		case 0x02:	// data must be padded to match key modulus
		case 0x12:	// SHA1 ...
		case 0x04:	// ECDSA (DATA in RAW format)
		  break;
		default:
		  return S0x6a81;	//Function not supported // change to wrong arg ?
		}
	      sign_algo = message[5 + i];
	      continue;
	    }
	  if (tag == 0x81)
	    {
	      flag |= 2;
	      if (taglen != 2)
		return S0x6a81;	//Function not supported      // change to wrong arg ?
	      DPRINT ("private key file id=%02x%02X\n", message[5 + i],
		      message[5 + i + 1]);
	      key_file_id = message[5 + i] << 8 | message[5 + i + 1];
	      continue;
	    }
	  if (tag == 0x83 || tag == 0x84)	// not required
	    {
	      if (taglen != 1)
		return S0x6a81;	//Function not supported      // change to wrong arg ?
	      DPRINT ("reference for key=%d\n", message[5 + i]);
	      if (message[5 + i] != 0)
		{
		  // MyEID support only one key per file, then this reference must be 0
		  return S0x6a81;	//Function not supported // change to wrong arg ?
		}
	      continue;
	    }
	  if (tag == 0x87)	// initialization vector - not required
	    {
	      // not used, experimental support for DES,AES only...
	      sec_env_valid |= SENV_INIT_VECTOR;
	      continue;
	    }
	  return S0x6a80;	// incorrect parameters in the data field / wrong data
	}
      if (flag != 3)
	{
	  DPRINT ("not all env variables present flag = %02x\n", flag);
	  sec_env_valid = 0;	//Function not supported // change to wrong arg ?
	  return S0x6a81;
	}
      return S_RET_OK;
    }
  return S0x6a81;		//Function not supported
}

static uint8_t
security_operation_rsa_ec_sign (uint8_t * message, struct iso7816_response *r)
{
  uint8_t flag = 0xff;
  if (M_LC == 0)
    return S0x6700;		//Incorrect length

  //read rest of apdu
  confirm_command (message);
  if (read_command_data (message))
    return S0x6984;		//invalid data

// is security enviroment set to sign ?
  if ((sec_env_valid & SENV_OP_MASK) != SENV_SIGN)
    {
      DPRINT ("invalid sec env\n");
      return S0x6985;		//    Conditions not satisfied
    }
  DPRINT ("%d %d %d\n", sec_env_valid, sign_algo, message[4]);
  if (sign_algo == 4)
    {
      DPRINT ("RAW-ECDSA-PKCS algo %02x\n", sign_algo);
      // this is  long operation, start sending NULL
      card_io_start_null ();
      // in buffer RAW data to be signed
      if (sign_ec_raw (message + 4, r))
	return resp_ready (r, r->len);
      return S0x6985;		//    Conditions not satisfied
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
	  DPRINT ("RSA sign OK\n");
	  // maximal size 256 bytes is send back as 0
	  return resp_ready (r, size & 0xff);
	}
      else
	{
	  return S0x6985;	//    Conditions not satisfied
	}
    }

  DPRINT ("sec environment %0x2 valid sign algo = 0x%02x, message len %d\n",
	  sec_env_valid, sign_algo, message[4]);
  DPRINT ("TODO .. this is unsupported now\n");
  return S0x6a81;		//Function not supported
}

static uint8_t
des_aes_cipher (uint16_t size, uint8_t * data, struct iso7816_response *r,
		uint8_t mode)
{
  uint8_t type;
  uint8_t ksize;


// there is 256 bytes free in r-data
  ksize = fs_key_read_part (r->data, 0xa0);

  type = fs_get_file_type ();
  DPRINT ("key type =%02x\n", type);
  if (type == 0x19)		// DES
    {
      uint8_t flag;

      if (ksize == 16)
	{
	  memcpy (r->data, r->data + 16, 8);
	  flag = DES_3DES;
	}
      else if (ksize == 24)
	flag = DES_3DES;
      else if (ksize == 8)
	flag = 0;
      else
	return S0x6981;		//incorect file type
      if (size != 8)
	return S0x6700;		//Incorrect length
      if (mode)
	flag |= DES_DECRYPTION_MODE;
      des_run (data, r->data, flag);
      memcpy (r->data, data, size);
      return resp_ready (r, size & 0xff);
    }
  else if (type == 0x29)	// AES
    {
      if (size != 16)
	return S0x6700;		//Incorrect length
      aes_run (data, r->data, ksize, mode);
      memcpy (r->data, data, size);
      return resp_ready (r, size & 0xff);
    }
  else
    return S0x6981;		//incorect file type
}


static uint8_t
decipher (uint16_t size, uint8_t * message, struct iso7816_response *r)
{

  DPRINT ("%s\n", __FUNCTION__);
// check key type, if DES/AES key is selected - key must be tagged with 0xa0 tag
  if (fs_key_read_part (NULL, 0xA0))
    {
// allow AES, DES only for experimental purposes (CLA 0x80)
      if (message[0] != 0x80)
	return S0x6a81;		//function not supported
      return des_aes_cipher (size, message + 5, r, 1 /*DECRYPTION_MODE */ );
    }

// RSA decrypt, and optional padding remove
  card_io_start_null ();
  size = rsa_raw (size, message, r->data, 0);

  if (size == 0)
    {
      DPRINT ("decrypt fail\n");
      return S0x6985;		// command not satisfied
    }
// remove padding
  if (sign_algo == 2)
    {
      // return error for not correct padding
      // allowed padding is: 00 || 02 || random data[8+] || 00 || real data
      DPRINT ("requested padding remove operation, (message len %d)\n", size);
      if (r->data[0] == 0 && r->data[1] == 2 && size > 11)
	{
	  uint8_t *padd = r->data + 2;
	  uint16_t s = size - 3;

	  for (; s > 0; s--, padd++)
	    if (*padd == 0)
	      {
		if (padd < r->data + 10)
		  {
		    DPRINT ("Wrong padding, below 8 bytes of random data\n");
		    return S0x6985;	// command not satisfied
		  }
		memcpy (r->data, padd + 1, s);
		size = s;
		DPRINT ("padding removed, (message len %d)\n", size);
		break;
	      }
	  if (!s)
	    {
	      DPRINT
		("Wrong padding, no 0x00 found after random padding data\n");
	      return S0x6985;	// command not satisfied
	    }
	}
      else
	{
	  DPRINT ("Unknown padding, %02x %02x,\n", r->data[0], r->data[1]);
	  return S0x6985;	// command not satisfied
	}
    }
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
  return resp_ready (r, size & 0xff);


}

static uint8_t
security_operation_encrypt (uint8_t * message, struct iso7816_response *r)
{
  DPRINT ("%s\n", __FUNCTION__);

  if ((sec_env_valid & SENV_OP_MASK) != SENV_ENCRYPT)
    {
      DPRINT ("security env not valid\n");
      return S0x6985;		//    Conditions not satisfied
    }
  DPRINT ("return enrypted data\n");

  if (M_P2 != 0x80)		// data field contains plaintext
    return S0x6984;		//invalid data

// security operation always need data
  if (M_LC == 0)
    return S0x6984;		//invalid data
  confirm_command (message);
  if (read_command_data (message))
    return S0x6984;		//invalid data

// allow AES, DES only for experimental purposes (CLA 0x80)
  if (message[0] != 0x80)
    return S0x6a81;		//function not supported

  return des_aes_cipher (M_LC, message + 5, r, 0);
}

static uint8_t
security_operation_decrypt (uint8_t * message, struct iso7816_response *r)
{
  uint16_t size;

  DPRINT ("%s\n", __FUNCTION__);
  if ((sec_env_valid & SENV_OP_MASK) != SENV_DECRYPT)
    {
      DPRINT ("security env not valid\n");
      return S0x6985;		//    Conditions not satisfied
    }
  DPRINT ("return decrypted data\n");
  DPRINT ("sec environment %02x valid sign algo = 0x%02x\n",
	  sec_env_valid, sign_algo);

// security operation always need data
  if (M_LC == 0)
    return S0x6984;		//invalid data
  confirm_command (message);
  if (read_command_data (message))
    return S0x6984;		//invalid data

// check M_P2 - according MyEID doc, 0x84 is used to mark encrypted data
// (AES or DES) and 0x86 is used to mark padding indicator concatenated
// with encrypted data (RSA, and ECC). Handle both cases similar, get plain
// data for decipher operation, then call rsa/ecc/aes/des operation.
// This allow us send encrypted data  to RSA/ECC too.

  if (M_P2 == 0x84)		// data field contains encrypted data
    {
      size = M_LC;
    }
  else if (M_P2 == 0x86)	// data field start with padding indicator
    {
      size = M_LC - 1;
      if (message[5] == 0)
	{
	  // move message to buffer start (rsa_calculate need 2x RSA_BYTES buffer)
	  memmove (message, message + 6, size);
	}
      else if (message[5] == 0x81)
	{
	  DPRINT ("First part of data to decypt, saving into temp buffer\n");
	  r->len = size;
	  // copy data into temp buffer (response)
	  memcpy (r->data, message + 6, size);
	  r->flag = R_TMP;
	  return S_RET_OK;
	}
      else if (message[5] == 0x82)
	{
	  DPRINT ("Second part of data to decrypt\n");
	  if (r->flag != R_TMP)
	    {
	      DPRINT ("First part of data missing\n");
	      return S0x6984;	// Invalid data
	    }
	  r->flag = R_NO_DATA;
	  if (r->len + size > 256)
	    {
	      DPRINT ("Message over 256 bytes ?\n");
	      return S0x6984;	//invalid data
	    }
	  // append data into temp buffer
	  memcpy (r->data + r->len, message + 6, size);
	  size += r->len;
	  // move data from temp buffer into message buffer
	  memcpy (message, r->data, size);
	}
      else
	{
	  DPRINT ("Unknown padding for decrypt data\n");
	  return S0x6984;	//invalid data    (unknown padding indicator)
	}
    }
  else
    {
      DPRINT ("Unknown P2 for decypher operation\n");
      return S0x6a86;		// incorrect P1/P2
    }
// data for decrypt operation in "message"
// decrypt data in "message" according to parameter in sec_env
  return decipher (size, message, r);
}


//APDU: 00 86 00 00 35
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
uint8_t
myeid_ecdh_derive (uint8_t * message, struct iso7816_response * r)
{
  // reuse result buffer for ec_param structure
  struct ec_param *ec = (struct ec_param *) message;
  ec_point_t *derived_key = (ec_point_t *) (r->data + L_ECDH_OFFSET);

  uint8_t ret;
  uint8_t t_len, *t;
  uint8_t tg, tl;

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 != 0 || M_P2 != 0)
    return S0x6a86;		//Incorrect parameters P1-P2

// is security enviroment set to derive ?
  if ((sec_env_valid & SENV_OP_MASK) != SENV_ECDH)
    {
      DPRINT ("invalid sec env\n");
      return S0x6985;		//    Conditions not satisfied
    }
// compare if selected file is same as file id from sec env
  if (fs_get_selected () != key_file_id)
    {
      DPRINT ("file selected not same as in sec env\n");
      return S0x6985;		//    Conditions not satisfied
    }

// security operation always need data
  if (M_LC == 0)
    return S0x6984;		//invalid data
  if (M_LC > L_ECDH_OFFSET)
    return S0x6700;		//Incorrect length
  confirm_command (message);
  if (read_command_data (message))
    return S0x6984;		//invalid data

  t = r->data;

// message is reused as ec_param structure
  memcpy (t, message + 5, M_LC);

// check rest of APDU
  if (*t++ != 0x7c)		// Dynamic autentification template
    return S0x6984;		// Invalid data

// parse ASN1 LEN value (0-255)
  t_len = *t++;
  if (t_len == 0x80)
    {
      if (t_len != 0x81)
	return S0x6984;		// Invalid data (ASN1 length > 255)
      t_len = *t++;
    }

  if (t_len != M_LC - 2)	// check length of template
    return S0x6984;		// Invalid data
////
  while (t_len > 1)
    {
      tg = *t++;
      // parse ASN1 LEN value (0-255)
      tl = *t++;
      if (tl & 0x80)
	{
	  if (t_len != 0x81)
	    return S0x6984;	// Invalid data (ASN1 length >255)
	  tl = *t++;
	}

      t_len -= 2;
      if (t_len < tl)
	{
	  DPRINT ("Wrong length of tag  %02x lenght %d (in buffer only %d)\n",
		  tg, tl, t_len);
	  return S0x6984;	// Invalid data
	}
      if (tg == 0x85)
	{
	  if (*t++ != 0x04)	// unexpanded point indicator
	    return S0x6984;	// Invalid data
	  if (tl != t_len)
	    return S0x6984;	// Invalid data
	  t_len--;
	  break;
	}
      else if (tg == 0x80)
	{
	  t += tl;
	  t_len -= tl;
	}
      else
	{
	  DPRINT ("Unknown tag %02x\n", tg);
	  return S0x6984;	// Invalid data
	}
    }

  // prepare Ec constant, use size based on key  (key from selected file)
  ret = prepare_ec_param (ec, NULL, 0);
  if (ret == 0)
    {
      DPRINT ("Error, unable to get EC parameters/key\n");
      return S0x6985;		//    Conditions not satisfied
    }
  if (ret * 2 != t_len)
    {
      DPRINT
	("Incorrect length of point data %d, selected file need %d bytes\n",
	 t_len, ret * 2);
      return S0x6984;		// Invalid data
    }
  reverse_copy ((uint8_t *) & (derived_key->X), t, ec->mp_size);
  reverse_copy ((uint8_t *) & (derived_key->Y), t + ret, ec->mp_size);
  // this is  long operation, start sending NULL
  card_io_start_null ();

  if (ec_derive_key (derived_key, ec))
    return S0x6985;		//    Conditions not satisfied

  reverse_copy (r->data, (uint8_t *) derived_key, ret);
  return resp_ready (r, ret);
}

#ifdef USE_P_Q_INV
static uint8_t
key_preproces (uint8_t * kpart, uint8_t m_size)
{
  struct
  {
    uint8_t type;
    uint8_t size;
    rsa_num t1;
  } tmp;

  uint16_t ret;

  ret = fs_key_write_part (kpart);
  if (ret != S_RET_OK)
    return ret;

  DPRINT ("calculating inverse of p/q size=%d\n", m_size);

  m_size = bn_set_bitlen (m_size * 8);
  tmp.type = 0x20 | kpart[0];
  tmp.size = m_size;

  rsa_inv_mod_N (&tmp.t1, (rsa_num *) (kpart + 2));

  return fs_key_write_part (&tmp.type);
}
#endif
uint8_t
security_operation (uint8_t * message, struct iso7816_response * r)
{
  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

// compare if selected file is same as file id from sec env
  if (fs_get_selected () != key_file_id)
    {
      DPRINT ("file selected not same as in sec env\n");
      return S0x6985;		//    Conditions not satisfied
    }

  // 0x9E = return digital signature
  // 0x9A = data in APDU = source for digital signature
  if (M_P1 == 0x9E && M_P2 == 0x9A)
    return security_operation_rsa_ec_sign (message, r);

  // decipher operation - return decrypted data
  if (M_P1 == 0x80)
    return security_operation_decrypt (message, r);
  // encipher
  if (M_P1 == 0x84)
    return security_operation_encrypt (message, r);
//  return S0x6a81;      //Function not supported
  return S0x6a86;		//Incorrect parameters P1-P2
}

static uint8_t
check_ec_key_file (uint16_t size, uint8_t type)
{
#ifndef NIST_ONLY
  if (type == 0x23)
    if (size == 256)
      return 0;
#endif
  if (type == 0x22)
    {
      if (size == 192)
	return 0;
      if (size == 256)
	return 0;
      if (size == 384)
	return 0;
    }
  return 1;
}

static uint8_t
check_rsa_key_size (uint16_t size)
{
  if (size & 63)
    return 1;
  if (size < 512)
    return 1;
  if (size > 2048)
    return 1;
  return 0;
}

static __attribute__ ((noinline))
     uint8_t myeid_generate_rsa_key (uint8_t * message,
				     struct iso7816_response *r)
{
  uint16_t k_size;
  uint16_t ret, err;
  struct rsa_crt_key key;
// check user suplied data (if any)

  if (M_LC)
    {

      // private RSA exponent in APDU (MyEID allow only 3 or 65537)
      // in data field sequence can be found:

      // 0x30 0x03 0x02 0x01 0x03           - public exponent = 3
      // 0x30 0x05 0x02 0x03 0x01 0x00 0x01 - public exponent = 65537
      //           ^^^^ is public exponent tag, but opensc uses 0x81 here

      confirm_command (message);
      if (read_command_data (message))
	return S0x6984;		//invalid data

// lot of stupid tests .. TODO do normal ASN parsing
      if (M_LC != 7)
	return S0x6984;		//invalid data
      if (message[5] != 0x30)
	return S0x6984;		//invalid data

// Workaround ..
      if (message[7] != 0x81 && message[7] != 2)
	return S0x6984;		//invalid data

// allow only matching lengths..
      if (message[6] != 5)
	return S0x6984;		//invalid data
// test for 65537 ..
      if (message[8] != 3)
	return S0x6984;		//invalid data

      if (message[9] != 1)
	return S0x6984;		//invalid data
      if (message[10] != 0)
	return S0x6984;		//invalid data
      if (message[11] != 1)
	return S0x6984;		//invalid data
    }
// user data are checked to public exponent 65537, even user does not specify
// public exponent, for now always 65537 public exponent is used

// key size is checked in rsa_keygen()
  k_size = fs_get_file_size ();
  if (check_rsa_key_size (k_size))
    return S0x6981;		//icorrect file type

  card_io_start_null ();

  // return: dP, dQ, qInv and d in  struct rsa_crt_key
  //         P,Q                in message
  //         modulus            in r->data
  ret = rsa_keygen (message + 4, r->data, &key, k_size);

  if (ret == 0)
    return S0x6a82;		// file not found ..

// save key parts into file

#ifndef USE_P_Q_INV
  message[2] = KEY_RSA_p | KEY_GENERATE;
  message[3] = ret;
  err = fs_key_write_part (message + 2);
  if (err != S_RET_OK)
    {
      DPRINT ("Unable to write KEY_RSA_p\n");
      return err;
    }

  message[128 + 2] = KEY_RSA_q | KEY_GENERATE;
  message[128 + 3] = ret;
  err = fs_key_write_part (message + 128 + 2);
  if (err != S_RET_OK)
    {
      DPRINT ("Unable to write KEY_RSA_q\n");
      return err;
    }
#else
  message[2] = KEY_RSA_p | KEY_GENERATE;
  message[3] = ret;
  err = key_preproces (message + 2, ret);
  if (err != S_RET_OK)
    {
      DPRINT ("Unable to write KEY_RSA_p and precalc data\n");
      return err;
    }

  message[128 + 2] = KEY_RSA_q | KEY_GENERATE;
  message[128 + 3] = ret;
  err = key_preproces (message + 128 + 2, ret);
  if (err != S_RET_OK)
    {
      DPRINT ("Unable to write KEY_RSA_q and precalc data\n");
      return err;
    }
#endif
  memcpy (message + 4, (uint8_t *) & key.dP, ret);	//dP
  message[2] = KEY_RSA_dP | KEY_GENERATE;
  err = fs_key_write_part (message + 2);
  if (err != S_RET_OK)
    {
      DPRINT ("Unable to write KEY_RSA_dP\n");
      return err;
    }

  memcpy (message + 4, (uint8_t *) & key.dQ, ret);	//dQ
  message[2] = KEY_RSA_dQ | KEY_GENERATE;
  err = fs_key_write_part (message + 2);
  if (err != S_RET_OK)
    {
      DPRINT ("Unable to write KEY_RSA_dQ\n");
      return err;
    }

  memcpy (message + 4, (uint8_t *) & key.qInv, ret);	//qInv
  message[2] = KEY_RSA_qInv | KEY_GENERATE;
  err = fs_key_write_part (message + 2);
  if (err != S_RET_OK)
    {
      DPRINT ("Unable to write KEY_RSA_qInv\n");
      return err;
    }

  if (k_size == 2048)
    {
      // modulus in two parts for 2048
      memcpy (message + 4, r->data, 128);
      message[2] = KEY_RSA_MOD_p2;
      message[3] = 128;
      err = fs_key_write_part (message + 2);
      if (err != S_RET_OK)
	{
	  DPRINT ("Unable to write 1st part of modulus\n");
	  return err;
	}
      memcpy (message + 4, 128 + r->data, 128);
      message[2] = KEY_RSA_MOD_p1;
      err = fs_key_write_part (message + 2);
      if (err != S_RET_OK)
	{
	  DPRINT ("Unable to write 2nd part of modulus\n");
	  return err;
	}
    }
  else
    {
      memcpy (message + 4, r->data, k_size / 8);
      message[2] = KEY_RSA_MOD;
      message[3] = k_size / 8;
      err = fs_key_write_part (message + 2);
      if (err != S_RET_OK)
	{
	  DPRINT ("Unable to write modulus to file\n");
	  return err;
	}
    }

  // Fixed public exponent 65537
  message[2] = KEY_RSA_EXP_PUB;
  message[3] = 3;
  message[4] = 1;
  message[5] = 0;
  message[6] = 1;
  err = fs_key_write_part (message + 2);
  if (err != S_RET_OK)
    {
      DPRINT ("Unable to write public exponent to file\n");
      return err;
    }

  // TODO return modulus in normal form (higest bytest first)
  // MyEID return here only modulus size
  // (TODO test this, because MyEID doc is not precise enough)

  reverse_string (r->data, ret * 2);
  return resp_ready (r, ret * 2);
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
uint8_t
myeid_generate_key (uint8_t * message, struct iso7816_response * r)
{
  uint16_t k_size;
  uint16_t ret;
  uint8_t type;

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 != 0 || M_P2 != 0)
    return S0x6a86;		//Incorrect parameters P1-P2

  type = fs_get_file_type ();
  // check file type
  if (type == 0x11)
    return myeid_generate_rsa_key (message, r);

// EC key generation is requested.., for now no user data are allowed
  if (M_LC)
    return S0x6985;		//    Conditions not satisfied


  uint8_t size;

  struct pub_key
  {
    ec_point_t key;
    uint8_t type;
    uint8_t size;
    uint8_t ui;			// for 0x04 = indicate uncompressed key
    uint8_t key_bytes[2 * sizeof (bignum_t)];
  };

  // reuse r->data and message for ec param structure and fo pub_key structure
  struct pub_key *pub_key = (struct pub_key *) r->data;
  struct ec_param *c = (struct ec_param *) (message);

// get key size (from file size), now only EC keys are supported (192,256,384 bits)
  k_size = fs_get_file_size ();
  if (check_ec_key_file (k_size, type))
    return S0x6985;		//    Conditions not satisfied

  card_io_start_null ();

  DPRINT ("Generating key, selected file 0x%04x, key size %d bits\n",
	  fs_get_selected (), k_size);

  if (0 == prepare_ec_param (c, &(pub_key->key), k_size / 8))
    {
      DPRINT ("Wrong EC parameteres\n");
      return S0x6985;		//    Conditions not satisfied
    }
  if (ec_key_gener (&(pub_key->key), c))
    {
      DPRINT ("Key wrong\n");
      return S0x6985;		//    Conditions not satisfied
    }
  // reverse key
  reverse_string ((uint8_t *) & (c->working_key), c->mp_size);

  reverse_copy ((uint8_t *) & (pub_key->key_bytes),
		(uint8_t *) & (pub_key->key.X), c->mp_size);
  reverse_copy (c->mp_size + (uint8_t *) & (pub_key->key_bytes),
		(uint8_t *) & (pub_key->key.Y), c->mp_size);

  // function for write key inspect size of key and checks ACL ..
  // (based on actually selected file)

  c->curve_type = KEY_EC_PRIVATE | KEY_GENERATE;
  size = c->mp_size;
  // warning, this depend on struct ec_param entries
  ret = fs_key_write_part ((uint8_t *) & (c->curve_type));
  if (ret != S_RET_OK)
    return ret;

  // store public key with 0x04 uncompressed indicator
  size = size * 2 + 1;
  pub_key->type = KEY_EC_PUBLIC | KEY_GENERATE;
  pub_key->size = size;
  pub_key->ui = 4;

  ret =
    fs_key_write_part ((uint8_t *) (pub_key) +
		       offsetof (struct pub_key, type));
  if (ret != S_RET_OK)
    return ret;
  size++;
  memcpy (r->data, &pub_key, size);
  // public key TAG
  r->data[0] = 0x86;
  return resp_ready (r, size);

}

static uint8_t
ecc_param (uint8_t v, struct iso7816_response *r)
{
  struct ec_param c;
  ec_point_t p;
  uint8_t len;

  len = prepare_ec_param (&c, &p, 0);
  if (!len)
    return S0x6a88;		//Referenced data (data objects) not found

  switch (v)
    {
    case 0x81:
      memcpy (r->data, &c.prime, len);
      break;
    case 0x82:
      memcpy (r->data, &c.a, len);
      break;
    case 0x83:
      memcpy (r->data, &c.b, len);
      break;
    case 0x84:
      memcpy (r->data, &p.Y, len);
      memcpy (r->data + len, &p.X, len);
      len *= 2;
      break;
    case 0x85:
      memcpy (r->data, &c.order, len);
      break;
    }
  reverse_string (r->data, len);
  return resp_ready (r, len);
}

/*

get/put data emulation of MYEID card

*/
uint8_t
myeid_get_data (uint8_t * message, struct iso7816_response * r)
{
  uint16_t ret;

  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_P1 != 1)
    return S0x6a88;		//Referenced data (data objects) not found

  if ((M_P2 & 0xb0) == 0xb0)
    return fs_return_pin_info (M_P2 & 0x0f, r);

  if (M_P2 >= 0x81 && M_P2 <= 0x85)
    return ecc_param (M_P2, r);

  switch (M_P2)
    {
    case 0xa0:
      get_constant (r->data, N_CARD_ID);
      return resp_ready (r, 20);
    case 0xa1:
    case 0xa2:
    case 0xa3:
    case 0xa4:
    case 0xa5:
    case 0xa6:
      return fs_list_files (M_P2, r);
    case 0xaa:
      get_constant (r->data, N_CARD_CAP_ID);
      return resp_ready (r, 11);
    case 0xac:
      ret = fs_get_access_condition ();
      r->data[0] = ret >> 8;
      r->data[1] = ret & 0xff;
      return resp_ready (r, 2);
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
	return S0x6a88;		//Referenced data (data objects) not found
      // TODO here for 65537 24 bit is calculated, but 17 bits is enough
      ret = ret * 8;
      r->data[2] = ret >> 8;
      r->data[3] = ret & 0xff;
      ret = fs_key_read_part (NULL, KEY_RSA_p);
      DPRINT ("ret=%d\n", ret);
      if (!ret)
	return S0x6a88;		//Referenced data (data objects) not found
      ret = ret * 16;
      r->data[4] = ret >> 8;
      r->data[5] = ret & 0xff;
      return resp_ready (r, 6);
    case 1:
      // modulus
      ret = fs_key_read_part (r->data, KEY_RSA_MOD);
      DPRINT ("ret1=%d\n", ret);
      if (!ret)
	{
	  uint16_t len;

	  ret = fs_key_read_part (r->data, KEY_RSA_MOD_p2);
	  DPRINT ("ret2=%d\n", ret);

	  if (!ret)
	    return S0x6a88;	//Referenced data (data objects) not found
// fs_key_read_part return maximum RSA_BYTES
#if RSA_BYTES > 128
#error posible overflow in response buffer
#endif
	  len = ret;
	  ret = fs_key_read_part (r->data + ret, KEY_RSA_MOD_p1);
	  DPRINT ("ret3=%d\n", ret);
	  if (!ret)
	    return S0x6a88;	//Referenced data (data objects) not found
	  ret += len;
	}
      reverse_string (r->data, ret);
      if (ret == 256)
	ret = 0;
      return resp_ready (r, ret);
    case 2:
      // public exponent
      ret = fs_key_read_part (r->data, KEY_RSA_EXP_PUB);
      DPRINT ("ret_p=%d\n", ret);
      if (!ret)
	return S0x6a88;		//Referenced data (data objects) not found
      return resp_ready (r, ret);

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
	ret = fs_key_read_part (r->data + 2, KEY_EC_PUBLIC);
	DPRINT ("Public key len %d\n", ret);
	if (ret == 0)
	  return S0x6985;	// conditions not satisfaied
	//correct first two bytes in response
	r->data[0] = 0x30;
	r->data[1] = ret;
	return resp_ready (r, ret + 2);
      }
    default:
      return S0x6a88;		//Referenced data (data objects) not found
    }
}

static uint8_t
myeid_upload_ec_key (uint8_t * message)
{
  DPRINT ("%s %02x %02x %02x\n", __FUNCTION__, M_P1, M_P2, M_LC);

//  message[5] = message[4];
  // EC key private key upload
  if (M_P2 == 0x87)
    message[3] = KEY_EC_PRIVATE;
  else if (M_P2 == 0x86)
    message[3] = KEY_EC_PUBLIC;
  else
    return S0x6985;		//    Conditions not satisfied

  card_io_start_null ();
  return fs_key_write_part (message + 3);
}

static uint8_t
myeid_upload_rsa_key (uint8_t * message, uint16_t size)
{
  uint16_t test_size;
  uint8_t m_size = M_LC;

  DPRINT ("uloading key type %02x\n", M_P2);

  // key part may start with 0x00 and M_LC is incremented by one (65 bytes for 1024 key)
  if ((m_size & 1) && (M_P2 != 0x81))
    {
      DPRINT ("M_LC is odd, message[5] = 0x%02x\n", message[5]);
      if (message[5] != 0)
	return S0x6985;		//    Conditions not satisfied
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

    case KEY_RSA_EXP_p1:
    case KEY_RSA_EXP_p2:
    case KEY_RSA_EXP:
// private exponent is not needed for CRT
      return S_RET_OK;

    case KEY_RSA_MOD:
      test_size = 8 * m_size;
      break;

    case KEY_RSA_EXP_PUB:
// allow any size of public exponet, if this size does not fil key file size, this fail in fs_key_write_part ()
      test_size = size;
      break;
    default:
      return S0x6985;		//    Conditions not satisfied
    }
  if (size != test_size)
    {
      DPRINT ("write size, key file %d size of part %d\n", size, m_size);
      return S0x6985;		//    Conditions not satisfied
    }
  card_io_start_null ();

  reverse_string (message + 5, m_size);
#ifdef USE_P_Q_INV
  // calculate n_
  if (M_P2 == KEY_RSA_p || M_P2 == KEY_RSA_q)
    return key_preproces (message + 3, m_size);
#endif
  return fs_key_write_part (message + 3);
}


static uint8_t
myeid_upload_keys (uint8_t * message)
{
  uint16_t k_size;
  uint8_t type;

  DPRINT ("%s \n", __FUNCTION__);
// key upload, file is already selected,

  k_size = fs_get_file_size ();
  if (!k_size)
    return S0x6a82;		//file not found

// EC key is stored to file with type 0x22, RSA to type 0x11
// AES 0x29, DES 0x19

  type = fs_get_file_type ();
  DPRINT ("Key size %d, type=0x%02x\n", k_size, type);

// DES, AES key
  if (type == 0x19)
    {
      if (k_size != 64 && k_size != 128 && k_size != 192)
	return S0x6700;		//Incorrect length
      return fs_key_write_part (message + 3);
    }
  if (type == 0x29)
    {
      if (k_size != 128 && k_size != 192 && k_size != 256)
	return S0x6700;		//Incorrect length
      return fs_key_write_part (message + 3);
    }

  if (0 == check_ec_key_file (k_size, type))
    return myeid_upload_ec_key (message);

  if (type == 0x11)
    {
      if (0 == check_rsa_key_size (k_size))
	return myeid_upload_rsa_key (message, k_size);
    }
  return S0x6981;		//icorrect file type
}

uint8_t
myeid_put_data (uint8_t * message, struct iso7816_response * r)
{
  DPRINT ("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

  if (M_LC)
    {
      //read rest of apdu
      confirm_command (message);
      if (read_command_data (message))
	return S0x6984;		//invalid data
    }

  if (M_P1 != 1)
    return S0x6a88;		//Referenced data (data objects) not found
  if (M_P2 == 0xe0)
    {				//initialize applet
      if (M_LC != 8)
	return S0x6700;		//Incorrect length
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
      if (M_LC < 0x10 || M_LC > (16 + 7 + 24))
	return S0x6700;		//Incorrect length
      DPRINT ("initialization of PIN %d\n", M_P2);
      return fs_initialize_pin (message + 3);
    }
  // Upload keys
  if ((M_P2 >= 0x80 && M_P2 <= 0x8B) || (M_P2 == 0xA0))
    return myeid_upload_keys (message);

  return S0x6a81;		//Function not supported
}


uint8_t
myeid_activate_applet (uint8_t * message)
{
  if (M_LC)
    {
      //read rest of apdu
      confirm_command (message);
      if (read_command_data (message))
	return S0x6984;		//invalid data
    }
  //TOTO check applet name
  fs_set_lifecycle ();
  return (S_RET_OK);
}
