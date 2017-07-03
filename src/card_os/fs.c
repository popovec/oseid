/*
    fs.c

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

    iso7816 compatible filesystem routines

*/
#ifdef DEBUG
#include <stdio.h>
#define  DPRINT(msg...) fprintf(stderr,msg)
#else
#define DPRINT(msg...)
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "card_io.h"
#include "mem_device.h"
#include "iso7816.h"
#include "fs.h"
#include "key.h"
/*

Limitation:
 file size max 32757 - limited in file create function
 filesystem size max 65536 bytes

All access to memory is done by calling 4 functions: 

- access to PIN (256 bytes of memory)
sec_device_read_block()
sec_device_write_block()

- access to EEPROM/FLASH:
device_read_block()
device_write_block()


Filesystem is designed for memory with default state "all bits on" EEPROM/FLASH
For default state "all pins zero" there is recommendation to invert all write/read operation
in mem_device layer.
*/

struct pin
{
  uint8_t pin[8];
  uint8_t puk[8];
//how many retries remain for check
  uint8_t pin_retry:4;
  uint8_t puk_retry:4;
//
  uint8_t pin_retry_max:4;
  uint8_t puk_retry_max:4;
} __attribute__ ((__packed__));

// sec_device is description for one 256 byte block for storing pin/puks and other security info

struct sec_device
{
  struct pin pins[14];
  uint16_t pin_lock;		// 1 - pin unlocked, 0 pin locked
  uint8_t lifecycle;		// 1 card in initialization state, 7 card is initialized
  uint8_t reserved;
} __attribute__ ((__packed__));



struct fs_data
{
  uint16_t id;			// file id from tag 0x83
  uint16_t size;		// from tag 0x80/0x81
  uint16_t uuid;		//
  uint16_t parent_uuid;		//
  uint8_t type;			// from tag 0x82
  uint8_t acl[3];		// from tag 0x86
  uint16_t prop;		// from tag 0x85

  uint8_t name_size:5;		// size of filename (only DF..)
  uint8_t tag_80_81:1;		// size of file by tag 81 or 80
  uint8_t no_allocate:1;	// file is DF, do not allocate space

} __attribute__ ((__packed__));


struct fs_response
{
  struct fs_data fs;
  uint16_t mem_offset;
} __attribute__ ((__packed__));


struct fs_response fci_sel __attribute__ ((section (".noinit")));
static uint16_t security_enable __attribute__ ((section (".noinit")));	//bit mapped security enabled levels (by pin 1..14)


uint16_t
fs_get_access_condition (void)
{
  return security_enable;
}

void
fs_deauth (uint8_t pin)
{
  uint16_t sec = 0xfffe;

  if (pin > 14)
    return;

  if (pin == 0)
    sec = 0;
  else
    {
      while (--pin)
	sec = sec * 2 | 1;
    }
  security_enable &= sec;
}

// mminimalize eeprom changes, normal lifecycle codes are 1 and 7,
// 0xff is default value for blank eeprom, this can be default for
// lifecycle 1 = do not control security status ..
// use xor 0xfe to get 0xff for 1 and 0xf9 for 7
static uint8_t
get_lifecycle (void)
{
  uint8_t lc;

  sec_device_read_block (&lc, offsetof (struct sec_device, lifecycle), 1);
  return lc ^ 0xfe;
}

static void
set_lifecycle (uint8_t lc)
{
  uint8_t temp, local_lc = 0xfe ^ lc;

  // change lifecycle only if needed
  temp = get_lifecycle ();
  if (temp != local_lc)
    sec_device_write_block (&local_lc,
			    offsetof (struct sec_device, lifecycle), 1);
}


// search file - parametric function based on "type" - most complicated routine to parse directory
// For lot of ISO7816 select types is here function to get propper file.
//
// functions by TYPE:
//
// list all files in DF, 1 list only EF in selected DF, 2 list all DF is selected DF
// (do not change type 0,1,2 - or check calculation in fs_list_files())
#define S_LIST     0
#define S_LIST_EF  1
#define S_LIST_DF  2
#define S_LIST_ALL 3

// search for P1=0, P2=0, LC=2
// (first check children, then parent and then neighborhood of selected file
#define S_0	  4
// search for P1=1, P2=0, LC=2
#define S_DF	  5
// search for P1=2, P2=0, LC=2
#define S_EF	  6
// search for P1=8/9, P2=0, LC=2..254
#define S_PATH    7
// search for P1=3, P2=0, LC=2
#define S_PARENT  8

// file create need detect colision of ID under children and need maximal UUID
// this function return RET_SEARCH_END if no colision is detected (entry then contain correct uuid)
// or return on colision RET_SEARCH_OK is returned.
#define S_MAX     9

#define	S_NAME	  10

#define RET_SEARCH_FAIL 2
#define RET_SEARCH_END  1
#define RET_SEARCH_OK	0

// WARNING, caller is responsible to set up "data" for type S_LIST (0,1,2) and S_PATH (6)
static uint8_t
fs_search_file (struct fs_response *entry, uint16_t id, uint8_t * data,
		uint8_t type)
{
  uint16_t max_uuid = 0;
  struct fs_response response, r0;
  uint8_t level = 0;
// get data for search from (selected) entry
  uint16_t uuid = entry->fs.uuid;
  uint16_t p_uuid = entry->fs.parent_uuid;
  uint8_t data_count = 0;
  uint8_t fname[16];
  uint8_t code;

  DPRINT
    ("%s searched ID %04x, parameters: uuid %04x parent ID %04x type=%d\n",
     __FUNCTION__, id, uuid, p_uuid, type);

  if (type == S_PATH)
    {
      data_count = *data;
      data++;
      id = *data << 8;
      data++;
      id |= *data;
      data++;
      data_count -= 2;
    }
  if (type == S_NAME)
    {
      data_count = *data;
      data++;
    }
  response.mem_offset = 0;
  while (0 ==
	 device_read_block (&response, response.mem_offset,
			    sizeof (struct fs_data)))
    {
      DPRINT
	("%s searched ID %04x, filesystem id %04x uuid %04x parent ID %04x\n",
	 __FUNCTION__, id, response.fs.id, response.fs.uuid,
	 response.fs.parent_uuid);

      // test for FS end
      if (response.fs.id == 0xffff)
	{
	  // not succesfull search, fill maximal uuid
	  if (type == S_MAX)
	    {
	      entry->fs.uuid = max_uuid + 1;
	      entry->mem_offset = response.mem_offset;
	    }
	  DPRINT ("%s filesystem end\n", __FUNCTION__);
	  if (type == S_0)
	    {
	      if (level != 0)
		{
		  DPRINT ("%s S_0, found at level %d\n", __FUNCTION__, level);
		  memcpy (entry, &r0, sizeof (struct fs_response));
		  return RET_SEARCH_OK;
		}
	    }
	  // WARN value depend on #define ..
	  if (type <= 3)
	    entry->fs.id = data_count;
	  return RET_SEARCH_END;
	}

      // calculate maximal uuid
      if (max_uuid < response.fs.uuid)
	max_uuid = response.fs.uuid;

      if (type == S_PARENT && response.fs.uuid == p_uuid)
	{
	  DPRINT ("%s PARENT ok\n", __FUNCTION__);
	  goto fs_search_file_ok;
	}

      code = 1 + (response.fs.type == 0x38);
// generate list if needed
      if (response.fs.parent_uuid == uuid)
	{
	  if (response.fs.id != 0x3f00)
	    if ((type | code) == S_LIST_ALL)
	      if (data_count < 127)
		{
		  DPRINT ("%s adding file %04x files count %d\n",
			  __FUNCTION__, response.fs.id, data_count + 1);
		  *data++ = response.fs.id >> 8;
		  *data++ = response.fs.id & 255;
		  data_count++;
		}
	}

      // search colision, DF, EF, path search
      if (response.fs.id == id)
	{
	  DPRINT ("%s id match %04x\n", __FUNCTION__, id);
	  if (type == S_0)
	    {
	      if (response.fs.parent_uuid == p_uuid)
		{
		  DPRINT ("%s S_0 search parent found (level 2)\n",
			  __FUNCTION__);
		  memcpy (&r0, &response, sizeof (struct fs_response));
		  // better candidate
		  level = 1;
		}

	      if (response.fs.uuid == p_uuid)
		{
		  DPRINT ("%s S_0 search neighbor (level 3)\n", __FUNCTION__);
		  // if nothing is found, set this entry as candidate
		  if (level == 0)
		    memcpy (&r0, &response, sizeof (struct fs_response));
		}
	    }
	  if (response.fs.parent_uuid == uuid)
	    {
	      // generate list if needed
	      code = 1 + (response.fs.type == 0x38);
	      if (response.fs.id != 0x3f00)
		if ((type | code) == S_LIST_ALL)
		  if (data_count < 127)
		    {
		      DPRINT ("%s adding file %04x files count %d\n",
			      __FUNCTION__, response.fs.id, data_count + 1);
		      *data++ = response.fs.id >> 8;
		      *data++ = response.fs.id & 255;
		      data_count++;
		    }

	      if (type == S_0)
		{
		  DPRINT ("%s S_0 search child found (level 1)\n",
			  __FUNCTION__);
		  // best candidate
		  goto fs_search_file_ok;
		}
	      // colision ?
	      if (type == S_MAX)
		goto fs_search_file_ok;
	      if (type == S_PATH)
		{
		  DPRINT ("%s rest data count %d\n", __FUNCTION__,
			  data_count);
		  if (!data_count)
		    goto fs_search_file_ok;
		  id = *data << 8;
		  data++;
		  id |= *data;
		  data++;
		  data_count -= 2;
		  uuid = response.fs.uuid;
		}
	      if (response.fs.type == 0x38)
		{
		  if (type == S_DF)
		    goto fs_search_file_ok;
		}
	      else
		{
		  if (type == S_EF)
		    goto fs_search_file_ok;
		}
	    }
	}
      // test filename
      if (response.fs.name_size && type == S_NAME)
	{
	  if (0 ==
	      device_read_block (fname,
				 response.mem_offset +
				 sizeof (struct fs_data), data_count))
	    {
	      if (0 == memcmp (data, fname, data_count))
		goto fs_search_file_ok;
	    }
	}
      //skip ..
      response.mem_offset += sizeof (struct fs_data);
      response.mem_offset += response.fs.name_size;
      //file without data ?
      if (response.fs.no_allocate)
	continue;
      response.mem_offset += response.fs.size;
    }
  DPRINT ("%s filesystem fail\n", __FUNCTION__);
  return RET_SEARCH_FAIL;

fs_search_file_ok:
  DPRINT ("%s search found\n", __FUNCTION__);
  memcpy (entry, &response, sizeof (struct fs_response));
  return RET_SEARCH_OK;
}

/*
// skip one tag in buffer
static uint8_t *
skip_tag (uint8_t * buffer, uint8_t * end)
{
  if (end - buffer < 3)
    return NULL;
  buffer++;
//tag with wrong len ?
  if (*buffer == 0)
    return NULL;
  buffer += *buffer + 1;
  if (buffer > end)
    return NULL;
  return buffer;

}
*/
/****************************************************************************************
*
*                      PIN / PUK functions 
*
****************************************************************************************/

//change lifecycle, this enables all FS security ACL 
void
fs_set_lifecycle (void)
{
  set_lifecycle (7);
}

#define PIN_UNLOCK 0
#define PIN_LOCK 1

static uint8_t
get_pin_lock (uint8_t pin)
{
  uint16_t pin_lock;
  uint16_t mask;
  if (pin < 1 && pin > 14)
    return 1;
  sec_device_read_block (&pin_lock, offsetof (struct sec_device, pin_lock),
			 sizeof (pin_lock));
  mask = (1 << (pin - 1));
  if (mask & pin_lock)
    return 0;
  return 1;

}

static uint8_t
lock_unlock_pin (uint8_t pin, uint8_t lock)
{
  uint16_t pin_lock;
  uint16_t mask;
  if (pin < 1 && pin > 14)
    return 1;

  if (sec_device_read_block
      (&pin_lock, offsetof (struct sec_device, pin_lock), sizeof (pin_lock)))
      return 1;

  mask = (1 << (pin - 1));
  if (lock == PIN_LOCK)
    pin_lock &= ~mask;
  else
    pin_lock |= mask;

  if (sec_device_write_block
      (&pin_lock, offsetof (struct sec_device, pin_lock), sizeof (pin_lock)))
      return 1;
  return 0;
}

// compare two pins with padding (0 or 0xff)
// return 0 if ok
static uint8_t
compare_pins_with_padding (uint8_t * p1, uint8_t * p2)
{
  uint8_t c;

  DPRINT ("%s\n", __FUNCTION__);

  // compare pins - skip padding
  for (c = 0; c < 8; c++)
    {
      DPRINT ("Comparing %02X %02X\n", p1[c], p2[c]);

      if (p1[c] == p2[c])
	continue;
      // minimal pin length is 4, ignore padding for pin characters 1..4
      if (c < 4)
	return 1;
      // padding can be on both sides, and padding byte is 0xff or 0x00..
      if (p1[c] == 0 && p2[c] == 0xff)
	continue;
      if (p2[c] == 0xff && p2[c] == 0)
	continue;
      return 1;
    }
  DPRINT ("PIN/PUK OK\n");
  return 0;
}


// input: pin number, pin value (8 byt string) 
// return 0 if ok, 
// if pin fail return 1-15 = pin retries
// if pin is NULL, return number of retries 1-15
// if pin is blocked 255 for blocked pin 
// renew pin retry count if verification is ok, or decrement retry count 
static uint8_t
compare_pin_puk (uint8_t pin, uint8_t * value, uint8_t puk)
{
  struct pin p;
  uint8_t ret = 0;

  uint8_t position;

  DPRINT ("%s\n", __FUNCTION__);
  DPRINT ("%s comparing %d\n", __FUNCTION__, puk);
  position =
    offsetof (struct sec_device, pins[1]) - offsetof (struct sec_device,
						      pins[0]);
  position *= (pin - 1);
  position += offsetof (struct sec_device, pins[0]);

  if (sec_device_read_block (&p, position, sizeof (struct pin)))
    return 15;			//unable to read pins, signalize maximum number of retries
  // PIN/PUK retry count is in negated form!
  if (puk)
    {
      // only return number of retries
      if (value == NULL)
	return 15 - p.puk_retry;
      if (p.puk_retry == 15)
	return 255;
      if (compare_pins_with_padding (value, p.puk))
	{
	  ret = 15 - (++p.puk_retry);
	  if (ret == 0)
	    ret = 255;
	}
      else
	p.puk_retry = p.puk_retry_max;
    }
  else
    {
      // only return number of retries
      if (value == NULL)
	return 15 - p.pin_retry;
      if (p.pin_retry == 15)
	return 255;
      if (compare_pins_with_padding (value, p.pin))
	{
	  ret = 15 - (++p.pin_retry);
	  if (ret == 0)
	    ret = 255;
	}
      else
	p.pin_retry = p.pin_retry_max;
    }
  // ignore write errors for now ..
  sec_device_write_block (&p, position, sizeof (struct pin));

  return ret;
}

static uint8_t
compare_pin (uint8_t pin, uint8_t * value)
{
  DPRINT ("%s\n", __FUNCTION__);
  return compare_pin_puk (pin, value, 0);
}

static uint8_t
compare_puk (uint8_t pin, uint8_t * value)
{
  DPRINT ("%s\n", __FUNCTION__);
  return compare_pin_puk (pin, value, 1);
}

// in buffer pin number, len of message, two 8 byt strings pin/new pin
uint16_t
fs_change_pin (uint8_t * message)
{
  struct pin p;
  uint8_t r;

  uint8_t position;

  DPRINT ("%s\n", __FUNCTION__);
  position =
    offsetof (struct sec_device, pins[1]) - offsetof (struct sec_device,
						      pins[0]);
  position *= (message[0] - 1);
  position += offsetof (struct sec_device, pins[0]);

  if (message[0] < 1 && message[0] > 14)
    return 0x6a86;		// Incorrect parameters P1-P2 
  if (message[1] != 16)
    return (0x6700);		//Incorrect length 

  // check if pin is OK
  r = compare_pin (message[0], message + 2);
  if (r == 255)
    return 0x6983;		//no more auth retries
  if (r != 0)
    return 0x63c0 | (r & 0xf);	//fail, retries remaining ..

  if (lock_unlock_pin (message[0], PIN_UNLOCK))
    return 0x63cf;		//unable to read pins, signalize maximum number of retries

  if (sec_device_read_block (&p, position, sizeof (struct pin)))
    return 0x63cf;		//unable to read pins, signalize maximum number of retries
  memcpy (p.pin, message + 10, 8);
  if (sec_device_write_block (&p, position, sizeof (struct pin)))
    return 0x63cf;		//unable to read pins, signalize maximum number of retries
  return 0x9000;
}



// set security AC for pin
// input "pin num","len","data"
uint16_t
fs_verify_pin (uint8_t * message)
{
  uint16_t sec = 1;
  uint8_t pin = message[0];
  uint8_t pad_pin[8];
  uint8_t r;

  DPRINT ("%s\n", __FUNCTION__);

  if (pin < 1 && pin > 14)
    return 0x6a86;		// Incorrect parameters P1-P2 

  //return number of retries
  if (message[1] == 0)
    {
      r = compare_pin (pin, NULL);
      if (r == 255)
	return 0x6983;		//no more auth retries
      //is pin locked ?
      if (get_pin_lock (pin))
	return 0x6985;		// Pin locked

      return (0x63c0 | (r & 0x0f));
    }
  //workaround, padding of pin..
  if (message[1] > 8)
    message[1] = 8;
  memset (pad_pin, 0xff, 8);
  memcpy (pad_pin, message + 2, message[1]);

  // check if pin is OK
  r = compare_pin (pin, pad_pin);
  if (r == 255)
    return 0x6983;		//no more auth retries
  //is pin locked ?
  if (get_pin_lock (pin))
    return 0x6985;		// Pin locked

  if (r != 0)
    return 0x63c0 | (r & 0xf);	//fail, retries remaining ..

  while (--pin)
    sec = sec * 2;
  security_enable |= sec;
  return 0x9000;
}


// unblock pin by puk
uint16_t
fs_reset_retry_count (uint8_t * message)
{
  struct pin p;
  uint8_t r;

  uint8_t position;

  DPRINT ("%s\n", __FUNCTION__);

  position =
    offsetof (struct sec_device, pins[1]) - offsetof (struct sec_device,
						      pins[0]);
  position *= (message[0] - 1);
  position += offsetof (struct sec_device, pins[0]);

  if (message[0] < 1 && message[0] > 14)
    return 0x6a86;		// Incorrect parameters P1-P2 

  //just return number of retries
  if (message[1] == 0)
    return (compare_puk (message[0], NULL) | (0x63c0 & 0x0f));

  if (message[1] != 16)
    return (0x6700);		//Incorrect length 

  //check if puk is ok
  r = compare_puk (message[0], message + 2);
  if (r == 255)
    return 0x6983;		//no more verification retries

  if (r != 0)
    return 0x63c0 | (r & 0xf);	//return number of retries

  if (sec_device_read_block (&p, position, sizeof (struct pin)))
    return 0x63cf;		//unable to read pins, signalize maximum number of retries

  // set new PIN
  memcpy (p.pin, message + 10, 8);
  // unblock pin
  p.pin_retry = p.pin_retry_max;

  if (sec_device_write_block (&p, position, sizeof (struct pin)))
    return 0x63cf;		//unable to read pins, signalize maximum number of retries
  return 0x9000;
}

uint16_t
fs_initialize_pin (uint8_t * message)
{
  struct pin p;
  uint8_t retry;
  uint8_t position;

  DPRINT ("%s\n", __FUNCTION__);

  if (1 != get_lifecycle ())
    return 0x6982;		//security status not satisfied

  position =
    offsetof (struct sec_device, pins[1]) -offsetof (struct sec_device,
						     pins[0]);
  position *= (message[0] - 1);
  position += offsetof (struct sec_device, pins[0]);

  if (message[1] < 16)
    return 0x6700;
  memcpy (p.pin, message + 2, 8);
  memcpy (p.puk, message + 10, 8);
  p.pin_retry_max = 3;
  p.puk_retry_max = 3;
  p.pin_retry = 3;
  p.puk_retry = 3;
  if (message[1] > 16)
    {
      retry = message[18];
      if (retry > 16)
	retry = 15;
      p.pin_retry_max = 15 - retry;
    }
  if (message[1] > 17)
    {
      retry = message[19];
      if (retry > 16)
	retry = 15;
      p.puk_retry_max = 15 - retry;
    }

  if (message[1] > 18)
    {
      //lock pin, pin must be changed to get unlocked ..
      if (message[20] & 1)
	lock_unlock_pin (message[0], PIN_LOCK);
      // TODO save state of bit 1 - pin lock after reset retry counter ..
      // IMHO this feature is not needed ..      
    }
  if (sec_device_write_block (&p, position, sizeof (struct pin)))
    return 0x6581;		//memory fail
  return 0x9000;
}

void
fs_reset_security (void)
{
  security_enable = 0;
}

/****************************************************************************************
*
*                      filesystem security functions 
*
****************************************************************************************/

static uint16_t
check_security_pin_ac (uint8_t pin)
{
  uint16_t sec = 1;

  DPRINT ("%s\n", __FUNCTION__);

  // check ACL only if lifecycle is 7 (otherwise return ENABLED)
  if (get_lifecycle () != 7)
    return 0;

  DPRINT ("LIFECYCLE activated, checking security\n");
  if (pin == 0)
    {
      DPRINT ("0 - ALWAIS ENABLED\n");
      return 0;
    };
  if (pin == 15)
    {
      DPRINT ("15 - ALWAIS DISABLED\n");
      return 1;
    };

  while (--pin)
    sec = sec * 2;

  DPRINT ("SEC_ENABLE %04X, testing PIN %d mask %04X\n", security_enable, pin,
	  sec);

  if (sec & security_enable)
    return 0;			//enabled .. 

  return 1;
}

#define SEC_CREATE_DF 1
#define SEC_CREATE_EF 2

#define SEC_READ 3
#define SEC_UPDATE 4
#define SEC_DELETE 5
#define SEC_GENERATE 6

//if allowed return 0  (file must be selected .. )

static uint8_t
check_EF_security (uint8_t type)
{
  DPRINT ("%s\n", __FUNCTION__);

  if (fci_sel.fs.id == 0xffff)
    return 1;

  DPRINT ("selected %04X ACL=%02X%02X%02X\n", fci_sel.fs.id,
	  fci_sel.fs.acl[0], fci_sel.fs.acl[1], fci_sel.fs.acl[2]);

  if (type == SEC_READ)
    return (check_security_pin_ac (fci_sel.fs.acl[0] >> 4));
  if (type == SEC_UPDATE)
    return (check_security_pin_ac (fci_sel.fs.acl[0] & 0xf));
  if (type == SEC_DELETE)
    return (check_security_pin_ac (fci_sel.fs.acl[1] >> 4));
  if (type == SEC_GENERATE)
    return (check_security_pin_ac (fci_sel.fs.acl[1] & 0xf));
  return 1;
}

static uint8_t
check_DF_security (uint8_t type)
{
  DPRINT ("%s\n", __FUNCTION__);

  if (fci_sel.fs.id == 0xffff)
    return 1;

  DPRINT ("selected %04X ACL=%02X%02X%02X\n", fci_sel.fs.id,
	  fci_sel.fs.acl[0], fci_sel.fs.acl[1], fci_sel.fs.acl[2]);

  if (type == SEC_CREATE_DF)
    return (check_security_pin_ac (fci_sel.fs.acl[0] & 0xf));
  if (type == SEC_CREATE_EF)
    return (check_security_pin_ac (fci_sel.fs.acl[0] >> 4));
  if (type == SEC_DELETE)
    return (check_security_pin_ac (fci_sel.fs.acl[1] >> 4));
  return 1;
}


static uint16_t
get_tag (uint8_t * buffer)
{
  if (buffer[1] == 1)
    return buffer[2];
  return buffer[2] << 8 | buffer[3];
}


static void
fs_mkfs (uint8_t * acl)
{
  uint8_t erase[3];

  DPRINT ("%s\n", __FUNCTION__);

  fci_sel.fs.id = 0x3f00;
  fci_sel.fs.parent_uuid = 0;
  fci_sel.fs.uuid = 0;
  fci_sel.fs.size = 64;
  fci_sel.fs.type = 0x38;
  if (acl != NULL)
    memcpy (fci_sel.fs.acl, acl, 3);
  else
    {
      fci_sel.fs.acl[0] = 0x11;
      fci_sel.fs.acl[1] = 0x3F;
      fci_sel.fs.acl[2] = 0xFF;
    }
  fci_sel.fs.prop = 0x0002;	// this DF can not be deleted
  fci_sel.fs.name_size = 3;
  fci_sel.fs.no_allocate = 1;
  fci_sel.fs.tag_80_81 = 1;
  //TODO check return code!
  device_write_block (&fci_sel.fs, 0, sizeof (struct fs_data));
  erase[0] = '\360';
  erase[1] = 'M';
  erase[2] = 'F';
  device_write_block (erase, sizeof (struct fs_data), 3);

  uint16_t i;
  uint8_t e = 0xff;

  for (i = 0; i < 256; i++)
    sec_device_write_block (&e, i, 1);

  // lifecycle must be set to 1 because no pins exists..

  set_lifecycle (1);
}

uint16_t
fs_erase_card (uint8_t * acl)
{
  uint16_t i = 0, j;
  int16_t ret;
  DPRINT ("%s\n", __FUNCTION__);

  // if MF exists, do ACL check
  fci_sel.fs.uuid = 0;
  if (RET_SEARCH_OK == fs_search_file (&fci_sel, 0x3f00, NULL, S_DF))
    {
      if (check_DF_security (SEC_DELETE))
	return 0x6982;		//security status not satisfied
    }
  for (;;)
    {
      ret = device_write_ff (i, 0);	// 0 = 256
      if (ret < 0)
	break;
      // to prevent overlap on 64kiB device
      j = ret + i;
      if (j < i)
	break;
      i = j;
    }

  fs_mkfs (acl);
  return 0x9000;
}

void
fs_init ()
{
  // test if some of security data are in tact
  uint8_t i = 0, val = 255, s;

  do
    {
      sec_device_read_block (&s, i, 1);
      val &= s;
    }
  while (++i);

  if (val == 255)
    {
      // no security data, check if master file exists
      //find free space in memory device, if at start, device is not initialized
      if (RET_SEARCH_END == fs_search_file (&fci_sel, 0xffff, NULL, S_MAX))
	if (fci_sel.mem_offset == 0)
	  fs_mkfs (NULL);
    }
  security_enable = 0;		//nothing enabled
  // select MF after ATR (to conform ISO)
  fci_sel.fs.uuid = 0;
  fs_search_file (&fci_sel, 0x3f00, NULL, S_DF);

//  fci_sel.fs.id = 0xffff;     //nothing is selected
}

// 0xffff if nothing is selected
uint16_t
fs_get_selected ()
{
  DPRINT ("%s\n", __FUNCTION__);
  return fci_sel.fs.id;
}

static uint16_t
fs_get_fci (struct iso7816_response *r)
{
  DPRINT ("%s\n", __FUNCTION__);

  r->data[0] = 0x6f;
  r->data[1] = 23;
  r->data[2] = 0x80 | (fci_sel.fs.tag_80_81 ? 1 : 0);
  r->data[3] = 2;
  r->data[4] = fci_sel.fs.size >> 8;
  r->data[5] = fci_sel.fs.size & 255;
  r->data[6] = 0x82;
  r->data[7] = 1;
  r->data[8] = fci_sel.fs.type;
  r->data[9] = 0x83;
  r->data[10] = 2;
  r->data[11] = fci_sel.fs.id >> 8;
  r->data[12] = fci_sel.fs.id & 255;
  r->data[13] = 0x86;
  r->data[14] = 3;
  r->data[15] = fci_sel.fs.acl[0];
  r->data[16] = fci_sel.fs.acl[1];
  r->data[17] = fci_sel.fs.acl[2];
  r->data[18] = 0x85;
  r->data[19] = 2;
  r->data[20] = fci_sel.fs.prop >> 8;
  r->data[21] = fci_sel.fs.prop & 255;
  r->data[22] = 0x8a;
  r->data[23] = 1;
  r->data[24] = get_lifecycle ();
  if (fci_sel.fs.name_size)
    {
      r->data[1] += (fci_sel.fs.name_size) + 2;
      r->data[25] = 0x84;
      r->data[26] = fci_sel.fs.name_size;
      if (1 ==
	  device_read_block (r->data + 27,
			     fci_sel.mem_offset + sizeof (struct fs_data),
			     fci_sel.fs.name_size))
	return -1;
    }
  r->len = r->data[1] + 2;
  r->flag = R_RESP_READY;
  return 0x61 << 8 | r->len;
}

uint16_t
fs_select_parent (struct iso7816_response * r)
{
  DPRINT ("%s\n", __FUNCTION__);

  if (fs_search_file (&fci_sel, 0, NULL, S_PARENT))
    return 0x6A82;
  return fs_get_fci (r);
}

// WARNING, caller is responsible to set up "buffer" to correct values (len <1..16>, data)
uint16_t
fs_select_by_name (uint8_t * buffer, struct iso7816_response * r)
{
  DPRINT ("%s\n", __FUNCTION__);

  if (RET_SEARCH_OK != fs_search_file (&fci_sel, 0, buffer, S_NAME))
    return 0x6A82;
  return fs_get_fci (r);
}

// WARNING, caller is responsible to set up "buffer" to correct values (len>=2, data)
uint16_t
fs_select_df (uint16_t id, struct iso7816_response * r)
{
  DPRINT ("%s\n", __FUNCTION__);

  if (fs_search_file (&fci_sel, id, NULL, S_DF))
    return 0x6A82;
  return fs_get_fci (r);
}

// WARNING, caller is responsible to set up "buffer" to correct values (len>=2, data)
uint16_t
fs_select_mf (struct iso7816_response * r)
{
  DPRINT ("%s\n", __FUNCTION__);

  fci_sel.fs.uuid = 0;
  return fs_select_df (0x3f00, r);
}

uint16_t
fs_select_0 (uint16_t id, struct iso7816_response * r)
{
  DPRINT ("%s\n", __FUNCTION__);

  // ISO - if P1,P2 == 00 00 and data field is empty od equal to 3f00 select MF
  if (fs_search_file (&fci_sel, id, NULL, S_0))
    return 0x6A82;
  return fs_get_fci (r);
}

uint16_t
fs_select_ef (uint16_t id, struct iso7816_response * r)
{
  DPRINT ("%s\n", __FUNCTION__);

  if (fs_search_file (&fci_sel, id, NULL, S_EF))
    return 0x6A82;
  return fs_get_fci (r);
}

uint16_t
fs_select_by_path_from_df (uint8_t * buffer, struct iso7816_response * r)
{
  DPRINT ("%s\n", __FUNCTION__);

  if (RET_SEARCH_OK != fs_search_file (&fci_sel, 0, buffer, S_PATH))
    return 0x6A82;
  return fs_get_fci (r);
}

uint16_t
fs_select_by_path_from_mf (uint8_t * buffer, struct iso7816_response * r)
{
  struct fs_response fr;

  DPRINT ("%s\n", __FUNCTION__);

  fr.fs.uuid = 0;
  if (RET_SEARCH_OK != fs_search_file (&fr, 0, buffer, S_PATH))
    return 0x6A82;
  memcpy (&fci_sel, &fr, sizeof (struct fs_response));
  return fs_get_fci (r);
}


// 0xffff if fail, filesize if OK
uint16_t
fs_get_file_size ()
{
  if (fci_sel.fs.id == 0xffff)
    return 0xffff;		//file not found

  return fci_sel.fs.size;
}

// 0xff fail
uint8_t
fs_get_file_type ()
{
  if (fci_sel.fs.id == 0xffff)
    return 0xff;		//file not found

  return fci_sel.fs.type;
}

// key file is organized in TAG/LEN/VAL, TAG, LEN is 8bit wide, length of VAL is in LEN variable.
// maximum part size in file is 256 bytes, if LEN = 0 real data len is 256 bytes
// TAG 0xff is mark of unused space in file, other values is used to mark type of VAL 

// return 0 if part does not exist (offset is positioned at first 0xff TAG in file)
// or 1 if part exist, offset is positioned to TAG of key part
// file length is assumed below 32767

// wrong key file
#define C_KEYp_WRONG 2
//when key part exists
#define C_KEYp_EXIST 1
// when free space is available
#define C_KEYp_FREE 0

static uint8_t
fs_key_part (uint16_t * offset, uint8_t part)
{
  uint8_t tl[2];
  int16_t flen;

  if (part == 0xff)
    return C_KEYp_WRONG;	// safety check .. TAG 0xff is "free space" in key file..

  if (fci_sel.fs.id == 0xffff)
    return C_KEYp_WRONG;	//file not found

// 0x11 for RSA 0x22 for EC keys, 0x23 for now for secp256k1 ..
  if (fci_sel.fs.type != 0x11 && fci_sel.fs.type != 0x22
      && fci_sel.fs.type != 0x23)
    return C_KEYp_WRONG;	//this file is not designed to hold key

  flen = fci_sel.fs.size;

  *offset = fci_sel.mem_offset;
  *offset += sizeof (struct fs_data);
  while (flen > 2)
    {
      if (device_read_block (tl, *offset, 2))
	return C_KEYp_WRONG;
      if (tl[0] == 0xff)
	return C_KEYp_FREE;
      if (tl[0] == part)
	return C_KEYp_EXIST;
      *offset += 2;		// skip TAG, LEN
      *offset += tl[1];		// skip VAL
      flen -= 2;
      flen -= tl[1];
      if (tl[1] == 0)
	{
	  *offset += 256;
	  flen -= 256;
	}
    }
  return C_KEYp_WRONG;
}

// read key part (tagged by 'type') and return part len (or 0 if error)
// if key == NULL return only part size
uint16_t
fs_key_read_part (uint8_t * key, uint8_t type)
{
  uint16_t offset;
  uint8_t size;

  DPRINT ("%s\n", __FUNCTION__);

  if (check_EF_security (SEC_READ))
    return 0;			//security status not satisfied

  type &= (uint8_t) ~ KEY_GENERATE;
  if (C_KEYp_EXIST == fs_key_part (&offset, type))
    {
      offset++;
      if (device_read_block (&size, offset, 1))
	return 0;
      offset++;
      if (size > RSA_BYTES)
	return 0;
      if (key)
	if (device_read_block (key, offset, size))
	  return 0;
      if (size == 0)
	return 256;
      else
	return size;
    }
  return 0;
}

#ifndef NIST_ONLY
// temp function to allow change file type for EC key to 0x23
uint16_t
fs_key_change_type ()
{
  DPRINT ("%s\n", __FUNCTION__);
  if (check_EF_security (SEC_UPDATE) && check_EF_security (SEC_GENERATE))
    return 0x6982;		//security status not satisfied
  if (fci_sel.fs.type == 0x23)
    return 0x9000;
  if (fci_sel.fs.type != 0x22)
    return 0x6985;		// condition of use not satisfied
  fci_sel.fs.type = 0x23;
  if (device_write_block
      (&fci_sel.fs, fci_sel.mem_offset, sizeof (struct fs_data)))
    return 0x6581;		//memory fail

  return 0x9000;
}
#endif

uint16_t
fs_key_write_part (uint8_t * key)
{
  uint16_t offset;
  uint16_t prop_flag = fci_sel.fs.prop;

#define K_TYPE key[0]
#define K_SIZE key[1]

  DPRINT ("%s type=%d size=%d\n", __FUNCTION__, K_TYPE, K_SIZE);

  // part size below 254 bytes to allow write type and part length
  // with one device_write_block() call

  if (K_SIZE == 0 || K_SIZE > 254)
    return 0x6984;		//invalid data

  if (K_TYPE & KEY_GENERATE)
    {
      K_TYPE &= (uint8_t) ~ KEY_GENERATE;
      prop_flag |= 0x200;	// prepare "generated" flag to file
      if (check_EF_security (SEC_GENERATE))
	return 0x6982;		//security status not satisfied
    }
  else
    {
      if (check_EF_security (SEC_UPDATE))
	return 0x6982;		//security status not satisfied
    }

  // allow only write to free space in key file
  if (C_KEYp_FREE != fs_key_part (&offset, K_TYPE))
    {
      DPRINT ("key part 0x%02x already exists\n", K_TYPE);
      return 0x6984;		//invalid data
    }

  // if most important part of key is loaded into key file, mark valid key file
  if (K_TYPE == KEY_EC_PRIVATE || K_TYPE == KEY_RSA_MOD
      || K_TYPE == KEY_RSA_MOD_p2)
    prop_flag |= 0x0100;	//mark as valid key file

  // write fci back if prop flag was changed
  if (prop_flag != fci_sel.fs.prop)
    {
      fci_sel.fs.prop = prop_flag;
      if (device_write_block
	  (&fci_sel.fs, fci_sel.mem_offset, sizeof (struct fs_data)))
	return 0x6581;		//memory fail
    }

  uint16_t size_test = offset - fci_sel.mem_offset;

  if (size_test + K_SIZE > fci_sel.fs.size)
    return 0x6b00;		//outside EF

  if (1 == device_write_block (key, offset, K_SIZE + 2))
    return 0x6581;		//memory fail

  return 0x9000;
#undef K_TYPE
#undef K_SIZE
}

static uint8_t
fs_transparent_file ()
{
  if (fci_sel.fs.type == 1)
    return 1;
  DPRINT ("%s fail, file type %02x\n", __FUNCTION__, fci_sel.fs.type);
  return 0;
}

uint16_t
fs_read_binary (uint16_t offset, uint16_t dlen, struct iso7816_response * r)
{
  DPRINT ("%s\n", __FUNCTION__);

  if (fci_sel.fs.id == 0xffff)
//    return 0x6a82;            //file or application not found
    return 0x6986;		//Command not allowed,(co current EF)

  if (!fs_transparent_file ())
    return 0x6985;		// condition of use not satisfied

  if (check_EF_security (SEC_READ))
    return 0x6982;		//security status not satisfied

  if (offset + dlen > fci_sel.fs.size)
    return 0x6282;		//end of size before LE

  offset += fci_sel.mem_offset;
  offset += sizeof (struct fs_data);
  offset += fci_sel.fs.name_size;

  memset (r->data, 0xff, dlen);	//prepare initialized data if device_read_block fail return
  //fail data not old buffer (may be with security data)
  r->len = dlen;
  r->flag = R_RESP_READY;
  if (1 == device_read_block (r->data, offset, dlen))
    return 0x6281;		//part of data is corrupted
  return 0x6100 | dlen;
}

uint16_t
fs_update_binary (uint8_t * buffer, uint16_t offset)
{
  uint8_t dlen = *buffer;

  DPRINT ("%s\n", __FUNCTION__);

  buffer++;

  if (fci_sel.fs.id == 0xffff)
//    return 0x6a82;            //file or application not found
    return 0x6986;		//Command not allowed,(co current EF)

  if (!fs_transparent_file ())
    return 0x6985;		// condition of use not satisfied

  if (check_EF_security (SEC_UPDATE))
    return 0x6982;		//security status not satisfied

  if (offset + dlen > fci_sel.fs.size)
    return 0x6b00;		//outside EF

  offset += fci_sel.mem_offset;
  offset += sizeof (struct fs_data);
  offset += fci_sel.fs.name_size;

  if (1 == device_write_block (buffer, offset, dlen))
    return 0x6581;		//memory fail
  return 0x9000;
}

static uint16_t
fs_ff (uint16_t offset, uint16_t size)
{
  int16_t ret;

  card_io_start_null ();

  while (size)
    {
      ret = device_write_ff (offset, (size >= 256 ? 0 : size));
      if (ret <= 0)
	return 0x6581;		//memory fail
      size -= ret;
      offset += ret;
    }
  return 0x9000;
}

uint16_t
fs_erase_binary (uint16_t offset)
{
  uint16_t size;

  DPRINT ("%s\n", __FUNCTION__);

  if (fci_sel.fs.id == 0xffff)
    return 0x6986;		//Command not allowed,(co current EF)

  if (!fs_transparent_file ())
    return 0x6985;		// condition of use not satisfied

  if (check_EF_security (SEC_UPDATE))
    return 0x6982;		//security status not satisfied

  if (offset > fci_sel.fs.size)
    return 0x6b00;		//outside EF
  size = fci_sel.fs.size - offset;
  offset += fci_sel.mem_offset;
  offset += sizeof (struct fs_data);
  offset += fci_sel.fs.name_size;
  return fs_ff (offset, size);
}

uint16_t
fs_delete_file ()
{
  struct fs_response fr1;
  uint16_t offset;
  uint16_t size;

  DPRINT ("%s\n", __FUNCTION__);

  if (fci_sel.fs.id == 0xffff)
    return 0x6986;		//Command not allowed,(co current EF)

  if (fci_sel.fs.type == 0x38)
    {
      DPRINT ("%s, DF delete\n", __FUNCTION__);
      if (fci_sel.fs.prop == 0x0002)
	return 0x6985;		// condition of use not satisfied
      if (check_DF_security (SEC_DELETE))
	return 0x6982;		//security status not satisfied
    }
  else
    {
      DPRINT ("%s, EF delete\n", __FUNCTION__);
      if (check_EF_security (SEC_DELETE))
	return 0x6982;		//security status not satisfied
    }
// Limitation: only last file is deletable

  size = sizeof (struct fs_data);
  if (!fci_sel.fs.no_allocate)
    size += fci_sel.fs.size;
  size += fci_sel.fs.name_size;
  offset = fci_sel.mem_offset;

  if (RET_SEARCH_END != fs_search_file (&fr1, 0xFFFF, NULL, S_MAX))
    {
      DPRINT ("%s no RET_SEARCH_END\n", __FUNCTION__);
      return 0x6985;		// condition of use not satisfied
    }
  if (fr1.mem_offset != offset + size)
    {
      DPRINT ("%s no last file %d %d %d \n", __FUNCTION__, fr1.mem_offset,
	      offset, size);
      return 0x6985;		// condition of use not satisfied
    }
  // select parent
  if (fs_search_file (&fci_sel, 0, NULL, S_PARENT))
    return 0x6A82;
  return fs_ff (offset, size);
}

int16_t
fs_create_file (uint8_t * buffer)
{
  struct fs_response fr1;
  struct fs_data fs;
  uint8_t xlen;
  uint8_t flag = 0;
  uint8_t *df_name = NULL;

  DPRINT ("%s\n", __FUNCTION__);

  if (fci_sel.fs.id == 0xffff)
    return 0x6a82;		//file not found

  if (fci_sel.fs.type != 0x38)	//no DF is selected
    return 0x6A82;

  fs.parent_uuid = fci_sel.fs.uuid;

  // FCP too small ?  
  if (buffer[0] < 2)
    return 0x6984;		//invalid data

  // test if FCP template is in buffer
  if (buffer[1] != 0x62)
    return 0x6984;		//invalid data

  xlen = buffer[2];

  if (buffer[0] + 2 < xlen)
    return 0x6984;		//invalid data

  buffer += 3;			//at position of first FCP  tag

  fs.name_size = 0;
  fs.tag_80_81 = 0;
  fs.prop = 0;			//not required tag

  for (;;)
    {
      {
	uint8_t dlen;

	if (xlen == 1)
	  if (*buffer != 0)
	    return 0x6984;	//invalid data

	if (xlen < 2)		// rest bytes .. no tag, no len or only tag 
	  {
	    if (flag != 0x0f)
	      return 0x6984;	//invalid data
	    break;
	  }

	dlen = buffer[1];

	if (dlen == 0)
	  {			//workaround for card-myeid.c bug in opensc, normally this test is not needed, and error is returned
	    if (flag != 0x0f)
	      return 0x6984;	//invalid data
	    break;
	  }
	if (dlen > 16)
	  return 0x6984;	//maximal tag size is 16 (filename);

	//check new tag
	if (xlen < 2 + dlen)
	  return 0x6984;	//invalid data (no enough data for this tag in buffer)

	switch (*buffer)
	  {
	    //size
	  case 0x81:
	    if (dlen != 2)
	      return 0x6984;	//invalid data
	    fs.tag_80_81 = 1;	// 1 = DF/EF key  0 = EF size
	  case 0x80:
	    if (dlen > 2)
	      return 0x6984;	//invalid data
	    if (flag & 1)
	      return 0x6984;	//invalid data  (duplicate tag 0x80/0x81)
	    flag |= 1;
	    fs.size = get_tag (buffer);
	    // limit filesize
	    if (fs.size > 32767)
	      return 0x6984;	//invalid data
	    break;
	    //type
	  case 0x82:
	    if (dlen > 4)
	      return 0x6984;	//invalid data
	    flag |= 2;
	    fs.type = buffer[2];
	    // allow only 0x01, 0x11, 0x22
	    if (fs.type != 0x01 && fs.type != 0x11 && fs.type != 0x22
		&& fs.type != 0x23 && fs.type != 0x38)
	      return 0x6984;	//invalid data
	    break;
	    //ID
	  case 0x83:
	    if (dlen != 2)
	      return 0x6984;	//invalid data
	    flag |= 4;
	    fs.id = get_tag (buffer);
	    if (fs.id == 0x3fff)
	      return 0x6984;	//invalid data
	    if (fs.id == 0x3f00)
	      return 0x6984;	//invalid data
	    if (fs.id == 0xffff)
	      return 0x6984;	//invalid data
	    break;
	    //prop info
	  case 0x85:
	    if (dlen != 2)
	      return 0x6984;	//invalid data
	    fs.prop = get_tag (buffer);
	    break;
	    //ACL
	  case 0x86:
	    // minimum 3 ACL bytes
	    if (dlen < 3)
	      return 0x6984;	//invalid data
	    flag |= 0x08;
	    fs.acl[0] = buffer[2];
	    fs.acl[1] = buffer[3];
	    fs.acl[2] = buffer[4];
	    break;
	    //filename
	  case 0x84:
	    if (dlen < 1)
	      return 0x6984;	//invalid data
	    // maximal tag len (16) is already checked
	    fs.name_size = dlen;
	    df_name = buffer + 1;
	    break;
	    //lifecycle info (skip this, this is globally replaced by security mechanism)
	  case 0x8a:
	    if (dlen != 1)
	      return 0x6984;	//invalid data
	  case 0:
	    break;
	  default:
	    return 0x6984;	//invalid data
	  }
	dlen += 2;
	xlen -= dlen;
	buffer += dlen;
      }
    }

  //DF checks
  if (fs.type == 0x38)
    {
      // DF does not need allocate space
      fs.no_allocate = 1;
      // DF need 0x81 tag ..
      if (!fs.tag_80_81)
	return 0x6984;		//invalid data
      if (check_DF_security (SEC_CREATE_DF))
	return 0x6982;		//security status not satisfied
      //all filenames must be different
      if (RET_SEARCH_OK == fs_search_file (&fr1, 0, df_name, S_NAME))
	return 0x6A89;		//already exists
    }
  else
    {
      fs.no_allocate = 0;
      // clear valid flag for key file
      if (fs.type == 0x11 || fs.type == 0x22 || fs.type != 0x23)
	fs.prop &= 0xf0ff;

      // EF does not have name
      if (df_name)
	return 0x6984;		//invalid data
      // EF size can be specified by 0x80 or 0x81 tag
      if (check_DF_security (SEC_CREATE_EF))
	return 0x6982;		//security status not satisfied
    }

  // search new UUID (and colision test)

  memcpy (&fr1, &fci_sel, sizeof (struct fs_response));
  if (RET_SEARCH_END != fs_search_file (&fr1, fs.id, NULL, S_MAX))
    return 0x6A89;		//already exists

  DPRINT ("%s filesystem position 0x%04x\n", __FUNCTION__, fr1.mem_offset);
  fs.uuid = fr1.fs.uuid;

  // there must be place for full file (+ 2 bytes for test  - FS end)

  if (0 !=
      device_read_block (&flag,
			 fr1.mem_offset + sizeof (struct fs_data) +
			 fs.name_size + fs.size + 2, 1))
    return 0x6985;		//condition not satisfied

  // save file header
  if (device_write_block (&fs, fr1.mem_offset, sizeof (struct fs_data)))
    return 0x6985;		//condition not satisfied
  // save filename if needed

  if (df_name)
    {
      DPRINT ("%s FCI write OK, writing name\n", __FUNCTION__);
      if (device_write_block
	  (df_name + 1, fr1.mem_offset + sizeof (struct fs_data),
	   fs.name_size))
	return 0x6985;		//condition not satisfied
    }
  return 0x9000;		//all ok
}


uint16_t
fs_list_files (uint8_t type, struct iso7816_response * r)
{
  struct fs_response fr;

  DPRINT ("%s\n", __FUNCTION__);

  if (fci_sel.fs.id == 0xffff)
    return 0x6a82;		//file not found

  if ((fci_sel.fs.type & 0x38) != 0x38)	//no DF is selected
    return 0x6A82;

  if (type > 2)
    type = 0;

  memcpy (&fr, &fci_sel, sizeof (struct fs_response));
  if (RET_SEARCH_END == fs_search_file (&fr, 0, r->data, S_LIST_ALL - type))
    {
      if (fr.fs.id == 0)
	return 0x9000;
      r->flag = R_RESP_READY;
      DPRINT ("%d %d\n", r->len, fr.fs.id);
      r->len = ((fr.fs.id << 1) & 0xff);
      return 0x6100 | r->len;
    }
  return 0x6a82;		//file not found
}
