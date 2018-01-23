/*
    mem_device.c

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

    xmega128a4u memory devices subsystem

    FLASH organization:

    0x00000 .. 0x0FFFF card software
    0x10000 .. 0x1FFFF for data (keys/certificates etc.)
    0x20000 .. 0x21FFF SPM code, ccid code usb code

*/
#include <stdint.h>
#include <string.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <avr/eeprom.h>
#include <util/atomic.h>
#include "mem_device.h"


//forward definitions:

void
device_write_page (uint16_t flash, uint8_t * ram, uint8_t * check,
		   uint8_t no_erase) __attribute__ ((section (".flash_end")));

void
device_write_page (uint16_t flash, uint8_t * ram, uint8_t * check,
		   uint8_t no_erase)
{
  asm volatile (		//
		 // prevent unattended jump here ..  last two operands must be same
		 "cp    r20,r22\n"	//
		 "brne  5f\n"	//
		 "cp    r21,r23\n"	//
		 "brne  5f\n"	//
//
		 "cli\n"	//
		 "ldi	r20,0x01\n"	// RAMPZ set to 1
		 "out	0x3b, r20\n"	//
		 "movw	r26,r22\n"	// ram pointer to X
		 "clr	r24\n"	// safety clear (clamp to page start)
		 "push	r25\n" "1:\n"	//
		 "lds	r20, 0x01CF\n"	// NVM_STATUS
		 "sbrc	r20, 7\n"	// NVM is busy ?
		 "rjmp	1b\n"	// wait in loop
//
		 "ldi	r21, 0x23\n"	// command LOAD FLASH BUFFER
		 "sts	0x01CA, r21\n"	// set command to NVM_CMD register
// load page
//
		 "2:\n"		//
		 "movw	r30,r24\n"	// flash address to Z
		 "ld	r0,X+\n"	// load ram
		 "ld	r1,X+\n"	//
		 "spm\n"	//
//
		 "adiw	r24,2\n"	// increment flash address
		 "tst	r24\n"	// 256 bytes ?
		 "brne	2b\n"	// loop if page is not fully loaded
//
// erase/write page to flash
		 "pop	r25\n" "clr	r24\n"
//
		 "3:\n"		//
		 "lds	r20, 0x01CF\n"	// NVM_STATUS
		 "sbrc	r20, 7\n"	// NVM is busy ?
		 "rjmp	3b\n"	// wait in loop
//
		 "movw	r30, r24\n"	// flash address to Z
//
// ERASE_WRITE_APP_PAGE  or only WRITE_APP_PAGE
		 "ldi	r21,0x25\n"	// command ERASE_WRITE_APP_PAGE
		 "cpse	r18,r24\n"	// test - 0 in r18 ?
		 "ldi	r21,0x24\n"	// command WRITE_APP_PAGE
		 "sts	0x01CA, r21\n"	// write command
		 "ldi	r20, 0x9D\n"	// unprotect SPM (0xd8 unprotect IO reg)
		 "sts	0x0034, r20\n"	// CCP
		 "spm\n"	//
//
//
		 "4:\n"		//
		 "lds	r20, 0x01CF\n"	// NVM_STATUS
		 "sbrc	r20, 7\n"	// NVM is busy ?
		 "rjmp	4b\n"	// wait in loop
//
		 "clr	r21\n"	// no command
		 "sts	0x01CA, r21\n"	//
//
		 "sei\n"	//
		 "clr	r1\n"	// ABI need r1=0
		 "5:\n"		//
		 :::"r0", "r1", "r20", "r21",
		 "r22", "r23", "r24", "r25", "r26", "r27", "r30", "r31");

}

uint8_t
device_write_block (void *buffer, uint16_t offset, uint8_t size)
{
  uint8_t *b = buffer;
  uint16_t p_base;
  uint8_t p_data[256];
  uint16_t s = size;
  uint16_t p_offset;
  uint16_t p_data_size, i;
  uint8_t f, r, no_erase = 1;

  s = size ? size : 256;

  if ((uint32_t) (offset + s) >= 0x10000)
    return 1;

  do
    {
      // get page start (aligned)
      p_base = offset & 0xff00;
      // get position of new data in page
      p_offset = offset & 255;
      // calculate size of new data
      p_data_size = 256 - p_offset;
      if (p_data_size > s)
	p_data_size = s;

      // copy old data (0 - 256)
      device_read_block (p_data, p_base, 0);

      for (i = 0; i < p_data_size; i++)
	{
	  f = p_data[p_offset];
	  r = b[i];
	  if (r != (r & f))
	    no_erase = 0;
	  p_data[p_offset++] = r;
	}
      //memcpy (p_data + p_offset, b, p_data_size);

      b += p_data_size;
      offset += p_data_size;
      s -= p_data_size;

      // write to flash
      device_write_page (p_base, p_data, p_data, no_erase);
    }
  while (s > 0);
  return 0;
}

// fill block at offset _offset_ with value 0xff of maximal length _size_
// return number of filled bytes (-1 on error)
int16_t
device_write_ff (uint16_t offset, uint8_t size_in)
{
  uint16_t s;
  uint16_t p_base;
  uint16_t p_offset;
  uint8_t p_data[256];
  uint16_t size = size_in;

  if (size_in == 0)
    size = 256;
  // offset is in range 0-65535, no check is needed

  // get page start (aligned)
  p_base = offset & 0xff00;
  // get position of new data in page
  p_offset = offset & 255;

  // copy old data (0 - 256)
  device_read_block (p_data, p_base, 0);

  s = 256 - p_offset;
  if (s > size)
    s = size;

  memset (p_data + p_offset, 0xff, s);

  // write to flash
  device_write_page (p_base, p_data, p_data, 0);
  return s;
}

// read max 256 bytes from flash into buffer (0 = 256)
uint8_t
device_read_block (void *buffer, uint16_t offset, uint8_t size)
{
  asm volatile (		//
		 "mov	r18,r20\n"	// r19,18 = size - 1
		 "clr	r19\n"	//
		 "dec	r18\n"	//
// if ((offset + size - 1) >= 0x10000 ) return error
		 "add	r18,r22\n"	// + offset
		 "adc	r19,r23\n"	//
		 "brcc	1f\n"	//
//
		 "ldi	r24,1\n"	// error code
		 "ret\n"	//
//
		 "1:\n"		//
		 "movw	r26,r24\n"	// buffer
		 "movw	r30,r22\n"	// offset
		 "ldi	r21,1\n"	// value for rampz
		 "out	%[rampz],r21\n"	//
		 "2:"		//
		 "elpm	r0,Z+\n"	// load data
		 "st	X+,r0\n"	// store data
		 "dec	r20\n"	// counter
		 "brne	2b\n"	// loop
		 ::		//
		 [rampz] "i" (_SFR_IO_ADDR (RAMPZ))	//
    );				//
  return 0;
}


// 1023 byte for security informations
uint8_t
sec_device_read_block (void *buffer, uint16_t offset, uint8_t size)
{
  uint16_t eeprom = offset, s;

  s = size ? size : 256;
  if (eeprom + s -1 > 1023)
    return 1;

  eeprom_read_block (buffer, (uint8_t *) (eeprom), s);
  return 0;
}


uint8_t
sec_device_write_block (void *buffer, uint16_t offset, uint8_t size)
{
  uint16_t eeprom = offset, s;

  s = size ? size : 256;
  if (eeprom + s -1 > 1023)
    return 1;

  cli ();
  eeprom_update_block (buffer, (uint8_t *) (eeprom), s);
  eeprom_busy_wait ();
  sei ();

  return 0;
}
