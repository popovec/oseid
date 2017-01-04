/*
    mem_device.c

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

    Atmega128 memory devices subsystem

*/
#include <stdint.h>
#include <string.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <avr/eeprom.h>
#include "mem_device.h"


static void
osccal_min (void)
{
  uint8_t osc;

  osc = OSCCAL;
  while (osc > 180)
    {
      osc -= 4;
      OSCCAL = osc;
// please read atmega errata anout this nop's
      asm volatile (		//
		     "nop\n"	//
		     "nop\n"	//
		     "nop\n"	//
		     "nop\n"	//
		     "nop\n"	//
		     "nop\n"	//
		     "nop\n"	//
		     "nop\n"	//
		     ::);	//
    }
}


// 256 byte for security informations 
uint8_t
sec_device_read_block (void *buffer, uint8_t offset, uint8_t size)
{
  uint16_t eeprom = offset;

  if (eeprom + size > 256)
    return 1;

  eeprom_read_block (buffer, (uint8_t *) (eeprom), size);
  return 0;
}


uint8_t
sec_device_write_block (void *buffer, uint8_t offset, uint8_t size)
{
  uint16_t eeprom = offset;


  if (eeprom + size > 256)
    return 1;

  cli ();
  osccal_min ();
  eeprom_update_block (buffer, (uint8_t *) (eeprom), size);
  eeprom_busy_wait ();
  sei ();

  return 0;
}

// FLASH organization:
// 0x00000 .. 0x0FFFF bytes is for program
// 0x10000 .. 0x1FF00 for data
// 0x1FF00 .. 0x1FFFF SPM code


// read max 256 bytes from flash into buffer (0 = 256)
uint8_t
device_read_block (void *buffer, uint16_t offset, uint8_t size)
{
  asm volatile (		//
		 "movw r26,r24\n"	// buffer
		 "movw r30,r22\n"	// offset
		 "ldi	 r21,1\n"	// value for rampz
		 "out  %[rampz],r21\n"	//
		 "1:"		//
		 "elpm r0,Z+\n"	// load data
		 "st   X+,r0\n"	// store data
		 "dec r20\n"	// counter 
		 "brne 1b\n"	// loop
		 ::		//   
		 [rampz] "i" (_SFR_IO_ADDR (RAMPZ))	//
    );				//
  return 0;
}


//forward definitions:
void device_write_page (uint16_t flash, uint8_t * ram, uint8_t * check)
  __attribute__ ((section (".flash_end")));

/*
static void
init_page (uint8_t * buffer, uint16_t page)
{

  asm volatile (		//
		 "movw r30,r24\n"	//target ram buffer
		 "movw r26,r22\n"	//source buffer in flash    
		 "ldi r24,127\n"	//counter
		 "1:\n"		//loop
		 "lpm r25,Z\n"	//load byte
		 "adiw r30,1\n"	//increment pointer in flash
		 "st  X+,r25\n"	//save byte
		 "dec r24\n"	//decrement counter
		 "sbrs r24,7\n"	//minus?
		 "rjmp 1b\n"	//
    );
}
*/


uint8_t
device_write_block (void *buffer, uint16_t offset, uint8_t size)
{
  uint8_t *b = buffer;
  uint16_t p_base;
  uint8_t p_data[256];
  uint16_t s = size;
  uint16_t p_offset;
  uint16_t p_data_size;

  if (s == 0)
    s = 256;

  if ((offset + s) >= 0xFF00 /*FLASHEND - 256 */ )	//last page is used for do_spm code!
    return 1;

  do
    {
      // get page start (aligned)
      p_base = offset & 0xff00;
      // get data position of new data in page
      p_offset = offset & 255;
      // calculate size of new data
      p_data_size = 256 - p_offset;
      if (p_data_size > s)
	p_data_size = s;

      // copy old data (0 - 256)
      device_read_block (p_data, p_base, 0);

      memcpy (p_data + p_offset, b, p_data_size);

      b += p_data_size;
      offset += p_data_size;
      s -= p_data_size;

      // write to flash
      // TODO prevent page erase if not needed..
      cli ();
      osccal_min ();
      device_write_page (p_base, p_data, p_data);
      sei ();
    }
  while (s > 0);
  return 0;
}

// fill block at offset _offset_ with value 0xff of maximal length _size_
// return number of filled bytes (-1 on error)
int16_t
device_write_ff (uint16_t offset, uint16_t size)
{
  uint16_t s;
  uint16_t p_base;
  uint16_t p_offset;

  uint8_t p_data[256];

  if (offset >= 0xFF00 /*FLASHEND - 256 */ )
    return 0;

  // get page start (aligned)
  p_base = offset & 0xff00;
  // get data position of new data in page
  p_offset = offset & 255;

  // copy old data (0 - 256)
  device_read_block (p_data, p_base, 0);

  s = 256 - p_offset;
  if (s > size)
    s = size;

  memset (p_data + p_offset, 0xff, s);

  // write to flash
  cli ();
  osccal_min ();
  device_write_page (p_base, p_data, p_data);
  sei ();
  return s;
}

void
device_write_page (uint16_t flash, uint8_t * ram, uint8_t * check)
{
// helper for do_spm must be placed into NRW place
//  bit names in SPMCSR
// SPMIE    RWWSB  unused   RWWSRE   BLBSET   PGWRT   PGERS   SPMEN
// SPM_PAGESIZE = 128 for atmega328
  asm volatile (		//
// prevent unattended jump here ..  last two operands must be same
		 "cp	r20,r22\n"	//
		 "brne	4f\n"	//
		 "cp	r21,r23\n"	//
		 "brne	4f\n"	//
		 "MOVW R30, R24\n"	//
		 "clr r30\n"	//      align to page start
		 "MOVW R26, R22\n"	//
		 "push r0\n"	//
		 "push r1\n"	//
		 "ldi r25,1\n"	//      preset rampz
		 "out  %[rampz],r25\n"	//
// erase page
		 "ldi r25,3\n"	// PGERS,SPMEN
		 "call do_spm\n"	//
// reenable RWW
		 "ldi r25,0x11\n"	//RWWSRE SPMEN
		 "call do_spm\n"	//
// load data from ram to page
		 "ldi r24,128\n"	//128 words = 256 bytes pagesize
		 "push r30\n"	//
		 "push r31\n"	// save Z
		 "1:\n"		//
		 "ld  r0,X+\n"	//
		 "ld  r1,X+\n"	//
		 "ldi r25,1\n"	// SPMEN
		 "call do_spm\n"	//
		 "adiw r30,2\n"	//
		 "subi r24,1\n"	//
		 "brne 1b\n"	// loop end
		 "pop r31\n"	// restore Z
		 "pop r30\n"	//
// write page
		 "ldi r25,5\n"	//PGWRT,SPMEN
		 "call do_spm\n"
//
		 "2:\n"		//
// reenable RWW
		 "ldi r25,0x11\n"	//RWWSRE SPMEN
		 "call do_spm\n"	//
		 "lds r25,%[spmcsr]\n"	//read SPMCSR
		 "sbrc r25,6\n"	// test RWWSB
		 "rjmp 2b\n"	//
		 "pop r1\n"	//
		 "pop r0\n"	//
		 "ret\n"	//
// wait for SPMCSR (for already running SPM to end)
		 "do_spm:\n"	//
		 "lds r23,%[spmcsr]\n"	//read SPMCSR
		 "sbrc r23,0\n"	//SPMEN
		 "rjmp do_spm\n"	//
// wait for EEPROM
		 "3:\n"		//
		 "sbic %[eecr],1\n"	//EEWE
		 "rjmp 3b\n"	//
//
		 "sts  %[spmcsr],r25\n"	//set SPMCSR
		 "spm\n"	//
		 "ret\n"	//
		 "4:\n"		//
		 "cli\n"	//
		 "jmp   0\n"	//
		 ::		//
		 [rampz] "i" (_SFR_IO_ADDR (RAMPZ)),	//
		 [spmcsr] "i" (_SFR_ADDR (SPMCSR)),	//
		 [eecr] "i" (_SFR_IO_ADDR (EECR))	//
    );				//
}
