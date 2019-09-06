/*
    constants.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2019 Peter Popovec, popovec.peter@gmail.com

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

    definition of constant values for eliptic curves, oids etc

    atmega128/1284  helper for read constants from eeprom or flash
    now default is EEPROM for atmega
    4kB eeprom, 0-0x7ff - constanst, 0x800-0xfff PINs (from mem_device.S)
    (xmega uses flash to store constants)

*/
#ifdef HAVE_GET_CONSTANTS
#ifndef __FLASH
#error, Your compiler does not support Named Address Space
#endif
#include <stdint.h>
#include "constants.h"

#if 1
const uint8_t  __attribute__ ((section (".eeprom")))  eeprom_constants[] = {
 C_CONSTANTS
 0xff
};

uint8_t
get_constant (void *here, uint8_t id)
{
  register uint8_t ret asm ("r24");
  asm volatile (		//
                 "ldi	r30,0\n"	//
                 "ldi	r31,0\n"	//
                 "clr	r24\n"		//
                 "1:\n"			//
                 "out	0x1f,r31\n"	// set address
                 "out	0x1e,r30\n"	//
                 "sbi	0x1c,0\n"	// trigger read
                 "adiw	r30,1\n"	// inc addr
                 "in	r25,0x1d\n"	//
//
                 "out	0x1f,r31\n"	// set address
                 "out	0x1e,r30\n"	//
                 "sbi	0x1c,0\n"	// trigger read
                 "adiw	r30,1\n"	// inc addr
                 "in	r0,0x1d\n"	//
//
                 "cp	r25,r22\n"	// match constant ID?
                 "breq	1f\n"		// ok found
                 "cpi	r25,0xff\n"
                 "breq	3f\n"		// fail, no constant found
                 "in	r0,0x1d\n"	//
                 "add	r30,r0\n"	//
                 "adc	r31,r1\n"	//
                 "rjmp	1b\n"		//
// copy
//
                 "1:\n"
                 "out	0x1f,r31\n"	// set address
                 "out	0x1e,r30\n"	//
                 "sbi	0x1c,0\n"	// trigger read
                 "adiw	r30,1\n"	// inc addr
                 "in	r25,0x1d\n"	//
                 "st	X+,r25\n"
                 "dec	r0\n"
                 "brne	1b\n"
//
                 "2:\n"
		 "ldi	r24,1\n"	//
		 "3:\n"
		 :"=r" (ret):"x" (here):);
  return ret;
}




#else

const uint8_t __flash constants[] = {
  C_CONSTANTS
//last position
  0xff
};

// C code with pgm_read_byte 64 bytes
// C code with named space   56 bytes
// ASM code                  40 bytes

#if 0
uint8_t
get_constant (void *here, uint8_t id)
{
  uint8_t *t;
  const __flash uint8_t *s = constants;
  uint8_t size, val;

  t = (uint8_t *) here;

  for (;;)
    {
      val = *s++;		//pgm_read_byte (s);
      if (val == 0xff)
	return 0;
      size = *s++;		//pgm_read_byte (s);
      if (val == id)
	{
	  while (size)
	    {
	      *t = *s;		//pgm_read_byte (s);
	      t++;
	      s++;
	      size--;
	    }
	  return 1;
	}
      s += size;
    }
}
#else
uint8_t
get_constant (void *here, uint8_t id)
{
  register uint8_t ret asm ("r24");
  asm volatile (		//
		 "1:\n"		//
		 "lpm	r21,Z+\n"	// load constant ID
		 "cpi	r21,0xff\n"	//
// test last constant ?
		 "brne	2f\n"	//
		 "clr	r24\n"	//
		 "ret	\n"	//
		 "2:\n"		//
		 "lpm	r20,Z+\n"	// load constant size
		 "cp	r21,r22\n"	// compare ID (r22 = id)?
		 "breq	3f\n"	//
// jump to next constant
		 "add	r30,r20\n"	//
		 "adc	r31,r1\n"	//
		 "rjmp	1b\n"	//
// ok, this constant to RAM
		 "3:\n"		//
		 "lpm	r0,Z+\n"	//
		 "st	X+,r0\n"	//
		 "dec	r20\n"	//
		 "brne	3b\n"	//
		 "ldi	r24,1\n"	//
		 :"=r" (ret):"z" (constants), "x" (here):);
  return ret;
}
#endif // C/ASM

#endif // EEPROM/FLASH
#endif	// have get constants
