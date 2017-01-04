/*
    constants.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015 Peter Popovec, popovec.peter@gmail.com

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
    xmega helper

*/
#ifdef HAVE_GET_CONSTANTS
#include <stdint.h>
#include <avr/pgmspace.h>
#include "constants.h"

/* *INDENT-OFF* */
const uint8_t constants[] PROGMEM  = {
  C_CONSTANTS
//last position
  0xff
};
/* *INDENT-ON* */

uint8_t
get_constant (void *here, uint8_t id)
{
  uint8_t *t;
  uint8_t *s = (uint8_t *) constants;
  uint8_t size, val;

  t = (uint8_t *) here;

  for (;;)
    {
      val = pgm_read_byte (s);
      if (val == 0xff)
	return 0;
      s++;
      size = pgm_read_byte (s);
      s++;
      if (val == id)
	{
	  while (size)
	    {
	      *t = pgm_read_byte (s);
	      t++;
	      s++;
	      size--;
	    }
	  return 1;
	}
      s += size;
    }
}
#endif