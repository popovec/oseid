/*
    constants.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015,2017 Peter Popovec, popovec.peter@gmail.com

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
    default helper
*/
#ifndef HAVE_GET_CONSTANTS
#include <stdint.h>
#include <stdio.h>
#include "constants.h"

/* *INDENT-OFF* */
uint8_t constants[] = {
  C_CONSTANTS
//last position
  0xff
};
/* *INDENT-ON* */

uint8_t
get_constant (void *here, uint8_t id)
{
  uint8_t *t;
  uint8_t *s = constants;
  uint8_t size;

  t = (uint8_t *) here;
  for (;;)
    {
      if (*s == 0xff)
	{
	  fprintf (stderr, "Unknown constant %d\n", id);
	  return 0;
	}
      if (*s == id)
	{
	  s++;
	  size = *s;
	  s++;
	  while (size)
	    {
	      *t = *s;
	      t++;
	      s++;
	      size--;
	    }
	  return 1;
	}
      s++;
      size = *s;
      s++;
      s += size;
    }
}
#endif
