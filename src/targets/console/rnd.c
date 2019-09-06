/*
    rnd.c

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

    // Emulator on linux, get random from /dev/urandom

*/
#include <stdint.h>
#include <stdio.h>
#include "rnd.h"

void
rnd_init (void)
{
}

void
rnd_get (uint8_t * rnd, uint8_t size)
{
  FILE *f;
  uint16_t s;
  uint16_t xsize = size;

  if (size == 0)
    xsize = 256;

  for (;;)
    {
      f = fopen ("/dev/urandom", "r");
      if (!f)
	continue;

      s = fread (rnd, sizeof (uint8_t), xsize, f);

      fclose (f);


      if (s == xsize)
	break;
    }
}
