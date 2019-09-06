/*
    rnd.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2017-2019 Peter Popovec, popovec.peter@gmail.com

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

    simulavr random generator (need patched simulavr!)

*/
#include <stdint.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <string.h>
#include "rnd.h"


void
rnd_init (void)
{
}

static void
rnd_setup ()
{
  asm volatile (			//
		 "ldi r24,3\n"		// RND function
		 "sts 0xff,r24\n"	// OsEID fifo function
    );
}

static uint8_t
get_rnd ()
{
  register uint8_t ret asm ("r24");
  asm volatile (			//
		 "lds r24,0xfe\n"	// OsEID fifo
		 :"=r" (ret));
  return ret;

}

void
rnd_get (uint8_t * r, uint8_t size)
{
  while (size--)
    {
      rnd_setup ();
      *r = get_rnd ();
      r++;
    }
}

void
rnd_stop ()
{
}
