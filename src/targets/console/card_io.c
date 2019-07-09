/*
    card_io.c

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


    input/output subsystem for OsEID - debug console version

*/

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <setjmp.h>
#include "card_io.h"



void
card_io_init (void)
{
  printf ("ATR\n");
}

uint8_t
card_io_rx (uint8_t * data, uint8_t len)
{
  ssize_t l;
  uint16_t xlen = len;
  char *line = NULL;
  size_t ilen = 0;
  char *endptr;
  long val;

  uint8_t count = 0;

  fflush (stdin);
  for (;;)
    {
      printf ("> ");

      l = getline (&line, &ilen, stdin);
      if (line == NULL)
	continue;

      if (l >= 4)
	if (0 == strncmp ("quit", line, 4) || 0 == strncmp ("QUIT", line, 4))
	  exit (0);

      if (l >= 5)
	if (0 == strncmp ("reset", line, 5)
	    || 0 == strncmp ("RESET", line, 5))
	  {
	    //free (line);
	    raise (SIGINT);
	    // wait for signal proccess
	    for (;;);
	  }
      if (l > 0)
	break;
      endptr = line;
      free (line);
    }

  endptr = line;
  for (; *endptr && xlen; xlen--)
    {
      val = strtol (endptr, &endptr, 16);
      val &= 0xff;
      data[count++] = (uint8_t) val;
      while (isspace (*endptr) && *endptr)
	endptr++;
    }
  free (line);
  return count;
}

// for len = 0 transmit 256 bytes
uint8_t
card_io_tx (uint8_t * data, uint8_t len)
{
  printf ("< ");
  do
    {
      printf ("%02x ", *data++);
    }
  while (--len);
  printf ("\n");

  return 0;
}

void
card_io_start_null (void)
{
  printf ("card_io_start_null\n");

}

void
card_io_stop_null (void)
{
  printf ("card_io_stop_null\n");
}
