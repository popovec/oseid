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

#define DEBUG_IFH
#include "debug.h"

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <setjmp.h>
#include "card_io.h"

uint8_t protocol;

void
card_io_init (void)
{
  fprintf (stdout, "< 3b:f5:18:00:02:80:01:4f:73:45:49:44:1a\n");
  DPRINT ("RESET, sending ATR, protocol reset to T0\n");
  protocol = 0;
}

uint16_t
card_io_rx (uint8_t * data, uint16_t len)
{
  ssize_t l;
  uint16_t xlen = len;
  char *line = NULL;
  size_t ilen = 0;
  char *endptr;
  long val;

  uint16_t count = 0;

  fflush (stdin);
  for (;;)
    {
//     printf ("> ");

      l = getline (&line, &ilen, stdin);
      if (line == NULL)
	continue;

      if (l == 4)
	{
	  if (0 == strncmp ("quit", line, 4)
	      || 0 == strncmp ("QUIT", line, 4))
	    exit (0);
	  if (0 == strncmp ("> D", line, 3))
	    {
	      DPRINT ("Power DOWN\n");
	      free (line);
	      line = NULL;
	      ilen = 0;
	      continue;
	    }
	  if (0 == strncmp ("> P", line, 3))
	    {
	      DPRINT ("Power UP\n");
	      free (line);
	      line = NULL;
	      ilen = 0;
	      fflush (stdin);
	      //free (line);
	      raise (SIGINT);
	      // wait for signal proccess
	      for (;;);

//              continue;
	    }
	  if (0 == strncmp ("> R", line, 3))
	    {
	      DPRINT ("RESET\n");
	      free (line);
	      line = NULL;
	      ilen = 0;
	      fflush (stdin);
	      //free (line);
	      raise (SIGINT);
	      // wait for signal proccess
	      for (;;);

//              continue;
	    }
	  if (0 == strncmp ("> 0", line, 3))
	    {
	      // TODO PTS allowed only after ATR
	      protocol = 0;
	      DPRINT ("New protocol T%d\n", protocol);
	      free (line);
	      line = NULL;
	      ilen = 0;
	      fprintf (stdout, "< 0\n");
	      continue;
	    }
	  if (0 == strncmp ("> 1", line, 3))
	    {
	      // TODO PTS allowed only after ATR
	      protocol = 1;
	      DPRINT ("New protocol T%d\n", protocol);
	      free (line);
	      line = NULL;
	      ilen = 0;
	      fprintf (stdout, "< 1\n");
	      continue;
	    }
	}

      if (l >= 5)
	if (0 == strncmp ("reset", line, 5)
	    || 0 == strncmp ("RESET", line, 5))
	  {
	    DPRINT ("received reset from reader\n");
	    fflush (stdin);
	    //free (line);
	    raise (SIGINT);
	    // wait for signal proccess
	    for (;;);
	  }
      if (l > 0)
	break;
      endptr = line;
      free (line);
      line = NULL;
      ilen = 0;
    }
  DPRINT ("parsing APDU hex string");
  endptr = line + 1;
  for (; *endptr && xlen; xlen--)
    {
      val = strtol (endptr, &endptr, 16);
      val &= 0xff;
      data[count++] = (uint8_t) val;
      while (isspace (*endptr) && *endptr)
	endptr++;
    }
  DPRINT (" %d bytes\n", count);

  free (line);

  return count | (protocol << 15);
}

// for len = 0 transmit 65536 bytes
uint8_t
card_io_tx (uint8_t * data, uint16_t len)
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
