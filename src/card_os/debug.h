/*
    debug.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2019-2021 Peter Popovec, popovec.peter@gmail.com

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

    function and constants for debugging OsEID - (simulated in PC)

*/


// aditional debug
//#define RSA_GEN_DEBUG 1

/*

 env variable OsEID_DEBUG is used to controll debug messages

 variable is bit mapped, bits 0,1,2,3 are reserved for simulated reader and pcscd
 
  1 - run pcscd with -d switch
  2 - enable debug from OsEID simulated reader (ifHandler)
  4 - RFU
  8 - RFU
 16 - low level input output - transport from reader to card and back, inclusive
      messages about NULL byte sending (to query more time for operation)

 below in #define codes for debug card internal functions 

*/


#ifdef DEBUG_IFH
#define DEBUG_V 2
#endif

#ifdef DEBUG_FS
#define DEBUG_V 32
#endif

#ifdef DEBUG_MyEID_EMU
#define DEBUG_V 256
#endif

#ifdef DEBUG_ISO7816
#define DEBUG_V 128
#endif

#ifdef DEBUG_BN_MATH
#define DEBUG_V 8192
#endif

#ifdef DEBUG_RSA
#define DEBUG_V 16384
#endif

#ifdef DEBUG_ECC
#define DEBUG_V 32768
#endif


#if !(defined __AVR__) && defined (DEBUG_V)
#include <stdlib.h>
#include <stdio.h>
#define DPRINT(msg...) {char *env_atr = getenv ("OsEID_DEBUG"); if(env_atr){if(atoi(env_atr)& DEBUG_V){fprintf(stderr,msg);}}}

#include <stdint.h>
// to print hexadecimal data
static void __attribute__((unused)) HPRINT (char *m, void *d, int size)
{
  uint8_t *data = (uint8_t *) d;

  char *env_atr = getenv ("OsEID_DEBUG");
  if (env_atr)
    {
      if (atoi (env_atr) & DEBUG_V)
	{

	  int j;
	  fprintf (stderr, "%s", m);

	  for (j = 0; j < size; j++)
	    {
	      if (j % 32 == 0 && j != 0)
		fprintf (stderr, "\n");
	      fprintf (stderr, "%02X ", *(data++));
	    }
	  fprintf (stderr, "\n");
	}
    }
}
// to print numbers (hexadecimal)
static void __attribute__((unused)) NPRINT (char *m, void *d, int size)
{
  uint8_t *data = (uint8_t *) d;

  char *env_atr = getenv ("OsEID_DEBUG");
  if (env_atr)
    {
      if (atoi (env_atr) & DEBUG_V)
	{
	  fprintf (stderr, "%s 0x", m);
	  data +=size;
          while(size--)
            fprintf (stderr, "%02X", *(--data));
	  fprintf (stderr, "\n");
	}
    }
}
#else
#define DPRINT(msg...)
#define HPRINT(msg, d, s)
#define NPRINT(msg, d, s)
#endif
