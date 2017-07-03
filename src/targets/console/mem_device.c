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

    mem device driver for filesystem in disc file

*/
#include <stdint.h>
#include "mem_device.h"

#include <stdio.h>
#define  DPRINT(msg...) fprintf(stderr,msg)
//#define DPRINT(msg...)

#include <string.h>


#define MEMSIZE 32767+16384
#if MEMSIZE > 65536
#error filesyste is designed to use max 65536 bytes!
#endif

static int initialized;
static uint8_t mem[MEMSIZE];

#define SECSIZE 256
static uint8_t sd[SECSIZE];


static uint8_t
device_writeback ()
{
  FILE *f;

  f = fopen ("card_mem", "w");
  if (!f)
    return 1;
  if (MEMSIZE != fwrite (mem, sizeof (uint8_t), MEMSIZE, f))
    {
      fclose (f);
      return 1;
    }
  if (SECSIZE != fwrite (sd, sizeof (uint8_t), SECSIZE, f))
    {
      fclose (f);
      return 1;
    }
  fclose (f);
  return 0;
}

static uint8_t
device_init ()
{
  FILE *f;

  if (initialized)
    return 0;
  f = fopen ("card_mem", "r");
  if (!f)
    {
      memset (mem, 0xff, MEMSIZE);
      memset (sd, 0xff, SECSIZE);
      if (device_writeback ())
	return 1;
      initialized = 1;
      return 0;
    }
  if (MEMSIZE != fread (mem, sizeof (uint8_t), MEMSIZE, f))
    {
      fclose (f);
      return 1;
    }
  if (SECSIZE != fread (sd, sizeof (uint8_t), SECSIZE, f))
    {
      fclose (f);
      return 1;
    }
  initialized = 1;
  return 0;
}

// size 0 is interpreted as 256!
uint8_t
sec_device_read_block (void *buffer, uint8_t offset, uint8_t size)
{
  uint16_t overflow, s;

  s = size ? size : 256;
  overflow = offset + s - 1;

  if (overflow > SECSIZE)
    return 1;

  if (device_init ())
    return 1;

  memcpy (buffer, sd + offset, s);
  return 0;
}

// size 0 is interpreted as 256!
uint8_t
sec_device_write_block (void *buffer, uint8_t offset, uint8_t size)
{
  uint16_t overflow, s;

  s = size ? size : 256;
  overflow = offset + s - 1;

  if (overflow > SECSIZE)
    return 1;

  if (device_init ())
    return 1;

  memcpy (sd + offset, buffer, s);

  if (device_writeback ())
    return 1;

  return 0;
}

// size 0 is interpreted as 256!
uint8_t
device_read_block (void *buffer, uint16_t offset, uint8_t size)
{
  uint32_t overflow, s;

  s = size ? size : 256;
  overflow = offset + s - 1;

  if (overflow > MEMSIZE)
    return 1;

  if (device_init ())
    return 1;

  memcpy (buffer, mem + offset, s);

  return 0;
}

// size 0 is interpreted as 256!
uint8_t
device_write_block (void *buffer, uint16_t offset, uint8_t size)
{
  uint32_t overflow, s;

  s = size ? size : 256;
  overflow = offset + s - 1;

  if (overflow > MEMSIZE)
    return 1;

  if (device_init ())
    return 1;

  memcpy (mem + offset, buffer, s);

  if (device_writeback ())
    return 1;

  return 0;
}

// fill block at offset _offset_ with value 0xff of maximal length _size_
// return number of filled bytes (-1 on error)
int16_t
device_write_ff (uint16_t offset, uint8_t size_in)
{
  uint32_t s;
  uint16_t size = size_in;

  if (size_in == 0)
    size = 256;

  if (device_init ())
    return -1;

#if MEMSIZE != 65536
  if (offset >= MEMSIZE)
    return -1;
#endif

  s = MEMSIZE - (uint32_t) offset;
  if (s > size)
    s = size;

  memset (mem + offset, 0xff, s);

  if (device_writeback ())
    return -1;

  return s;
}
