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

    mem device driver for filesystem in disc file

*/
#include <stdint.h>
#include "mem_device.h"

#include <stdio.h>
#define  DPRINT(msg...) fprintf(stderr,msg)
//#define DPRINT(msg...)

#include <string.h>

//Warning maximum size is 2^16-256, otherwise overflow is not checked!
#define MEMSIZE 32767+16384
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

// read max 256 bytes from flash/eeprom into buffer from memory offset 
// signalize error by non zero return value
uint8_t
device_read_block (void *buffer, uint16_t offset, uint8_t size)
{

  if (device_init ())
    return 1;

  if (size == 0)
    {
      if ((uint32_t) offset + 256 > MEMSIZE)
	{
	  DPRINT ("%s - out of memory\n", __FUNCTION__);
	  return 1;
	}
      memcpy (buffer, mem + offset, 256);
    }
  else
    {
      if ((uint32_t) offset + size > MEMSIZE)
	{
	  DPRINT ("%s - out of memory\n", __FUNCTION__);
	  return 1;
	}
      memcpy (buffer, mem + offset, size);
    }
  return 0;
}

uint8_t
device_write_block (void *buffer, uint16_t offset, uint8_t size)
{
  if (device_init ())
    return 1;

  if (size == 0)
    {
      if ((uint32_t) offset + 256 > MEMSIZE)
	{
	  DPRINT ("%s - out of memory\n", __FUNCTION__);
	  return 1;
	}
      memcpy (mem + offset, buffer, 256);
    }
  else
    {
      if ((uint32_t) offset + size > MEMSIZE)
	{
	  DPRINT ("%s - out of memory\n", __FUNCTION__);
	  return 1;
	}
      memcpy (mem + offset, buffer, size);
    }
  if (device_writeback ())
    return 1;

  return 0;
}

// fill block at offset _offset_ with value 0xff of maximal length _size_
// return number of filled bytes (-1 on error)
int16_t
device_write_ff (uint16_t offset, uint16_t size)
{
  if (device_init ())
    return -1;

  if ((uint32_t) offset + size > MEMSIZE)
    {
      DPRINT ("%s - out of memory\n", __FUNCTION__);
      return -1;
    }
  memset (mem + offset, 0xff, size);

  if (device_writeback ())
    return -1;

  return size;
}

uint8_t
sec_device_read_block (void *buffer, uint8_t offset, uint8_t size)
{
  uint16_t overflow = size + offset;

  if (device_init ())
    return 1;

  if (overflow > SECSIZE)
    return 1;
  memcpy (buffer, sd + offset, size);
  return 0;
}

uint8_t
sec_device_write_block (void *buffer, uint8_t offset, uint8_t size)
{
  uint16_t overflow = size + offset;

  if (device_init ())
    return 1;

  if (overflow > SECSIZE)
    return 1;
  memcpy (sd + offset, buffer, size);

  if (device_writeback ())
    return 1;

  return 0;
}
