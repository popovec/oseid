/*
    mem_device.c

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

    mem device driver for filesystem in disc file

*/
#include <stdint.h>
#include "mem_device.h"

#include <stdio.h>
#define  DPRINT(msg...) fprintf(stderr,msg)
//#define DPRINT(msg...)

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// to match simulavr for atmega128 use 64kiB - 256bytes
#define MEMSIZE 65536-256
#if MEMSIZE > 65536
#error filesyste is designed to use max 65536 bytes!
#endif

static int initialized;
static uint8_t mem[MEMSIZE];

#define SECSIZE 1024
static uint8_t sd[SECSIZE];


static uint8_t
device_writeback (void)
{
  int f;
  int size, xsize;

  f = open ("card_mem", O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
  if (f < 0)
    return 1;

  size = MEMSIZE;
  while (size)
    {
      xsize = write (f, mem, size);
      if (xsize < 0)
	{
	  close (f);
	  return 1;
	}
      size -= xsize;
    }
  if (SECSIZE != write (f, sd, SECSIZE))
    {
      close (f);
      return 1;
    }
  close (f);
  return 0;
}

static uint8_t
device_init (void)
{
  int f;
  int size, xsize;

  if (initialized)
    return 0;
  f = open ("card_mem", O_RDONLY);
  if (f < 0)
    {
      memset (mem, 0xff, MEMSIZE);
      memset (sd, 0xff, SECSIZE);
      if (device_writeback ())
	return 1;
      initialized = 1;
      return 0;
    }
  size = MEMSIZE;
  while (size)
    {
      xsize = read (f, mem, size);
      if (xsize < 0)
	{
	  close (f);
	  return 1;
	}
      size -= xsize;
    }
  if (SECSIZE != read (f, sd, SECSIZE))
    {
      close (f);
      return 1;
    }
  initialized = 1;
  close (f);
  return 0;
}

// size 0 is interpreted as 256!
uint8_t
sec_device_read_block (void *buffer, uint16_t offset, uint8_t size)
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
sec_device_write_block (void *buffer, uint16_t offset, uint8_t size)
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
