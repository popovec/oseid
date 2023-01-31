/*
    mem_device.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2023 Peter Popovec, popovec.peter@gmail.com

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
/* *INDENT-OFF* */
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

uint8_t change_counter[2];

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
  if (sizeof(change_counter) != write (f, &change_counter, sizeof(change_counter)))
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
      change_counter[0] = 0;
      change_counter[1] = 0;
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
  if (sizeof(change_counter) != read (f, change_counter, sizeof(change_counter)))
    {
      close (f);
      return 1;
    }
  initialized = 1;
  close (f);
  return 0;
}

static void update_change_counter(void){
	int c;

	if(device_init ())
		return;
	c = change_counter[0];
	c |= change_counter[1] << 8;
	c++;
	change_counter[0] = c & 0xff;
	change_counter[1] = c >> 8;
}

uint16_t device_get_change_counter(){
	return change_counter[0] | ((uint16_t)change_counter[1] << 8);
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
  update_change_counter();
  if (device_writeback ())
    return 1;

  return 0;
}
/* *INDENT-ON* */

// fill block at offset _offset_ with value 0xff
uint8_t device_write_ff(uint16_t offset, uint8_t size)
{
	uint32_t overflow, s;

	s = size ? size : 256;
	overflow = offset + s - 1;

	if (overflow > MEMSIZE)
		return 1;

	if (device_init())
		return -1;

	memset(mem + offset, 0xff, s);
	update_change_counter();

	if (device_writeback())
		return -1;

	return 0;
}

uint8_t device_format()
{

	if (device_init())
		return -1;
	memset(mem, 0xff, MEMSIZE);
	if (device_writeback())
		return -1;
	return 0;
}

uint8_t sec_device_format()
{

	if (device_init())
		return -1;

	memset(sd, 0xff, SECSIZE);

	if (device_writeback())
		return -1;
	return 0;
}
