/*
    mem_device.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2024 Peter Popovec, popovec.peter@gmail.com

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

    mem device driver

*/
#include <stdint.h>
#include <string.h>
#include "mem_device.h"
#include "flash_cow_dev.h"

#if SEC_MEM_SIZE != 1024
#error please recheck SEC_MEM_SIZE
#endif

#define DEV_SIZE ((FLASH_PAGE_COUNT - 2) * 1024)
// size 0 is interpreted as 256!
uint8_t sec_device_read_block(void *buffer, uint16_t offset, uint8_t size)
{
	uint16_t overflow, s;

	s = size ? size : 256;
	overflow = offset + s - 1;
	if (overflow > SEC_MEM_SIZE)
		return 1;
	return flash_device_read_block(buffer, offset, s);
}

// size 0 is interpreted as 256!
uint8_t sec_device_write_block(void *buffer, uint16_t offset, uint8_t size)
{
	uint16_t overflow, s;

	s = size ? size : 256;
	overflow = offset + s - 1;
	if (overflow > SEC_MEM_SIZE)
		return 1;
	return flash_device_write_block(buffer, offset, s);
}

uint8_t sec_device_format()
{
	uint8_t ffblock[1024];
	memset(ffblock, 0xff, sizeof(ffblock));

	return flash_device_write_block(ffblock, 0, 1024);
}

uint16_t device_get_change_counter()
{
	return flash_device_get_changecounter();
}

//size 0 is interpreted as 256 !
uint8_t device_read_block(void *buffer, uint16_t offset, uint8_t size)
{
	uint32_t overflow, s;

	s = size ? size : 256;
	overflow = offset + s - 1;
	if (overflow > DEV_SIZE)
		return 1;
	return flash_device_read_block(buffer, offset + 1024, s);
}

//size 0 is interpreted as 256 !
uint8_t device_write_block(void *buffer, uint16_t offset, uint8_t size)
{
	uint32_t overflow, s;
	s = size ? size : 256;

	overflow = offset + s - 1;
	if (overflow > 65536)
		return 1;
	return flash_device_write_block(buffer, offset + 1024, s);
}

//size 0 is interpreted as 256 !
uint8_t device_write_ff(uint16_t offset, uint8_t size)
{
	uint8_t ffblock[256];
	uint32_t overflow, s;

	s = size ? size : 256;
	overflow = offset + s - 1;
	if (overflow > DEV_SIZE)
		return 1;
	memset(ffblock, 0xff, sizeof(ffblock));
	return flash_device_write_block(ffblock, offset + 1024, s);
}

uint8_t device_format()
{
	uint8_t ffblock[1024];

	memset(ffblock, 0xff, sizeof(ffblock));
	for (int i = 0; i < (FLASH_PAGE_COUNT - 2); i++)
		if (flash_device_write_block(ffblock, 1024 + i * 1024, 1024))
			return 1;
	return 0;
}
