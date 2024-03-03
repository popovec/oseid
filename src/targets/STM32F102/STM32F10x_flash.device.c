/*
    STM32F10x_flash.device.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2024 Peter Popovec, popovec.peter@gmail.com

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

    Driver for FLASH memory in STM32F102CB

    No HAL is used, this is pure bare metal code!

*/
#include <stdint.h>
#include "STM32F10x_flash.device.h"

#define FPEC_BASE 0x40022000
#define FPEC_RDPRT_key 0x00A5
#define FPEC_KEY1 0x45670123
#define FPEC_KEY2 0xCDEF89AB

#define FLASH_KEYR 1
#define FLASH_CR (0x10/4)
#define FLASH_SR (0xc/4)

static void flash_unlock()
{
	volatile uint32_t *fpec = (uint32_t *) (FPEC_BASE);

	fpec[FLASH_KEYR] = FPEC_KEY1;
	fpec[FLASH_KEYR] = FPEC_KEY2;
}

static void flash_lock()
{
	volatile uint32_t *fpec = (uint32_t *) (FPEC_BASE);
// disable wtite, page erase etc..
	fpec[FLASH_CR] = 0;
	// lock
	fpec[FLASH_CR] |= (1 << 7);
}

int flash_hw_erase_page(void *address)
{
	volatile uint32_t *fpec = (uint32_t *) (FPEC_BASE);

	uint32_t *a = (uint32_t *) address;
	int i = 256;
	uint32_t test = 0xffffffff;

	if ((uint8_t *) address < (uint8_t *) FLASH_MAP_BASE)
		return 1;
	if ((uint8_t *) address >= (uint8_t *) 0x08020000)
		return 1;
	//check if page must be erased...
	while (i--)
		test &= *(a++);
	if (test == 0xffffffff)
		return 0;
	a = (uint32_t *) address;
	flash_unlock();
	// page erase.. wait if BUSY
	while (fpec[FLASH_SR] & 1) ;
	// set PER
	fpec[FLASH_CR] |= (1 << 1);

	// set address (address within page)
	fpec[0x14 / 4] = (uint32_t) a;
	// start;
	fpec[FLASH_CR] |= (1 << 6);
	// wait end
	while (fpec[FLASH_SR] & 1) ;
	flash_lock();

// recheck
	//check if page is erased...
	a = (uint32_t *) address;
	test = 0xffffffff;
	i = 256;
	while (i--)
		test &= *(a++);
	if (test != 0xffffffff)
		return 2;
	return 0;
}

int flash_hw_write_data(void *dst, void *src, uint16_t size)
{
	volatile uint32_t *fpec = (uint32_t *) (FPEC_BASE);

	uint16_t *d = (uint16_t *) dst;
	uint16_t *s = (uint16_t *) src;
	uint8_t *test = (uint8_t *) dst;
	uint16_t i;

	if (test < (uint8_t *) FLASH_MAP_BASE)
		return 1;
	if (test + size > (uint8_t *) 0x08020000)
		return 1;
	flash_unlock();
	//enable write
	fpec[FLASH_CR] |= 1;

	for (i = 0; i < size / 2; i++, d++, s++) {
		if (*s == 0xffff)
			continue;
		if (*s == *d)
			continue;
		*d = *s;
		while (fpec[FLASH_SR] & 1) ;
	}
	flash_lock();

	d = (uint16_t *) dst;
	s = (uint16_t *) src;
	for (i = 0; i < size / 2; i++, d++, s++)
		if (*s != *d)
			return 2;
	return 0;
}
