/*
    rnd.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2024 Peter Popovec, popovec.peter@gmail.com

    based on OsEID project, file targets/xmega128a4u/rnd.c
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

    STM32F102 random number generator (from temperature sensor)
    only bit 0 from ADC conversion is used

*/
#include <stdint.h>
#include "rnd.h"

#define ADC1_BASE       0x40012400U
void rnd_init(void)
{
	volatile uint32_t *address = (uint32_t *) (ADC1_BASE);
	// 239.5 cycles (20uS at 12MHz ADC clock)
	address[0x0c / 4] = (7 << 18);
	// ADC channel TEMP
	address[2] = (1 << 23);
	// powert on
	address[2] |= 1;
}

static uint32_t entropy_crc(uint32_t crc, uint8_t n)
{
	int j;
	uint32_t mask;

	crc = crc ^ n;
	for (j = 7; j >= 0; j--) {
		mask = -(crc & 1);
		crc = (crc >> 1) ^ (0xEDB88320 & mask);
	}
	return ~crc;
}

void rnd_get(uint8_t * r, uint8_t size)
{
	static uint32_t __attribute__((section(".noinit"))) random;
	volatile uint32_t *address = (uint32_t *) (ADC1_BASE);
	uint32_t val;
	int c;
	uint8_t b = 0;

	while (size--) {
		for (c = 0; c < 8; c++) {
			// start
			address[2] |= 1;
			// wait conversion
			while ((address[0] & (1 << 1)) == 0) ;
			// lowest bit only
			val = address[0x4c / 4];
			b <<= 1;
			b |= (val & 1);
		}
		random = entropy_crc(random, b);
		*(r++) = random & 0xff;
		random >>= 7;
	}
}
