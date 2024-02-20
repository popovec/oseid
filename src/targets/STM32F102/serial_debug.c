/*
    serial debug module

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2017-2024 Peter Popovec, popovec.peter@gmail.com

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

    this module is used to dump USB traffic to serial port (for debug only)

*/
#ifdef SERIAL_DEBUG
#include <stdint.h>

#include "serial_debug.h"

#define USART1_BASE	0x40013800U
#define GPIOA_BASE      0x40010800U
#define RCC_BASE        0x40021000U

void serial_init()
{
	volatile uint32_t *gpio = (uint32_t *) USART1_BASE;
	volatile uint32_t *usart = (uint32_t *) USART1_BASE;
	volatile uint32_t *rcc = (uint32_t *) (RCC_BASE);

// enable USART1 clock (APB2 bus)
	rcc[0x18 / 4] |= (1 << 14);

// enable GPIOA clock (APB2 bus)
	rcc[0x18 / 4] |= 4;

// enable usart, enable TX
	usart[3] = (1 << 13) | (1 << 3);	// CTRL1

// clock PCLK2 <- from APB2 prescaler[1] <- AHB prescaler [1] <- PLL [72 MHz]
	usart[2] = 144;		// 500k

// overwrite GPIO pin function to alternate fcion - USART
	gpio = (uint32_t *) GPIOA_BASE;
	gpio[4 / 4] &= 0xFFFFFF0F;
//      gpio[4 / 4] |= 0x0010;       // PA9 push pull, 10MHz
	gpio[4 / 4] |= 0x00A0;	// alternate ..  USART 1 TX
}

void serial_putchar(uint8_t b)
{
	volatile uint8_t *usart = (uint8_t *) USART1_BASE;
	uint16_t val;
	volatile uint16_t *usart16 = (uint16_t *) USART1_BASE;
	usart16 = (uint16_t *) USART1_BASE;

	for (;;) {
		val = *usart16;	// USART_STS
		if (val & 0x80)	// TDE (transmit register empty)
			break;
	}
	usart = (uint8_t *) USART1_BASE;
	usart[4] = b;
}

static void serial_print_nibble(uint8_t d)
{
	d &= 15;
	if (d > 9)
		d += 'a' - 10;
	else
		d += '0';
	serial_putchar(d);

}

void serial_print_hex(uint8_t data)
{
	serial_putchar(' ');
	serial_print_nibble(data >> 4);
	serial_print_nibble(data);
}

void serial_print_hex16(uint16_t data)
{
	serial_print_nibble(data >> 12);
	serial_print_nibble(data >> 8);
	serial_print_nibble(data >> 4);
	serial_print_nibble(data);
}

void serial_dump_block(uint8_t * data, uint16_t len)
{
	uint8_t cr = 0;

	while (len--) {
		serial_print_hex(*data);
		data++;
		cr++;
		if (cr == 32) {
			serial_putchar(0x0a);
			cr = 0;
		}
	}
	serial_putchar(' ');
	serial_putchar(0x0a);
}

void serial_print_string(char *c)
{

	while (*c) {
		serial_putchar((char)*c);
		c++;
	}
}
#endif				//SERIAL_DEBUG
