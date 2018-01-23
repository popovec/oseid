/*
    serial debug module

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2017 Peter Popovec, popovec.peter@gmail.com

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

    this module is used to dump USB trafic to serial port (for debug only)

*/
#ifdef SERIAL_DEBUG
#define USART USARTC0
#include <stdint.h>
#include <avr/io.h>


#include "serial_debug.h"
void
serial_init ()
{
#if 0
  uint8_t ok = 1;

// test pin, set as input, test pull up/down, then enable output if all ok
  PORTC.DIRCLR = PIN3_bm;
  PORTC.PIN3CTRL = (3 << 3);	// totem pole pull up
  if ((PORTC.IN & 0x08) != 0x08)
    ok = 0;
  PORTC.PIN3CTRL = (2 << 3);	// totem pole pull down
  if ((PORTC.IN & 0x08) == 0x08)
    ok = 0;
// if all ok, PC3 output
  if (ok)
    PORTC.DIRSET = PIN3_bm;
#else
  // PC3 output
  PORTC.DIRSET = PIN3_bm;
#endif
  // PC2  input
  PORTC.DIRCLR = PIN2_bm;

  USARTC0_CTRLA = 0;		// no interrupts from usart
// enable transmiter only..
  USARTC0_CTRLB = USART_TXEN_bm;	// | USART_RXEN_bm;
  USARTC0_CTRLC = USART_CHSIZE_8BIT_gc;	// 8 bit no parity 1 stop bit
#if 0
  USART.BAUDCTRLA = 33;
  USART.BAUDCTRLB = 0xf0;	// 115200 (bsel=33, bscale=-1)
#else
//  USART.BAUDCTRLA = 75;
//  USART.BAUDCTRLB = 0xa0;             //921.6kbit
  USART.BAUDCTRLA = 107;	//460.8
  USART.BAUDCTRLB = 0xb0;

#endif
}

void
serial_putchar (uint8_t c)
{
//  while ((USART.STATUS & 0x20)!=0x20);
  while (!(USARTC0_STATUS & USART_DREIF_bm));
  USART.DATA = c;
}

static void
serial_print_nibble (uint8_t d)
{
  d &= 15;
  if (d > 9)
    d += 'a' - 10;
  else
    d += '0';
  serial_putchar (d);

}

void
serial_print_hex (uint8_t data)
{
  serial_putchar (' ');
  serial_print_nibble (data >> 4);
  serial_print_nibble (data);
}

void
serial_dump_block (uint8_t * data, uint16_t len)
{
  uint8_t cr = 0;

  while (len--)
    {
      serial_print_hex (*data);
      data++;
      cr++;
      if (cr == 32)
	{
	  serial_putchar (0x0a);
	  cr = 0;
	}
    }
  serial_putchar (' ');
  serial_putchar (0x0a);
}

void
serial_print_string (char *c)
{

  while (*c)
    {
      serial_putchar ((char) *c);
      c++;
    }
}
#endif //SERIAL_DEBUG
