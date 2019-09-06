/*
    rnd.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015, 2017-2019 Peter Popovec, popovec.peter@gmail.com

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

    Atmega128 random generator

*/
#include <stdint.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include "des.h"
#include "rnd.h"

void
rnd_init (void)
{
  // ADC conversion channel:
  ADMUX = 0x5E;			//reference AVcc, measuring internal 1.1V bandgap, ADLAR=0

  // Initialize ADC, clock /64 ( RC oscilator run at ~13.5 MHz, /64 = ~210kHz
  ADCSRA = (1 << ADEN) | (1 << ADSC) | (1 << ADFR) | (1 << ADPS2) | (1 << ADPS1);	// | (1 <<  ADPS0);
}

static void
rnd_get_16 (uint8_t * r)
{
  uint8_t i, d, j;

  for (j = 0; j < 16; j++)
    {
      for (i = 0; i < 8; i++)
	{
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
	  d <<= 1;
	  d |= ADCL & 1;
	  ADCH;			// ADC data register is not updated until ADCH is read!
	  ADCSRA |= (1 << ADIF);	// clear interrupt flag
	  while (!(ADCSRA & (1 << ADIF)));	// wait for conversion end
	}
      *r = d;
      r++;
    }
}

// size 0 -> 256 bytes
void
rnd_get (uint8_t * r, uint8_t size)
{
  uint8_t data[16], *d;
  uint8_t k = 0;

  do
    {
      if (k == 0)
	{
	  rnd_get_16 (data);
	  des_run (data, data + 8, 0);
	  d = data;
	  k = 8;
	}
      *r = *d ^ *(d + 8);
      d++;
      r++;
      k--;
    }
  while (--size);
}
