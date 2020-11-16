/*
    rnd.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2020 Peter Popovec, popovec.peter@gmail.com

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

    AVR128DA random number generator (from temperature sensor)
    only bit 0 from ADC conversion is used

*/
#include <stdint.h>
#include <stddef.h>

#include "rnd.h"

#define l_VREF_ADC0REF 0xa0
#define l_ADC0 0x600
void
rnd_init (void)
{
// define register position,  AVR128DA is new device, lot of people does not have gcc include file for this CPU
  volatile uint8_t *adc_base = (uint8_t *) 0x600;
  volatile uint8_t *vref_base = (uint8_t *) 0xa0;

// use VDD - minimal VDD for band gap is 2.5V, but card is able to run at 1.8V
  vref_base[0] = 0x85;

// single ended, right adjusted conversion, enable ADC /CTRLA/
  adc_base[0] = 1;		//
// AVR is running at 24MHz internal oscilator, but tuned to max.. (about 27MHz)
// clock divisor 24 (27) MHz/ 256 = about 93 (105) kHz /CTRLC/
  adc_base[2] = 0x0d;
// mux to temperature sensor /MUXPOS/
  adc_base[8] = 0x42;
}

void
rnd_get (uint8_t * r, uint8_t size)
{
  uint8_t v;
  uint8_t pos = 0, b;

  volatile uint8_t *adc_base = (uint8_t *) 0x600;

  do
    {
      v = r[pos];
      for (b = 0; b < 8; b++)
	{
	  //start conversion (ADC0_COMMAND = 1)
	  adc_base[10] = 1;
	  // wait for conversion
	  while (adc_base[10] & 1);
#pragma GCC diagnostic ignored "-Wuninitialized"
	  v <<= 1;
	  v |= adc_base[16] & 1;	// 1st read low part of result
	  adc_base[17];		// read 2nd part
	}
      r[pos] ^= v;
      pos++;
    }
  while (--size);
}
