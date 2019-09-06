/*
    rnd.c

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

    xmega (TEMP code)

*/
#include <stdint.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <stddef.h>
#include "rnd.h"
//#include <string.h>


static uint8_t
GetCalibration (uint8_t pos)
{
  uint8_t ret;

  NVM_CMD = NVM_CMD_READ_CALIB_ROW_gc;
  ret = pgm_read_byte (pos);
  NVM_CMD = NVM_CMD_NO_OPERATION_gc;

  return ret;
}




void
rnd_init (void)
{
  ADCA.CTRLA = ADC_ENABLE_bm;
  ADCA.CALL = GetCalibration (offsetof (NVM_PROD_SIGNATURES_t, ADCACAL0));
  ADCA.CALH = GetCalibration (offsetof (NVM_PROD_SIGNATURES_t, ADCACAL1));

  ADCA.PRESCALER = ADC_PRESCALER_DIV32_gc;
  ADCA.REFCTRL = ADC_REFSEL_INT1V_gc | ADC_TEMPREF_bm;	// ADC_REFSEL_INT1V_gc | ADC_BANDGAP_bm | ADC_TEMPREF_bm;
  ADCA.CTRLB = ADC_RESOLUTION_12BIT_gc;	//ADC_CONVMODE_bm | ADC_FREERUN_bm
  ADCA.CH0.CTRL = ADC_CH_INPUTMODE_INTERNAL_gc;	// | ADC_CH_GAIN_1X_gc;
  ADCA.CH0.MUXCTRL = ADC_CH_MUXINT_TEMP_gc;;
}

void
rnd_get (uint8_t * r, uint8_t size)
{
  uint8_t v;
  uint8_t pos = 0, b;

  do
    {
      v = r[pos];
      for (b = 0; b < 8; b++)
	{
	  //start conversion
	  ADCA.CH0.CTRL |= ADC_CH_START_bm;
	  // wait for conversion
	  while ((ADCA.CH0.INTFLAGS & ADC_CH_CHIF_bm) == 0);
	  ADCA.CH0.INTFLAGS = ADC_CH_CHIF_bm;
#pragma GCC diagnostic ignored "-Wuninitialized"
	  v <<= 1;
	  v |= (ADCA.CH0.RESL & 1);
	}
      r[pos] ^= v;
      pos++;
    }
  while (--size);
}
