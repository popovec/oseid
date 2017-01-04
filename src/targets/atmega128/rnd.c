/*
    rnd.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015 Peter Popovec, popovec.peter@gmail.com

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
#include <string.h>

#define RND_ASSEMBLER
// WARNING do not change RND_SIZE over 32 .. (32 bytes= 256 bits = bit counter is only 8 bit long!)
#define RND_SIZE 32

static volatile uint8_t rnd_count __attribute__ ((section (".noinit")));
static uint8_t rnd[RND_SIZE] __attribute__ ((section (".noinit")));


void
rnd_init (void)
{

  rnd_count = 0;
  // ADC conversion channel:
  ADMUX = 0x5E;			//reference AVcc, measuring internal 1.1V bandgap, ADLAR=0

  // Initialize ADC, clock /128 (at 8MHz about 62 kHz)
  // for 25 ticks per conversion this generates about 2500 bits per second 
  // (with RC oscilator tuned at max, about 4500 bits per second)
  ADCSRA =
    (1 << ADEN) | (1 << ADIF) | (1 << ADIE) | (1 << ADPS2) | (1 << ADPS1) | (1
									     <<
									     ADPS0);
  // start first conversion
  ADCSRA |= (1 << ADSC);
}

#ifndef RND_ASSEMBLER

ISR (ADC_vect)
{

  uint8_t v;
  uint8_t pos;

  pos = rnd_count / 8;

  v = rnd[pos] << 1;
  v |= ADC & 1;
  rnd[pos] = v;

  if (rnd_count != 255)
    rnd_count++;
  //restart conversions

  ADCSRA |= (1 << ADSC);
}
#else
// ISR below 58 ticks inclusive call and RETI ..
ISR (ADC_vect, ISR_NAKED)
{

  asm volatile (		//
		 "push r24\n"	//
		 "push r25\n"	//
		 "push r30\n"	//
		 "push r31\n"	//
		 "in  r25,__SREG__\n"	// save sreg too
//registers saved
// load rnd position
		 "ldi r30,lo8(%[rnd])\n"	//
		 "ldi r31,hi8(%[rnd])\n"	//
// load bit position
		 "lds r24,%[pos]\n"	//
// increment bit position, do not overflow
		 "inc r24\n"	//      increment bit position
		 "brne .+2\n"	//      //clamp to 255 ..
		 "dec r24\n"	//
// save bit position
		 "sts %[pos],r24\n"	//
// calculate byte position
		 "lsr r24\n"	//
		 "lsr r24\n"	//
		 "lsr r24\n"	//
// calculate byte pointer
		 "add r30,r24\n"	//
		 "ldi r24,0\n"	//
		 "adc r31,r24\n"	//
// read values from ADC
		 "lds r24,%[adcl]\n"	// read ADCL
		 "lsr r24\n"	// ADC bit 0 into C
		 "ld  r24,Z\n"	//
		 "rol r24\n"	//insert ADC bit into random number
		 "st  Z,r24\n"	//
		 "lds r24,%[adch]\n"	// read ADCH    //is this really needed  new conversion if not forced ?
// start new adc conversion
		 "ldi r24,0xcf\n"	//
		 "sts %[adcsra],r24\n"	// ADCSRA
// restore regs
		 "out __SREG__,r25\n"	//
		 "pop r31\n"	//
		 "pop r30\n"	//
		 "pop r25\n"	//
		 "pop r24\n"	//
		 "reti\n"	//
		 ::		//
		 [rnd] "m" (rnd),	//
		 [pos] "m" (rnd_count),	//
		 [adcl] "M" (_SFR_ADDR (ADCL)),	//
		 [adch] "M" (_SFR_ADDR (ADCH)),	//
		 [adcsra] "M" (_SFR_ADDR (ADCSRA))	//
    );
}
#endif

uint8_t
rnd_get (uint8_t * r, uint8_t size)
{
  uint8_t bsize;
  if (size > 32)
    return 1;

  bsize = 8 * size;
  if (rnd_count != 255)
    {
      if (rnd_count < bsize)
	return 1;
    }
  memcpy (r, rnd, size);
  cli ();
  memcpy (rnd, rnd + size, RND_SIZE - size);
  rnd_count -= bsize;
  sei ();
  return 0;
}

void
rnd_stop ()
{
  ADCSRA = 0;
}
