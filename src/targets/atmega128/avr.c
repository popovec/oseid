/*
    avr.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015,2016 Peter Popovec, popovec.peter@gmail.com

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

    fuses setting for atmega128

*/
#include <avr/io.h>
#include <avr/fuse.h>
#include <avr/lock.h>

FUSES =
{				//
//
// enable BOD(4V), SUT 00 = 0ms   (6CK), clock source internal RC (8MHz)
//  .low = 0x04,			// default 0xE1
// enable BOD(4V), SUT 01 = 4.1ms (6CK), clock source internal RC (8MHz)
  .low = 0x14,
// disable JTAG
  .high = 0xD9,			// default 0x99
//
// no watchdogm no atmega103 comp. mode
  .extended = 0xFF,		// default 0xFD
};

//LOCKBITS = (LB_MODE_1 & BLB0_MODE_1 & BLB1_MODE_1);
LOCKBITS = (LB_MODE_3);
