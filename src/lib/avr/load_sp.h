/*
    load_sp.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015,2016,2018 Peter Popovec, popovec.peter@gmail.com

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

    Atmega/Xmega assembler routines - atomic SP load
*/

/////////////////////////////////////////////////////////////

/*
There is a diference in atmega and xmega in I flag handling.
atmega:
-------
 cli
 in     r24,  0x3f
 ori	r24,  0x80
 out    0x3f, r24 // irq not enabled
 nop              // irq enabled

xmega:
------
 cli
 in     r24,  0x3f
 ori	r24,  0x80
 out    0x3f, r24 // irq enabled
 nop              // irq enabled

XMEGA does not need cli before changing SP, because writing
to SPL automaticaly disables interrupts for 4 cycles or until the
next IO memory write

Update Wed Oct  3 12:37:28 CEST 2018

There is new microchip docs available for example for atmega 328p with some
changes in stack pointer registers description.  Especialy, there is mention
about related link to "Accessing 16-bit Timer/Counter Registers" in this
section.

This related link is not relevant for SPL/SPH update, SPH is updated
directly, not over TEMP reg.


*/

// if ISR_ENABLE_FORCE is defined, interrupts are enabled, otherwise
// previous state of I flag is restored
// if ISR_DISABLED is defined, stack pointer is changed without CLI
#ifdef ISR_DISABLED
// it is assumed, interrupts are always disabled
.macro  LOAD_SP tmp   RL RH
        out     0x3d, \RL
        out     0x3e, \RH
.endm
.macro  LOAD_SP_SREG   tmp   RL RH
        out     0x3d, \RL
        out     0x3e, \RH
.endm
#else
#ifndef ISR_ENABLE_FORCE
#if __AVR_XMEGA__ == 1
// reenable old state I flag 0 or 1
// xmega code
.macro  LOAD_SP tmp   RL RH
        out     0x3d, \RL
        out     0x3e, \RH
.endm
.macro  LOAD_SP_SREG   tmp   RL RH
        out     0x3d, \RL
        out     0x3e, \RH
.endm
#else 
// atmega code
.macro  LOAD_SP tmp   RL RH
        in      \tmp,0x3f
        cli
        out     0x3d, \RL
        out     0x3f, \tmp
        out     0x3e, \RH
.endm
.macro  LOAD_SP_SREG   tmp   RL RH
        cli
        out     0x3d, \RL
        out     0x3f, \tmp
        out     0x3e, \RH
.endm
#endif
#else // ISR_ENABLE_FORCE
#if __AVR_XMEGA__ == 1
// xmega code ISR_ENABLE_FORCE
#warning ISR_ENABLE_FORCE is not recomended for xmega!
.macro  LOAD_SP tmp   RL RH
        out     0x3d, \RL
        out     0x3e, \RH
        sei
.endm
.macro  LOAD_SP_SREG   tmp   RL RH
        out     0x3d, \RL
        out     0x3e, \RH
        sei
.endm
#else
// atmega code ISR_ENABLE_FORCE
.macro  LOAD_SP tmp   RL RH
        cli
        out     0x3d, \RL
        sei
        out     0x3e, \RH
.endm
.macro  LOAD_SP_SREG   tmp   RL RH
        cli
        out     0x3d, \RL
        sei
        out     0x3e, \RH
.endm
#endif                            
#endif // ISR_ENABLE_FORCE
#endif // ISR_DISABLED
