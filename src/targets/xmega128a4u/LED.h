/*
    LED.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2017 Peter Popovec, popovec.peter@gmail.com

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

    Macro definition for LEDs

*/

// signalize reader state
// WAIT = reader wait for command from host
// BUSY = reader toggles LED (waiting wor card, null byt sending)
// RUN  = command parsing/response generating


#if 1
// led is on on idle, of on run
#define LED1_INIT()  PORTA.PIN6CTRL = PORT_OPC_TOTEM_gc; PORTA.DIRSET = PIN6_bm
#define LED1_IDLE()  PORTA.OUTSET = PIN6_bm
#define LED1_BUSY()  PORTA.OUTTGL = PIN6_bm
#define LED1_RUN()   PORTA.OUTCLR = PIN6_bm
#define LED1_OFF()   PORTA.OUTCLR = PIN6_bm
#else
#define LED1_INIT()
#define LED1_IDLE()
#define LED1_BUSY()
#define LED1_RUN()
#define LED1_OFF()
#endif

// signalize suspend/online
#if 1
#define LED2_INIT()  PORTA.PIN5CTRL = PORT_OPC_TOTEM_gc; PORTA.DIRSET = PIN5_bm
#define LED2_RUN()   PORTA.OUTSET = PIN5_bm
#define LED2_SUSPEND()   PORTA.OUTCLR = PIN5_bm
#else
#define LED2_INIT()
#define LED2_SUSPEND()
#define LED2_RUN()
#endif
