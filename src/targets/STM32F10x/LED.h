/*
    LED.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2024 Peter Popovec, popovec.peter@gmail.com

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

#ifndef SERIAL_DEBUG
void led1_on(void);
void led1_off(void);
void led1_toggle(void);
void led2_on(void);
void led2_off(void);

// led is on on idle, of on run
#define LED1_INIT()
#define LED1_BUSY()	led1_toggle()
#define LED1_IDLE()	led1_on()
#define LED1_RUN()	led1_off()
#define LED1_OFF()	led1_off()
#else
#define LED1_INIT()
#define LED1_IDLE()
#define LED1_BUSY()
#define LED1_RUN()
#define LED1_OFF()
#endif

// signalize suspend/online
#ifndef SERIAL_DEBUG
#define LED2_INIT()
#define LED2_SUSPEND()	led2_off()
#define LED2_RUN()	led2_on()
#else
#define LED2_INIT()
#define LED2_SUSPEND()
#define LED2_RUN()
#endif
