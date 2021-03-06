/*
    avr_os.h

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

    CPU initialization and fuses setting for xmega128a4u
    Special: this part of code is responsible for restart of main
    (main must be restarted if card is powered down or on USB suspend etc.)

*/

// this can be called from high/middle level irq or main
void CPU_do_sleep ();
void CPU_do_restart_main ();
// turn CPU into IDLE sleep mode, interrupt is enabled
void CPU_idle ();
