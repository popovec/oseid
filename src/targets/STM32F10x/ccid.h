/*
    ccid.h

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

    CCID subsystem, header file

*/
// shoud be called before USB initialization
void CCID_Init (void);
// should be called SetConfiguration and after resume
void CCID_notify(void);

// called if BULK endpoint receive some data from host
void CCID_Handler_from_host(uint8_t * ccid_out, uint16_t cnt);

