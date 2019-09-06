/*
    serial.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2016 Peter Popovec, popovec.peter@gmail.com

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

    linux serial port I/O for OsEID simulator (header file)

*/

#define RET_OK 0
#define RET_FAIL 1
RESPONSECODE OpenGBP (DWORD lun, LPSTR dev_name);
RESPONSECODE WritePort (DWORD lun, DWORD length, unsigned char *Buffer);
RESPONSECODE ReadPort (DWORD lun, unsigned long *length, unsigned char *Buffer);
RESPONSECODE CloseGBP (DWORD lun);
RESPONSECODE OpenPortByName (DWORD lun, LPSTR dev_name);
RESPONSECODE ClosePort (DWORD lun);
RESPONSECODE OpenPort (DWORD lun, DWORD channel);
