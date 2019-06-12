/*
    des.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2017,2019 Peter Popovec, popovec.peter@gmail.com

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

    DES cipher header file

*/
#ifndef _DES_H_
#define _DES_H_

#define DES_ENCRYPTION_MODE 0
#define DES_DECRYPTION_MODE 3
#define DES_3DES            0x0c

void des_run (uint8_t * data,  uint8_t *key, uint8_t mode);
// transform 7 bytes of key to 8 bytes (with parity bits)
void des_56to64 (uint8_t * key);
#endif
