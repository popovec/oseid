/*
    aes.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2017 Peter Popovec, popovec.peter@gmail.com

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

    AES(128,192,256) enc/dec routines (designed for 8 bit CPU)

This version of AES is designed for minimal flash space.  The design of the
algorithm does not make the speed as important for this code. Key is
expanded in RAM, SBOX and INV SBOX is calculated in RAM.
*/

void aes_run (uint8_t * data, uint8_t * key, uint8_t keysize, uint8_t mode);
