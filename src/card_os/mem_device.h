/*
    mem_device.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2023 Peter Popovec, popovec.peter@gmail.com

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

    non volatile memory driver,  header file

*/

/****************************************************

 normal memory for files - data do not change often

*****************************************************/
// for size = 0 size is interpreted as 256
// on error 1 is returned, 0 = no error

uint8_t device_read_block (void *buffer, uint16_t offset, uint8_t size);
uint8_t device_write_block (void *buffer, uint16_t offset, uint8_t size);
uint8_t device_write_ff (uint16_t offset, uint8_t size);

// clear memory device
uint8_t device_format(void);

/****************************************************************

This memory is used for security data that may change more often
(etc couter of unsucessful login ..)

****************************************************************/
// offset in range 0-1023
// size 0 = 256 bytes
uint8_t sec_device_read_block(void *buffer, uint16_t offset, uint8_t size);
uint8_t sec_device_write_block(void *buffer, uint16_t offset, uint8_t size);
// clear sec memory
uint8_t sec_device_format(void);

/****************************************************************

every change in the card's file system is tracked by a change counter
This function is used to read the change counter value.

****************************************************************/
uint16_t device_get_change_counter(void);
