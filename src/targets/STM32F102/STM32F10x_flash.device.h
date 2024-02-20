/*
    STM32F10x_flash.device.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2024 Peter Popovec, popovec.peter@gmail.com

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

    Driver for FLASH memory in STM32F102CB

    No HAL is used, this is pure bare metal code!

*/

// erase page at address "address"
// return 0 if OK
int __attribute__((warn_unused_result)) flash_hw_erase_page(void *address);
// return 0 if OK
// write data to flash
int __attribute__((warn_unused_result)) flash_hw_write_data(void *dst, void *src, uint16_t size);
