/*
    serial.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2017-2021 Peter Popovec, popovec.peter@gmail.com

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

    this module is used to dump USB trafic to serial port (for debug only)
    header file

*/
#ifdef SERIAL_DEBUG

void serial_init ();
void serial_print_string (char *c);
void serial_dump_block (uint8_t * data, uint16_t len);
void serial_putchar (uint8_t c);
void serial_print_hex (uint8_t data);
#define DEBUG_init() serial_init ()
#define DEBUG_print_string(c) serial_print_string (c)
#define DEBUG_dump_block(d,l) serial_dump_block (d,l)
#define DEBUG_putchar(c) serial_putchar (c)
#define DEBUG_print_hex(d) serial_print_hex (d)
#else
#define DEBUG_init()
#define DEBUG_print_string(c)
#define DEBUG_dump_block(d,l)
#define DEBUG_putchar(c)
#define DEBUG_print_hex (d)
#endif

