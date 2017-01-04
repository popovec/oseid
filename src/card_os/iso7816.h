/*
    iso7816.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015 Peter Popovec, popovec.peter@gmail.com

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

    header file for iso7816 functions

*/
#ifndef CS_ISO7816_H
#define CS_ISO7816_H


void confirm_command (uint8_t * message);
uint8_t read_command_data (uint8_t * message);

void card_poll(void);

void response_clear(void);

struct iso7816_response
{
  uint8_t data[256];		//256 real bytes 
  uint8_t len;			//0 = 256, 1=1 ... 255=255
  uint8_t flag;			//check #define below ..
  uint8_t input_len;
  uint8_t input[255+5];		//5 bytes command, max 255 bytes data
};

// definition of values in struct iso7816_response.flag
// response data in buffer invalid
#define  R_NO_DATA  0
// response data is available in buffer
#define  R_RESP_READY  1
// no response data in buffer, buffer is used to other data (temporary)
#define  R_TMP	    2
#endif
