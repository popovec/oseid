/*
    hex2bytes.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2019 Peter Popovec, popovec.peter@gmail.com

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

    very tolerant hex to binary converter (max 256 bytes)

*/
#include <stdint.h>
#include <ctype.h>
int
hex2bytes (char *r_buffer, int already_read, uint8_t * buffer)
{
  uint32_t length = 0, i;
  int byte = 0;
  int flag = 0;
  char c;

  for (i = 0;; i++)
    {
      // allow maximal size of extended APDU
      if (length == 5+2+65536+2)
	return length;

      if (i == already_read)
	goto end;

      c = r_buffer[i];
      if (!isxdigit (c))
	{
	end:
	  if (flag)
	    {
	      // no hex digit but some hex digit already parsed
	      // save byte
	      buffer[length] = byte;
	      byte = 0;
	      flag = 0;
	      length++;
	    }
	  if (i == already_read)
	    return length;
	  if (c == 0x0d)
	    return length;
	  if (c == 0x0a)
	    return length;
	}
      else
	{
	  flag++;
	  if (flag == 3)
	    {
	      // save byte
	      buffer[length] = byte;
	      byte = 0;
	      flag = 0;
	      length++;
	    }
	  c -= '0';
	  if (c > 9)
	    c -= 7;
	  if (c > 16)
	    c -= 32;
	  byte *= 16;
	  byte += c;
	}
    }
  return length;
}
