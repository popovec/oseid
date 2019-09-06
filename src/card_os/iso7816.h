/*
    iso7816.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2019 Peter Popovec, popovec.peter@gmail.com

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

// RSA 2048 need 256 bytes of data + padding indicator -> 257 bytes data part of APDU
// 5 bytes header, max 257 bytes data +2+2 (to support Case 3E, 4E ISO786-3)
#ifndef APDU_CMD_LEN
#define APDU_CMD_LEN 261+5
#endif
// 257 bytes (this buffer is used as case of apdu chaining and RSA proprietary padding..)
#ifndef APDU_RESP_LEN
#define APDU_RESP_LEN 257
#endif
void card_poll (void);

void response_clear (void);

struct iso7816_response
{
  uint8_t protocol;		// 0 T0 1 T1
  uint16_t Nc;			// 0, Lc not present, 1..65535 Lc
  uint16_t Ne;			// 0, Le not present, 1..65535 Le  (iso allow 65536 here, but for limited RAM in hardware this is not used)
  uint8_t chaining_active;
  uint16_t len16;
  uint16_t tmp_len;		// how many bytes are  stored in response (in case of flag == R_TMP)
  uint8_t flag;			//check #define below ..
  uint8_t data[APDU_RESP_LEN];
  uint8_t input[APDU_CMD_LEN];
};

// definition of values in struct iso7816_response.flag
// response data in buffer invalid
#define  R_NO_DATA  0
// response data is available in buffer
#define  R_RESP_READY  1
// no response data in buffer, buffer is used to other data (temporary)
#define  R_TMP	    2
// no response data in buffer, buffer is used by envelope command
#define  R_ENVELOPE	    3


uint8_t resp_ready (struct iso7816_response *r, uint16_t len);

// 0x9000
#define S_RET_OK   0
#define S_RET_GET_RESPONSE 1		// used by GET RESPONSE to signalize data must be returned
#define S0x6100 0x10		// response length in low byte

#define S0x6281 0x21
#define S0x6282 0x22

#define S0x63c0 0x30
/*
#define S0x63c1 0x31
#define S0x63c2 0x32
#define S0x63c3 0x33
#define S0x63c4 0x34
#define S0x63c5 0x35
#define S0x63c6 0x36
#define S0x63c7 0x37
#define S0x63c8 0x38
#define S0x63c9 0x39
#define S0x63ca 0x3a
#define S0x63cb 0x3b
#define S0x63cc 0x3c
#define S0x63cd 0x3d
#define S0x63ce 0x3e
*/
#define S0x63cf 0x3f

#define S0x6581 0x51

#define S0x6700 0x70		//fixed 6700

#define S0x6883	0x83
#define S0x6884	0x84

#define S0x6981 0x91
#define S0x6982 0x92
#define S0x6983 0x93
#define S0x6984 0x94
#define S0x6985 0x95
#define S0x6986 0x96

#define S0x6a80 0xa0
#define S0x6a81 0xa1
#define S0x6a82 0xa2
#define S0x6a86 0xa6
#define S0x6a87 0xa7
#define S0x6a88 0xa8
#define S0x6a89 0xa9

#define S0x6b00 	0xb0	//fixed 6b00

#define S0x6c00		0xc0	//same as 0x61xx

#define S0x6d00 	0xd0	//fixed 6d00
#define S0x6e00 	0xe0	//fixed 6e00
#define S0x6f00 	0xf0	//fixed 6f00


#endif
