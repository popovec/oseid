/*
    ifdhandler.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2016-2021 Peter Popovec, popovec.peter@gmail.com

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

    OsEID simulator - card reader emulation for pcscd

*/
/*
Protocol: any reader dommand to card start with '>', end with '\r'

reader output:          operation
> D                     power down, no response needed
> P                     power up, reader wait for ATR
> R                     reset, reader wait for ATR
> 0                     PTS for T0, reader wait for PTS response
> 1                     PTS for T1, reader wait for PTS response
> XX XX XX XX... XX     XX represents hexadecimal numbers (APDU)

Responses: (before character '<' any characters may be received)

< XX XX ... XX          ATR or response APDU or status or procedure byte
< 00                     confirmed T0
< 01                     confirmed T1



Example  for T1 protocol, one command APDU, one response APDU:
(TPDU version planed in future)

> 00 a4 00 00
< 6F 17 81 02 7F FF 82 01 38 83 02 3F 00 86 03 11 3F FF 85 02 00 02 8A 01 07 90 00

> 00 a4 00 00 02 3f 00 00 FF
< 6F 17 81 02 7F FF 82 01 38 83 02 3F 00 86 03 11 3F FF 85 02 00 02 8A 01 07 90 00

> 00 a4 00 00 02 3f 00 00 FF
< 61 19

> 00 c0 00 00 00
< 6F 17 81 02 7F FF 82 01 38 83 02 3F 00 86 03 11 3F FF 85 02 00 02 8A 01 07 90 00

Examples T0 - header, return procedure byte or status, send rest (receive for C0)

# no transfer of data, returned status word
< 00 a4 00 00 00
> 61 19

# data transfer
> 00 a4 00 00 02
< A4
> 3f 00
< 61 19

# pin verify check
> 00 20 00 01 00
< 69 83

ISO 7816-3 - after any transfer in/out, reader is waiting for new procedure byte or status
> 00 c0 00 00 00
< c0
< 6F 17 81 02 7F FF 82 01 38 83 02 3F 00 86 03 11 3F FF 85 02 00 02 8A 01 07
< 90 00

alt:
> 00 c0 00 00 00
< c0 6F 17 81 02 7F FF 82 01 38 83 02 3F 00 86 03 11 3F FF 85 02 00 02 8A 01 07 90 00


*/
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ifdhandler.h>
#include <PCSC/debuglog.h>
#include <reader.h>
#include <stdlib.h>
#include "serial.h"

static uint8_t cached_atr[MAX_ATR_SIZE];
static uint8_t cached_atr_len = 0;
static uint8_t proto;

int hex2bytes (char *from, int size, uint8_t * to);
/* Helper for parsing string to hex and back */
static void
s2hex (PUCHAR s, PUCHAR c, DWORD len)
{
  memset (s, 0, len);
  while (len--)
    {
      sprintf ((char *) s, "%02x ", *c);
      c++;
      s += 3;
    }
  s--;
  *s = 10;
}

RESPONSECODE
IFDHCreateChannelByName (DWORD Lun, LPSTR lpcDevice)
{
  Log3 (PCSC_LOG_INFO, "lun: %" PRIx64 ", device: %s", Lun, lpcDevice);

  if (Lun)
    return IFD_COMMUNICATION_ERROR;

  Log1 (PCSC_LOG_INFO, "opening port");
  if (OpenPortByName (Lun, lpcDevice) != IFD_SUCCESS)
    {
      Log1 (PCSC_LOG_CRITICAL, "OpenPort failed");
      return IFD_COMMUNICATION_ERROR;
    }
  Log1 (PCSC_LOG_INFO, "Port opened");
  return IFD_SUCCESS;
}

RESPONSECODE
IFDHCreateChannel (DWORD Lun, DWORD Channel)
{
  RESPONSECODE return_value = IFD_SUCCESS;

  if (Lun)
    return IFD_COMMUNICATION_ERROR;


  if (OpenPort (Lun, Channel) != IFD_SUCCESS)
    {
      Log1 (PCSC_LOG_CRITICAL, "OpenReader failed");
      return_value = IFD_COMMUNICATION_ERROR;
    }

  return return_value;
}

RESPONSECODE
IFDHCloseChannel (DWORD Lun)
{
  if (Lun)
    return IFD_COMMUNICATION_ERROR;

  ClosePort (Lun);
  return IFD_SUCCESS;
}

RESPONSECODE
IFDHGetCapabilities (DWORD Lun, DWORD Tag, PDWORD Length, PUCHAR Value)
{
  if (Lun)
    return IFD_COMMUNICATION_ERROR;

  switch (Tag)
    {
    case SCARD_ATTR_ATR_STRING:
    case TAG_IFD_ATR:
      if (*Length > MAX_ATR_SIZE)
	*Length = MAX_ATR_SIZE;
      if (cached_atr_len == 0)
	{
	  Log1 (PCSC_LOG_INFO, "ATR for memory card (cached)\n");
	  // fake memory card ATR
	  memset (Value, 0, *Length);
	  break;
	}
      if (*Length < cached_atr_len)
	return IFD_ERROR_INSUFFICIENT_BUFFER;
      *Length = cached_atr_len;
      memcpy (Value, cached_atr, *Length);
      log_xxd (PCSC_LOG_DEBUG, "ATR cached: ", Value, *Length);
      break;

// only one reader, only one slot only one simult. access
    case TAG_IFD_SIMULTANEOUS_ACCESS:
    case TAG_IFD_SLOTS_NUMBER:
    case TAG_IFD_SLOT_THREAD_SAFE:
    case TAG_IFD_THREAD_SAFE:
      if (*Length >= 1)
	{
	  *Length = 1;
	  *Value = 0;
	  break;
	}
      return IFD_ERROR_INSUFFICIENT_BUFFER;

    default:
      Log2 (PCSC_LOG_INFO, "unknown tag 0x%" PRIx64, Tag);
      return IFD_ERROR_TAG;
    }
  return IFD_SUCCESS;
}

RESPONSECODE
IFDHSetCapabilities (DWORD Lun, DWORD Tag, DWORD Length, PUCHAR Value)
{
  // ignore this (only used in IFDHandler v1.0)
  if (Lun)
    return IFD_COMMUNICATION_ERROR;
  return IFD_SUCCESS;
}

RESPONSECODE
IFDHSetProtocolParameters (DWORD Lun, DWORD Protocol,
			   UCHAR Flags, UCHAR PTS1, UCHAR PTS2, UCHAR PTS3)
{

  uint8_t buffer[10];
  DWORD blen = 10;

  if (Lun)
    return IFD_COMMUNICATION_ERROR;

  if (Protocol == SCARD_PROTOCOL_T0)
    {
      Log1 (PCSC_LOG_INFO, "Protocol 0 PTS");
      WritePort (Lun, 4, (uint8_t *) "> 0\n");

      if (RET_OK == ReadPort (Lun, &blen, buffer))
	    if (blen == 1)
	      if (*buffer == 0)
		{
		  proto = 0;
		  Log1 (PCSC_LOG_INFO, "Protocol 0 confirmed");
		  return IFD_SUCCESS;
		}
    }
  else if (Protocol == SCARD_PROTOCOL_T1)
    {
      Log1 (PCSC_LOG_INFO, "Protocol 1");
      WritePort (Lun, 4, (uint8_t *) "> 1\n");

      if (RET_OK == ReadPort (Lun, &blen, buffer))
	    if (blen == 1)
	      if (*buffer == 1)
		{
		  proto = 1;
		  Log1 (PCSC_LOG_INFO, "Protocol 1 confirmed");
		  return IFD_SUCCESS;
		}
    }

  return IFD_PROTOCOL_NOT_SUPPORTED;
}

RESPONSECODE
IFDHPowerICC (DWORD Lun, DWORD Action, PUCHAR Atr, PDWORD AtrLength)
{
  static uint8_t first_run = 0;
  if (Lun)
    return IFD_COMMUNICATION_ERROR;

  switch (Action)
    {
    case IFD_POWER_UP:
      Log1 (PCSC_LOG_INFO, "Card power up");
      if (first_run != 0)
	{
	  WritePort (Lun, 4, (uint8_t *) "> P\n");
	  break;
	}
      Log1 (PCSC_LOG_INFO,
	    "1st run, this power up does not send ATR (memory card");
      first_run = 1;
      memset (Atr, 0, *AtrLength);
      memset (cached_atr, 0, MAX_ATR_SIZE);
      *AtrLength = 0;
      proto = 0;
      return IFD_ERROR_POWER_ACTION;

    case IFD_RESET:
      Log1 (PCSC_LOG_INFO, "Card reset");
      WritePort (Lun, 4, (uint8_t *) "> R\n");
      break;

    case IFD_POWER_DOWN:
      Log1 (PCSC_LOG_INFO, "Card power down");
      WritePort (Lun, 4, (uint8_t *) "> D\n");
      return IFD_SUCCESS;

    default:
      Log1 (PCSC_LOG_CRITICAL, "Action not supported");
      return IFD_NOT_SUPPORTED;
    }

  if (*AtrLength > MAX_ATR_SIZE)
    *AtrLength = MAX_ATR_SIZE;

  proto = 0;

  // read ATR from card
  Log1 (PCSC_LOG_INFO, "Waiting for ATR");

  // read max AtrLength bytes into buffer Atr
  // AtrLength is updated to real received bytes
  if (RET_OK != ReadPort (Lun, AtrLength, Atr))
    {
      // invalidate cache
      memset (cached_atr, 0, MAX_ATR_SIZE);
      cached_atr_len = 0;

      *AtrLength = 0;
      Log1 (PCSC_LOG_INFO, "ATR timeout");
      return IFD_ERROR_POWER_ACTION;
    }

  log_xxd (PCSC_LOG_DEBUG, "ATR from card: ", Atr, *AtrLength);
  // reject ATR if below 2 bytes
  if (*AtrLength < 2)
    return IFD_COMMUNICATION_ERROR;

  // atr cache for IFDHGetCapabilities()
  memcpy (cached_atr, Atr, *AtrLength);
  cached_atr_len = *AtrLength;
  return IFD_SUCCESS;
}

#define R_SIZE 3000
RESPONSECODE
IFDHTransmitToICC (DWORD Lun, SCARD_IO_HEADER SendPci,
		   PUCHAR TxBuffer, DWORD TxLength,
		   PUCHAR RxBuffer, PDWORD RxLength, PSCARD_IO_HEADER RecvPci)
{
  uint8_t command[5];
  uint8_t command_s[5 * 3 + 3];
  // T0 allow us to send only shot APDU
  uint8_t buffer[(5 + 255) * 3 + 3];
  uint8_t rest_len;
  uint8_t card_resp[R_SIZE];
  DWORD r_space;
  uint8_t *ptr_r;
  unsigned long r_len;
  DWORD protocol;
  DWORD exp_resp_len = 0;


  Log1 (PCSC_LOG_INFO, "IFDHTransmitToICC");

  Log2 (PCSC_LOG_INFO, "Transmit Len = %" PRIu64, TxLength);
  Log2 (PCSC_LOG_INFO, "Receive Len = %" PRIu64, *RxLength);
  Log2 (PCSC_LOG_INFO, "negotiated protocol = %" PRIu8, proto);
  log_xxd (PCSC_LOG_DEBUG, "APDU: ", TxBuffer, TxLength);

  if (TxLength < 4)
    {
      Log1 (PCSC_LOG_INFO, "TxLength < 4");
      *RxLength = 0;
      return IFD_COMMUNICATION_ERROR;
    }

  if (*RxLength > 65535)
    r_space = 65535;
  else
    r_space = *RxLength;

  *RxLength = 0;
  ptr_r = RxBuffer;

  if (Lun)
    return IFD_COMMUNICATION_ERROR;

  protocol = SendPci.Protocol;
  if (protocol > 1)
    return IFD_PROTOCOL_NOT_SUPPORTED;

  if (proto != protocol)
    {
      Log1 (PCSC_LOG_INFO, "not negotiated protocol");
      return IFD_COMMUNICATION_ERROR;
    }
  if (TxLength > 261 + 5)
    {
      Log1 (PCSC_LOG_INFO, "too many characters in message");
      return IFD_COMMUNICATION_ERROR;
    }

  if (proto == 1)
    {
      // space for extended APDU,
      uint8_t buffer_l[(5 + 2 + 65536 + 2) * 3 + 2];

      // minimal APDU size 4 bytes already checked..
      Log1 (PCSC_LOG_INFO, "protocol T1, sending whole APDU");
      buffer_l[0] = '>';
      buffer_l[1] = ' ';
      s2hex (buffer_l + 2, TxBuffer, TxLength);
      WritePort (Lun, 2 + TxLength * 3, buffer_l);

      if (RET_OK != ReadPort (Lun, &r_space, buffer_l))
	{
	  Log1 (PCSC_LOG_INFO, "Read port failed");
	  memset (RxBuffer, 0, *RxLength);
	  *RxLength = 0;
	  return IFD_COMMUNICATION_ERROR;
	}
      // exp_resp_len is not used here .
      memcpy (RxBuffer, buffer_l, r_space);
      *RxLength = r_space;;
      return IFD_SUCCESS;
    }

/*
Please read doc about this implementation of T0 protocol

*/
  // protocol T0 construct header
  // minimal APDU size 4 bytes already checked..
  // exp_resp_len is without bytes for SW1,SW2

//  safety check
  if ((TxBuffer[1] & 0xf0) == 0x60 || (TxBuffer[1] & 0xf0) == 0x90)
    {
      *RxLength = 0;
      Log1 (PCSC_LOG_INFO, "not allowed INS");
      return IFD_COMMUNICATION_ERROR;
    }
// check APDU case, remap extended APDU to short if it is possible.
  if (TxLength == 4)
    {
      // CASE 1S
      memset (command, 0, 5);
      memcpy (command, TxBuffer, TxLength);
      exp_resp_len = 0;
      rest_len = 0;
    }
  else
    {
      memcpy (command, TxBuffer, 5);
      if (command[4])
	{
	  if (TxLength == 5)
	    {
	      // CASE 2S
	      exp_resp_len = command[4];
	      rest_len = 0;
	    }
	  else if (TxLength == (5 + command[4]))
	    {
	      // CASE 3S
	      exp_resp_len = 0;
	      rest_len = command[4];
	    }
	  else if (TxLength == (6 + command[4]))
	    {
	      // CASE 4S
	      exp_resp_len = 0;
	      rest_len = command[4];
	    }
	  else
	    {
	      *RxLength = 0;
	      Log1 (PCSC_LOG_INFO, "wrong APDU size (P3!=0)");
	      return IFD_COMMUNICATION_ERROR;
	    }
	}
      else
	{
	  // P3 == 0 TxLength > 4
	  if (TxLength == 5)
	    {
	      // CASE 2S
	      exp_resp_len = 256;
	      rest_len = 0;
	    }
	  else if (TxLength == 6)
	    {
	      *RxLength = 0;
	      Log1 (PCSC_LOG_INFO, "P3 == 0, TxLength  6");
	      return IFD_COMMUNICATION_ERROR;

	    }
	  else
	    {
	      // TxLength > 6
	      uint16_t LcEX = TxBuffer[5] << 8 | TxBuffer[6];

	      if (TxLength == 7)
		{
		  // CASE 2E, 1st response max 256 bytes, then get response..
		  exp_resp_len = 256;
		  rest_len = 0;
		  if (LcEX < 256)
		    exp_resp_len = LcEX;
		}
	      else if (TxLength == 7 + LcEX)
		{
		  // CASE 3E
		  exp_resp_len = 0;
		  if (LcEX < 256)
		    rest_len = LcEX;
		  else
		    {
		      *RxLength = 0;
		      Log1 (PCSC_LOG_INFO,
			    "Extended APDU case 3E, Nc>255, T0 is unable to transport this (use chanining/Envelope)");
		      return IFD_COMMUNICATION_ERROR;
		    }
		}
	      else if (TxLength == 9 + LcEX)
		{
		  // CASE 4E
		  if (LcEX < 256)
		    rest_len = LcEX;
		  else
		    {
		      *RxLength = 0;
		      Log1 (PCSC_LOG_INFO,
			    "Extended APDU case 4E, Nc>255, T0 is unable to transport this (use chanining/Envelope)");
		      return IFD_COMMUNICATION_ERROR;
		    }
		  LcEX = TxBuffer[TxLength - 2] << 8 | TxBuffer[TxLength - 1];
		  if (LcEX < 256)
		    exp_resp_len = LcEX;
		  else
		    exp_resp_len = 256;
		}
	      else
		{
		  *RxLength = 0;
		  Log1 (PCSC_LOG_INFO,
			"P3 == 0, TxLength  does not corresponds to any case of APDU");
		  return IFD_COMMUNICATION_ERROR;
		}
	    }
	}
    }


  Log1 (PCSC_LOG_INFO, "sending first 5 bytes");

  // send APDU header - 5 bytes
  command_s[0] = '>';
  command_s[1] = ' ';
  s2hex (command_s + 2, command, 5);
  WritePort (Lun, 2 + 5 * 3, command_s);

  for (;;)
    {
      r_len = R_SIZE;
      // wait procedure byte / status bytes
      Log1 (PCSC_LOG_INFO, "waiting procedure/status byte(s)");
      if (ReadPort (Lun, &r_len, card_resp))
	{
	  *RxLength = 0;
	  return IFD_RESPONSE_TIMEOUT;
	}
      if (!r_len)
	continue;
      Log2 (PCSC_LOG_INFO, "proc bytes = %" PRIu64, r_len);
      log_xxd (PCSC_LOG_DEBUG, "bytes: ", card_resp, r_len);

      if (r_len == 1)		//procedure byte
	{
	  Log2 (PCSC_LOG_INFO, "proc byte = %" PRIx8, card_resp[0]);
	  if (card_resp[0] == 0x60)	//NULL
	    {
	      Log1 (PCSC_LOG_INFO, "procedure byte 60, extend time");
	      continue;
	    }
	  if ((card_resp[0] & 0xF0) == 0x60)
	    {
	      Log1 (PCSC_LOG_INFO,
		    "Internal error, status word with only one byte");
	      goto err;
	    }
	  if ((card_resp[0] & 0xF0) == 0x90)
	    {
	      Log1 (PCSC_LOG_INFO,
		    "Internal error, status word with only one byte");
	      goto err;
	    }
	  if (card_resp[0] != TxBuffer[1])
	    {
	      *RxLength = 0;
	      Log1 (PCSC_LOG_INFO,
		    "Error procedure byte wrong (not SW, not NULL not INS");
	      goto err;
	    }
	  if (exp_resp_len)
	    {
	      // read response
	      r_len = R_SIZE;
	      if (ReadPort (Lun, &r_len, card_resp))
		{
		  *RxLength = 0;
		  return IFD_RESPONSE_TIMEOUT;
		}
	      Log2 (PCSC_LOG_INFO, "bytes from card = %" PRIu64, r_len);
	      log_xxd (PCSC_LOG_DEBUG, "bytes: ", card_resp, r_len);
	      // for now error if wrong lenght is received
	      if (exp_resp_len != r_len)
		{
		  Log3 (PCSC_LOG_INFO,
			"Expected size is %" PRIu64 ", received %" PRIu64
			" error", exp_resp_len, r_len);
		  goto err;
		}
	      if (r_space >= r_len)
		{
		  // copy received data to response
		  memcpy (ptr_r, card_resp, r_len);
		  ptr_r += r_len;
		  *RxLength += r_len;
		  r_space -= r_len;
		}
	      else
		{
		  Log1 (PCSC_LOG_INFO, "No space in buffer");
		  goto err;
		}
	      continue;

	    }
	  else if (rest_len)
	    {
	      buffer[0] = '>';
	      buffer[1] = ' ';
	      s2hex (buffer + 2, TxBuffer + 5, rest_len);
	      WritePort (Lun, 2 + rest_len * 3, buffer);
	      rest_len = 0;
	      continue;
	    }
	}
      else if (r_len == 2)	// Status
	{
	  // is there space in buffer ?
	  if (r_space < 2)
	    {
	      goto err;
	    }
	  if ((card_resp[0] & 0xF0) == 0x90)
	    {
	      Log1 (PCSC_LOG_INFO, "procedure byte 9X");
	      memcpy (ptr_r, card_resp, 2);
	      Log2 (PCSC_LOG_INFO, "RxLength=%" PRIu64, *RxLength);
	      Log2 (PCSC_LOG_INFO, "rlen=%" PRIu64, r_len);
	      *RxLength += r_len;
	      return IFD_SUCCESS;
	    }
	  else if ((card_resp[0] & 0xF0) == 0x60)
	    {
	      Log1 (PCSC_LOG_INFO, "procedure byte 6X");
	      memcpy (ptr_r, card_resp, 2);
	      *RxLength += r_len;
	      return IFD_SUCCESS;
	    }
	  else
	    {
	      Log2 (PCSC_LOG_INFO, "Unknown status byte %" PRIx8,
		    card_resp[0]);
	      goto err;
	    }
	}
      else
	{
	  uint8_t sw1 = card_resp[r_len - 2];

	  // in one frame - procedure byte, data, sw
	  if (card_resp[0] != TxBuffer[1])
	    {
	      Log1 (PCSC_LOG_INFO,
		    "Error procedure byte wrong (does not match INS)");
	      goto err;
	    }
	  // NULL is handled for r_len=1
	  if (sw1 == 0x60)
	    {
	      Log1 (PCSC_LOG_INFO, "fail, SW1 = 0x60");
	      return IFD_COMMUNICATION_ERROR;
	    }

	  if ((sw1 & 0xf0) != 0x60 && (sw1 & 0xf0) != 0x90)
	    {
	      Log1 (PCSC_LOG_INFO, "fail, SW1 not 0x9X or 0x6X");
	      goto err;
	    }

	  Log2 (PCSC_LOG_INFO, "bytes from card = %" PRIu64, r_len);
	  log_xxd (PCSC_LOG_DEBUG, "bytes: ", card_resp, r_len);

	  // a short response that expected is allowed .. ? exp_resp_len < r_len - 3
	  // for now error if wrong lenght is received
	  if (exp_resp_len != r_len - 3)
	    {
	      Log3 (PCSC_LOG_INFO,
		    "Expected size is %" PRIu64 " received %" PRIu64 " error",
		    exp_resp_len, r_len);
	      goto err;
	    }
	  if (r_space >= r_len)
	    {
	      // copy received data to response (skip procedure byte)
	      memcpy (ptr_r, card_resp + 1, r_len - 1);
	      *RxLength = r_len - 1;
	      return IFD_SUCCESS;

	    }
	  else
	    {
	      Log1 (PCSC_LOG_INFO, "No space in buffer");
	      goto err;
	    }
	}
    }
err:
  *RxLength = 0;
  return IFD_COMMUNICATION_ERROR;
}

RESPONSECODE
IFDHControl (DWORD Lun, DWORD ControlCode,
	     PUCHAR TxBuffer, DWORD TxLength,
	     PUCHAR RxBuffer, DWORD RxLength, PDWORD pdwBytesReturned)
{
  // nothing to do, no LCD, no PIN pad
  *pdwBytesReturned = 0;
  return IFD_SUCCESS;
//  return IFD_COMMUNICATION_ERROR;
}

RESPONSECODE
IFDHICCPresence (DWORD Lun)
{
  if (Lun)
    return IFD_COMMUNICATION_ERROR;
// card is  always present ..
  return IFD_ICC_PRESENT;
}
