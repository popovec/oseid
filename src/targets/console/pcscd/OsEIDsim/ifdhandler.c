/*
    ifdhandler.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2016-2017 Peter Popovec, popovec.peter@gmail.com

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
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ifdhandler.h>
#include <PCSC/debuglog.h>
#include "serial.h"

// this is OsEID ATR, used in years 2015-2017 (Only T0 protocol)
#if 0
uint8_t fixed_atr[] =
  { 0x3b, 0xf5, 0x18, 0x00, 0x02, 0x10, 0x80, 'O', 's', 'E', 'I', 'D' };
#define FIXED_ATR_SIZE 12

#else
// new OsEID ATR, support for T0 and T1 protocol
uint8_t fixed_atr[] =
  { 0x3B, 0xF5, 0x18, 0x00, 0x02, 0x80, 0x01, 'O', 's', 'E', 'I', 'D', 0x1a };
#define FIXED_ATR_SIZE 13
#endif

#if MAX_ATR_SIZE < FIXED_ATR_SIZE
#error Ehm  wrong ATR size?
#endif
uint8_t proto;
/* Helper for parsing test to hex and back */
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
  Log3 (PCSC_LOG_INFO, "lun: %lX, device: %s", Lun, lpcDevice);

  if (Lun)
    return IFD_COMMUNICATION_ERROR;

  Log1 (PCSC_LOG_INFO, "opening port\n");
  if (OpenPortByName (Lun, lpcDevice) != IFD_SUCCESS)
    {
      Log1 (PCSC_LOG_CRITICAL, "OpenPort failed");
      return IFD_COMMUNICATION_ERROR;
    }
  Log1 (PCSC_LOG_INFO, "Port opened\n");
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
    case TAG_IFD_ATR:
      if (*Length >= FIXED_ATR_SIZE)
	{
	  *Length = FIXED_ATR_SIZE;
	  memcpy (Value, fixed_atr, FIXED_ATR_SIZE);
	  break;
	}
      return IFD_ERROR_TAG;
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
      return IFD_ERROR_TAG;

    default:
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
  if (Lun)
    return IFD_COMMUNICATION_ERROR;

  if (Protocol == SCARD_PROTOCOL_T0)
    {
      Log1 (PCSC_LOG_INFO, "Protocol 0\n");
      proto = 1;
    }
  else if (Protocol == SCARD_PROTOCOL_T1)
    {
      Log1 (PCSC_LOG_INFO, "Protocol 1\n");
      proto = 0;
    }
  else
    return IFD_PROTOCOL_NOT_SUPPORTED;
// This is simulation, changing PTS is supported
  return IFD_SUCCESS;
}

RESPONSECODE
IFDHPowerICC (DWORD Lun, DWORD Action, PUCHAR Atr, PDWORD AtrLength)
{
  RESPONSECODE return_value = IFD_SUCCESS;
  if (Lun)
    return IFD_COMMUNICATION_ERROR;

  switch (Action)
    {
    case IFD_POWER_UP:
    case IFD_RESET:
      Log1 (PCSC_LOG_INFO, "Power up or reset\n");

      WritePort (Lun, 6, (uint8_t *) "reset\n");

      *AtrLength = FIXED_ATR_SIZE;
      memcpy (Atr, fixed_atr, FIXED_ATR_SIZE);

      return IFD_SUCCESS;

    case IFD_POWER_DOWN:
      Log1 (PCSC_LOG_INFO, "Power down\n");

      return_value = IFD_SUCCESS;
      break;

    default:
      Log1 (PCSC_LOG_CRITICAL, "Action not supported");
      return_value = IFD_NOT_SUPPORTED;
    }

  return return_value;
}

RESPONSECODE
IFDHTransmitToICC (DWORD Lun, SCARD_IO_HEADER SendPci,
		   PUCHAR TxBuffer, DWORD TxLength,
		   PUCHAR RxBuffer, PDWORD RxLength, PSCARD_IO_HEADER RecvPci)
{
  uint8_t command[5];
  uint8_t command_s[5 * 3 + 3];
  uint8_t buffer[255 * 3 + 3];
  uint8_t rest_len;
  uint8_t card_resp[256];
  uint16_t r_space;
  uint8_t *ptr_r;
  unsigned long r_len;
  uint8_t proc_byte_received = 0;

  DWORD protocol;


  if (*RxLength > 65535)
    r_space = 65535;
  else
    r_space = *RxLength;
  Log1 (PCSC_LOG_INFO, "IFDHTransmitToICC\n");

  Log2 (PCSC_LOG_INFO, "Transmit Len = %d", (int) TxLength);
  Log2 (PCSC_LOG_INFO, "Receive Len = %d", (int) r_space);

  log_xxd (PCSC_LOG_DEBUG, "APDU: ", TxBuffer, TxLength);

  *RxLength = 0;
  ptr_r = RxBuffer;

  if (Lun)
    return IFD_COMMUNICATION_ERROR;

  protocol = SendPci.Protocol;
  if (protocol > 1)
    {
      *RxLength = 0;
      return IFD_PROTOCOL_NOT_SUPPORTED;
    }

  if (TxLength > 261)
    {
      Log1 (PCSC_LOG_INFO, "too many characters in message\n");
      return IFD_COMMUNICATION_ERROR;
    }
  if (TxLength < 5)
    {
      memset (command, 0, 5);
      memcpy (command, TxBuffer, TxLength);
    }
  else
    {
      memcpy (command, TxBuffer, 5);
    }
  rest_len = command[4];

  Log1 (PCSC_LOG_INFO, "sending first 5 bytes\n");

  // send 5 bytes .. (Internaly OsEID uses T0 protocol)
  s2hex (command_s, command, 5);
  WritePort (Lun, 5 * 3, command_s);

  for (;;)
    {
      // wait procedure byte / status bytes
      Log1 (PCSC_LOG_INFO, "waiting procedure/status byte(s)\n");
      if (ReadPort (Lun, &r_len, card_resp))
	{
	  *RxLength = 0;
	  return IFD_RESPONSE_TIMEOUT;
	}
      if (!r_len)
	continue;
      Log2 (PCSC_LOG_INFO, "proc bytes = %d", (int) r_len);
      log_xxd (PCSC_LOG_DEBUG, "bytes: ", card_resp, r_len);

      if (r_len == 1)		//procedure byte
	{
	  Log2 (PCSC_LOG_INFO, "proc byte = %d", (int) card_resp[0]);
	  if (card_resp[0] == 0x60)	//NULL
	    {
	      Log1 (PCSC_LOG_INFO, "procedure byte 60, extend time\n");
	      continue;
	    }
	  if (proc_byte_received)
	    {
	      Log1 (PCSC_LOG_INFO, "procedure byte alerady received\n");
	      *RxLength = 0;
	      return IFD_COMMUNICATION_ERROR;
	    }
	  proc_byte_received = 1;	// marker, received procedure byte
	  if (card_resp[0] == 0xc0)	// GET_RESPONSE
	    {
	      // read response
	      if (ReadPort (Lun, &r_len, card_resp))
		{
		  *RxLength = 0;
		  return IFD_RESPONSE_TIMEOUT;
		}
	      Log2 (PCSC_LOG_INFO, "bytes from card = %d", (int) r_len);
	      log_xxd (PCSC_LOG_DEBUG, "bytes: ", card_resp, r_len);
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
		  Log1 (PCSC_LOG_INFO, "No space in buffer\n");
		  *RxLength = 0;
		  return IFD_COMMUNICATION_ERROR;
		}
	      continue;
	    }
	  if (card_resp[0] == TxBuffer[1])
	    {
	      // send rest
	      if (rest_len)
		{
		  s2hex (buffer, TxBuffer + 5, rest_len);
		  WritePort (Lun, rest_len * 3, buffer);
		  continue;
		}
	      else
		{
		  Log1 (PCSC_LOG_INFO,
			"card command confirmed but no data to send\n");
		  *RxLength = 0;
		  return IFD_COMMUNICATION_ERROR;
		}
	    }
	}
      else if (r_len == 2)	// Status
	{
	  uint16_t rrlen = card_resp[1] ? card_resp[1] : 256;

	  // is there space in buffer ?
	  if (r_space < 2)
	    {
	      *RxLength = 0;
	      return IFD_COMMUNICATION_ERROR;
	    }
	  // OsEID is running internaly only T0 protocol, if T1 is requested,
	  // do some preprocesing here, If there is space in RxBuffer, call get_response here
	  if (card_resp[0] == 0x61 && protocol == 1 && rrlen + 2 <= r_space)
	    {
	      uint8_t resp[5], resp_s[5 * 3 + 3];

	      proc_byte_received = 0;	// clear marker (new procedure byte is waiting from now)
	      Log2 (PCSC_LOG_INFO, "Get response.. bytes = %d",
		    (int) card_resp[1]);
	      resp[0] = 0;
	      resp[1] = 0xc0;
	      resp[2] = 0;
	      resp[3] = 0;
	      resp[4] = rrlen <= 128 ? rrlen : 128;
	      Log2 (PCSC_LOG_INFO, "Requesting %d bytes of response",
		    resp[4]);
	      s2hex (resp_s, resp, 5);
	      WritePort (Lun, 5 * 3, resp_s);
	      continue;
	    }
	  else if ((card_resp[0] & 0xF0) == 0x90)
	    {
	      Log1 (PCSC_LOG_INFO, "procedure byte 9X\n");
	      memcpy (ptr_r, card_resp, 2);
	      *RxLength += r_len;
	      return IFD_SUCCESS;
	    }
	  else if ((card_resp[0] & 0xF0) == 0x60)
	    {
	      Log1 (PCSC_LOG_INFO, "procedure byte 6X\n");
	      memcpy (ptr_r, card_resp, 2);
	      *RxLength += r_len;
	      return IFD_SUCCESS;
	    }
	  else
	    {
	      Log1 (PCSC_LOG_INFO, "Unknown status byte \n");
	      *RxLength = 0;
	      return IFD_COMMUNICATION_ERROR;
	    }
	}
      else
	{
	  *RxLength = 0;
	  return IFD_COMMUNICATION_ERROR;
	}
    }

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
