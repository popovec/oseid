/*
    ifdhandler.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2016 Peter Popovec, popovec.peter@gmail.com

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

    OsEID simulator - card reader emulation for pcscd (only T0 protocol)

*/
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ifdhandler.h>
#include <PCSC/debuglog.h>
#include "serial.h"

#ifdef Infineon
uint8_t fixed_atr[] =
  { 0x3B, 0xF5, 0x96, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x4D, 0x79, 0x45,
0x49, 0x44, 0x15 };
#define FIXED_ATR_SIZE 15
#else
uint8_t fixed_atr[] =
  { 0x3b, 0xf5, 0x18, 0x00, 0x02, 0x10, 0x80, 'O', 's', 'E', 'I', 'D' };
#define FIXED_ATR_SIZE 12
#endif

#if MAX_ATR_SIZE < FIXED_ATR_SIZE
#error Ehm  wrong ATR size?
#endif

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
// only protocol T0
  if (Protocol)
    return IFD_PROTOCOL_NOT_SUPPORTED;
// if PTS is requested  this action is not supported .. 
  if (Flags)
    return IFD_NOT_SUPPORTED;
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
  uint8_t rbuffer[261];
  unsigned long r_len;

  DWORD protocol;

  (void) RecvPci;

  *RxLength = 0;

  if (Lun)
    return IFD_COMMUNICATION_ERROR;

  protocol = SendPci.Protocol;

  switch (protocol)
    {
    case 0:
      Log2 (PCSC_LOG_INFO, "Len = %d", (int) TxLength);
      log_xxd (PCSC_LOG_DEBUG, "APDU: ", TxBuffer, TxLength);

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

      // send 5 bytes .. 
      s2hex (command_s, command, 5);
      WritePort (Lun, 5 * 3, command_s);
      for (;;)
	{
	  // wait procedure byte
	  Log1 (PCSC_LOG_INFO, "waiting procedure byte\n");

	  if (ReadPort (Lun, &r_len, rbuffer))
	    {
	      *RxLength = 0;
	      return IFD_RESPONSE_TIMEOUT;
	    }
	  if (!r_len)
	    continue;

	  Log2 (PCSC_LOG_INFO, "proc bytes = %d", (int) r_len);
	  log_xxd (PCSC_LOG_DEBUG, "bytes: ", rbuffer, r_len);
#warning, better checks needed
	  if (*rbuffer == 0x60)
	    {
	      Log1 (PCSC_LOG_INFO, "procedure byte 60, extend time\n");
	      continue;
	    }
	  else if (*rbuffer == 0xc0)
	    {
	      // read response
	      if (ReadPort (Lun, &r_len, rbuffer))
		{
		  *RxLength = 0;
		  return IFD_RESPONSE_TIMEOUT;
		}

	      Log2 (PCSC_LOG_INFO, "bytes from card = %d", (int) r_len);
	      log_xxd (PCSC_LOG_DEBUG, "bytes: ", rbuffer, r_len);
	      *RxLength = r_len;
	      // read status
	      if (ReadPort (Lun, &r_len, rbuffer + r_len))
		{
		  RxLength = 0;
		  return IFD_RESPONSE_TIMEOUT;

		}
	      while (!r_len);
	      *RxLength += r_len;
	      memcpy (RxBuffer, rbuffer, *RxLength);
	      Log2 (PCSC_LOG_INFO, "full response from card = %d",
		    (int) *RxLength);
	      log_xxd (PCSC_LOG_DEBUG, "bytes: ", RxBuffer, *RxLength);
	      return IFD_SUCCESS;
	    }
	  else if ((*rbuffer & 0xF0) == 0x90)
	    {
	      Log1 (PCSC_LOG_INFO, "procedure byte 9X\n");
	      memcpy (RxBuffer, rbuffer, r_len);
	      *RxLength = r_len;
	      return IFD_SUCCESS;
	    }
	  else if ((*rbuffer & 0xF0) == 0x60)
	    {
	      Log1 (PCSC_LOG_INFO, "procedure byte 6X\n");
	      memcpy (RxBuffer, rbuffer, r_len);
	      *RxLength = r_len;
	      return IFD_SUCCESS;

	    }
	  else if (*rbuffer == TxBuffer[1])
	    {
	      // send rest
	      if (rest_len)
		{
		  s2hex (buffer, TxBuffer + 5, rest_len);
		  WritePort (Lun, rest_len * 3, buffer);
		}
	      else
		{
		  Log1 (PCSC_LOG_INFO,
			"card command confirmed but no data to send\n");
		  memcpy (RxBuffer, rbuffer, r_len);
		  *RxLength = r_len;
		  return IFD_SUCCESS;
		}
	    }
	}
    default:
      *RxLength = 0;
      return IFD_PROTOCOL_NOT_SUPPORTED;
    }

}

RESPONSECODE
IFDHControl (DWORD Lun, DWORD ControlCode, PUCHAR TxBuffer,
	     DWORD TxLength, PUCHAR RxBuffer, DWORD RxLength,
	     PDWORD pdwBytesReturned)
{
  // nothing to do, no LCD, no PIN pad

  *pdwBytesReturned = 0;
  return IFD_COMMUNICATION_ERROR;
}

RESPONSECODE
IFDHICCPresence (DWORD Lun)
{
  if (Lun)
    return IFD_COMMUNICATION_ERROR;

// card is  always present .. 
  return IFD_ICC_PRESENT;
}
