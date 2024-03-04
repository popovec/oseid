/*
    ccid.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2024 Peter Popovec, popovec.peter@gmail.com

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

    CCID layer - parse USB CCID in/out, transmit/receive from card

*/
#include <stdint.h>
#include <string.h>

#include "card_io.h"
#include "ccid.h"
#include "usb.h"
#include "LED.h"
#include "os.h"
#include "serial_debug.h"

// This is anouced in USB CCID descriptor
#define MaxCCIDMsgLen 271

#define C_RDR_to_PC_DataBlock  0x80
#define C_RDR_to_PC_SlotStatus 0x81
#define C_RDR_to_PC_Parameters 0x82
#define C_RDR_to_PC_Escape     0x83
#define C_RDR_to_PC_DataRateAndClockFrequency 0x84

static uint8_t SlotError __attribute__((section(".noinit")));

#define PPS_ATR_SENT 0
#define PPS_READY 1
#define PPS_OK 2
// initialized from func_PC_to_RDR_IccPowerOn();
static uint8_t pps_status __attribute__((section(".noinit")));

// slot status:
union Slot_Status_Register {
	struct {
		uint8_t bmICCStatus:2;
		uint8_t RFU:4;
		uint8_t bmCommandStatus:2;
	};
	uint8_t SlotStatus;
} Status __attribute__((section(".noinit")));

static uint8_t ATR[33] __attribute__((section(".noinit")));

enum TPDU_states {
	T_IDLE,
	T_RUNNING,
};
// do not change this, read  PC_to_RDR_SetParameters description 1st..

struct ReaderParam {
	uint8_t protocol;
	uint8_t bmFindexDindex;
	union {
		uint8_t bmTCCKST0;
		uint8_t bmTCCKST1;
	};
	union {
		uint8_t bGuardTimeT0;
		uint8_t bGuardTimeT1;
	};
	union {
		uint8_t bWaitingIntegerT0;
		uint8_t bWaitingIntegersT1;
	};

	uint8_t bClockStop;
	uint8_t bIFSC;
	uint8_t bNadValue;

} ReaderParam __attribute__((section(".noinit")));

static uint16_t null_count __attribute__((section(".noinit")));
static volatile uint8_t TPDU_state __attribute__((section(".noinit")));

// card IO buffers/variables
// 0  no data for card, or data len
static volatile uint16_t card_rx_len __attribute__((section(".noinit")));
static uint8_t CCID_card_io_buffer[MaxCCIDMsgLen] __attribute__((section(".noinit")));
static uint8_t *card_rx_buffer __attribute__((section(".noinit")));

static uint8_t CCID_message_from_host[MaxCCIDMsgLen] __attribute__((section(".noinit")));
static volatile uint16_t CCID_message_from_host_count __attribute__((section(".noinit")));
static uint8_t CCID_short_response[63] __attribute__((section(".noinit")));

// NOT called from ISR
uint16_t card_io_rx(uint8_t * data, uint16_t len)
{
	uint16_t l_len;

	// wait for data from CCID layer
	while (!card_rx_len)
		CPU_idle();

	// read only requested chars, rest is discarded!
	// T0 protocol: procedure byte is used to transfer more bytes..
	l_len = card_rx_len;
	if (len < l_len)
		l_len = len;
	card_rx_len = 0;

	// copy data to card ..
	memcpy(data, card_rx_buffer, l_len);
	// special handling for PPS:
	if (pps_status == PPS_READY) {
		data[1] = l_len & 0xff;
		memcpy(data + 2, card_rx_buffer, l_len);
		l_len = 0;
	}
	pps_status = PPS_OK;
	return l_len;
}

// NOT called from ISR
void card_io_tx(uint8_t * data, uint16_t len)
{
	// do not handle data from card if CCID layer does not request data
	if (TPDU_state == T_IDLE)
		return;

	// T0 protocol may request rest of APDU
	if (ReaderParam.protocol == 0) {
		// Test procedure byte (INS in CCID_card_io_buffer[11])
		if (data[0] == CCID_card_io_buffer[11]) {
			if (len == 1) {
				// procedure byte OK, send rest of command APDU
				if (CCID_card_io_buffer[14]) {
					card_rx_buffer = CCID_card_io_buffer + 15;
					card_rx_len = CCID_card_io_buffer[14];	// max 255 bytes
					CCID_card_io_buffer[14] = 0;
				}
				return;
			} else {
				// buffer: procedure byte, response, SW1,SW2
				// remove procedure byte from response
				data++;
				len--;
			}
		}
//        else
//              no procedure byte, do not check for valid SW, return as is to host
	}
	// return response to host
	// card message is truncated if it does not fit into dwMaxCCIDMSgLen
	if (len == 0)		// 65536
		len = MaxCCIDMsgLen - 10;
	if (len > MaxCCIDMsgLen - 10)
		len = MaxCCIDMsgLen - 10;
	// construct response
	memcpy(CCID_card_io_buffer + 10, data, len);
	CCID_card_io_buffer[0] = C_RDR_to_PC_DataBlock;
	// update size in CCID header
	CCID_card_io_buffer[1] = len & 0xff;
	CCID_card_io_buffer[2] = len >> 8;
	// do not change byte 5,6 (slot, sequence)
	TPDU_state = T_IDLE;

	null_count = 0;
	Status.bmCommandStatus = 0;	// command ok
	SlotError = 0;		// unused for bmCommandStatus = 0
	CCID_card_io_buffer[7] = Status.SlotStatus;
	CCID_card_io_buffer[8] = SlotError;
	USB_send_data_to_host(2, CCID_card_io_buffer, len + 10);
	return;
}

///////////////////////////////////////////////////////////////////////////////////
//            CCID part
//
// this is called from CCID layer (in ISR) for PC_to_RDR_XfrBlock in ISR
// 0 - all ok, data deliviering to card
// 10 - error - return CCID response to host
static uint8_t run_card(uint8_t * ccid_command)
{
	uint16_t len = ccid_command[2] << 8 | ccid_command[1];

	if (TPDU_state != T_IDLE) {
		Status.bmCommandStatus = 1;
		SlotError = 0xe0;	// slot busy;
		return 10;	// CCID header length
	}

	memcpy(CCID_card_io_buffer, ccid_command, len + 10);

// 1st frame after ATR ?
	if (pps_status == PPS_ATR_SENT) {
// if 1st frame is not PPS frame, continue with default parameters
		pps_status = PPS_OK;
// if this is PPS frame, do parsing and generate PPS for application in card
		if (ccid_command[10] == 0xff) {
			uint8_t pps_ok = 1;
			uint8_t ppslen = ccid_command[1];
			uint8_t pck = 0;

			// check PPS
			// over 255 bytes ?
			if (ccid_command[2])
				pps_ok = 0;

			// PPS1 - bitfield to length
			// (mask bit 0, T0/T1 protocol allowed)
			switch (ccid_command[11] & 0xfe) {
			case 0x00:
				if (ppslen != 3)
					pps_ok = 0;
				break;
			case 0x10:
			case 0x20:
			case 0x40:
				if (ppslen != 4)
					pps_ok = 0;
				break;
			case 0x30:
			case 0x60:
			case 0x50:
				if (ppslen != 5)
					pps_ok = 0;
				break;
			case 0x70:
				if (ppslen != 6)
					pps_ok = 0;
				break;
			default:
				pps_ok = 0;
			}
			// PCK
			while (ppslen--)
				pck ^= ccid_command[10 + ppslen];
			if (pck)
				pps_ok = 0;

			if (pps_ok != 1) {
				Status.bmCommandStatus = 1;
				SlotError = 0xfe;	// ICC MUTE
				return 10;
			}
			pps_status = PPS_READY;
		}
	} else {
		if (CCID_card_io_buffer[2] == 0) {
			// if command is below 4 bytes return error
			if (CCID_card_io_buffer[1] < 4) {
				Status.bmCommandStatus = 1;	// error
				SlotError = 1;	// slot error = wrong length (1st wrong byte at 0x01)
				return 10;
			}
			if (ReaderParam.protocol == 0) {
				// fix P3
				if (CCID_card_io_buffer[1] < 5)
					CCID_card_io_buffer[14] = 0;
				len = 5;
			}
		}
	}
	card_rx_buffer = CCID_card_io_buffer + 10;
	card_rx_len = len;
	Status.bmCommandStatus = 0;	// command ok
	SlotError = 0;		// unused for bmCommandStatus = 0
	TPDU_state = T_RUNNING;
	return 0;
}

//////////////////////////////////////////////////////////////////////////

// parse command
#define PC_to_RDR_IccPowerOn 0x62
#define PC_to_RDR_IccPowerOff 0x63
#define PC_to_RDR_GetSlotStatus 0x65
#define PC_to_RDR_XfrBlock 0x6f
#define PC_to_RDR_GetParameters 0x6c
#define PC_to_RDR_ResetParameters 0x6d
#define PC_to_RDR_SetParameters  0x61
#define PC_to_RDR_Escape  0x6b
#define PC_to_RDR_IccClock 0x6e
#define PC_to_RDR_T0APDU  0x6a
#define PC_to_RDR_Secure  0x69
#define PC_to_RDR_Mechanical 0x71
#define PC_to_RDR_Abort 0x72
#define PC_to_RDR_SetDataRateAndClockFrequency 0x73

static uint8_t RDR_to_PC_DataBlock_wrong_slot(void)
{
	Status.bmICCStatus = 2;	// No ICC present
	Status.bmCommandStatus = 1;	// failed
	SlotError = 5;		// slot does not exist (index 5 in CCID header)
	return 10;		// CCID header length
}

static uint8_t RDR_to_PC_DataBlock_busy_slot(void)
{
	Status.bmCommandStatus = 1;	// failed
	SlotError = 0xe0;	// slot busy;
	return 10;		// CCID header length
}

static void reset_ReaderParam(struct ReaderParam *rp)
{
	ReaderParam.bmFindexDindex = ATR[2];

	if (ATR[0] == 0x3b)
		ReaderParam.bmTCCKST0 = 0;	// direct
	else
		ReaderParam.bmTCCKST0 = 2;	// inverse conversion
	ReaderParam.bGuardTimeT0 = 2;
	ReaderParam.bWaitingIntegerT0 = 10;
	ReaderParam.bClockStop = 0;
	ReaderParam.bIFSC = 254;
	ReaderParam.bNadValue = 0;

	if (rp->protocol == 1) {
		ReaderParam.bmTCCKST1 = ReaderParam.bmTCCKST0 | 0x10;
		ReaderParam.bWaitingIntegersT1 = 0x95;
	}
}

static uint8_t RDR_to_PC_SlotStatus_busy_slot(void)
    __attribute__((alias("RDR_to_PC_DataBlock_busy_slot")));

static uint8_t func_PC_to_RDR_IccPowerOn(uint8_t * command, uint8_t * response)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot();

// initialize reader buffers, protocol
	ReaderParam.protocol = 0;
	pps_status = PPS_ATR_SENT;
	TPDU_state = T_IDLE;
	CPU_do_restart_main();

// ATR is always available
#define C_ATR_LEN  14
// ATR is always available
	ATR[0] = 0x3b;
	ATR[1] = 0xd5;
	ATR[2] = 0x96;
	ATR[3] = 0x02;
	ATR[4] = 0x80;
	ATR[5] = 0x31;
//      ATR[6] = 0x14;          // IFS 20
	ATR[6] = 0xfe;		// IFS 254
	ATR[7] = 0x95;
	ATR[8] = 'O';
	ATR[9] = 's';
	ATR[10] = 'E';
	ATR[11] = 'I';
	ATR[12] = 'D';
//      ATR[13] = 0x05;         // checksum (LRC)
	ATR[13] = 0xef;		// checksum (LRC)

	// copy ATR to response
	memcpy(response + 10, ATR, C_ATR_LEN);

	reset_ReaderParam(&ReaderParam);

	Status.bmCommandStatus = 0;	// command ok
	Status.bmICCStatus = 0;	// ICC present, active
	SlotError = 0;		// unused for bmCommandStatus = 0
	response[1] = C_ATR_LEN;	// set response length
	return C_ATR_LEN + 10;
}

static uint8_t func_PC_to_RDR_GetSlotStatus(uint8_t * command)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot();

	if (TPDU_state != T_IDLE) {
		Status.bmCommandStatus = 1;
		return RDR_to_PC_SlotStatus_busy_slot();
	}
	Status.bmCommandStatus = 0;	// command ok
	SlotError = 0;		// unused for bmCommandStatus = 0
	return 10;
}

static uint8_t func_PC_to_RDR_SetDataRateAndClockFrequency(uint8_t * command, uint8_t * response)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot();

	Status.bmCommandStatus = 1;

	if (TPDU_state != T_IDLE)
		return RDR_to_PC_SlotStatus_busy_slot();

	if (command[2] != 0) {
		SlotError = 1;	// slot error = wrong length (1st wrong byte at index 0x01)
		return 10;
	}
	if (command[1] != 8) {
		SlotError = 1;	// slot error = wrong length (1st wrong byte at index 0x01)
		return 10;
	}
// 3x RFU byte
	if (command[7] != 0) {
		SlotError = 7;	// slot error = wrong parameter at index 0x07
		return 10;
	}
	if (command[8] != 0) {
		SlotError = 8;	// slot error = wrong parameter at index 0x08
		return 10;
	}
	if (command[9] != 0) {
		SlotError = 9;	// slot error = wrong parameter at index 0x09
		return 10;
	}
// ignore forced parameters, return "real" values

	Status.bmCommandStatus = 0;	// command OK
	SlotError = 0;		// unused for bmCommandStatus = 0
	response[1] = 8;	// response data len

// 4.8MHz is reported in descriptor, Fi/Di 16 clock cycles per bit
	response[10] = 4800L & 255;
	response[11] = (48000L >> 8) & 255;
	response[12] = (4800L >> 16) & 255;
	response[13] = (4800L >> 24) & 255;
	response[14] = 300000L & 255;
	response[15] = (300000L >> 8) & 255;
	response[16] = (300000L >> 16) & 255;
	response[17] = (300000L >> 24) & 255;
	return 18;
}

static uint8_t func_PC_to_RDR_GetParameters(uint8_t * command, uint8_t * response)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot();

	Status.bmCommandStatus = 1;

	if (TPDU_state != T_IDLE)
		return RDR_to_PC_SlotStatus_busy_slot();

	if (command[1] != 0 && command[2] != 0) {
		SlotError = 1;	// slot error = wrong length (1st wrong byte at index 0x01)
		return 10;
	}

	reset_ReaderParam(&ReaderParam);

	Status.bmCommandStatus = 0;
	SlotError = 0;		// unused for bmCommandStatus = 0;

	memcpy(response + 9, &ReaderParam, 6 + 2 * ReaderParam.protocol);
	return 15 + 2 * ReaderParam.protocol;
}

static uint8_t func_PC_to_RDR_ResetParameters(uint8_t * command, uint8_t * response)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot();

	Status.bmCommandStatus = 1;

	if (TPDU_state != T_IDLE)
		return RDR_to_PC_SlotStatus_busy_slot();

	if (command[1] != 0 && command[2] != 0) {
		SlotError = 1;	// slot error = wrong length (1st wrong byte at index 0x01)
		return 10;
	}

	Status.bmCommandStatus = 0;
	SlotError = 0;		// unused for bmCommandStatus = 0

	memcpy(response + 9, &ReaderParam, 6 + 2 * ReaderParam.protocol);
	return 15 + 2 * ReaderParam.protocol;
}

static uint8_t func_PC_to_RDR_SetParameters(uint8_t * command, uint8_t * response)
{
	uint8_t ret_len;
	struct ReaderParam *rp;

	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot();

	Status.bmCommandStatus = 1;

	if (TPDU_state != T_IDLE)
		return RDR_to_PC_SlotStatus_busy_slot();

	if (command[2] != 0) {
		SlotError = 1;	// slot error = wrong length (1st wrong byte at 0x01)
		return 10;
	}
	if (command[7] > 1)	// only T0/T1 protocol
	{
		SlotError = 7;	// slot error = Protocol invalid or not supported (at index 7)
		return 10;
	}
	if (command[7] == 0) {
		if (command[1] != 5) {
			SlotError = 1;	// slot error = wrong length (1st wrong byte at index 0x01)
			return 10;
		}
	} else {
		if (command[1] != 7) {
			SlotError = 1;	// slot error = wrong length (1st wrong byte at index 0x01)
			return 10;
		}
	}
	ret_len = command[1] + 10;
	Status.bmCommandStatus = 0;	// command OK
	SlotError = 0;		// unused for bmCommandStatus = 0

// Do not handle baud rate convention, here no real transport is used, allow
// any value for this parameters except RFU ..
	rp = (struct ReaderParam *)(command + 9);

// check Fi, any values except RFU allowed
	switch (rp->bmFindexDindex & 0xf0) {
	case 0x70:
	case 0x80:
	case 0xe0:
	case 0xf0:
		SlotError = 10;	// slot error, 1st wrong byte at index 10
		return ret_len;
	}
// check Di, any values except RFU allowed
	if ((rp->bmFindexDindex & 0xf) > 9 || (rp->bmFindexDindex & 0xf) == 0) {
		SlotError = 10;	// slot error, 1st wrong byte at index 10
		return ret_len;
	}
// check rest ...
	if (command[7] == 0) {
// check inverse/direct convention
		if ((ATR[0] == 0x3b) && rp->bmTCCKST0 != 0) {
			SlotError = 11;	// slot error, 1st wrong byte at index 11
			return ret_len;
		}
		if ((ATR[0] == 0x3f) && rp->bmTCCKST0 != 2) {
			SlotError = 11;	// slot error, 1st wrong byte at index 11
			return ret_len;
		}
// clock stop..
		if (rp->bClockStop > 3) {
			SlotError = 14;	// slot error, 1st wrong byte at index 14
			return ret_len;
		}
	} else {
		// check if upper bits are correct
		if ((command[11] & 0xfc) != 0x10) {
			SlotError = 11;	// slot error, 1st wrong byte at index 11
			return ret_len;
		}
// check inverse/direct convention
		if ((ATR[0] == 0x3b) && (rp->bmTCCKST1 & 2) != 0) {
			SlotError = 11;	// slot error, 1st wrong byte at index 11
			return ret_len;
		}
		if ((ATR[0] == 0x3f) && (rp->bmTCCKST1 & 2) != 2) {
			SlotError = 11;	// slot error, 1st wrong byte at index 11
			return ret_len;
		}
		// CRC is not allowed
		if (rp->bmTCCKST1 & 1) {
			SlotError = 11;	// slot error, 1st wrong byte at index 11
			return ret_len;
		}
		if ((rp->bGuardTimeT1 & 0xf0) > 0x90) {
			SlotError = 13;	// slot error, 1st wrong byte at index 13
			return ret_len;
		}
		if (rp->bClockStop > 3) {
			SlotError = 14;	// slot error, 1st wrong byte at index 14
			return ret_len;
		}
		if (rp->bIFSC == 0 || command[15] == 0xff) {
			SlotError = 15;	// slot error, 1st wrong byte at index 15
			return ret_len;
		}
// check invalid NAD values
		if (rp->bNadValue == 0xff || rp->bNadValue & 0x88) {
			SlotError = 16;	// slot error, 1st wrong byte at index 16
			return ret_len;
		}
	}
// ALL ok, set parameters
	memcpy(&ReaderParam, rp, 6 + 2 * ReaderParam.protocol);
	ReaderParam.protocol = command[7];
// copy to response
	memcpy(response + 9, &ReaderParam, 6 + 2 * ReaderParam.protocol);
	return 15 + 2 * ReaderParam.protocol;
}

static uint8_t func_PC_to_RDR_IccPowerOff(uint8_t * command)
{
	// power off card in slot 0
	if (command[5] == 0) {
		if (TPDU_state != T_IDLE)
			CPU_do_restart_main();
		Status.bmICCStatus = 1;	// ICC present, inactive
		Status.bmCommandStatus = 0;	// command ok
		SlotError = 0;	// unused for bmCommandStatus = 0
		return 10;
	}
	return func_PC_to_RDR_GetSlotStatus(command);
}

static uint8_t func_Unsupported(uint8_t * command)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot();
	if (TPDU_state != T_IDLE) {
		Status.bmCommandStatus = 1;
		return RDR_to_PC_SlotStatus_busy_slot();
	}
	Status.bmCommandStatus = 1;
	SlotError = 0;		// not supported command, 1st wrong byte at index 0
	return 10;
}

static uint8_t func_PC_to_RDR_XfrBlock(uint8_t * command)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot();

// return CCID message (if returned size >0)
// or return 0 if card is running a command
	return run_card(command);
}

// check if CCID command is correct (return 0 if not)
static uint8_t CCID_check_command(uint8_t command)
{
#if 0
	switch (command) {
	case PC_to_RDR_IccPowerOn:
		return C_RDR_to_PC_DataBlock;
	case PC_to_RDR_IccPowerOff:
		return C_RDR_to_PC_SlotStatus;
	case PC_to_RDR_GetSlotStatus:
		return C_RDR_to_PC_SlotStatus;
	case PC_to_RDR_XfrBlock:
		return C_RDR_to_PC_DataBlock;
	case PC_to_RDR_GetParameters:
		return C_RDR_to_PC_Parameters;
	case PC_to_RDR_ResetParameters:
		return C_RDR_to_PC_Parameters;
	case PC_to_RDR_SetParameters:
		return C_RDR_to_PC_Parameters;
	case PC_to_RDR_Escape:
		return C_RDR_to_PC_Escape;
	case PC_to_RDR_IccClock:
		return C_RDR_to_PC_SlotStatus;
	case PC_to_RDR_T0APDU:
		return C_RDR_to_PC_SlotStatus;
	case PC_to_RDR_Secure:
		return C_RDR_to_PC_DataBlock;
	case PC_to_RDR_Mechanical:
		return C_RDR_to_PC_SlotStatus;
	case PC_to_RDR_Abort:
		return C_RDR_to_PC_SlotStatus;
	case PC_to_RDR_SetDataRateAndClockFrequency:
		return C_RDR_to_PC_DataRateAndClockFrequency;

	default:
		return 0;
	}
#else
	if (command == PC_to_RDR_IccPowerOn)
		return C_RDR_to_PC_DataBlock;
	else if (command == PC_to_RDR_IccPowerOff)
		return C_RDR_to_PC_SlotStatus;
	else if (command == PC_to_RDR_GetSlotStatus)
		return C_RDR_to_PC_SlotStatus;
	else if (command == PC_to_RDR_XfrBlock)
		return C_RDR_to_PC_DataBlock;
	else if (command == PC_to_RDR_GetParameters)
		return C_RDR_to_PC_Parameters;
	else if (command == PC_to_RDR_ResetParameters)
		return C_RDR_to_PC_Parameters;
	else if (command == PC_to_RDR_SetParameters)
		return C_RDR_to_PC_Parameters;
	else if (command == PC_to_RDR_Escape)
		return C_RDR_to_PC_Escape;
	else if (command == PC_to_RDR_IccClock)
		return C_RDR_to_PC_SlotStatus;
	else if (command == PC_to_RDR_T0APDU)
		return C_RDR_to_PC_SlotStatus;
	else if (command == PC_to_RDR_Secure)
		return C_RDR_to_PC_DataBlock;
	else if (command == PC_to_RDR_Mechanical)
		return C_RDR_to_PC_SlotStatus;
	else if (command == PC_to_RDR_Abort)
		return C_RDR_to_PC_SlotStatus;
	else if (command == PC_to_RDR_SetDataRateAndClockFrequency)
		return C_RDR_to_PC_DataRateAndClockFrequency;
	else
		return 0;
#endif
}

// return 0 or number of bytes to send back to host over BULK IN endpoint
// return can specify 1-63 bytes message only!
static uint8_t parse_command(uint8_t * command, uint16_t count)
{
	uint8_t *ccid_response = CCID_short_response;
	// fill CCID response header
	memset(ccid_response, 0, 10);
	// copy available data..
	if (count >= 6) {
		ccid_response[5] = command[5];	// copy slot number
		ccid_response[6] = command[6];	// copy seq number
	}
	Status.bmCommandStatus = 1;	// command failed
	// 1. undersized/oversized message
	// 2. check upper bytes of length in CCID header
	// 3. check length in CCID header match length of message
	if ((count < 10) || count > MaxCCIDMsgLen ||
	    (command[3] != 0) || (command[4] != 0) ||
	    (10 + command[1] + (command[2] << 8) != count)) {
		SlotError = 1;	// slot error,  1st wrong byte at index 1
		return 10;
	}
	ccid_response[0] = CCID_check_command(command[0]);
	// check if CCID command is in message
	if (ccid_response[0] == 0) {
		// no signalize error
		SlotError = 0;	// not supported command, 1st wrong byte at index 0
		ccid_response[0] = C_RDR_to_PC_SlotStatus;
		return 10;
	}
	// OK, CCID BULK OUT seems to be correct, proceed command
#if 1
	switch (command[0]) {
////////////////////////////////////////////////////////////////
	case PC_to_RDR_IccPowerOn:
		return func_PC_to_RDR_IccPowerOn(command, ccid_response);
////////////////////////////////////////////////////////////////
	case PC_to_RDR_IccPowerOff:
		return func_PC_to_RDR_IccPowerOff(command);
////////////////////////////////////////////////////////////////
	case PC_to_RDR_SetParameters:
		return func_PC_to_RDR_SetParameters(command, ccid_response);
////////////////////////////////////////////////////////////////
	case PC_to_RDR_ResetParameters:
		return func_PC_to_RDR_ResetParameters(command, ccid_response);
////////////////////////////////////////////////////////////////
	case PC_to_RDR_GetParameters:
		return func_PC_to_RDR_GetParameters(command, ccid_response);
////////////////////////////////////////////////////////////////
	case PC_to_RDR_GetSlotStatus:
		return func_PC_to_RDR_GetSlotStatus(command);
////////////////////////////////////////////////////////////////
	case PC_to_RDR_SetDataRateAndClockFrequency:
		return func_PC_to_RDR_SetDataRateAndClockFrequency(command, ccid_response);
////////////////////////////////////////////////////////////////
	case PC_to_RDR_XfrBlock:
		return func_PC_to_RDR_XfrBlock(command);
////////////////////////////////////////////////////////////////
	default:
		return func_Unsupported(command);
	}
#else
	if (command[0] == PC_to_RDR_IccPowerOn)
		return func_PC_to_RDR_IccPowerOn(command, ccid_response);
	else if (command[0] == PC_to_RDR_IccPowerOff)
		return func_PC_to_RDR_IccPowerOff(command);
	else if (command[0] == PC_to_RDR_SetParameters)
		return func_PC_to_RDR_SetParameters(command, ccid_response);
	else if (command[0] == PC_to_RDR_ResetParameters)
		return func_PC_to_RDR_ResetParameters(command, ccid_response);
	else if (command[0] == PC_to_RDR_GetParameters)
		return func_PC_to_RDR_GetParameters(command, ccid_response);
	else if (command[0] == PC_to_RDR_GetSlotStatus)
		return func_PC_to_RDR_GetSlotStatus(command);
	else if (command[0] == PC_to_RDR_SetDataRateAndClockFrequency)
		return func_PC_to_RDR_SetDataRateAndClockFrequency(command, ccid_response);
	else if (command[0] == PC_to_RDR_XfrBlock)
		return func_PC_to_RDR_XfrBlock(command);
	else
		return func_Unsupported(command);
#endif
}

void CCID_Handler_from_host(uint8_t * ccid_out, uint16_t cnt)
{
	uint8_t ret;

	// handle oversized message
	if (cnt > MaxCCIDMsgLen || CCID_message_from_host_count + cnt > MaxCCIDMsgLen) {
		CCID_message_from_host_count = MaxCCIDMsgLen + 1;
	} else {
		memcpy(CCID_message_from_host + CCID_message_from_host_count, ccid_out, cnt);
		CCID_message_from_host_count += cnt;
	}
	// wait for more bytes
	if (cnt == 64)
		return;

	LED1_RUN();

	ret = parse_command(CCID_message_from_host, CCID_message_from_host_count);
	if (ret) {
		LED1_IDLE();
		CCID_short_response[7] = Status.SlotStatus;
		CCID_short_response[8] = SlotError;
		USB_send_data_to_host(2, CCID_short_response, ret);
	}
	CCID_message_from_host_count = 0;
}

void card_io_init(void)
{
// no init here, CCID layer is initialized after USB is initialized (before main)
}

//
void card_io_start_null()
{
	null_count = 500;	// 500ms
	return;
}

void CCID_send_null(void)
{
	uint8_t msg[11];
	if (null_count == 0)
		return;
	if (null_count > 1) {
		null_count--;
		return;
	}
	LED1_BUSY();
	// null_count = 1, send message
	null_count = 500;
	memset(msg, 0, 11);
	msg[0] = 0x80;
	msg[1] = 1;
	msg[6] = CCID_card_io_buffer[6];	// seq number
	msg[7] = 0x80;
	msg[8] = 1;		// multiplier for BWT/WWT

	USB_send_data_to_host(2, msg, 11);
}

void CCID_Init()
{
	CCID_message_from_host_count = 0;
	null_count = 0;
	card_rx_len = 0;
	TPDU_state = T_IDLE;
	SlotError = 0;
	Status.SlotStatus = 0;
	Status.bmICCStatus = 1;	// ICC present, inactive
	LED1_INIT();
	LED1_IDLE();
	LED2_INIT();
	LED2_RUN();
}

// called after resume and after USB set configuration
void CCID_notify()
{
	uint8_t notify[2];

	CCID_Init();
	notify[0] = 0x50;
	notify[1] = 3;		// slot changed, card present
	USB_send_data_to_host(3, notify, 2);
}
