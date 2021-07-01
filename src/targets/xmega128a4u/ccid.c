/*
    ccid.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2021 Peter Popovec, popovec.peter@gmail.com

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

    CCID layer (T0, T1 protocol - inclusive T1 state machine) this layer
    adapt T1 protocol to OsEID card - send 1st 5 bytes of APDU to card, then
    if card request rest of APDU sent rest data.  If card return data, this
    layer request data from card by injecting GET DATA command to card.

*/
#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include "card_io.h"
#include "ccid.h"
#include "usb.h"
#include "LED.h"
#include "avr_os.h"
#include "serial_debug.h"

#define C_RDR_to_PC_DataBlock  0x80
#define C_RDR_to_PC_SlotStatus 0x81
#define C_RDR_to_PC_Parameters 0x82
#define C_RDR_to_PC_Escape     0x83
#define C_RDR_to_PC_DataRateAndClockFrequency 0x84

uint8_t SlotError __attribute__((section(".noinit")));
uint8_t pps_sent __attribute__((section(".noinit")));

//slot status:
union Slot_Status_Register {
	struct {
		uint8_t bmICCStatus:2;
		uint8_t RFU:4;
		uint8_t bmCommandStatus:2;
	};
	uint8_t SlotStatus;
} Status __attribute__((section(".noinit")));

uint8_t ATR[33] __attribute__((section(".noinit")));

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

volatile uint8_t TPDU_state __attribute__((section(".noinit")));

uint8_t card_ins __attribute__((section(".noinit")));

// card IO buffers/variables
// 0  no data for card, or data len
volatile uint16_t card_rx_len __attribute__((section(".noinit")));
uint8_t CCID_card_buffer[271] __attribute__((section(".noinit")));
uint8_t *card_rx_buffer __attribute__((section(".noinit")));

// response from card (259 bytes of response + status 2 bytes.. + 10 bytes for CCID part)
#define MAX_RESP_LEN 271
uint8_t card_response[MAX_RESP_LEN] __attribute__((section(".noinit")));
uint16_t card_response_len __attribute__((section(".noinit")));

/////////////////////////////////////////////////////////////////
// TPDU T0  handling code
//
/////////////////////////////////////////////////////////////////
#define t1_STATE_SENDING	0
#define t1_STATE_RECEIVING      1

#define MAX_T1_APDU (5+2+257+2)
uint8_t T1_APDU_buffer_recv[MAX_T1_APDU] __attribute__((section(".noinit")));
uint16_t T1_APDU_len_recv __attribute__((section(".noinit")));

// same as card_response, but without CCID part (used for retransit)
uint8_t T1_APDU_response[MAX_RESP_LEN - 10]
    __attribute__((section(".noinit")));
uint16_t T1_APDU_response_len __attribute__((section(".noinit")));

#if 0
// DEBUG function
void blink_led()
{
	uint8_t i;
	volatile uint32_t p;
	for (i = 0; i < 4; i++) {
		PORTA.OUTTGL = PIN6_bm;
		PORTA.OUTTGL = PIN5_bm;
		for (p = 30000; p > 0; p--) ;
	}
}
#endif

// NOT called from ISR
uint16_t card_io_rx(uint8_t * data, uint16_t len)
{
	uint16_t l_len;

	// wait for data from CCID layer
	while (!card_rx_len)
		CPU_idle();

	//read only requested chars, rest is discarded!
	l_len = card_rx_len;
	if (len < l_len)
		l_len = len;
	card_rx_len = 0;

	// copy data to card ..
	memcpy(data, card_rx_buffer, l_len);

	return l_len;
}

// NOT called from ISR
void card_io_tx(uint8_t * data, uint16_t len)
{
	uint8_t pps = 0;
	// do not handle data from card if CCID layer does not request data
	if (TPDU_state == T_IDLE)
		return;

	if (pps_sent == 1) {
		pps = 1;
		pps_sent = 2;
	}
	// if len == 0 65536 bytes in buffer, do not check "len"

	// T0 protocol may request rest of APDU
// for now only T0 protocol is sended to card ..
	if (ReaderParam.protocol == 0 && pps == 0) {
		if (data[0] == card_ins) {
			if (len == 1) {
				// send rest of APDU  to card
				// OsEID card can handle all APDU cases, card send single
				// INS only if rest of  APDU is needed.
				if (CCID_card_buffer[14]) {
					card_rx_buffer = CCID_card_buffer + 15;
					card_rx_len = CCID_card_buffer[14];	// max 255 bytes
					CCID_card_buffer[14] = 0;
				}
				return;
			} else {
				// in buffer: procedure byte, response, SW1,SW2
				// remove procedure byte from response
				data++;
				len--;
			}
		}
//        else
//              no procedure byte, do not check for valid SW, return as is to host
	}
	// return response to host
	if (card_response_len + len > MAX_RESP_LEN)
		len = MAX_RESP_LEN - card_response_len;
	memcpy(card_response + card_response_len, data, len);
	card_response_len += len;
	// update size in CCID header
	card_response[1] = (card_response_len - 10) & 0xff;
	card_response[2] = (card_response_len - 10) >> 8;
	TPDU_state = T_IDLE;
	CCID_response_to_host(card_response, card_response_len);
	return;
}

void card_io_start_null()
{
	CCID_start_null(card_response[6]);	//seq number
	return;
}

void card_io_stop_null()
{
	return;
}

///////////////////////////////////////////////////////////////////////////////////
//            CCID part
//
// this is called from CCID layer (in ISR) for PC_to_RDR_XfrBlock in ISR
// 0 - all ok, data deliviering to card
// 1 - error
static int8_t run_card(uint8_t * ccid_command, uint8_t * response)
{
//  uint8_t ret;
//  uint16_t t1_size = 0;

// PPS ? (1st frame after ATR)
	if (ccid_command[10] == 0xff && pps_sent == 0) {
		uint8_t pps_ok = 1;
		uint8_t len = ccid_command[1];
		uint8_t pck = 0;

		// check PPS
		// over 255 bytes ?
		if (ccid_command[2])
			pps_ok = 0;

		// PPS1 - bitfield to legth
		switch (ccid_command[11] & 0xfe) {
		case 0x00:
			if (len != 3)
				pps_ok = 0;
			break;
		case 0x10:
		case 0x20:
		case 0x40:
			if (len != 4)
				pps_ok = 0;
			break;
		case 0x30:
		case 0x60:
		case 0x50:
			if (len != 5)
				pps_ok = 0;
			break;
		case 0x70:
			if (len != 7)
				pps_ok = 0;
			break;
		}
		// PCK
		while (len--)
			pck ^= ccid_command[10 + len];
		if (pck)
			pps_ok = 0;
		if (TPDU_state != T_IDLE) {
			Status.bmCommandStatus = 1;
			response[7] = Status.SlotStatus;
			response[8] = 0xe0;	// slot busy;
			return 10;	// CCID header length
		}

		if (pps_ok != 1) {
			Status.bmCommandStatus = 1;
			response[7] = Status.SlotStatus;
			response[8] = 0xfe;	// ICC MUTE
			return 10;
		}

		memcpy(CCID_card_buffer, ccid_command, 16);
		card_rx_buffer = CCID_card_buffer + 10;
		card_rx_len = ccid_command[1];

		Status.bmCommandStatus = 0;	// command ok
		response[7] = Status.SlotStatus;
		response[8] = SlotError;

		TPDU_state = T_RUNNING;
		memcpy(card_response, response, 10);
		// offset for response
		card_response_len = 10;
		pps_sent = 1;
		return 0;
	}

	if (TPDU_state == T_IDLE) {
		// just copy ccid data into CCID_card_buffer
		memcpy(CCID_card_buffer, ccid_command, 271);
	} else {
		Status.bmCommandStatus = 1;
		response[7] = Status.SlotStatus;
		response[8] = 0xe0;	// slot busy;
		return 10;	// CCID header length
	}
	// prepare response
	memcpy(card_response, response, 10);
	if (CCID_card_buffer[2] == 0) {
		// if command is below 4 bytes return error
		if (CCID_card_buffer[1] < 4) {
			Status.bmCommandStatus = 1;	// error
			SlotError = 1;	// wrong len
			return 1;
		}
		// normal command, no data
		if (CCID_card_buffer[1] < 5) {
			// append LC
			CCID_card_buffer[1] = 5;
			CCID_card_buffer[14] = 0;
		}
	}
	card_ins = CCID_card_buffer[11];
/*
// check if command is correct
#if 0
  if (card_ins & 1 || (card_ins & 0xf0) == 0x60 || (card_ins & 0xf0) == 0x90)
#else
// Allow reader to send odd command as defined in ISO
// card is responsible to handle errors or disable odd commands (T0 proto)
  if ((card_ins & 0xf0) == 0x60 || (card_ins & 0xf0) == 0x90)
#endif
    {
      Status.bmCommandStatus = 1;
      SlotError = 11;		// wrong command
      response[7] = Status.SlotStatus;
      response[8] = SlotError;
      return 10;
    }
*/
// send command to card (card software wait for card_rx_len in busy loop)

	card_rx_buffer = CCID_card_buffer + 10;
	if (ReaderParam.protocol == 0)
		card_rx_len = 5;
	else
		card_rx_len = ccid_command[2] << 8 | ccid_command[1];;

	TPDU_state = T_RUNNING;
// CCID header is already prepared, set only status/error
	Status.bmCommandStatus = 0;	// command ok

	card_response[7] = Status.SlotStatus;
	card_response[8] = SlotError;

	// offset for response
	card_response_len = 10;
	return 0;

// TODO: if card  main() get locked (by sw error etc), here timer must be
// started and main must be restarted by CPU_do_restart_main() (timeout
// message from ccid layer must be sended too)

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

static int8_t RDR_to_PC_DataBlock_wrong_slot(uint8_t * l_response)
{
	l_response[7] = 0x42;	// No ICC present, command failed error in error reg
	l_response[8] = 5;	// slot does not exist;
	return 10;		// CCID header length
}

static int8_t RDR_to_PC_DataBlock_busy_slot(uint8_t * response)
{
	Status.bmCommandStatus = 1;
	response[7] = Status.SlotStatus;
	response[8] = 0xe0;	// slot busy;
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

//static void RDR_to_PC_DataBlock_busy_slot(uint8_t *l_responsel) __attribute__((alias ("RDR_to_PC_SlotStatus_busy_slot")));
static int8_t RDR_to_PC_SlotStatus_busy_slot(uint8_t * l_responsel)
    __attribute__((alias("RDR_to_PC_DataBlock_busy_slot")));

static int8_t func_PC_to_RDR_IccPowerOn(uint8_t * command, uint8_t * response)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot(response);

// initialize reader buffers, protocol
	T1_APDU_len_recv = 0;
	ReaderParam.protocol = 0;
	pps_sent = 0;
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

	//copy ATR to respone
	memcpy(response + 10, ATR, C_ATR_LEN);

	reset_ReaderParam(&ReaderParam);

	Status.bmCommandStatus = 0;	// command ok
	Status.bmICCStatus = 0;	//ICC present, active
	response[7] = Status.SlotStatus;
	response[8] = SlotError;
	response[1] = C_ATR_LEN;	// set response length
	return C_ATR_LEN + 10;
}

static int8_t func_PC_to_RDR_GetSlotStatus(uint8_t * command, uint8_t * response)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot(response);

	if (TPDU_state != T_IDLE) {
		Status.bmCommandStatus = 1;
		return RDR_to_PC_SlotStatus_busy_slot(response);
	}
	Status.bmCommandStatus = 0;	// command ok
	response[7] = Status.SlotStatus;
	response[8] = SlotError;
	return 10;
}

static int8_t func_PC_to_RDR_SetDataRateAndClockFrequency(uint8_t * command, uint8_t * response)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot(response);

	Status.bmCommandStatus = 1;
	response[7] = Status.SlotStatus;

	if (TPDU_state != T_IDLE)
		return RDR_to_PC_SlotStatus_busy_slot(response);

	if (command[2] != 0) {
		response[8] = 1;	// slot error = wrong length
		return 10;
	}
	if (command[1] != 8) {
		response[8] = 1;	// slot error = wrong length
		return 10;
	}
// 3x RFU byte
	if (command[7] != 0) {
		response[8] = 7;	// slot error = wrong parameter
		return 10;
	}
	if (command[8] != 0) {
		response[8] = 8;	// slot error = wrong parameter
		return 10;
	}
	if (command[9] != 0) {
		response[8] = 9;	// slot error = wrong parameter
		return 10;
	}

// ignore forced parameters, return "real" values

	Status.bmCommandStatus = 0;	// command OK
	response[7] = Status.SlotStatus;
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

static int8_t func_PC_to_RDR_GetParameters(uint8_t * command, uint8_t * response)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot(response);

	Status.bmCommandStatus = 1;
	response[7] = Status.SlotStatus;

	if (TPDU_state != T_IDLE)
		return RDR_to_PC_SlotStatus_busy_slot(response);

	if (command[1] != 0 && command[2] != 0) {
		response[8] = 1;	// slot error = wrong length
		return 10;
	}

	reset_ReaderParam(&ReaderParam);

	Status.bmCommandStatus = 0;
	response[7] = Status.SlotStatus;

	memcpy(response + 9, &ReaderParam, 6 + 2 * ReaderParam.protocol);
	if (ReaderParam.protocol == 1) {
		T1_APDU_len_recv = 0;
		T1_APDU_response_len = 0;
	}
	return 15 + 2 * ReaderParam.protocol;
}

static int8_t func_PC_to_RDR_ResetParameters(uint8_t * command, uint8_t * response)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot(response);

	Status.bmCommandStatus = 1;
	response[7] = Status.SlotStatus;

	if (TPDU_state != T_IDLE)
		return RDR_to_PC_SlotStatus_busy_slot(response);

	if (command[1] != 0 && command[2] != 0) {
		response[8] = 1;	// slot error = wrong length
		return 10;
	}

	Status.bmCommandStatus = 0;
	response[7] = Status.SlotStatus;

	memcpy(response + 9, &ReaderParam, 6 + 2 * ReaderParam.protocol);
	if (ReaderParam.protocol == 1) {
		T1_APDU_len_recv = 0;
		T1_APDU_response_len = 0;
	}
	return 15 + 2 * ReaderParam.protocol;
}

static int8_t func_PC_to_RDR_SetParameters(uint8_t * command, uint8_t * response)
{
	int8_t ret_len;
	struct ReaderParam *rp;

	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot(response);

	Status.bmCommandStatus = 1;
	response[7] = Status.SlotStatus;

	if (TPDU_state != T_IDLE)
		return RDR_to_PC_SlotStatus_busy_slot(response);

	if (command[2] != 0) {
		SlotError = 1;	// slot error = wrong length (1st wrong byte at 0x01)
		response[8] = 1;
		return 10;
	}
	if (command[7] > 1)	// only T0/T1 protocol
	{
		SlotError = 7;	// slot error = Protocol invalid or not supported
		response[8] = 7;
		return 10;
	}
	if (command[7] == 0) {
		if (command[1] != 5) {
			SlotError = 1;	// slot error = wrong length (1st wrong byte at 0x01)
			response[8] = 1;
			return 10;
		}
	} else {
		if (command[1] != 7) {
			SlotError = 1;	// slot error = wrong length (1st wrong byte at 0x01)
			response[8] = 1;
			return 10;
		}
	}
	ret_len = command[1] + 10;
	SlotError = 0;
	Status.bmCommandStatus = 0;	// command OK
	response[7] = Status.SlotStatus;

// Do not handle baud rate convention, here no real transport is used, allow
// any value for this parameters except RFU ..
	rp = (struct ReaderParam *)(command + 9);

// check Fi, any values exceprt RFU allowed
	switch (rp->bmFindexDindex & 0xf0) {
	case 0x70:
	case 0x80:
	case 0xe0:
	case 0xf0:
		SlotError = 10;
		return ret_len;
	}
// check Di, any values exceprt RFU allowed
	if ((rp->bmFindexDindex & 0xf) > 9 || (rp->bmFindexDindex & 0xf) == 0) {
		SlotError = 10;
		return ret_len;
	}
// check rest ...
	if (command[7] == 0) {
// check inverse/direct convention
		if ((ATR[0] == 0x3b) && rp->bmTCCKST0 != 0) {
			SlotError = 11;
			return ret_len;
		}
		if ((ATR[0] == 0x3f) && rp->bmTCCKST0 != 2) {
			SlotError = 11;
			return ret_len;
		}
// clock stop..
		if (rp->bClockStop > 3) {
			SlotError = 14;
			return ret_len;
		}
	} else {
		// check if upper bits are correct
		if ((command[11] & 0xfc) != 0x10) {
			SlotError = 11;
			return ret_len;
		}
// check inverse/direct convention
		if ((ATR[0] == 0x3b) && (rp->bmTCCKST1 & 2) != 0) {
			SlotError = 11;
			return ret_len;
		}
		if ((ATR[0] == 0x3f) && (rp->bmTCCKST1 & 2) != 2) {
			SlotError = 11;
			return ret_len;
		}
		// CRC is not allowed
		if (rp->bmTCCKST1 & 1) {
			SlotError = 11;
			return ret_len;
		}
		if ((rp->bGuardTimeT1 & 0xf0) > 0x90) {
			SlotError = 13;
			return ret_len;
		}
		if (rp->bClockStop > 3) {
			SlotError = 14;
			return ret_len;
		}
		if (rp->bIFSC == 0 || command[15] == 0xff) {
			SlotError = 15;
			return ret_len;
		}
// check invalid NAD values
		if (rp->bNadValue == 0xff || rp->bNadValue & 0x88) {
			SlotError = 16;
			return ret_len;
		}
	}
// ALL ok, set parameters
	memcpy(&ReaderParam, rp, 6 + 2 * ReaderParam.protocol);
	ReaderParam.protocol = command[7];
// copy to response
	memcpy(response + 9, &ReaderParam, 6 + 2 * ReaderParam.protocol);
	if (ReaderParam.protocol == 1) {
		T1_APDU_len_recv = 0;
		T1_APDU_response_len = 0;
	}
	return 15 + 2 * ReaderParam.protocol;
}

static int8_t func_PC_to_RDR_IccPowerOff(uint8_t * command, uint8_t * response)
{
	// power off card in slot 0
	if (command[5] == 0) {
		if (TPDU_state != T_IDLE)
			CPU_do_restart_main();
		Status.bmICCStatus = 1;	//ICC present, inactive
		Status.bmCommandStatus = 0;	// command ok
		response[7] = Status.SlotStatus;
		response[8] = SlotError;
		return 10;
	}
	return func_PC_to_RDR_GetSlotStatus(command, response);
}

static int8_t func_Unsupported(uint8_t * command, uint8_t * response)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot(response);
	if (TPDU_state != T_IDLE) {
		Status.bmCommandStatus = 1;
		return RDR_to_PC_SlotStatus_busy_slot(response);
	}
	Status.bmCommandStatus = 1;
	SlotError = 0;		//not supported command
	response[7] = Status.SlotStatus;
	response[8] = SlotError;
	return 10;
}

static int8_t func_PC_to_RDR_XfrBlock(uint8_t * command, uint8_t * response)
{
	if (command[5] != 0)	// wrong slot
		return RDR_to_PC_DataBlock_wrong_slot(response);

// return CCID message (if returned size >0)
// or return 0 if card is running a command
	return run_card(command, response);
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

// CCID parser, maximal length of data 271 bytes

// return 0 or number of bytes to send back to host over BULK IN endpoint
// return can specify 1-63 bytes message only!
// -1 is used to signalize more data needed (incomplette message)
// return codes 64..127 and -128..-2 reserved
int8_t parse_command(uint8_t * command, uint16_t count, uint8_t * ccid_response)
{
	// TODO TODO checking of CCID BULK OUT mesage is not fully
	// implemented due incomplette documentation of CCID class

	// ignore short message (below CCID header size)
	// this handle ZLP too..
	if (count == 0)
		return -1;

	// fill CCID response header
	ccid_response[1] = 0;
	ccid_response[2] = 0;
	ccid_response[3] = 0;
	ccid_response[4] = 0;
	ccid_response[5] = command[5];	//copy slot number
	ccid_response[6] = command[6];	//copy seq number
	ccid_response[7] = 0x40;	// command failed
	ccid_response[8] = 0;	// slot error = unsupported command
	ccid_response[9] = 0;

	ccid_response[0] = CCID_check_command(command[0]);
	// check if CCID command is in message
	if (ccid_response[0] == 0) {
		// no signalize error
		ccid_response[0] = C_RDR_to_PC_SlotStatus;
		return 10;
	}
	if ((count < 10) ||
	    ((command[1] + (command[2] << 8)) > 261) || (command[3] != 0) || (command[4] != 0)) {
		ccid_response[8] = 1;	// slot error = wrong length
		return 10;
	}
	// check if message data part correspond to data size in ccid header
	{
		uint16_t len = 10 + command[1] + (command[2] << 8);

		if (count < len) {
			// BULK OUT message not complette (receiving in chunk of 64 bytes)
			if ((count % 64) == 0)
				return -1;
			// this is definitively short BULK OUT message (size in header
			// not correspond to real received data size)
			// TODO how handle this ?
			// now reporting wrong size
			ccid_response[8] = 1;	// slot error = wrong length
			return 10;
		}
		// TODO
		// zeroize oversized data or report error?
		//
		if (len < count) {
			memset(command + len, 0, 271 - len);
			count = len;
		}
	}
	// OK, CCID BULK OUT seems to be correct, proceed command
#if 1
	switch (command[0]) {
////////////////////////////////////////////////////////////////
	case PC_to_RDR_IccPowerOn:
		return func_PC_to_RDR_IccPowerOn(command, ccid_response);
////////////////////////////////////////////////////////////////
	case PC_to_RDR_IccPowerOff:
		return func_PC_to_RDR_IccPowerOff(command, ccid_response);
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
		return func_PC_to_RDR_GetSlotStatus(command, ccid_response);
////////////////////////////////////////////////////////////////
	case PC_to_RDR_SetDataRateAndClockFrequency:
		return func_PC_to_RDR_SetDataRateAndClockFrequency(command, ccid_response);
////////////////////////////////////////////////////////////////
	case PC_to_RDR_XfrBlock:
		return func_PC_to_RDR_XfrBlock(command, ccid_response);
////////////////////////////////////////////////////////////////
	default:
		return func_Unsupported(command, ccid_response);
	}
#else
	if (command[0] == PC_to_RDR_IccPowerOn)
		return func_PC_to_RDR_IccPowerOn(command, ccid_response);
	else if (command[0] == PC_to_RDR_IccPowerOff)
		return func_PC_to_RDR_IccPowerOff(command, ccid_response);
	else if (command[0] == PC_to_RDR_SetParameters)
		return func_PC_to_RDR_SetParameters(command, ccid_response);
	else if (command[0] == PC_to_RDR_ResetParameters)
		return func_PC_to_RDR_ResetParameters(command, ccid_response);
	else if (command[0] == PC_to_RDR_GetParameters)
		return func_PC_to_RDR_GetParameters(command, ccid_response);
	else if (command[0] == PC_to_RDR_GetSlotStatus)
		return func_PC_to_RDR_GetSlotStatus(command, ccid_response);
	else if (command[0] == PC_to_RDR_SetDataRateAndClockFrequency)
		return func_PC_to_RDR_SetDataRateAndClockFrequency(command, ccid_response);
	else if (command[0] == PC_to_RDR_XfrBlock)
		return func_PC_to_RDR_XfrBlock(command, ccid_response);
	else
		return func_Unsupported(command, ccid_response);
#endif
}

/** Configures the board hardware and chip peripherals for the demo's functionality. */
void card_io_init(void)
{
// no init here, CCID layer is initialized after USB is initialized (before main)
}

// called from USB_Init()

void CCID_Init()
{
	TPDU_state = T_IDLE;
	SlotError = 0;
	Status.SlotStatus = 0;
	Status.bmICCStatus = 1;	//ICC present, inactive
	LED1_INIT();
	LED1_IDLE();
	LED2_INIT();
	LED2_RUN();
}
