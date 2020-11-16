/*
    ccid.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2020 Peter Popovec, popovec.peter@gmail.com

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


uint8_t SlotError __attribute__((section (".noinit")));
uint8_t reader_protocol __attribute__((section (".noinit")));

//slot status:
union Slot_Status_Register
{
  struct
  {
    uint8_t bmICCStatus:2;
    uint8_t RFU:4;
    uint8_t bmCommandStatus:2;
  };
  uint8_t SlotStatus;
} Status __attribute__((section (".noinit")));

uint8_t ATR[33] __attribute__((section (".noinit")));

enum TPDU_states
{
  T_IDLE,
  T_RUNNING,
};

volatile uint8_t TPDU_state __attribute__((section (".noinit")));

uint8_t card_ins __attribute__((section (".noinit")));

// card IO buffers/variables
// 0  no data for card, or data len
volatile uint16_t card_rx_len __attribute__((section (".noinit")));
uint8_t CCID_card_buffer[271] __attribute__((section (".noinit")));
uint8_t *card_rx_buffer __attribute__((section (".noinit")));

// response from card (259 bytes of response + status 2 bytes.. + 10 bytes for CCID part)
#define MAX_RESP_LEN 271
uint8_t card_response[MAX_RESP_LEN] __attribute__((section (".noinit")));
uint16_t card_response_len __attribute__((section (".noinit")));



/////////////////////////////////////////////////////////////////
// TPDU T0  handling code
//
/////////////////////////////////////////////////////////////////
#define t1_STATE_SENDING	0
#define t1_STATE_RECEIVING      1

/* I block */
#define T1_I_SEQ_SHIFT          6

/* R block */
#define T1_IS_ERROR(pcb)        ((pcb) & 0x0F)
#define T1_EDC_ERROR            0x01
#define T1_OTHER_ERROR          0x02
#define T1_R_SEQ_SHIFT          4

/* S block stuff */
#define T1_S_IS_RESPONSE(pcb)   ((pcb) & T1_S_RESPONSE)
#define T1_S_TYPE(pcb)          ((pcb) & 0x0F)
#define T1_S_RESPONSE           0x20
#define T1_S_RESYNC             0x00
#define T1_S_IFS                0x01
#define T1_S_ABORT              0x02
#define T1_S_WTX                0x03

#define swap_nibbles(x) ( (x >> 4) | ((x & 0xF) << 4) )

#define F_IFS_REQUEST 0xc1
#define F_IFS_RESPONSE 0xe1
#define F_ABORT_REQUEST 0xc2
#define F_ABORT_RESPONSE 0xe2
#define F_RESYNC_REQUEST 0xc0
#define F_RESYNC_RESPONSE 0xe0
#define F_WTX_REQUEST 0xc3
#define F_WTX_RESPONSE 0xe3
#define T1_NAD 0
#define T1_PCB 1
#define T1_LEN 2
#define T1_DATA 3
// xmega uses 64 bytes USB packet
// limit max size: (T1 protocol 48 bytes) + (10 bytes CCID header) < 64
#define F_IFS_SIZE 48

#define MAX_T1_APDU (5+2+257+2)
uint8_t T1_APDU_buffer_recv[MAX_T1_APDU] __attribute__((section (".noinit")));
uint16_t T1_APDU_len_recv __attribute__((section (".noinit")));

// same as card_response, but without CCID part (used for retransit)
uint8_t T1_APDU_response[MAX_RESP_LEN - 10]
  __attribute__((section (".noinit")));
uint16_t T1_APDU_response_len __attribute__((section (".noinit")));

struct t1
{
  uint8_t ifd_send_chain;	// 0/0x20 if IFD send a chained I blocks
  uint8_t icc_send_chain;
  uint8_t receive_only;
  uint8_t need_ack;		// icc sended I frame, and need acknowledge
  uint8_t ifs_icc;		// Information size for ICC sending
  uint8_t ifs_ifd;		// size for CCID proto receiving
  uint8_t n_icc;		// sequence number - for ICC
  uint8_t n_ifd;		// sequence number - for IFD
  uint8_t wtx;			// waiting time
  uint8_t prev_S[4];		// copy of last sended S request
  uint8_t prev[4];		// copy of last sended frame
  uint8_t last_len;
} t1 __attribute__((section (".noinit")));

static void
t1_init ()
{
  t1.ifd_send_chain = 0;
  t1.icc_send_chain = 0;
  t1.receive_only = 0;		// only receive, do not send any I frame
  t1.need_ack = 0;
  t1.n_icc = 0;
  t1.n_ifd = 0;
  t1.ifs_icc = 32;
  t1.ifs_ifd = 32;
  t1.wtx = 0;
  t1.prev_S[T1_PCB] = 0;	// no sended S frame
  t1.prev[T1_PCB] = 1;		//no previous block
}

// calculate lrc of frame
static uint8_t
t1_lrc (uint8_t * f1_rblock, uint8_t rlen)
{
  uint8_t ret = 0;

  while (rlen--)
    ret ^= *f1_rblock++;
  return ret;
}

// parse T1 frame at t1_data
// construct response T1 frame or APDU in t1_data
// return back response frame in t1_data
// return value 1 - T1 response
// return value 2 = APDU ready
// return value 0 - no T1 response to host



static uint8_t
t1_send_data (uint8_t * buffer)
{
  uint8_t len = t1.ifs_ifd;

// do not use reader IFS, xmega USB transport uses max 63 bytes
  if (len > F_IFS_SIZE)
    len = F_IFS_SIZE;

  if (T1_APDU_response_len < len)
    len = T1_APDU_response_len;

  buffer[T1_PCB] = (t1.n_icc << 1);	// seq. bit
  buffer[T1_LEN] = len;

  if (T1_APDU_response_len - len > 0)
    buffer[T1_PCB] |= 0x20;	// chain bit set

  memcpy (buffer + 3, T1_APDU_response, len);
  t1.last_len = len;
  return len;
}

static void
t1_next_data ()
{
  uint8_t len = t1.last_len;

  T1_APDU_response_len -= len;
  memcpy (T1_APDU_response, T1_APDU_response + len, T1_APDU_response_len);
}

#if 0
// DEBUG function
void
blink_led ()
{
  uint8_t i;
  volatile uint32_t p;
  for (i = 0; i < 4; i++)
    {
      PORTA.OUTTGL = PIN6_bm;
      PORTA.OUTTGL = PIN5_bm;
      for (p = 30000; p > 0; p--);
    }
}
#endif
// Please read iso7816-3 for Rules/Scenarios io some comment is non self explained

static uint8_t
T1_wrapper (uint8_t * t1_data, uint16_t t1_len)
{
  uint8_t seq;

// ERROR frame checking
// timeout -  ICC (this code) ignore any timeouts, IFD generate T1_wrapper_frame_error
// BWT, CWT is ignored in this code too, this is not real ISO7816-1/2 transmision,
// all data comes from USB CCID layer.

// 1st check if frame is ok, assume received frame length is correct
  if (t1_lrc (t1_data, t1_len))
    {
      t1_data[T1_PCB] = 0x81;
      goto T1_wrapper_frame_error;
    }

// check frame parameters ..
  if ((t1_len < 4) || t1_data[T1_LEN] == 0xff ||
      t1_data[T1_NAD] != 0 || t1_len - 4 != t1_data[T1_LEN])
    {
      t1_data[T1_PCB] = 0x82;;
      goto T1_wrapper_frame_error;
    }

// ICC is waiting S response frame ? Rule 8, Scenario 14.2, 15.3,  16.2, 17.3
  if ((t1.prev_S[T1_PCB] & 0xec) == 0xc0)
    {
      t1.prev_S[T1_PCB] = 0;	// clear request, only one retransmision is allowed
// response to different S frame ?
      if ((t1_data[T1_PCB] | 0x20) != t1.prev_S[T1_PCB])
	goto T1_wrapper_frame_error;
// non matching len/data ?
      if (t1_data[T1_LEN])
	if (t1.prev_S[T1_DATA] != t1_data[T1_DATA])
	  goto T1_wrapper_frame_error;
// correct response received
      return 0;			// do not send any frame OsEID request only ABORT, and then goes into receiving mode
    }

// S request handling
  if ((t1_data[T1_PCB] & 0xec) == 0xc0)
    {
      //check length of request (1 byte for IFS and WTX request)
      if ((t1_data[T1_PCB] & 1) != t1_data[T1_LEN])
	goto T1_wrapper_other_error;
      t1.receive_only = 0;	// clear error
      // turn request to response, handle request functions
      t1_data[T1_PCB] |= 0x20;
      if ((t1_data[T1_PCB] & 3) == 0)	// resync
	t1_init ();
      else if ((t1_data[T1_PCB] & 3) == 1)	//
	t1.ifs_ifd = t1_data[3];	// here check for range 32..254 ?
      else if ((t1_data[T1_PCB] & 3) == 3)	//
	t1.wtx = t1_data[T1_DATA];
      goto T1_wrapper_response;
    }

// R frame handling
  if ((t1_data[T1_PCB] & 0xec) == 0x80 && (t1_data[T1_PCB] & 3) < 3)
    {
      if (t1_data[T1_LEN] != 0)	// LEN !=0
	goto T1_wrapper_other_error;

// R frame as response to S request is already handled above
      if (!(t1.need_ack))
	goto T1_wrapper_other_error;

// This R frame request retransmit of previous I frame or
// transmit new I frame, test seq. number
      seq = (t1_data[T1_PCB] & 0x10) << 1;

// if this R frame is type "No error" sequence number must signalize next frame
// or same sequence number can be arrived only if this R frame signalize error
      if ((seq != t1.n_icc) ^ ((t1_data[T1_PCB] & 3) == 0))
	goto T1_wrapper_other_error;

// ok, data can be sended (retransmit or next data)
      if (seq != t1.n_icc)
	{
	  t1_next_data ();
	  t1.n_icc = seq;
	  t1.need_ack = 0;
	}
      if (t1_send_data (t1_data))
	{
	  t1.need_ack = 1;
	  goto T1_wrapper_return_frame;
	}
      return 0;
    }

// I frame test
  if ((t1_data[T1_PCB] & 0x9f) == 0)
    {
      // I frame is not alowed if ICC transmit a chain
      if (t1.icc_send_chain)
	goto T1_wrapper_other_error;
      // test expected seq. number ..
      seq = (t1_data[T1_PCB] & 0x40) >> 1;
      if (seq != t1.n_ifd)
	goto T1_wrapper_other_error;

      // save chain bit .. (if IFD send chain, do not send I frames back)
      t1.ifd_send_chain = t1_data[T1_PCB] & 0x20;
      // next sequence number
      seq ^= 0x20;		// warning seq is used below too!
      t1.n_ifd = seq;
      // this frame is acknowledge for previous sended "I" frame ..
      t1.receive_only = 0;	// clear error
      if (t1.need_ack)
	{
	  t1.n_icc ^= 0x20;
	  t1_next_data ();
	  t1.need_ack = 0;
	}
      // is space in buffer ?
      if (T1_APDU_len_recv + t1_data[T1_LEN] > MAX_T1_APDU)
	{
	  t1_data[T1_PCB] = F_ABORT_REQUEST;
	  t1_data[T1_LEN] = 0;
	  goto T1_wrapper_response;
	}
      // save data in buffer
      memcpy (T1_APDU_buffer_recv + T1_APDU_len_recv, t1_data + 3,
	      t1_data[T1_LEN]);
      T1_APDU_len_recv += t1_data[T1_LEN];
      // this is last frame ? (run ADPU in card)
      if ((t1_data[T1_PCB] & 0x20) == 0)
	return 2;
      // send back R frame = confirm receiving of I frame
      t1_data[T1_PCB] = 0x80 | (seq >> 1);
      t1_data[T1_LEN] = 0;
      goto T1_wrapper_response;
    }

// unknown frame error
T1_wrapper_other_error:
// send R frame with expected seq. number
  t1_data[T1_PCB] = 0x82 | (t1.n_ifd >> 1);

//T1_wrapper_R:
  t1_data[T1_LEN] = 0;
/*
Do not enable this, always send new R frame, TODO .. check ISO ..
// check if previous block is R
  if ((t1.prev[1] & 0xec) == 0x80 && (t1.prev[1] & 3) < 3)
    {
      // Rule 7.4.3
      if (t1.receive_only)
	return 0;
      // previous block is R block, repeat this block
      t1_data[T1_PCB] = t1.prev[1];
      t1.receive_only = 1;
    }
*/
T1_wrapper_response:
// copy last frame
  memcpy (t1.prev, t1_data, 4);
// copy last S request frame sended
  if ((t1_data[T1_PCB] & 0xec) == 0xc0)
    memcpy (t1.prev_S, t1_data, 4);

T1_wrapper_return_frame:
  t1_data[T1_NAD] = 0;
  t1_data[t1_data[T1_LEN] + 3] = t1_lrc (t1_data, t1_data[T1_LEN] + 3);
  return 1;


////////////////////////////////////////////////////////////////
// arrived frame with error
//
T1_wrapper_frame_error:
// Rule 7.4.3 - do not repeat S frame or R frame after second attempt
  if (t1.receive_only)
    return 0;			// nothing to do
  t1.receive_only = 1;
// is this frame failed response to S request ?
// Scenario 14.2, 15.3,  16.2, 17.3,
  if ((t1.prev_S[T1_PCB] & 0xec) == 0xc0)
    memcpy (t1_data, t1.prev_S, 4);
  else
    {
// send R frame with expected sequence number
      t1_data[T1_PCB] |= (t1.n_ifd >> 1);
      t1_data[T1_LEN] = 0;
    }
  memcpy (t1.prev, t1_data, 4);
  goto T1_wrapper_return_frame;
}

// not ISR routine, send card response as T1 I frame
static void
T1_return_data ()
{
  uint8_t buffer[63];
  uint16_t size = card_response_len - 10;
  uint8_t *t1_data = buffer + 10;

// save data for retransmit (but not CCID part!)
  memcpy (T1_APDU_response, card_response + 10, size);
  T1_APDU_response_len = size;

  memcpy (buffer, card_response, 10);	// CCID part

  t1_data[T1_NAD] = 0;
  size = t1_send_data (t1_data);

  // CCID header ..
  buffer[1] = size + 4;		// add 4 bytes for CCID frame (NAD,PCB,SIZE,LRC)
  buffer[2] = 0;

  t1_data[t1_data[T1_LEN] + 3] = t1_lrc (t1_data, t1_data[T1_LEN] + 3);
  t1.need_ack = 1;
  CCID_response_to_host (buffer, size + 14);	// 10 CCID, 4 for T1 frame
}

// NOT called from ISR
uint16_t
card_io_rx (uint8_t * data, uint16_t len)
{
  uint16_t l_len;

  // wait for data from CCID layer
  while (!card_rx_len)
    CPU_idle ();

  //read only requested chars, rest is discarded!
  l_len = card_rx_len;
  if (len < l_len)
    l_len = len;
  card_rx_len = 0;

  // copy data to card ..
  memcpy (data, card_rx_buffer, l_len);

  if (reader_protocol)
    return l_len | 0x8000;
  return l_len;
}

// NOT called from ISR
uint8_t
card_io_tx (uint8_t * data, uint16_t len)
{
  // do not handle data from card if CCID layer does not request data
  if (TPDU_state == T_IDLE)
    return 0;

  // if len == 0 65536 bytes in buffer, do not check "len"

  // T0 protocol may request rest of APDU
// for now only T0 protocol is sended to card ..
  if (reader_protocol == 0)
    {
      if (data[0] == card_ins)
	{
	  if (len == 1)
	    {
	      // send rest of APDU  to card
	      // OsEID card can handle all APDU cases, card send single
	      // INS only if rest of  APDU is needed.
	      if (CCID_card_buffer[14])
		{
		  card_rx_buffer = CCID_card_buffer + 15;
		  card_rx_len = CCID_card_buffer[14];	// max 255 bytes
		  CCID_card_buffer[14] = 0;
		}
	      return 0;
	    }
	  else
	    {
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
  memcpy (card_response + card_response_len, data, len);
  card_response_len += len;
  // update size in CCID header
  card_response[1] = (card_response_len - 10) & 0xff;
  card_response[2] = (card_response_len - 10) >> 8;
  TPDU_state = T_IDLE;
  if (reader_protocol == 1)
    T1_return_data ();
  else
    CCID_response_to_host (card_response, card_response_len);
  return 0;
}

void
card_io_start_null ()
{
  CCID_start_null (card_response[6]);	//seq number
  return;
}

void
card_io_stop_null ()
{
  return;
}

///////////////////////////////////////////////////////////////////////////////////
//            CCID part
//
// this is called from CCID layer (in ISR) for PC_to_RDR_XfrBlock in ISR
// 0 - all ok, data deliviering to card
// 1 - error
static int8_t
run_card (uint8_t * ccid_command, uint8_t * response)
{
  uint8_t ret;
  uint16_t t1_size = 0;

  if (reader_protocol == 1)
    {
      // T1 protocol
      uint16_t t1_len;
      uint8_t *t1_data;
      t1_data = ccid_command + 10;
      t1_len = ccid_command[1] | ccid_command[2] << 8;
      // return T1 frame (max 53 bytes + 10 for CCID header)
      ret = T1_wrapper (t1_data, t1_len);
      if (ret == 1)
	{
	  // safety check (USB packet allow us only 63 bytes)
	  if (t1_data[T1_LEN] > 53)
	    t1_data[T1_LEN] = 53;
	  memcpy (response + 10, t1_data, 4 + t1_data[T1_LEN]);
	  response[1] = 4 + t1_data[T1_LEN];
	  response[2] = 0;
	  Status.bmCommandStatus = 0;
	  response[7] = Status.SlotStatus;
	  response[8] = SlotError;
	  return response[1] + 10;
	}
      // nothing to do
      if (ret == 0)
	return 0;

      if (TPDU_state == T_IDLE)
	{
	  //APDU in buffer, handle similar to T0 protocol
	  memcpy (CCID_card_buffer, ccid_command, 10);
	  CCID_card_buffer[1] = T1_APDU_len_recv & 0xff;
	  CCID_card_buffer[2] = T1_APDU_len_recv >> 8;
	  memcpy (CCID_card_buffer + 10, T1_APDU_buffer_recv, 261);
	  t1_size = T1_APDU_len_recv;
	  T1_APDU_len_recv = 0;
	}
    }
  else
    {
      // protocol T0
      if (TPDU_state == T_IDLE)
	// just copy ccid data into CCID_card_buffer
	memcpy (CCID_card_buffer, ccid_command, 271);
    }
  if (TPDU_state != T_IDLE)
    {
      Status.bmCommandStatus = 1;
      response[7] = Status.SlotStatus;
      response[8] = 0xe0;	// slot busy;
      return 10;		// CCID header length
    }
  // prepare response
  memcpy (card_response, response, 10);
  if (CCID_card_buffer[2] == 0)
    {
      // if command is below 4 bytes return error
      if (CCID_card_buffer[1] < 4)
	{
	  Status.bmCommandStatus = 1;	// error
	  SlotError = 1;	// wrong len
	  return 1;
	}
      // normal command, no data
      if (CCID_card_buffer[1] < 5)
	{
	  // append LC
	  CCID_card_buffer[1] = 5;
	  CCID_card_buffer[14] = 0;
	}
    }
  card_ins = CCID_card_buffer[11];
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
// send command to card (card software wait for card_rx_len in busy loop)

  card_rx_buffer = CCID_card_buffer + 10;
  if (reader_protocol == 0)
    card_rx_len = 5;
  else
    card_rx_len = t1_size;

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


static int8_t
RDR_to_PC_DataBlock_wrong_slot (uint8_t * l_response)
{
  l_response[7] = 0x42;		// No ICC present, command failed error in error reg
  l_response[8] = 5;		// slot does not exist;
  return 10;			// CCID header length
}


static int8_t
RDR_to_PC_DataBlock_busy_slot (uint8_t * response)
{
  Status.bmCommandStatus = 1;
  response[7] = Status.SlotStatus;
  response[8] = 0xe0;		// slot busy;
  return 10;			// CCID header length
}

//static void RDR_to_PC_DataBlock_busy_slot(uint8_t *l_responsel) __attribute__((alias ("RDR_to_PC_SlotStatus_busy_slot")));
static int8_t RDR_to_PC_SlotStatus_busy_slot (uint8_t * l_responsel)
  __attribute__((alias ("RDR_to_PC_DataBlock_busy_slot")));

static int8_t
func_PC_to_RDR_IccPowerOn (uint8_t * command, uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);

// initialize reader buffers, protocol
  T1_APDU_len_recv = 0;
  reader_protocol = 0;
  CPU_do_restart_main ();
// ATR is always available
// new OsEID ATR (T0 and T1 protocol)
#if 1
// 3b:f5:18:00:02:80:01:4f:73:45:49:44:1a

#define C_ATR_LEN  13
#define C_ATR_HIST 5

  ATR[0] = 0x3b;
  ATR[1] = 0xf0 | C_ATR_HIST;
  ATR[2] = 0x18;		// Fi=372, Di=12, 31 cycles/ETU
  ATR[3] = 0x00;		// Vpp not  elec. connected
  ATR[4] = 0x02;		// extra guardtime
  ATR[5] = 0x80;		// protocol 0
  ATR[6] = 0x01;		// protocol 1
  ATR[7] = 0x4f;		//O
  ATR[8] = 0x73;		//s
  ATR[9] = 0x45;		//E
  ATR[10] = 0x49;		//I
  ATR[11] = 0x44;		//D
  ATR[12] = 0x1a;		// checksum (LRC)
/*
// myeid 3B F5 18 00 00 81 31 FE 45 4D 79 45 49 44 9A
#define C_ATR_LEN  15
  ATR[0] = 0x3b;
  ATR[1] = 0xf5;
  ATR[2] = 0x18;		// Fi=372, Di=12, 31 cycles/ETU
  ATR[3] = 0x00;		// Vpp not  elec. connected
  ATR[4] = 0x00;		// extra guardtime
  ATR[5] = 0x81;		// protocol 1
  ATR[6] = 0x31;		// protocol 1
  ATR[7] = 0xfe;		// IFSC: 254
  ATR[8] = 0x45;		// Block Waiting Integer: 4 - Character Waiting Integer: 5
  ATR[9] = 0x4d;		//M
  ATR[10] = 0x79;		//y
  ATR[11] = 0x45;		//E
  ATR[12] = 0x49;		//I
  ATR[13] = 0x44;		//D
  ATR[14] = 0x9a;		// checksum (LRC)
*/
#else
// normal OsEID ATR (only T0 protocol)
// 3b:f7:18:00:02:10:80:4f:73:45:49:44
#define C_ATR_LEN  12
#define C_ATR_HIST 5
  ATR[0] = 0x3b;
  ATR[1] = 0xf0 | C_ATR_HIST;
  ATR[2] = 0x18;		// Fi=372, Di=12, 31 cycles/ETU
  ATR[3] = 0x00;		// Vpp not  elec. connected
  ATR[4] = 0x02;		// extra guardtime
  ATR[5] = 0x10;		// protocol 0
  ATR[6] = 0x80;		// Protocol to be used in spec mode: T=0
  ATR[7] = 0x4f;		//O
  ATR[8] = 0x73;		//s
  ATR[9] = 0x45;		//E
  ATR[10] = 0x49;		//I
  ATR[11] = 0x44;		//D
#endif
  //copy ATR to respone
  memcpy (response + 10, ATR, C_ATR_LEN);

  Status.bmCommandStatus = 0;	// command ok
  Status.bmICCStatus = 0;	//ICC present, active
  response[7] = Status.SlotStatus;
  response[8] = SlotError;
  response[1] = C_ATR_LEN;	// set response length
  return C_ATR_LEN + 10;
}

static int8_t
func_PC_to_RDR_GetSlotStatus (uint8_t * command, uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);

  if (TPDU_state != T_IDLE)
    {
      Status.bmCommandStatus = 1;
      return RDR_to_PC_SlotStatus_busy_slot (response);
    }
  Status.bmCommandStatus = 0;	// command ok
  response[7] = Status.SlotStatus;
  response[8] = SlotError;
  return 10;
}


static int8_t
func_PC_to_RDR_ResetParameters (uint8_t * command, uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);

  Status.bmCommandStatus = 1;
  response[7] = Status.SlotStatus;

  if (TPDU_state != T_IDLE)
    return RDR_to_PC_SlotStatus_busy_slot (response);

  if (command[1] != 0 && command[2] != 0)
    {
      response[8] = 1;		// slot error = wrong length
      return 10;
    }
// initialize reader buffers, protocol
  T1_APDU_len_recv = 0;
  reader_protocol = 0;
  Status.bmCommandStatus = 0;	// command OK
  response[7] = Status.SlotStatus;
  response[1] = 5;		// response data len

  response[10] = ATR[1];
  if (ATR[0] == 0x3b)
    response[11] = 0;		// direct
  else
    response[11] = 2;		// inverse conversion
  response[12] = 2;		// guard time
  response[13] = 10;		// WI
  response[14] = 0;		// Stopping the Clock is not allowed
  return 15;
}

static int8_t
func_PC_to_RDR_SetDataRateAndClockFrequency (uint8_t * command,
					     uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);

  Status.bmCommandStatus = 1;
  response[7] = Status.SlotStatus;

  if (TPDU_state != T_IDLE)
    return RDR_to_PC_SlotStatus_busy_slot (response);

  if (command[1] != 8 || command[2] != 0)
    {
      response[8] = 1;		// slot error = wrong length
      return 10;
    }
  if (command[7] != 0)
    {
      response[8] = 7;		// slot error = wrong parameter
      return 10;
    }
  if (command[8] != 0)
    {
      response[8] = 8;		// slot error = wrong parameter
      return 10;
    }
  if (command[9] != 0)
    {
      response[8] = 9;		// slot error = wrong parameter
      return 10;
    }
// ignore forced parameters, return "real" values

  Status.bmCommandStatus = 0;	// command OK
  response[7] = Status.SlotStatus;
  response[1] = 8;		// response data len

// 4MHz is reported in descriptor -> max baud = 129032
  response[10] = 4000L & 255;
  response[11] = (4000L >> 8) & 255;
  response[12] = (4000L >> 16) & 255;
  response[13] = (4000L >> 24) & 255;
  response[14] = 129032L & 255;
  response[15] = (129032L >> 8) & 255;
  response[16] = (129032L >> 16) & 255;
  response[17] = (129032L >> 24) & 255;

  return 18;
}


static int8_t
func_PC_to_RDR_SetParameters (uint8_t * command, uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);

  Status.bmCommandStatus = 1;
  response[7] = Status.SlotStatus;

  if (TPDU_state != T_IDLE)
    return RDR_to_PC_SlotStatus_busy_slot (response);

  if (command[2] != 0)
    {
      response[8] = 1;		// slot error = wrong length
      return 10;
    }
  if (command[7] > 1)		// only T0/T1 protocol
    {
      response[8] = 7;		// wrong protocol
      return 10;
    }
  reader_protocol = command[7];
  if (reader_protocol == 1)
    {
      t1_init ();
      T1_APDU_len_recv = 0;
      T1_APDU_response_len = 0;
    }
  if (command[7] == 0)
    {
      if (command[1] != 5)
	{
	  response[8] = 1;	// wrong len
	  return 10;
	}
    }
  else
    {
      if (command[1] != 7)
	{
	  response[8] = 1;	// wrong len
	  return 10;
	}
    }
  // command is OK, parse parameters, signalize wrong
  // values, but do not return error

  Status.bmCommandStatus = 0;	// command OK
  response[7] = Status.SlotStatus;
// T0/T1 protocol
  response[10] = ATR[1];
  if (ATR[0] == 0x3b)
    response[11] = 0;		// direct
  else
    response[11] = 2;		// inverse conversion
// CCID ignores this parameter
//if (response[11] != command[11])        // direct/inverse conv
//response[8] = 11;
  response[14] = 0;		// Stopping the Clock is not allowed
  if (response[14] != command[14])	// clock stop (not allowed)
    response[8] = 14;
  if (reader_protocol == 0)
    {
      response[1] = 5;		// response data len
      response[9] = 0;		// T0
      response[12] = 2;		// guard time
      response[13] = 10;	// WI
      if (response[10] != command[10])	//Fi,Di
	response[8] = 10;
      if (response[12] != command[12])	// guard time
	response[8] = 12;
      if (response[13] != command[13])	// work waiting time
	response[8] = 13;
      return 15;
    }
  else
    {				// protocol 1
      response[1] = 7;		// response data len
      response[9] = 1;		// T1
      response[11] |= 4;	// T1 protocol
//    response[11] |= 1;        // CRC=1, LRC=0
      response[12] = command[12];	// extra guard time
      response[13] = command[13];	// 7..4 = BWI, 3..0 CWI
      if (response[13] > 0x9f)
	response[8] = 13;
      response[15] = command[15];	// IFSC
      if (response[15] == 0xff)
	response[8] = 15;
      response[16] = command[16];	// node address
      return 17;
    }
}

static int8_t
func_PC_to_RDR_IccPowerOff (uint8_t * command, uint8_t * response)
{
  // power off card in slot 0
  if (command[5] == 0)
    {
      if (TPDU_state != T_IDLE)
	CPU_do_restart_main ();
      Status.bmICCStatus = 1;	//ICC present, inactive
      Status.bmCommandStatus = 0;	// command ok
      response[7] = Status.SlotStatus;
      response[8] = SlotError;
      return 10;
    }
  return func_PC_to_RDR_GetSlotStatus (command, response);
}


static int8_t
func_Unsupported (uint8_t * command, uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);
  if (TPDU_state != T_IDLE)
    {
      Status.bmCommandStatus = 1;
      return RDR_to_PC_SlotStatus_busy_slot (response);
    }
  Status.bmCommandStatus = 1;
  SlotError = 0;		//not supported command
  response[7] = Status.SlotStatus;
  response[8] = SlotError;
  return 10;
}


static int8_t
func_PC_to_RDR_XfrBlock (uint8_t * command, uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);
  // handle PTS/PPS here, TODO  PTS/PPS is accepted only after ATR !!!
  if (command[10] == 0xff)
    {
      if ((command[11] & 0xf) == 1)
	{
	  t1_init ();
	  T1_APDU_len_recv = 0;
	  T1_APDU_response_len = 0;
	}
      memcpy (response + 10, command + 10, command[1]);
      Status.bmCommandStatus = 0;	// command ok
      response[1] = command[1];	// set response length
      response[7] = Status.SlotStatus;
      response[8] = SlotError;
      return command[1] + 10;
    }
// return CCID message (if returned size >0)
// or return 0 if card is running a command
  return run_card (command, response);
}


// check if CCID command is correct (return 0 if not)
static uint8_t
CCID_check_command (uint8_t command)
{
#if 0
  switch (command)
    {
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
int8_t
parse_command (uint8_t * command, uint16_t count, uint8_t * ccid_response)
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
  ccid_response[8] = 0;		// slot error = unsupported command
  ccid_response[9] = 0;


  ccid_response[0] = CCID_check_command (command[0]);
  // check if CCID command is in message
  if (ccid_response[0] == 0)
    {
      // no signalize error
      ccid_response[0] = C_RDR_to_PC_SlotStatus;
      return 10;
    }
  if ((count < 10) ||
      ((command[1] + (command[2] << 8)) > 261) ||
      (command[3] != 0) || (command[4] != 0))
    {
      ccid_response[8] = 1;	// slot error = wrong length
      return 10;
    }
  // check if message data part correspond to data size in ccid header
  {
    uint16_t len = 10 + command[1] + (command[2] << 8);

    if (count < len)
      {
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
    if (len < count)
      {
	memset (command + len, 0, 271 - len);
	count = len;
      }
  }
  // OK, CCID BULK OUT seems to be correct, proceed command
#if 1
  switch (command[0])
    {
////////////////////////////////////////////////////////////////
    case PC_to_RDR_IccPowerOn:
      return func_PC_to_RDR_IccPowerOn (command, ccid_response);
////////////////////////////////////////////////////////////////
    case PC_to_RDR_IccPowerOff:
      return func_PC_to_RDR_IccPowerOff (command, ccid_response);
////////////////////////////////////////////////////////////////
    case PC_to_RDR_SetParameters:
      return func_PC_to_RDR_SetParameters (command, ccid_response);
////////////////////////////////////////////////////////////////
    case PC_to_RDR_ResetParameters:
      return func_PC_to_RDR_ResetParameters (command, ccid_response);
////////////////////////////////////////////////////////////////
    case PC_to_RDR_GetSlotStatus:
      return func_PC_to_RDR_GetSlotStatus (command, ccid_response);
////////////////////////////////////////////////////////////////
    case PC_to_RDR_SetDataRateAndClockFrequency:
      return
	func_PC_to_RDR_SetDataRateAndClockFrequency (command, ccid_response);
////////////////////////////////////////////////////////////////
    case PC_to_RDR_XfrBlock:
      return func_PC_to_RDR_XfrBlock (command, ccid_response);
////////////////////////////////////////////////////////////////
    default:
      return func_Unsupported (command, ccid_response);
    }
#else
  if (command[0] == PC_to_RDR_IccPowerOn)
    return func_PC_to_RDR_IccPowerOn (command, ccid_response);
  else if (command[0] == PC_to_RDR_IccPowerOff)
    return func_PC_to_RDR_IccPowerOff (command, ccid_response);
  else if (command[0] == PC_to_RDR_SetParameters)
    return func_PC_to_RDR_SetParameters (command, ccid_response);
  else if (command[0] == PC_to_RDR_ResetParameters)
    return func_PC_to_RDR_ResetParameters (command, ccid_response);
  else if (command[0] == PC_to_RDR_GetSlotStatus)
    return func_PC_to_RDR_GetSlotStatus (command, ccid_response);
  else if (command[0] == PC_to_RDR_SetDataRateAndClockFrequency)
    return
      func_PC_to_RDR_SetDataRateAndClockFrequency (command, ccid_response);
  else if (command[0] == PC_to_RDR_XfrBlock)
    return func_PC_to_RDR_XfrBlock (command, ccid_response);
  else
    return func_Unsupported (command, ccid_response);
#endif
}


/** Configures the board hardware and chip peripherals for the demo's functionality. */
void
card_io_init (void)
{
// ccid layer init
  TPDU_state = T_IDLE;
// Reader LEDs
  LED1_INIT ();
  LED1_IDLE ();
  LED2_INIT ();
  LED2_RUN ();
}

void
CCID_Init ()
{
  SlotError = 0;
  Status.SlotStatus = 0;
  Status.bmICCStatus = 1;	//ICC present, inactive
}
