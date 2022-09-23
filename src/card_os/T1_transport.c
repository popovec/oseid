/*
    T1_transport.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2021 Peter Popovec, popovec.peter@gmail.com

    This code is based on card_io.S from atmega128 target in this project
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

    T1 transport wrapper (ISO7816-3:2006 chapter 11)

    This code is designed to be included to file card_os/iso7816.c
*/

#include <stdint.h>
#include <string.h>

#define F_WTX_REQUEST 0xc3
#define F_WTX_RESPONSE 0xe3
#define T1_NAD 0
#define T1_PCB 1
#define T1_LEN 2
#define T1_DATA 3

#ifndef T1_IFS
#define T1_IFS 254
#endif

#if T1_IFS > 254
#error IFS over 254
#endif

// please read commentc below - CRC code id not fully working
// uncomment this if CRC is to be used instead of LRC
//#define T1_CRC

struct t1 {
	uint8_t direction;	// 1 - the card is sending I blocks (chain)
	uint8_t receive_only;
	uint8_t need_ack;	// card sent I block, and need acknowledge
	uint8_t ifs_reader;	// maximal I block data len (to reader)
	uint8_t n_card;		// sequence number - for ICC
	uint8_t n_reader;	// sequence number - for IFD
	uint8_t prev[4];	// copy of last sent block (I,R,S, initial part)
	uint16_t apdu_len;	// size of response APDU, size of received command APDU
	uint8_t *apdu;		// response APDU
	uint8_t apdu_failed;	// received apdu is truncated
	uint8_t I_block_len;	// block size (card -> reader)
	uint8_t nad;		// copy of sender/receiver address

} t1 __attribute__((section(".noinit")));

#define T1_INIT() {memset(&t1, 0, sizeof(struct t1));t1.ifs_reader = 32;}

#ifdef T1_CRC
#error Working only for linux driver and TPDU readers, WIN10 uses different checksumm
#define T1_MIN_FRAME 5
//                           reverse   direct
// x^16 + x^12 + x^5 + 1  => 0x8408 or 0x1021
//                           (bit 0)   (bit 15)
// linux CCID
#define T1_CRC_POLY 0x8408
#define T1_CRC_INIT 0xffff
// windows
//#define T1_CRC_POLY 0xA001
//#define T1_CRC_INIT 0

unsigned short t1_checksum(uint8_t * data_p, uint16_t length)
{
	uint8_t i;
	uint8_t data;
	uint16_t crc = T1_CRC_INIT;
#if 0
	if (length == 0)
		return (~crc);
#endif
	do {
		crc ^= *(data_p++);
		for (i = 0; i < 8; i++) {
			if (crc & 1)
				crc = (crc >> 1) ^ T1_CRC_POLY;
			else
				crc >>= 1;
			data >>= 1;
		}
	} while (--length);
	return (crc);
}
#else
#define T1_MIN_FRAME 4
// calculate lrc of block
static uint8_t t1_checksum(uint8_t * f1_rblock, uint16_t rlen)
{
	uint8_t ret = 0;

	while (rlen--)
		ret ^= *f1_rblock++;
	return ret;
}
#endif

// Please read iso7816-3 for Rules/Scenarios io some comment is non self explained

/*!
  @brief parse block from card reader

  @param t1_data[in,out]	T1 block from to reader
  @param t1_len[in]		Length of received T1 block
				Because T1 block length is in range 4 to 258 bytes (5..259)
				codes 0,1,2,3 and > 259 are error codes for T1_machine, see below
  @param apdu[in,out]		buffer for response APDU/command APDU
  @param apdu_len[in]		size of response ADPU/maximal received size of command ADPU

  Note: t1_data - buffer for minimum 258 bytes (if CRC is used 259 bytes)
  Note: NAD sended back to reader is same as NAD received from reader

  @retval 0 - we need  more data from reader
	- read data from the card reader, read T1 block to buffer
	- recall T1_parser:
		't1_data'	pointer to buffer
		't1_len'	length of data
		'apdu'		pointer where final APDU is stored
		'apdu_len'	APDU buffer size
	- use return code to determine next action

  @retval any other value - whole APDU from card reader is in buffer, returned value is size of APDU
	- return value 1..3 error (because T1 APDU minimal size is 4 - generate SW 0x6700)
	- return value > 3, use APDU (pointer 'apdu'...), generate response
	- recall T1_parser:
		'apdu'		pointer to response
		'apdu_len'	size of response
		't1_data'	is pointer to buffer where T1 block is constructed
	- use return code to determine next action

   WTX request
        WTX is handled outside this code (in IO layer)
*/

uint16_t T1_parser(struct t1 *t1, uint8_t t1_data[254 + 4], uint16_t t1_len,
		   uint8_t * apdu, uint16_t apdu_len)
{
	uint8_t seq;
	uint8_t ret;
	uint8_t pcb;
	uint8_t len;
	uint8_t nad;

// ======================================================================================
// direction card to reader
	if (t1->direction == 1) {
// if t1->apdu is not set, set this apdu as response then send this in chain
// chain is always terminated by I block with length 0
		if (t1->apdu == NULL) {
			t1->apdu = apdu;
			t1->apdu_len = apdu_len;
			// flag: this block is not acked
			t1->need_ack = 1;
			goto T1_send_I_frame;
		}
	}
// ======================================================================================

// direction reader to card

// t1_data - data from reader, length t1_len
// length 0,1,2,3 is handled as patity error error (minimal block NAD, PCB, LEN, LRC)

// 1st check if block is ok

	ret = 0x81;		// redundancy code error/parity error  PCB:  R block 10 || 0 N(R) || 0001
	if (t1_len < T1_MIN_FRAME)	// character parity error
		goto T1_wrapper_block_error;
// LRC CRC error
#ifdef T1_CRC
	// CRC is stored quite unhappily
	nad = t1_data[t1_len - 1];
	t1_data[t1_len - 1] = t1_data[t1_len - 2];
	t1_data[t1_len - 2] = nad;
	if (t1_checksum(t1_data, t1_len))
		goto T1_wrapper_block_error;
#else
	if (t1_checksum(t1_data, t1_len))
		goto T1_wrapper_block_error;
#endif
	nad = t1_data[T1_NAD];
	pcb = t1_data[T1_PCB];
	len = t1_data[T1_LEN];

// check block parameters ..
	ret = 0x82;		// other errors PCB: R block 10 || 0 N(R) || 0010

// incorrect LEN field
	if (len > T1_IFS)
		goto T1_wrapper_block_error;

// 11.6.3.1 loss of synchronization because the block size and the number encoded by LEN are inconsistent
	if (len + T1_MIN_FRAME != t1_len)
		goto T1_wrapper_block_error;

#if 0
// 0xFF in NAD field is handled outside this code
	if (nad == 0xff)	// 0xff is reserved for PPSS
		goto T1_wrapper_block_error;
#endif
// TODO same source/dest address (except 0,0) is error
// TODO bits 8,4 - shall be set to zero
// block Ok, save NAD
	t1->nad = (nad & 0xff) << 4 | nad >> 4;

///////////////////////////////////////////////////////////////////////////////////////////////
// OK, block can be parsed

// 1st check failure to receive the relevant S(response) after having transmitted S(request).
// OsEID does not send any S request.. no code here

// S request handling, WTX from reader is handled as error..
	if (len == 1) {
		// IFS request
		if (pcb == 0xc1) {
			// handle incorrect values as not received block - parity/other error
			if (t1_data[T1_DATA] == 255 || t1_data[T1_DATA] == 0)
				goto T1_wrapper_block_error;
			t1->ifs_reader = t1_data[T1_DATA];
#if T1_IFS != 254
			if (t1_data[T1_DATA] > T1_IFS)
				t1->ifs_reader = T1_IFS;
#endif
			goto S_request_response;
		}
	}			// len == 1
//
	if (len == 0) {
		// resync - rule 6.2
		if (pcb == 0xc0) {
			// do not call t1_init() - this save some bytes in flash
			memset(t1, 0, sizeof(struct t1));
			t1->ifs_reader = 32;
			goto S_request_response;
		}
		// ABORT
		if (pcb == 0xc2) {
#if 0				// We using very simple handling for ABORT below...
			if (t1->direction) {
				// card is sending chain - scenario 28
				if (t1->apdu == NULL)	//  check if chain is started..
					goto T1_wrapper_block_error;
				t1->direction = 0;
				t1->need_ack = 0;
			} else {
				// reader is sending chain - scenario 25
				if (t1->apdu_len == 0)	// there is no chained I block received
					goto T1_wrapper_block_error;
				// drop already received APDU..
				t1->apdu_len = 0;
			}
#else
			t1->direction = 0;
			t1->need_ack = 0;
#endif
			goto S_request_response;
		}
//
// R block handling [10|0|N(R)|00|code] (code 0,1,2), len 0
		if ((pcb & 0xec) == 0x80 && (pcb & 3) != 3) {
// I block was sent to reader, we are waiting for response
			if (t1->need_ack) {
				// is this confirmation of previous block?
				seq = t1->n_card ^ 0x10;
				if ((pcb & 0x13) == seq) {
					if (t1->direction == 0)	// last block should be confirmed by I block
						goto T1_wrapper_block_error;
					// OK, move to the next part of the apdu
					t1->apdu_len -= t1->I_block_len;
					t1->apdu += t1->I_block_len;
					t1->n_card = seq;
				}
 T1_send_I_frame:
				//  new I block or repeat previous I block
				len = t1->ifs_reader;
				if (len > t1->apdu_len)
					len = t1->apdu_len;
				t1->I_block_len = len;
				t1_data[T1_LEN] = len;

				pcb = (t1->n_card << 2);
				if (len == 0) {
					t1->direction = 0;
				} else {
					pcb |= 0x20;
					memcpy(t1_data + 3, t1->apdu, len);
				}
				t1_data[T1_PCB] = pcb;
				goto T1_wrapper_response;
			}
			// we do not waiting a ack, this block is wrong, fall though to T1_wrapper_block_error
		}
	}			// len == 0
//
// I block: bit 8 = 0, bit 7 N(S), bit 6: chain (M)
// 11.3.2.2:  Bits 5 to 1 are reserved for future use and shall be set to 0.
	if ((pcb & 0x9f) == 0) {
		ret = 0x80;
		// check direction, if card-> reader, then this I block from reader is incorrect
		if (t1->direction)	// rule 7.1, 7.2, 7.3
			goto T1_wrapper_block_error;

		// test expected seq. number ..
		seq = (pcb >> 2) & 0x10;
		if (seq != t1->n_reader)
			goto T1_wrapper_block_error;

		// next sequence number
		seq ^= 0x10;	// warning seq is used below too!
		t1->n_reader = seq;

		// prepare R block to request more data
		t1_data[T1_PCB] = 0x80 | seq;
		t1_data[T1_LEN] = 0;

		// this block is acknowledge for previous sended "I" block ..
		if (t1->need_ack) {
			t1->n_card ^= 0x10;
			t1->need_ack = 0;
		}
		// is space in buffer ?
		// we assume here, that apdu_len is always >= IFS, then apdu_len - len is always >=0
		if (t1->apdu_len > apdu_len - len || t1->apdu_failed) {
			// no space in buffer, discard this APDU
			// in this case function return APDU size 1 - this is handled in
			// iso7816.c as wrong len (SW=0x6700)
			t1->apdu_len = 1;
			t1->apdu_failed = 1;
		} else {
			// save data in buffer
			memcpy(apdu + t1->apdu_len, t1_data + 3, len);
			t1->apdu_len += len;
		}
		// this is last block ?
		if ((pcb & 0x20) != 0)
			goto T1_wrapper_response;
		// we have whole APDU, this is not acked, card ack this by I block (Scenario 1)
		// or by requesting waiting time (Scenario 2.2)

		t1->direction = 1;	// switch direction, card is now sending I blocks
		t1->apdu = NULL;
		t1->apdu_failed = 0;
		return t1->apdu_len;
	}
// unknown PCB, handle this as not received block - parity/other error

// wrong block arrived (checksum/parity error), retransmit previous S block or generate R block
 T1_wrapper_block_error:
// Rule 7.4.3 - do not repeat S block or R block after second attempt
	if (t1->receive_only)
		return 0;
	// nothing to do, wait for resync etc.
	t1->receive_only = 1;

// reaction based on previous state, for R,S block repeat..
	if (t1->prev[T1_PCB] & 0x80) {
// repeat S block (rule 7.3), this also ensures compliance with rule 8.
// repeat R block (rule 7.2)
		memcpy(t1_data, t1->prev, 4);
	} else {
// rule 7.1, if previous block was I block, send R(N) for expected I block
// rule 7.5, wrong 1st block, request R(0), (for 1st block n_reader is 0)
		t1_data[T1_PCB] = ret | t1->n_reader;
		t1_data[T1_LEN] = 0;
	}
//
 T1_wrapper_response_0:
	t1_data[T1_NAD] = t1->nad;
	len = t1_data[T1_LEN];
	// save block (for retransmit on error)
	memcpy(t1->prev, t1_data, 4);
// calculate checksumm and send data to reader
#ifdef T1_CRC
	{
		uint16_t crc = t1_checksum(t1_data, len + 3);
		t1_data[len + 3] = crc >> 8;
		t1_data[len + 4] = crc & 0xff;
	}
#else
	t1_data[len + 3] = t1_checksum(t1_data, len + 3);
#endif
	card_io_tx(t1_data, len + T1_MIN_FRAME);
	return 0;
//
 S_request_response:
	// turn request to response
	t1_data[T1_PCB] = pcb | 0x20;
// ok send response to reader
 T1_wrapper_response:
//      t1_data[T1_LEN] = len;
	// clear error, we can send response back
	t1->receive_only = 0;
	goto T1_wrapper_response_0;
}
