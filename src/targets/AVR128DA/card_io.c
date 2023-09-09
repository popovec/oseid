/*
    card_io.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2023 Peter Popovec, popovec.peter@gmail.com
    Card low-level IO functions in C code.

    - RX code is different from ASM version (here voting is used to get 0/1)
    - Slightly worse resistance to noise in the RX code.
    - Tested NEGOTIABLE mode, T0/T1 protocol
    - speed up to 300kbit/s (card reader 4.8MHz)
    - If you want to use this implementation, replace card_io.S with
      card_io.c in the corresponding Makefile (Makefile.AVR128DA).
    - Warning, this implementation may not be maintained in the future,
      the ASM version will be preferred (due code size).

    Copyright (C) 2015-2022 Peter Popovec, popovec.peter@gmail.com
    (This code is based on card_io.S from atmega128 target in this
    project and card_io.S from AVR128DA32 target in this project)

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

    AVR128DA card IO

    please check card_io.h for functions in this module

   Pin assignment:
   ISO7816-3    AVR128DA
   ----------------------
   I/O          PA4 receive/transmit
   CLK          PA2
   RESET        PA3

   Fuse 5 is programmed to 0xc0 - hardware RESET from PF6 is not used.
   Card reset in handled in avr.S, please read section .init9

*/

/* enable PPS parsing strict check - not needed for OsEID */
//#define STRICT_PPS_CHECK

#include <stdint.h>
#include "card_io.h"

//#define C_TS 0x3f
#define C_TS 0x3b

#if !defined(TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE) && !defined(TRANSMISSION_PROTOCOL_MODE_SPECIFIC)
//#define TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
#define TRANSMISSION_PROTOCOL_MODE_SPECIFIC
#endif

#define C_ETU_ATR 372

#if (C_TS != 0x3b) && (C_TS != 0x3f)
#error Wrong TS value
#endif

// this can be replaced by standard avr header file ..
typedef struct EVSYS_struct {
	volatile uint8_t reserved_0[17];
	volatile uint8_t CHANNEL1;
	volatile uint8_t reserved_1[41];
	volatile uint8_t USERTCA0CNTA;
} EVSYS_t;
#define EVSYS               (*(EVSYS_t *) 0x0200)

typedef enum EVSYS_CHANNEL1_enum {
	EVSYS_CHANNEL1_PORTA_PIN2_gc = (0x42 << 0),	/* Port A Pin 2 */
} EVSYS_CHANNEL1_t;

#define TCA0_SINGLE_CTRLA  	(*(volatile uint8_t *) 0x0A00)
#define TCA0_SINGLE_CTRLB  	(*(volatile uint8_t *) 0x0A01)
#define TCA0_SINGLE_EVCTRL	(*(volatile uint8_t *) 0x0A09)
#define TCA0_SINGLE_INTCTRL	(*(volatile uint8_t *) 0x0A0A)
#define TCA0_SINGLE_INTFLAGS	(*(volatile uint8_t *) 0x0A0B)
#define TCA0_SINGLE_CNT  	(*(volatile uint16_t *) 0x0A20)
#define TCA0_SINGLE_PER  	(*(volatile uint16_t *) 0x0A26)

static struct card_io_data {
	volatile uint8_t null_send;
	volatile uint16_t etu;
#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
	volatile uint16_t etu_negotiated;
#if defined (PROTOCOL_T0) &&  defined (PROTOCOL_T1)
	volatile uint8_t proto;
	volatile uint8_t proto_negotiated;
#endif
#endif
#ifdef PROTOCOL_T1
	volatile uint8_t NAD;
#endif
} card_io_data __attribute__((section(".noinit")));

#define PORTA_OUTCLR  		(*(volatile uint8_t *) 0x0406)
#define PORTA_PIN4CTRL  	(*(volatile uint8_t *) 0x0414)
#define VPORTA_DIR  		(*(volatile uint8_t *) 0x0000)
#define VPORTA_IN		(*(volatile uint8_t *) 0x0002)

#define C_ATR_TA1 0x96
#define C_ETU      16

//#define C_ATR_TA1 0x18
//#define C_ETU      31

//#define C_ATR_TA1 0x95
//#define C_ETU      32

//#define C_ATR_TA1 0x13
//#define C_ETU      93

//#define C_ATR_TA1 0x12
//#define C_ETU      186

//#define C_ATR_TA1 0x11
//#define C_ETU      372

#ifdef TRANSMISSION_PROTOCOL_MODE_SPECIFIC

#if defined (PROTOCOL_T0)
const uint8_t __attribute__((used, section(".progmem.gcc"))) card_io_atr_string[] = {
	C_TS, 0xf5, C_ATR_TA1, 0, 2, 0x10, 0x80, 'O', 's', 'E', 'I', 'D'
};
#elif defined (PROTOCOL_T1)
#error T1 protocol in SPECIFIC mode is not tested
const uint8_t __attribute__((used, section(".progmem.gcc"))) card_io_atr_string[] = {
	C_TS, 0xF5, C_ATR_TA1, 0, 2, 0x91, 0x81, 0x31, 0xFE, 0x65, 'O', 's', 'E', 'I', 'D', 0xac
};
#else
#error no protocol
#endif

#endif

#ifdef  TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
#if C_ATR_TA1 == 0x95
const uint8_t __attribute__((used, section(".progmem.gcc"))) card_io_atr_string[] = {
	C_TS, 0xD5, C_ATR_TA1, 0x02, 0x80, 0x31, 0xFE, 0x65, 'O', 's', 'E', 'I', 'D', 0x1c
};
#elif C_ATR_TA1 == 0x96
const uint8_t __attribute__((used, section(".progmem.gcc"))) card_io_atr_string[] = {
	C_TS, 0xD5, C_ATR_TA1, 0x02, 0x80, 0x31, 0xFE, 0x65, 'O', 's', 'E', 'I', 'D', 0x1f
};
#else
#error no atr
#endif

struct cnt_data {
	uint8_t TA;
	uint16_t val;
};

const struct cnt_data __attribute__((aligned(2), used, section(".progmem.gcc"))) TA_to_CNT[] = {	//
	{0x96, 16 - 1},		// 16
	{0x95, 32 - 1},		// 32
	{0x94, 64 - 1},		// 64
	{0x93, 128 - 1},	// 128
	{0x92, 256 - 1},	// 256
	{0x91, 512 - 1},	// 512
	{0x18, 372 / 12 - 1},	// 31
//      {0x15, 372 / 8 - 1},    // 46.5
	{0x14, 372 / 4 - 1},	// 93
	{0x13, 372 / 3 - 1},	// 124
	{0x12, 372 / 2 - 1},	// 176
	{0x11, 372 - 1},	// 372
	{0x08, 372 / 12 - 1},	// 31
//      {0x05, 372 / 8 - 1},    // 46.5
	{0x04, 372 / 4 - 1},	// 93
	{0x03, 372 / 3 - 1},	// 124
	{0x02, 372 / 2 - 1},	// 176
	{0x01, 372 - 1},	// 372
	{0, 372 - 1}		// 372
};
#endif

static void __attribute__((noinline)) card_io_program_timer(uint16_t val)
{
// disable interrupt from timer overflow
	TCA0_SINGLE_INTCTRL = 0;
	TCA0_SINGLE_PER = val;
	TCA0_SINGLE_CNT = 0;
// clear overflow
	TCA0_SINGLE_INTFLAGS = 1;
}

void card_io_start_null(void)
{
	card_io_program_timer(0xffff);
	card_io_data.null_send = 0;
// enable interrupt from timer overflow
	TCA0_SINGLE_INTCTRL = 1;
}

// deprecated, but used internally, will be renamed and changed to "static"
static void card_io_timer_etu(void)
{
	card_io_program_timer(card_io_data.etu);
}

static void send_C(uint8_t data)
{
// send Z if data != 0 is set else A
// Z = 1 (pull up)
// A = 0

	while ((TCA0_SINGLE_INTFLAGS & 1) == 0) ;	// wait clock pulse
	TCA0_SINGLE_INTFLAGS = 1;	// clear OVF
	if (data)
		VPORTA_DIR &= ~0x10;
	else
		VPORTA_DIR |= 0x10;	// bit mask for I/O line
}

#if defined (PROTOCOL_T0) &&  defined (PROTOCOL_T1)
static uint8_t card_io_tx_byte(uint8_t byte, uint8_t proto)
#else
static uint8_t card_io_tx_byte(uint8_t byte)
#endif
{
	uint8_t bitcounter = 8;
	uint8_t parity = 0;
#if C_TS == 0x3f
	byte = ~byte;
#endif
	send_C(0);		// start bit
	do {
		parity ^= byte;	// calculate parity (in bit 7 or bit 0)

#if C_TS == 0x3f
		send_C(byte & 0x80);
		byte <<= 1;
#else
		send_C(byte & 1);
		byte >>= 1;
#endif

	} while (--bitcounter);
// parity bit
#if C_TS == 0x3f
	parity = ~parity;
	parity &= 0x80;
#else
	parity &= 1;
#endif
	send_C(parity);
// 1st stop bit
	send_C(1);
// 1st stop bit is already on line, send second stop bit
	send_C(1);
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
	if (proto == 0) {
		if (!(VPORTA_IN & 0x10)) {
// on error send next (3rd) stop bit
			send_C(1);
			return 1;
		}
	}
#elif defined (PROTOCOL_T0)
	if (!(VPORTA_IN & 0x10)) {
// on error send next (3rd) stop bit
		send_C(1);
		return 1;
	}
#endif
	return 0;
}

void card_io_tx(uint8_t * data, uint16_t len)
{
#if defined (PROTOCOL_T0)
// limit retransmitions (requested by error signal)
	uint8_t max_errors = 20;
#endif
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
	uint8_t proto = card_io_data.proto;
#endif
// reinitialize timer (actual ETU)
	card_io_timer_etu();
	do {
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
		if (card_io_data.proto == 0) {
			for (;;) {
				if (card_io_tx_byte(*data, proto) == 0)
					break;
				if (--max_errors == 0)
					return;
			}
		} else
			card_io_tx_byte(*data, proto);
#elif defined (PROTOCOL_T0)
		for (;;) {
			if (card_io_tx_byte(*data) == 0)
				break;
			if (--max_errors == 0)
				return;
		}
#elif defined (PROTOCOL_T1)
		card_io_tx_byte(*data);
#endif
		data++;

	} while (--len);
#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
// switch to PPS values
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
	card_io_data.proto = card_io_data.proto_negotiated;
#endif
	card_io_data.etu = card_io_data.etu_negotiated;
// reinitialize timer (for next Rx)
	card_io_timer_etu();
#endif
}

void card_io_init(void)
{
// initialize I/O
// ISO 7816 pin
// I/O          to PA4 <= USART2 TX (receive/ transmit)
// CLK          to PA2
// ISO7816 pin CLK - used as clock source for bit transmit/receive
// connect (PIN 32 on TQFP 32 package) PA2 = CLK in, to event system (channel 1)

	EVSYS.CHANNEL1 = EVSYS_CHANNEL1_PORTA_PIN2_gc;
// connect channel1 to TCA timer/counter
	EVSYS.USERTCA0CNTA = 2;	// channel 1  (channel +1 here, because 0 = no input)
	TCA0_SINGLE_EVCTRL = 1;	// Input event A, count on positive edge,

	card_io_data.etu = C_ETU_ATR - 1;
#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
	card_io_data.etu_negotiated = C_ETU_ATR - 1;
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
// initial protocol
	card_io_data.proto = 0;
	card_io_data.proto_negotiated = 0;
#endif
#endif
// PORT setup, open collector (drive port to low, enable pull up, use port
// DIR to transmit 0/1
	PORTA_PIN4CTRL = 8;	// enable pull up
	PORTA_OUTCLR = (1 << 4);	// if pin is output pin, drive to zero
// timer:
	TCA0_SINGLE_CTRLA = 1;	// enable timer TCA, no clock prescaler ..
	TCA0_SINGLE_CTRLB = 0;	// normal mode
// program PER and CNT, disable interrupt from overflow
// we need wait (535) clock cycles and then ATR is sent back to reader
// (min 400, max 40000)
	card_io_program_timer(500);
// wait ..
	while ((TCA0_SINGLE_INTFLAGS & 1) == 0) ;	// wait clock pulse

// transit ATR to reader
// card_io_atr_string is in section .progmem (in 1st 32kiB page)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored  "-Warray-bounds"
	card_io_tx((uint8_t *) (card_io_atr_string) + 0x8000, sizeof(card_io_atr_string));
#pragma GCC diagnostic pop
// mark ATR sent
	card_io_data.null_send = 0xff;

#ifdef TRANSMISSION_PROTOCOL_MODE_SPECIFIC
// switch speed as defined by Ta1 (specific mode)
	card_io_data.etu = C_ETU - 1;
#endif
}

#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
static uint16_t parse_pps(uint8_t * pps, uint16_t len)
{
	uint8_t parse_byte, pck, pps0, pps1;
	const struct cnt_data *ta = (const struct cnt_data *)((uint8_t *) TA_to_CNT + 0x8000);
	uint8_t *data = pps;

	pck = 0xff;
	*(data++) = 2;		//PPS error code

#ifdef STRICT_PPS_CHECK
	// short PPS?
	if (0 == --len)
		return 0;
#else
	len--;
#endif
	// load PPS0
	pps0 = *(data++);
	pck ^= pps0;
#ifdef STRICT_PPS_CHECK
	if (0 == --len)
		return 0;
#else
	len--;
#endif
// protocol (0,1 or 0)
#ifdef T1_TRANSPORT
	if ((pps0 & 0x0f) > 1)
#else
	if ((pps0 & 0x0f) != 0)
#endif
		return 0;
	// PPS1 handling..
	pps1 = 0;		// default PPS1
	if (pps0 & 0x10) {
		pps1 = *(data++);
		pck ^= pps1;
#ifdef STRICT_PPS_CHECK
		if (0 == --len)
			return 0;
#else
		len--;
#endif
	}
	// PPS2
	if (pps0 & 0x20) {
		parse_byte = *(data++);
		pck ^= parse_byte;
#ifdef STRICT_PPS_CHECK
		if (0 == --len)
			return 0;
#else
		len--;
#endif
	}
	// PPS3
	if (pps0 & 0x40) {
		parse_byte = *(data++);
		pck ^= parse_byte;
#ifdef STRICT_PPS_CHECK
		if (0 == --len)
			return 0;
#else
		len--;
#endif
	}
	// highest bite in PPS0 should be 0 (ISO7816-3/2006 9.2)
	if (pps0 & 0x80)
		return 0;
	// check PCK
	pck ^= *(data++);
	if (pck)
		return 0;
	if (0 != --len)
		return 0;

	// search parameters...
	for (;;) {
		if (ta->TA == 0) {
			break;
		}
		if (ta->TA == pps1)
			break;
		ta++;
	}
	card_io_data.etu_negotiated = ta->val;
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
	card_io_data.proto_negotiated = pps0 & 1;
#endif
	// construct response:
	pps[0] = CARD_IO_PPS;
	pps[1] = 3;

	pck = 0xff;
	pps[2] = pck;

	// no not return PPS2, PPS3
	pps0 &= 0x11;

	// for default parameters do not send PPS1 back
	if (ta->TA == 0)
		pps0 &= 1;
	pps[3] = pps0;
	data = pps + 4;

	pck ^= pps0;
	// return PPS1 if needed
	if (pps0 & 0x10) {
		*(data++) = ta->TA;
		pck ^= ta->TA;
		pps[1] = 4;
	}

	*(data++) = pck;
	return 0;
}
#endif

uint16_t card_io_rx(uint8_t * data, uint16_t len)
{
#if defined (PROTOCOL_T0)
// limit retransmitions (requested by error signal)
	uint8_t max_errors = 20;
#endif
	uint8_t sample_count, bit_count, parity, error = 0;
	uint16_t sample_byte, rx_count = 0;

// wait IDLE on line (ISO7816 recommends minimal 3 samples!
	for (;;) {
		while (0x10 != (VPORTA_IN & 0x10)) ;
		if (0x10 != (VPORTA_IN & 0x10))
			continue;
		if (VPORTA_IN & 0x10)
			break;
	}
// line is idle
	for (;;) {
// wait start bit
		for (;;) {
			while (VPORTA_IN & 0x10) ;
// init timer to half ETU (+3 => precompensation, read before middle of bit)
			TCA0_SINGLE_CNT = (card_io_data.etu + 3) / 2;
			TCA0_SINGLE_INTFLAGS = 1;	// clear OVF
			if (VPORTA_IN & 0x10)
				continue;
			if (!(VPORTA_IN & 0x10))
				break;
		}
// byte loop (start, 8 data bits, 1x parity bit, stop bit)
// start bit is checked by parity..
		bit_count = 11;
		parity = 0x20;
		sample_byte = 0;

		do {
			while ((TCA0_SINGLE_INTFLAGS & 1) == 0) ;	// wait clock pulse
			TCA0_SINGLE_INTFLAGS = 1;	// clear OVF
// possible values: 0x00,0x10,0x20,0x30 -> bit 5 = line state
			sample_count = VPORTA_IN & 0x10;
			sample_count += (VPORTA_IN & 0x10);
			sample_count += (VPORTA_IN & 0x10);
			parity ^= sample_count;	// bit 5 = parity
#if C_TS == 0x3f
// final: Start 0 1 2 3 4 5 6 7 Parity Stop
			sample_byte <<= 1;
			sample_count >>= 5;
			sample_byte |= sample_count;
#else
// final: Stop P 7 6 5 4 3 2 1 0 Start
			sample_byte >>= 1;
			if (sample_count & 0x20)
				sample_byte |= 0x400;
#endif
		} while (--bit_count);

// in middle of 1st stop bit
// check stop bit ..
#if C_TS == 0x3f
		if (!(sample_byte & 1)) {
#else
		if (!(sample_byte & 0x400)) {
#endif
// out of byte sync
			error = CARD_IO_PARITY_ERROR;
		}
// check parity bit
		if (parity & 0x20) {
#if defined PROTOCOL_T0 && defined PROTOCOL_T1
			if (card_io_data.proto == 0 && max_errors) {
				max_errors--;
				// in middle of 1st stop bit
				VPORTA_DIR &= ~0x10;	// signalize repeat
				send_C(0);
				// in middle of 2nd stop bit
				send_C(1);
				// in middle of 3rd stop bit
				continue;	// wait repeated start bit
			} else {
				error = CARD_IO_PARITY_ERROR;
			}
#elif defined PROTOCOL_T0
			if (max_errors) {
				max_errors--;
				// in middle of 1st stop bit
				VPORTA_DIR &= ~0x10;	// signalize repeat
				send_C(0);
				// in middle of 2nd stop bit
				send_C(1);
				// in middle of 3rd stop bit
				continue;	// wait repeated start bit
			} else {
				error = CARD_IO_PARITY_ERROR;
			}
#elif defined PROTOCOL_T1
			error = CARD_IO_PARITY_ERROR;
#endif
		}
// save byte to buffer
		if (len) {
			len--;
#if C_TS == 0x3f
			sample_byte >>= 2;
			*(data++) = ~(sample_byte & 0xff);
#else
			sample_byte >>= 1;
			*(data++) = sample_byte & 0xff;
#endif
			rx_count++;
		}
// wait IDLE on line (ISO7816 recommends minimal 3 samples!
		for (;;) {
			while (!(VPORTA_IN & 0x10)) ;
			if (!(VPORTA_IN & 0x10))
				continue;
			if (VPORTA_IN & 0x10)
				break;
		}
// wait 14 more stop bits
		sample_count = 14;
		for (;;) {
			// timer overflow ?
			if ((TCA0_SINGLE_INTFLAGS & 1) == 1) {
				TCA0_SINGLE_INTFLAGS = 1;
				if ((--sample_count) == 0) {
					data -= rx_count;
					if (error) {
						*(data) = error;
						return 0;
					}
#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
// here at least 1st byte is available (this does not apply if "len" was 0), this is ignored here!
#ifdef PROTOCOL_T1
					// save NAD value
					card_io_data.NAD = *data;
#endif
					// test PPSS
					if (card_io_data.null_send == 0xff) {
						card_io_data.null_send = 0;
						if (0xff == *data)
							return parse_pps(data, rx_count);
					}
#endif
					return rx_count;
				}
			}
			// possible start bit (at least two samples)
			if (0 == (VPORTA_IN & 0x10)) {
				if (!(VPORTA_IN & 0x10))
					break;

			}
		}
	}
}

#if defined PROTOCOL_T0
static uint8_t vector_3_t0_top()
{
// T0 protocol:
// max time .. 960 * WI * FI/f (WI is coded in TC2, if not present WI = 10)
// 372 or 512 from TA1 = Fi, 65536 divisor factor for timer3
// max value for 372 960*10*372/65535 = 54
// max value for 512 960*10*512/65535 = 75
#if (C_ATR_TA1 & 0xF0) == 0x90
	return 68;
#elif (C_ATR_TA1 & 0xF0) == 0
	return 48;
#elif (C_ATR_TA1 & 0xF0) == 0x10
	return 48;
#else
#error Please check TA1 value, Fi is not 512 or 372
#endif
}
#endif				// PROTOCOL_T0

#if defined PROTOCOL_T1
static uint8_t vector_3_t1_top()
{
// T1 protocol:
// timer is programmed to divide reader clock by 65535, count up to 250
// (number of overflows). This is 250*65535 clock cycles, for 5MHz reader,
// this is about 3.2 sec. BWT in ATR is set to 6, then 960* 2^6 *372/5MHz
// this is about 4.5 seconds.
	return 250;
}

static void vector_3_t1_wtx()
{
#ifdef T1_CRC
#error TODO .. missing code for CRC
#endif
	uint8_t wtx_data[5];
	uint8_t nad = card_io_data.NAD;

	nad = (nad >> 4) | ((nad & 0x0f) << 4);
	wtx_data[0] = nad;
	wtx_data[1] = 0xc3;	// request WTX (S block)
	wtx_data[2] = 1;	// data len 1 byte
	wtx_data[3] = 1;	// request "one" WTX
	wtx_data[4] = nad ^ 0xc3;	// // LRC (CRC is not supported!)

	card_io_tx(wtx_data, 5);
	card_io_rx(wtx_data, 5);
}
#endif				// PROTOCOL_T1

// This is TCA0_OVF_vect, but compact vector table is turned on,
// read targets/AVR128DA/avr.S
void __vector_3(void) __attribute__((signal));
void __vector_3(void)
{
	uint8_t top, counter;

#if defined PROTOCOL_T0 && defined PROTOCOL_T1
	uint8_t proto = card_io_data.proto;

	if (proto == 0)
		top = vector_3_t0_top();
	else
		top = vector_3_t1_top();

#elif defined PROTOCOL_T0
	top = vector_3_t0_top();
#elif defined PROTOCOL_T1
	top = vector_3_t1_top();
#endif
	counter = card_io_data.null_send + 1;
	card_io_data.null_send = counter;
	if (counter == top) {
// reprogram timer back to count to ETU
		card_io_timer_etu();

#if defined PROTOCOL_T0 && defined PROTOCOL_T1
		if (proto == 0)
			card_io_tx_byte(0x60, 0);
		else
			vector_3_t1_wtx();
#elif defined PROTOCOL_T0
		card_io_tx_byte(0x60);
#elif defined PROTOCOL_T1
		vector_3_t1_wtx();
#endif
		card_io_start_null();
	}
	TCA0_SINGLE_INTFLAGS = 1;
}
