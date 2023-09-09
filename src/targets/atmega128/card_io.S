/*
    card_io.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2023 Peter Popovec, popovec.peter@gmail.com

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

    Atmega128 card IO

    please check card_io.h for functions in this module

*/
#include <avr/io.h>
#include "card_io.h"


#if !defined (TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE) && !defined(TRANSMISSION_PROTOCOL_MODE_SPECIFIC)
#define TRANSMISSION_PROTOCOL_MODE_SPECIFIC
#endif

#if defined (TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE) && defined(TRANSMISSION_PROTOCOL_MODE_SPECIFIC)
#error both TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE and TRANSMISSION_PROTOCOL_MODE_SPECIFIC defined
#endif

#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1) && defined(TRANSMISSION_PROTOCOL_MODE_SPECIFIC)
#error SPECIFIC mode and both T0,T1 protocol defined..
#endif


// For TX: (T0 mode), if receiver generates too many requests for
// retransmit, after "STOP_IO_AFTER_ERRORS" parity errors, character transmission
// is stopped. There is no way to signalize this to caller.
// For RX: after "STOP_IO_AFTER_ERRORS" in T0 mode, stop signaling errors.
// Receive with errors, return 0 as return code (1st byte in buffer = CARD_IO_PARITY_ERROR )
// in T1 mode "STOP_IO_AFTER_ERRORS" is not used (continue in reception, but
// return 0 and 1st character in buffer = CARD_IO_PARITY_ERROR
// In RX mode: if input buffer is full, receiving is not stopped, received data
// is discarded. This is not signalized to caller (APDU parsing finds this error
// and card generates an appropriate response


#define STOP_IO_AFTER_ERRORS 10

	.global	card_io_tx
	.type	card_io_tx, @function
// void card_io_tx(uint8_t * data, uint16_t len)

	.global	card_io_rx
	.type	card_io_rx, @function
// uint8_t card_io_rx (uint8_t * data, uint16_t len)

//#define C_TS 0x3f
#define C_TS 0x3b

// at limit on 4.8MHz reader ... (RC oscillator tuned at 13.5MHz)
// there is about 45 clock cycles for one ETU, ISO7816-3 recoments max
// 0.2 ETU latency = 9 clock cycles. Reading ETIFR (in loop) latency is
// at worst case 9 clock cyles...

#define C_ATR_TA1 0x96
#define C_ETU      16

// tested, working, but real C_ETU is 18.6 - not recommended
//#define C_ATR_TA1 0x19
//#define C_ETU 18

// tested, working, but real C_ETU is 23.25 - not recommended
// may fail on some card readers
//#define C_ATR_TA1 0x15
//#define C_ETU	23

//#define C_ATR_TA1 0x18
//#define C_ETU      31

//#define C_ATR_TA1 0x13
//#define C_ETU      93

//#define C_ATR_TA1 0x12
//#define C_ETU      186

#define C_ETU_ATR 372


#if (C_TS != 0x3b) && (C_TS != 0x3f)
#error Wrong TS value
#endif

#define CARD_IO_PORT _SFR_IO_ADDR(PORTB)
#define CARD_IO_DIR  _SFR_IO_ADDR(DDRB)
#define CARD_IO_BIT  1
#define CARD_IO_IN_MASK (1<<CARD_IO_BIT)
#define CARD_IO_IN   _SFR_IO_ADDR(PINB)


#define ETIFR_OFF (ETIFR-ETIFR)
#define ETIMSK_OFF (ETIMSK-ETIFR)
#define OCR_L_OFF (OCR3AL-ETIFR)
#define OCR_H_OFF (OCR3AH-ETIFR)
#define TCNT_L_OFF (TCNT3L-ETIFR)
#define TCNT_H_OFF (TCNT3H-ETIFR)
#define TCCR_A_OFF (TCCR3A-ETIFR)
#define TCCR_B_OFF (TCCR3B-ETIFR)

#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
// table TA1 to ETU
TA_to_CNT:
//	.byte	0x99,	hi8(512/20-1), lo8(512/20-1)	// 25.6
//	.byte	0x98,	hi8(512/12-1), lo8(512/12-1)	// 42.66666667
//	.byte	0x97,	hi8(512/64-1), lo8(512/64-1)	// 8
	.byte	0x96,	hi8(512/32-1), lo8(512/32-1)	// 16
	.byte	0x95,	hi8(512/16-1), lo8(512/16-1)	// 32
	.byte	0x94,	hi8(512/8-1),  lo8(512/8-1)	// 64
	.byte	0x93,	hi8(512/4-1),  lo8(512/4-1)	// 128
	.byte	0x92,	hi8(512/2-1),  lo8(512/2-1)	// 256
	.byte	0x91,	hi8(512/1-1),  lo8(512/1-1)	// 512

//	.byte	0x19	hi8(372/20-1), lo8(372/20-1)	// 18.6
	.byte	0x18,	hi8(372/12-1), lo8(372/12-1)	// 31
//	.byte	0x17,	hi8(372/64-1), lo8(372/64-1)	// 5.8125
//	.byte	0x16,	hi8(372/32-1), lo8(372/32-1)	// 11.625
//	.byte	0x15,	hi8(372/16-1), lo8(372/16-1)	// 23.25
	.byte	0x14,	hi8(372/8-1),  lo8(372/8-1)	// 93
	.byte	0x13,	hi8(372/4-1),  lo8(372/4-1)	// 124
	.byte	0x12,	hi8(372/2-1),  lo8(372/2-1)	// 176
	.byte	0x11,	hi8(372-1),    lo8(372-1)	// 372

//	.byte	0x09	hi8(372/20-1), lo8(372/20-1)	// 18.6
	.byte	0x08,	hi8(372/12-1), lo8(372/12-1)	// 31
//	.byte	0x07,	hi8(372/64-1), lo8(372/64-1)	// 5.8125
//	.byte	0x06,	hi8(372/32-1), lo8(372/32-1)	// 11.625
//	.byte	0x05,	hi8(372/16-1), lo8(372/16-1)	// 23.25
	.byte	0x04,	hi8(372/8-1),  lo8(372/8-1)	// 93
	.byte	0x03,	hi8(372/4-1),  lo8(372/4-1)	// 124
	.byte	0x02,	hi8(372/2-1),  lo8(372/2-1)	// 176
	.byte	0x01,	hi8(372-1),    lo8(372-1)	// 372


// if we fail to find F/D from PPS1, this is default
	.byte	0,	hi8(372-1),    lo8(372-1)	// 372
card_io_atr_string:

#if defined(PROTOCOL_T0) && defined(PROTOCOL_T1)
#if C_ATR_TA1 == 0x96
	.byte 0x3b,0xD5,0x96,0x02,0x80,0x31,0xFE,0x65,'O','s','E','I','D',0x1f
#elif C_ATR_TA1 == 0x18
	.byte 0x3b,0xD5,0x18,0x02,0x80,0x31,0xFE,0x65,'O','s','E','I','D',0x91
#else
#error Please define ATR for this TA1
#endif

#elif defined(PROTOCOL_T0)
//     - TS from #define ..
//0xf5 = SEND Ta1..TD1 .. 5 hist. bytes
//     - TA1 from #define .
//0    = TB1
//2    = TC1 gurad time extended by two bits
//0x00 = TD1
//hist. bytes OsEID...
	.byte C_TS,0xf5,C_ATR_TA1,0,2,0x00,'O','s','E','I','D'
#else
// T1 only
#if C_ATR_TA1 == 0x96
	.byte C_TS,0xD5,0x96,0x02,0x81,0x31,0xFE,0x65,'O','s','E','I','D',0x1e
#elif C_ATR_TA1 == 0x18
	.byte C_TS,0xD5,0x18,0x02,0x81,0x31,0xFE,0x65,'O','s','E','I','D',0x90
#else
#error Please define ATR for this TA1
#endif

#endif

#else	// TRANSMISSION_PROTOCOL_MODE_SPECIFIC
#if defined(PROTOCOL_T0)
card_io_atr_string:
//     - TS from #define ..
//0xf5 = SEND Ta1..TD1 .. 5 hist. bytes
//     - TA1 from #define .
//0    = TB1
//2    = TC1 gurad time extended by two bits
//0x10 = TD1 - send TA2
//0x80 = TA2 - only T0 protocol
//hist. bytes OsEID...
	.byte C_TS,0xf5,C_ATR_TA1,0,2,0x10,0x80,'O','s','E','I','D'
#else
// protocol T1 (specific mode)
	.byte 0x3B,0xF5,0x18,0x00,0x02,0x91,0x81,0x31,0xFE,0x65,'O','s','E','I','D',0x21
#endif
#endif
card_io_atr_string_end:
#define ATR_LEN (card_io_atr_string_end - card_io_atr_string)
.balign 2


// tune osccal to maximum
card_io_osccal_max:
// calibrate oscillator at maximum
	lds	r23,OSCCAL
	in	r22,0x3f
	cli
0:
	inc	r23
	brne	1f
	out	0x3f,r22
	ret
1:
	ori	r23,3
// read atmega errata - after OSCCAL change device
// may execute some of the subsequent instructions
// incorrectly.
	sts	OSCCAL,r23
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	rjmp	0b


// preset r21 for mode 0xf = 4 CTC or 0x7 = NORMAL
// clear TCNT, in r30,r31 timer registers offset (from etifr)
// clear r20
card_io_timer_mode:
	clr	r20
	ldi	r30,lo8(ETIFR)
	ldi	r31,hi8(ETIFR)
//disable interrupt from timer
	std	Z+ETIMSK_OFF,r20
// top OCR3A od 0xffff
	std	Z+TCCR_A_OFF,r20
	std	Z+TCCR_B_OFF,r21
// count from 0
	std	Z+TCNT_H_OFF,r20
	std	Z+TCNT_L_OFF,r20
// clear OCF3A and TOV3 request
	ldi	r21,0x14
	std    Z+ETIFR_OFF,r21
	ret
////////////////////////////////////////////////////////////////
// used registers:
// r30,31 pointer to ETIFR
// r20 input/output r21,22 clamped, r23 clamped in send_Z/send_A
// r19 clamped if fast output mode is used (out not cbi/sbi)
// return: r20 = 0 and ZERO if character retransmit requested (T0 protocol)

card_io_tx_byte:
// initial parity
#if C_TS == 0x3f
	ldi	r22,0x7f
#else
	ldi	r22,0x01
// inverse .. A/Z
	com	r20
#endif
// bite counter (start bit + 8 bits)
	ldi	r21,9
// send start bit (negative logic)
	sec
// character loop
card_io_tx0_ch_loop:
// calculate parity
	eor	r22,r20
card_io_tx0_ch_loop2:
// two types of output, cbi/sbi or out (4/5 clock cysles, or 3 slock cycles)
#if 0
1:
	ldd	r23,Z+ETIFR_OFF
	andi	r23,0x10
	breq	1b
	brcs    1f
	cbi	CARD_IO_DIR,CARD_IO_BIT
	rjmp	2f
1:
	sbi     CARD_IO_DIR,CARD_IO_BIT
2:
#else
	sbc	r19,r19
	andi	r19,CARD_IO_IN_MASK
1:
	ldd	r23,Z+ETIFR_OFF
	andi	r23,0x10
	breq	1b

	out	CARD_IO_DIR,r19
#endif
	std	Z+ETIFR_OFF,r23
#if C_TS == 0x3f
	lsl	r20
#else
	lsr	r20
#endif
// decrement bite counter
	dec	r21
	brne	card_io_tx0_ch_loop
// after 8 bits r20 is 0
#if C_TS == 0x3f
// 1st round, r20 = 0x00, r20 - 0xc1 = 0x3f, C is set
// 2nd round, r20 = 0xfc, r20 - 0xc1 - 0x3c, C is cleared
	subi	r20,0xc1
	brcc	1f
	lsl	r22
#else
// 1st round, r20 = 0x00, r20 - 0x04 = 0xfc, C is set
// 2nd round, r20 = 0x3f, r20 - 0x04 = 0x3B, C is cleared
	subi	r20,4
	brcc	1f
	lsr	r22
#endif
// r20 is used as stop bit data
// after 1st round r20 is 0x3f or 0xfc (2 stop bits negated)
// counter: parity bit + 2x stop bit
	ldi	r21,3
	rjmp	card_io_tx0_ch_loop2

1:
#ifdef PROTOCOL_T0
#ifdef PROTOCOL_T1
// protocol T1, do not test error signal
	lds	r20,card_io_proto
	tst	r20
// ZERO is not set ..
	brne	1f
#endif
// vote from 3 samples
	in	r20,CARD_IO_IN
	andi	r20,CARD_IO_IN_MASK
	in	r21,CARD_IO_IN
	andi	r21,CARD_IO_IN_MASK
	in	r22,CARD_IO_IN
	andi	r22,CARD_IO_IN_MASK
	add	r20,r22
	add	r20,r21
// 0 = retransmit character (ZERO is set)
	andi	r20,(CARD_IO_IN_MASK * 2)
#endif
1:
	ret

card_io_tx:
// X is now buffer pointer
	movw	r26,r24
// length
	movw	r24,r22
	rcall	card_io_osccal_max
// Setup TIMER mode 4 (top in OCR3A)
	ldi	r21,0x0f
	rcall	card_io_timer_mode
// Delay TX - one ETU, for ATR this is 372 clock cycles,
// another delay is in card_io_tx_byte, this is > 400 clock
// cycles which we need to have as a pause before sending
// the ATR. This delay is not interesting for normal TX.
	ldi	r23,0x10
	std	Z+ETIFR_OFF,r23
1:
	ldd	r23,Z+ETIFR_OFF
	andi	r23,0x10
	breq	1b
#ifdef PROTOCOL_T0
// parity error counter, max STOP_IO_AFTER_ERRORS parity errors, then mute TX
	ldi	r18,-(STOP_IO_AFTER_ERRORS)
// transmit is delayed by 2 ETU (to save FLASH, retransmit code here)
card_io_tx0_repeat:
// retransmit counter, do not continue after 256 errors
	inc	r18
	breq	2f
// at this moment second stop bit is on line
// wait for end of error signal
1:
	sbis	CARD_IO_IN,CARD_IO_BIT
	rjmp	1b
	sbis	CARD_IO_IN,CARD_IO_BIT
	rjmp	1b
#endif
// clear overflow (the card_io_tx_byte is waiting for new overflow)
// r23 is already set to 0x10
//	ldi	r23,0x10
	std	Z+ETIFR_OFF,r23
//buffer loop
///////////////////////////////////////////
card_io_tx0_buffer_loop:
// load byte
	ld	r20,X
	rcall	card_io_tx_byte
#ifdef PROTOCOL_T0
// 0    - character repeat (Z is set)
	breq	card_io_tx0_repeat
#endif
// next character ..
	adiw	r26,1
	sbiw	r24,1
	brne	card_io_tx0_buffer_loop

#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
	lds	r20,card_io_etu
	lds	r21,card_io_etu+1
	std	Z+OCR_H_OFF,r21
	std	Z+OCR_L_OFF,r20
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
	lds	r20,card_io_proto_new
	sts	card_io_proto,r20
#endif
#endif
2:
	ret


//////////////////////////////////////////////////////////////////////////
// uint16_t card_io_rx (uint8_t * data, uint16_t len);

card_io_rx:
	push	r16
	push	r17
	push	r28
	push	r29
	movw	r28, r22
	movw	r26, r24
#if defined(PROTOCOL_T0) && defined(PROTOCOL_T1)
// load protocol 0/1 into T
	lds	r22,card_io_proto
	bst	r22,1
#endif
// parity error counter, max STOP_IO_AFTER_ERRORS parity errors, then mute
// error signaling
	ldi	r22,-(STOP_IO_AFTER_ERRORS)
	ldi	r30,lo8(ETIFR)
	ldi	r31,hi8(ETIFR)
// preload half ETU (precompensate timer value...)
#if defined(TRANSMISSION_PROTOCOL_MODE_SPECIFIC)
	ldi	r18,lo8(((C_ETU+4)/2))
	ldi	r19,hi8(((C_ETU+4)/2))
#else // TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
	ldd	r25,Z+OCR_H_OFF
	ldd	r24,Z+OCR_L_OFF
	adiw	r24,5
	lsr	r25
	ror	r24
	movw	r18,r24
#endif
// counter of really received character
	clr	r24
	clr	r25
// wait line idle
card_io_idle1:
	sbis	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle1
	sbis	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle1
	sbis	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle1
// wait start bit
card_io_start1:
// test IO line
	sbic	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_start1
	sbic	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_start1
// resample at middle of bit..

// possible start bit .. sync timer	//
	std	Z+TCNT_H_OFF,r19
	std	Z+TCNT_L_OFF,r18

// clear overflow
	ldi	r23,0x10
	std	Z+ETIFR_OFF,r23
card_io_start1_loop:
// test timer tick
	ldd	r23,Z+ETIFR_OFF
	andi	r23,0x10
	breq	card_io_start1_loop
// middle of star bit
	sbic	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle1
	sbic	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle1
// ok start bit found


/////////////////////////////////////////////////////////
// byte loop
card_io_byte_loop:
// sample 8 bits + parity
	ldi	r21,9
// parity counter in r1 (zero register)
// clear this register (loop)
	clr	r1
// bite loop
card_io_rx_next_bit:
// clear overflow
	std	Z+ETIFR_OFF,r23
// test timer tick
1:
	ldd	r23,Z+ETIFR_OFF
	andi	r23,0x10
	breq	1b

// vote from 3 samples
	in	r16,CARD_IO_IN
	andi	r16,CARD_IO_IN_MASK
	in	r17,CARD_IO_IN
	andi	r17,CARD_IO_IN_MASK
	in	r20,CARD_IO_IN
	andi	r20,CARD_IO_IN_MASK
	add	r20,r16
	add	r20,r17

// calculate parity
	eor	r1,r20
	dec	r21
	breq	card_io_rx_byte_received
// load input into C
	cpi	r20,(CARD_IO_IN_MASK * 2)
#if C_TS == 0x3f
	rol	r0
#else
	ror	r0
#endif
	rjmp	card_io_rx_next_bit

card_io_rx_byte_received:
#if C_TS == 0x3f
        nop
#else
        com	r0
#endif
// wait 1st stop bit
	std	Z+ETIFR_OFF,r23
card_io_wait_1st_stop:
	ldd	r23,Z+ETIFR_OFF
	andi	r23,0x10
	breq	card_io_wait_1st_stop

// test stop bit
	sbis	CARD_IO_IN,CARD_IO_BIT
	clr	r22	// set error flag
	sbis	CARD_IO_IN,CARD_IO_BIT
	clr	r22	// set error flag

#if C_TS == 0x3f
// signalize parity error or save character
	sbrc	r1,(CARD_IO_BIT + 1)
	rjmp	card_io_byte_ok
#else
// signalize parity error or save character
	sbrs	r1,(CARD_IO_BIT + 1)
	rjmp	card_io_byte_ok
#endif
#ifdef PROTOCOL_T1
#ifdef PROTOCOL_T0
	brtc	1f
#endif
// active T1 protocol, parity error, set error flag
	clr	r22
1:
#endif
#ifdef PROTOCOL_T0
#ifdef PROTOCOL_T1
// skip error signaling for T1 protocol
	brts	1f
#endif
// active protocol T0, parity error, request retransmit
	tst	r22
	breq	1f	// too many retransmits, skip...
// request retransmission of character
	cbi	CARD_IO_DIR,CARD_IO_BIT
// clear timer compare flag
	std	Z+ETIFR_OFF, r23
card_io_p_error1:
	ldd	r23,Z+ETIFR_OFF
	andi	r23,0x10
	breq	card_io_p_error1
	std	Z+ETIFR_OFF,r23
card_io_p_error2:
	ldd	r23,Z+ETIFR_OFF
	andi	r23,0x10
	breq	card_io_p_error2
	std	Z+ETIFR_OFF, r23
	sbi	CARD_IO_DIR,CARD_IO_BIT
	rjmp	card_io_idle1	// wait for retransmit
1:
#endif
card_io_byte_ok:
// check if buffer space is available
	sbiw	r28,0
	breq	card_io_idle2
// save char
	st	X+,r0
	sbiw	r28,1
	adiw	r24,1

// wait line idle
card_io_idle2:
	sbis	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle2
	sbis	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle2
	sbis	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle2

// wait 20 more stop bits
	ldi	r21,20
card_io_start2:
// test IO line
	sbic	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle3
	sbic	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle3
// resample at middle of bit..

// possible start bit .. sync timer	//
	std	Z+TCNT_H_OFF,r19
	std	Z+TCNT_L_OFF,r18
// clear overflow
	ldi	r23,0x10
	std	Z+ETIFR_OFF,r23
card_io_start2_loop:
// test timer tick
	ldd	r23,Z+ETIFR_OFF
	andi	r23,0x10
	breq	card_io_start2_loop
// middle of star bit
	sbic	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle2		// false start
	sbic	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle2		// false start
	rjmp	card_io_byte_loop

card_io_idle3:
	ldd	r23,Z+ETIFR_OFF
	andi	r23,0x10
	breq	card_io_start2
	std	Z+ETIFR_OFF,r23
// decrement stop bit counter
	dec	r21
	brne	card_io_start2
// ok full frame received
// X is pointer to frame, r25:24 is counter of characters
// pointer back to start
	sub	r26,r24
	sbc	r27,r25
// if r22 = 0, frame is received with error
	tst	r22
	brne	1f
// store error code into buffer, return zero...
	ldi	r24,CARD_IO_PARITY_ERROR
	st	X,r24
card_io_error_end:
	clr	r24
	clr	r25
	rjmp	card_io_rx_end
1:
#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
	movw	r28,r26		// save buffer pointer
#endif
#if defined (TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE) || defined(PROTOCOL_T1)
// load 1st byte
	ld	r22,X+
#if defined(PROTOCOL_T1)
// save CLA (this is NAD in T1 protocol, we need this for S block - WTX request)
	sts	card_io_NAD,r22
#endif
#endif
// test if this is 1st received frame after ATR (0xff in null_send)
	lds	r23,null_send
	inc	r23
	brne	card_io_rx_end
	sts	null_send,r23	// clear null_send
#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
// 0xff in 1st byte?
	cpi	r22,0xff	// test if this is PPSS (and use r22 to check PCK)
	breq	card_io_pps_parse
#endif
card_io_rx_end:
	clr	r1
	pop	r29
	pop	r28
	pop	r17
	pop	r16
	ret
#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
card_io_pps_error:
// signalize error, (size = 0, return value in returned data)
	ldi	r24,CARD_IO_PPS_ERROR
	st	Y,r24
	rjmp	card_io_error_end

card_io_pps_parse:
	tst	r25	// length > 255, erroneous PPS, no response
	brne	card_io_pps_error
	subi	r24,2	// not enough bytes for PPS ?
#ifdef STRICT_PPS_CHECK
	brcs	card_io_pps_error
#endif
	ld	r20,X+	// load PPS0
	eor	r22,r20	// calculate PCK in r22
	swap	r20
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
        cpi     r20,0x20        // protocol 0,1 (r20 = 0...0x1f)
	brcc	card_io_pps_error	// erroneous PPS, unknown protocol, no response
#elif defined (PROTOCOL_T0)
        cpi     r20,0x10        // protocol 0 (r20 = 0...0x0f)
	brcc	card_io_pps_error	// erroneous PPS, unknown protocol, no response
#elif defined (PROTOCOL_T1)
	cpi	r20,0x10	// 0...0x0f - error
	brcs	card_io_pps_error	// erroneous PPS, unknown protocol, no response
	cpi	r20,0x20	// > 0x1f - error
	brcc	card_io_pps_error	// erroneous PPS, unknown protocol, no response
#endif
// default F/D (If PPS1 is missing from PPS)
//	clr	r23	// default for PPS1, already cleared

	lsr	r20
	brcc	card_io_pps_no_PPS1
	dec	r24
#ifdef STRICT_PPS_CHECK
	breq	card_io_pps_error
#endif
	ld	r23,X+	// load PPS1
	eor	r22,r23	// update PCK for received PPS

card_io_pps_no_PPS1:
	lsr	r20
	brcc	card_io_pps_no_PPS2
	dec	r24
#ifdef STRICT_PPS_CHECK
	breq	card_io_pps_error
#endif
	ld	r21,X+	// load PPS2
	eor	r22,r21	// update PCK for received PPS

card_io_pps_no_PPS2:
	lsr	r20
	brcc	card_io_pps_no_PPS3
	dec	r24
#ifdef STRICT_PPS_CHECK
	breq	card_io_pps_error
#endif
	ld	r21,X+	// load PPS2
	eor	r22,r21	// update PCK for received PPS

card_io_pps_no_PPS3:
	lsr	r20
	brcs	card_io_pps_error	// highest bite in PPS0 should be 0 (ISO7816-3/2006 9.2)
	dec	r24
	brne	card_io_pps_error

	ld	r21,X
	eor	r22,r21	// update PCK for received PPS
	brne	card_io_pps_error

// PPS frame OK
//=========================================================
// construct response
	ldi	r21,3		// initial PPS length
// test if we can use PPS1, if yes, add PPS1
// Table F/D to timer value
	ldi	r30,lo8(TA_to_CNT)
	ldi	r31,hi8(TA_to_CNT)
1:
	lpm	r0,Z+
// load timer values
	lpm	r18,Z+
	lpm	r19,Z+
	tst	r0
	breq	2f	// no match found
	cp	r23,r0	// compare PPS1 to value from table
	brne	1b

// OK PPS1 found in table, return PPS1
	ori	r20,0x10	// update PPS0
	inc	r21		// increment length
2:
//
	ldi	r22,CARD_IO_PPS
	st	Y+,r22
#if CARD_IO_PPS != 0xff
	ldi	r22,0xff	// PPSS (also used for PCK)
#endif
	st	Y+,r21	// PPS frame length
	st	Y+,r22	// PPSS
	st	Y+,r20	// PPS0

	eor	r22,r20	// update PCK by PPS0
	eor	r22,r0	// update PCK (by PPS1 or 0)
// skip PPS1 ?
	sbrc	r20,4
	st	Y+,r0	// PPS1
	st	Y+,r22	// PCK

// r24,25 is 0 (PPS in buffer)
// save timer value and protocol
	ldi	r28,lo8(card_io_data)
	ldi	r29,hi8(card_io_data)
// new timer value for negotiated F/D
	std	Y+(card_io_etu-card_io_data),r19
	std	Y+(card_io_etu-card_io_data+1),r18
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
// negotiated protocol
	std	Y+(card_io_proto_new-card_io_data),r20
#endif
	rjmp	card_io_rx_end
#endif

///////////////////////////////////////////////////////////////////////////////////////////////////////////
	.global TIMER3_OVF_vect
	.type TIMER3_OVF_vect, @function
TIMER3_OVF_vect:
	push	r0
	in	r0,0x3f
	push	r0
	push	r1
	push	r18
	push	r19
// count overflows
	lds	r1,null_send
	inc	r1

#if defined (TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE)

#if defined PROTOCOL_T1
// T1 protocol:
// timer is programmed to divide reader clock by 65535, here r18=200 (number
// of overflows). This is 200*65535 clock cycles, for 5MHz reader, this is
// about 2.6 sec. BWT in ATR is set to 6, then 960* 2^6 *372/5MHz, this is
// about 4.5 seconds.
	ldi	r18,200
#endif
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
	lds	r19,card_io_proto
	sbrs	r19,0
#endif
#if defined PROTOCOL_T0
// T0 protocol:
// TODO use better value (corresponding to TS from PPS)
	ldi	r18,27
#endif

#else // TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE/TRANSMISSION_PROTOCOL_MODE_SPECIFIC
#if defined PROTOCOL_T0
// max time .. 960 * WI * FI/f (WI is coded in TC2, if not present WI = 10)
// 372 or 512 from TA1 = Fi, 65536 divisor factor for timer3
// max value for 372 960*10*372/65535 = 54
// max value for 512 960*10*512/65535 = 75
// We will use half values.
#if (C_ATR_TA1 & 0xF0) == 0x90
	ldi	r18,37
#elif (C_ATR_TA1 & 0xF0) == 0
	ldi	r18,27
#elif (C_ATR_TA1 & 0xF0) == 0x10
	ldi	r18,27
#else
#error Please check TA1 value, Fi is not 512 or 372
#endif
#else // PROTOCOL_T0
// PROTOCOL_T1
	ldi	r18,200
#endif
#endif // TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE/TRANSMISSION_PROTOCOL_MODE_SPECIFIC
	cp	r18,r1
	breq	vector_null_send
vector_null_send_end:
	sts	null_send,r1
	pop	r19
	pop	r18
	pop	r1
	pop	r0
	out	0x3f,r0
	pop	r0
	reti

vector_null_send:
// send null byte
// need more registers..
	push	r20
	push	r21
	push	r22
	push	r23
	push	r24
	push	r25
	push	r26
	push	r27
	push	r28
	push	r29
	push	r30
	push	r31

	clr	r1

	ldi	r23,0
#if defined (PROTOCOL_T0)
	ldi	r22,1
	ldi	r24,0x60
#endif
#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
	sbrs	r19,0
	rjmp	1f
#endif

#if defined (PROTOCOL_T1)
	ldi	r22,5
	lds	r24,card_io_NAD
	swap	r24
	ldi	r25,0xc3
	eor	r25,r24
	push	r25		// checksum
	ldi	r25,1
	push	r25		// data
	push	r25		// data len
	ldi	r25,0xc3
	push	r25		// 0xc3
#endif
1:
	push	r24		// T0: 0x60  T1: NAD

	in	r28,0x3d
	in	r29,0x3e
	adiw	r28,1
	movw	r24,r28

#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
	push	r19		// T0/T1 proto
#endif
	rcall	card_io_tx

#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1)
	pop	r19
	sbrs	r19,0
	rjmp	1f
#endif
#if defined (PROTOCOL_T1)
	movw    r24,r28
	ldi	r23,0
	ldi	r22,5
	sei
	rcall	card_io_rx

	pop	r20	// checksum
	pop	r20	// 0x01
	pop	r20	// 0x01
	pop	r20	// 0xc3
#endif
1:
	pop	r20	// T0: 0x60  T1: NAD


	rcall 	card_io_start_null
	pop	r31
	pop	r30
	pop	r29
	pop	r28
	pop	r27
	pop	r26
	pop	r25
	pop	r24
	pop	r23
	pop	r22
	pop	r21
	pop	r20
	rjmp	vector_null_send_end

	.global card_io_start_null
	.type card_io_start_null, @function
card_io_start_null:
// reprogram timer to normal mode (count from 0 to 0xffff)
// Timer 3 mode CTC TOP 0xffff (mode 0)
// timer source T3,
// load timer register offset (ETIFR) into Z
	ldi	r21,0x07
	rcall	card_io_timer_mode
// r20 is zero (from card_io_timer_mode)
	sts	null_send,r20
// enable interrupt from overflow
	ldi	r20,4
	std	Z+ETIMSK_OFF,r20
	ret

// card reset
	.global USART0_RX_vect
	.type USART0_RX_vect, @function
USART0_RX_vect:
	jmp 	0


	.global card_io_init
	.type card_io_init, @function
card_io_init:
	ldi	r30,lo8(card_io_atr_string + ATR_LEN)
	ldi	r31,hi8(card_io_atr_string + ATR_LEN)
	ldi	r23,ATR_LEN
	mov	r22,r23
card_io_init_atr_loop:
// get stack address (as ATR string pointer for card_io_send_atr call)
// (slower but here speed is no problem, save one adiw instruction)
	in	r24,0x3d
	in	r25,0x3e
	sbiw	r30,1
	lpm	r20,Z
	push	r20
	dec	r23
	brne	card_io_init_atr_loop
// length in r23,r22, position r25:r24
	cli
// disable pull ups
	ldi	r20,0
	out	CARD_IO_PORT,r20
// all pins input
	out	CARD_IO_DIR,r20
#if defined(PROTOCOL_T0) && defined(PROTOCOL_T1)
	sts	card_io_proto,r20
	sts	card_io_proto_new,r20
#endif
// wait RESET
1:
	sbis	_SFR_IO_ADDR(PINE),0
	rjmp	1b

// initialize USART to receive, if start bit is received, this is
// RESET from reader
// baud rate
	ldi	r21,0xff
	out	0x09,r21	//UBRR0L
	ldi	r21,0
//	sts	0x90,r21	//UBRR0H - default after reset
// disable all USART fcion
	out	0x0a,r21	//UCSR0B
// enable RX, and irq from RX complete
	ldi	r21,0x90
	out	0x0a,r21	//UCSR0B

// Timer 3 mode CTC TOP by OCRA (mode 4)
// timer source T3,
// load timer register offset (ETIFR) into Z
	ldi	r21,0x0f
	rcall	card_io_timer_mode
// timer compare at 372 - normal ETU for ATR
	ldi	r20,lo8((C_ETU_ATR-1))
	ldi	r21,hi8((C_ETU_ATR-1))
	std	Z+OCR_H_OFF,r21
	std	Z+OCR_L_OFF,r20
#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
	sts	card_io_etu,r20
	sts	card_io_etu+1,r21
#endif
	rcall	card_io_tx

#if defined (TRANSMISSION_PROTOCOL_MODE_SPECIFIC)
// Z is pointer to ETIFR (thiw is set in card_io_tx)
	ldi	r20,lo8((C_ETU-1))
	ldi	r21,hi8((C_ETU-1))
	std	Z+OCR_H_OFF,r21
	std	Z+OCR_L_OFF,r20
#endif

	ldi	r24,0xff
	sts	null_send,r24	// mark ATR sent

// renew stack
	in	r24,0x3d
	in	r25,0x3e
	adiw	r24,ATR_LEN
	cli
	out	0x3d,r24
	sei
	out	0x3e,r25
	ret
.section	.noinit,"aw",@nobits

// multifunction variable
// a) after ATR this is set to 0xff, 1st received frame clear this
//    1st frame is checed for PTS - if yes, this is handled internally
// b) if null sending mode is requested, this is incremented from 0.. max 68
card_io_data:
null_send:
	.skip	1
#if defined (TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE)
card_io_etu:
	.skip	2	// timer value (from PPS negotiation)
#if defined(PROTOCOL_T0) && defined(PROTOCOL_T1)
card_io_proto:
	.skip	1       // actual protocol
card_io_proto_new:
	.skip   1	// negotiated protocol (by PPS)
#endif
#endif
#if  defined(PROTOCOL_T1)
card_io_NAD:
	.skip	1
#endif
