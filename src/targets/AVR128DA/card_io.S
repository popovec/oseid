/*
    card_io.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2020-2021 Peter Popovec, popovec.peter@gmail.com
    (This code is based on card_io.S from atmega128 target in this project)
    Copyright (C) 2015-2018 Peter Popovec, popovec.peter@gmail.com

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

   For now, software serial is used, but hardware USART on AVR128DA device
   is planed to be used in future.

   Pin assigment:
   ISO7816-3    AVR128DA
   ----------------------
   I/O          PA4 receive/transmit
   CLK          PA2
   RESET	PA3

   Fuse 5 is programmed to 0xc0 - hardware RESET from PF6 is not used.
   Card reset in handled in avr.S, please read section .init9

   Warning, all register addresses without names, number corresponds to
   AVR128DA device only!
   For lot of assembler lines C equivalent code is available in comments.
   (Especially in device setup i.e. EVENT system setup, TIMER setup...)

*/

//#define ENABLE_WARM_ATR

#if !defined(TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE) && !defined(TRANSMISSION_PROTOCOL_MODE_SPECIFIC)
#define TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
//#define TRANSMISSION_PROTOCOL_MODE_SPECIFIC
#endif 
//#define C_TS 0x3f
#define C_TS 0x3b


#define C_ATR_TA1 0x96
#define C_ETU      16

//#define C_ATR_TA1 0x95
//#define C_ETU      32

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

// PORT A AVR128DA .. (VPORTA)
// 0x00 .. DIR
// 0x01 .. OUT
// 0x02 .. IN
// 0x03 flags
//#define CARD_IO_PORT	0x15	// not used here
#define CARD_IO_DIR	0x00
#define CARD_IO_BIT	4
#define CARD_IO_BIT_MASK 0x10
#define CARD_IO_IN	0x02

// TCA CNT
#define TIMER_REG_L	0x0A20
#define TIMER_REG_H	0x0A21

	.section .progmem.card_io_data,"ax",@progbits
#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
// table TA1 to ETU
TA_to_CNT:
	.byte	0x96,	0,             16-1
	.byte	0x95,	0,             32-1
	.byte	0x94,	0,             64-1
	.byte	0x93,	hi8(128-1),    lo8(128-1)
	.byte	0x92,	hi8(256-1),    lo8(256-1)
	.byte	0x91,	hi8(512-1),    lo8(512-1)

	.byte	0x18,	hi8(372/12-1), lo8(372/12-1)	// 31
//	.byte	0x15,	hi8(372/8-1),  lo8(372/8-1)	// 46.5
	.byte	0x14,	hi8(372/4-1),  lo8(372/4-1)	// 93
	.byte	0x13,	hi8(372/3-1),  lo8(372/3-1)	// 124
	.byte	0x12,	hi8(372/2-1),  lo8(372/2-1)	// 176
	.byte	0x11,	hi8(372-1),    lo8(372-1)	// 372


	.byte	0x08,	hi8(372/12-1), lo8(372/12-1)	// 31
//	.byte	0x05,	hi8(372/8-1),  lo8(372/8-1)	// 46.5
	.byte	0x04,	hi8(372/4-1),  lo8(372/4-1)	// 93
	.byte	0x03,	hi8(372/3-1),  lo8(372/3-1)	// 124
	.byte	0x02,	hi8(372/2-1),  lo8(372/2-1)	// 176
// default 372 at last position!
// label card_io_pps_PPS1: r18,r19 is set to this value..
	.byte	0x01,	hi8(372-1),    lo8(372-1)	// 372
	.byte	0
#endif
//     - TS from #define ..
//0xf5 = SEND Ta1..TD1 .. 5 hist. bytes
//     - TA1 from #define .
//0    = TB1
//2    = TC1 gurad time extended by two bits
//0x10 = TD1 - send TA2
//0x80 = TA2 - only T0 protocol
//hist. bytes OsEID...
card_io_atr_string:
#ifdef TRANSMISSION_PROTOCOL_MODE_SPECIFIC
	.byte C_TS,0xf5,C_ATR_TA1,0,2,0x10,0x80,'O','s','E','I','D'
#define ATR_LEN 12
#ifdef ENABLE_WARM_ATR
card_io_atr_warm_string:
	.byte C_TS,0xf5,C_ATR_TA1,0,2,0x10,0x80,'O','s','E','I','D'
#define WARM_ATR_LEN 12
#endif
#endif

#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
#ifdef T1_TRANSPORT
#ifndef T1_IFS
#error no IFS defined
#endif
#if T1_IFS != 254
#error No ATR for this IFS
#endif
#ifdef T1_CRC	// LRC/CRC
#warning There is no CRC block for WTI (code below .. vector_null_send:)
	.byte C_TS,0xD5,C_ATR_TA1,0x02,0x80,0x71,0xFE,0x65,0x01,'O','s','E','I','D',0x5e
#define ATR_LEN 15
#else	// LRC/CRC
	.byte C_TS,0xD5,C_ATR_TA1,0x02,0x80,0x31,0xFE,0x65,'O','s','E','I','D',0x1f
#define ATR_LEN 14
#endif	// LRC/CRC

#else
	.byte C_TS,0xD5,C_ATR_TA1,0x02,0x00,'O','s','E','I','D'
#define ATR_LEN 10
#endif
#ifdef ENABLE_WARM_ATR
	.byte C_TS,0xD5,0x11,0x02,0x00,'O','s','E','I','D'
#define WARM_ATR_LEN 10
#endif
#endif

//.balign 2

/*
card_io_rx uses error signaling, character frames:

T1 character (of course, more stop bits are accepted too)
   S   0   1   2   3   4   5   6   7   P   s1  S(next)
_     _______________________________________     __
 |   |   |   |   |   |   |   |   |   |   |   |   |
 +---+---+---+---+---+---+---+---+---+---+   +---+--

T0 character
   S   0   1   2   3   4   5   6   7   P   s1  s2  S(next)
_     ___________________________________________     __
 |   |   |   |   |   |   |   |   |   |   |   |   |   |
 +---+---+---+---+---+---+---+---+---+---+       +---+--

Card to reader error signaling (only T0), two ETU for error signal
   S   0   1   2   3   4   5   6   7   P   s1  s2  s3  S(repeat)
_     _____________________________________  .   .  _     __
 |   |   |   |   |   |   |   |   |   |   | |       | |   |
 +---+---+---+---+---+---+---+---+---+---+ +-------+ +---+--


card_io_tx always uses two stop bits (T0/T1 protocol). For T0
protocol after 1st stop bit  line is sampled and if error signal
is detected, one more stop bit is send to reader.

   S   0   1   2   3   4   5   6   7   P   s1  s2         S(repeat)
_     _____________________________________  .   _______     __
 |   |   |   |   |   |   |   |   |   |   | |    ////    |   |
 +---+---+---+---+---+---+---+---+---+---+ +---+---+    +---+--

*/

	.section .text.card_io,"ax",@progbits
	.global	card_io_rx
	.type	card_io_rx, @function

// uint16_t card_io_rx (uint8_t * data, uint16_t len);
// return code 0:
//   1st character in buffer:
//	1 parity error
//	2 PPS error

// define maximum parity error per one character
#define MAX_PARITY_ERR 1
card_io_rx:
	push	r28
	push	r29

	movw	r26, r24		// buffer pointer
	movw	r28, r22		//size
// save protocol into T
	lds	r22,card_io_proto
	bst	r22,0
// parity error counter (per character)
	ldi	r22,MAX_PARITY_ERR
// preload half ETU
	lds	r18,card_io_etu
	lds	r19,card_io_etu+1
	lsr	r19
	ror	r18
// counter of realy received character
	ldi	r24, 0
	ldi	r25, 0
// parity error counter (per character)
	ldi	r22,MAX_PARITY_ERR
// wait line idle
	ldi	r20,4
	sec
card_io_idle1:
	sbis	CARD_IO_IN,CARD_IO_BIT
	subi	r20,1
	adc	r20,r1
	cpi	r20,7
	brne	card_io_idle1
// wait start bit
card_io_start1:
// test IO line
	sbic	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_start1

// posible start bit .. sync timer TCA_CNT = half ETU
	sts	0x0A20, r18
	sts	0x0A21, r19
	dec	r20

card_io_start1_loop:
// filter IO, if jump to 7, go back to wait
// start bit, if fall below 3, this is real start bit
// update io filter
	cpi	r20,7
	breq	card_io_start1
	sbis	CARD_IO_IN,CARD_IO_BIT
	subi	r20,1
	adc	r20,r1
	cpi	r20,3
	brne	card_io_start1_loop
//	rjmp	.+0


/////////////////////////////////////////////////////////
// byte loop
card_io_byte_loop:
// clear timer overflow
	ldi	r23,1
	sts     0x0A0B, r23
// sample 10 bits (start, 1..8 parity)
	ldi	r21,10
// parity counter
	ldi	r30,1
// bite loop
card_io_bite_loop:
// update io filter
	cpi	r20,7
	sbis	CARD_IO_IN,CARD_IO_BIT
	subi	r20,1
	adc	r20,r1
// test timer tick
	lds	r23,0x0A0B
	andi	r23,1
	breq	card_io_bite_loop
// time tick, clear request
	sts	0x0A0B,r23
// calculate parity
// load bite from io_filter
	cpi	r20,4
	adc	r30,r1
// rotate bite to register
// load bite from io_filter
	cpi	r20,4
#if C_TS == 0x3f
	rol	r0
#else
	ror	r0
#endif
// decrement bit counter
	dec	r21
	brne	card_io_bite_loop
// 10 bits rotate parity bit to C
#if C_TS == 0x3f
	ror	r0
	inc	r30
#else
	rol	r0
	com	r0
#endif
// signalize parity error or save character
	andi	r30,1
	breq	card_io_parity_error

// renew parity error counter (per character)
	ldi	r22,MAX_PARITY_ERR
card_io_save_char:
// check if buffer space is available (maximum received chars 255)
	adiw	r28,0
	breq	1f
// save char
	st	X+,r0
	sbiw	r28,1
	adiw	r24,1
1:
// Time position:
// middle of parity bit
	rjmp	card_io_wait_next_stop_bit
//---------------------------------------------------
card_io_parity_error:
// T1 protocol .. save parity error
	brts	card_io_parity_too_many
// wrong parity, check number of parity errors
// per character
	tst	r22
	breq	card_io_parity_too_many		// already too many errors
// Time position:
// T0 protocol - middle of parity bit
1:
	lds	r23,0x0A0B
	andi	r23,1
	breq	1b
// Time position:
// T0 protocol - middle of 1st stop bit
// retransmition request, turn direction to output, PORT is already at 0
	sbi	CARD_IO_DIR,CARD_IO_BIT
// clear timer compare flag
	sts	0x0A0B, r23
// decrement counter of error per character
	dec	r22
	rjmp	card_io_wait_next_stop_bit

card_io_parity_too_many:
// repeated character received with parity error too
// clear buffer space counter and counter of
// received characters (RX continues, but all
// characters are ignored)

// return data size = 0, 1st character in buffer: 1 = parity error
// rewind to buffer start
	sub	r26,r24
	sbc	r27,r25
// error code
	ldi	r24,1
	st	X,r24
// clear size
	clr	r28
	clr	r29
	movw	r24,r28

card_io_wait_next_stop_bit:
// Time position:
// a) T1 protocol - middle of parity bit
// b) T0 protocol - middle of parity bit
// c) TO protocol, error signaling - middle of 1st stop bit
	brts	card_io_wait_last_stop_bit
// for T0 protocol add wait for one more stop bit
1:
	lds	r23,0x0A0B
	andi	r23,1
	breq	1b
// clear timer compare flag
	sts	0x0A0B, r23

card_io_wait_last_stop_bit:
// Time position:
// a) T1 protocol - middle of parity bit
// b) T0 protocol - middle of 1st stop bit
// c) TO protocol, error signaling - middle of 2nd stop bit
1:
	lds	r23,0x0A0B
	andi	r23,1
	breq	1b
// clear timer compare flag
	sts	0x0A0B, r23
// Time position:
// a) T1 protocol - middle of 1st stop bit
// b) T0 protocol - middle of 2nd stop bit
// c) TO protocol, error signaling - middle of 3rd stop bit
//
// clear error signal (this dows nothing if error signal was not active)
	cbi	CARD_IO_DIR,CARD_IO_BIT
// wait line idle
	ldi	r20,4
	sec
card_io_idle2:
	sbis	CARD_IO_IN,CARD_IO_BIT
	subi	r20,1
	adc	r20,r1
	cpi	r20,7
	brne	card_io_idle2

// wait 12 more stop bits
	ldi	r21,12
// wait start bit, minimal latency 7 cpu ticks
// maximal 20 cpu ticks
card_io_start2:
// test IO line
	sbic	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle3
// posible start bit .. sync timer TCA_CNT = C_ETU/2
	sts	0x0A20, r18
	sts	0x0A21, r19
	dec	r20

card_io_start3:
// filter IO, if jump to 7, go back to wait
// start bit, if fall below 3, this is real start bit
// update io filter
	cpi	r20,7
	breq	card_io_start2
	sbis	CARD_IO_IN,CARD_IO_BIT
	subi	r20,1
	adc	r20,r1
	cpi	r20,3
	brne	card_io_start3
	rjmp	card_io_byte_loop
//////////////////////////////////////////
// line is idle ..
card_io_idle3:
// timer expired?
	lds	r23,0x0A0B
	andi	r23,1
	breq	card_io_start2
// time tick, clear request
	sts	0x0A0B,r23
// decrement stop bit counter
	dec	r21
	brne	card_io_start2
// ok full frame received
#if defined (TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE) || defined(PROTOCOL_T1)
// X is pointer to frame, r25:24 is counter of characters
// poiter back to start
	sub	r26,r24
	sbc	r27,r25
	movw	r30,r26		// save buffer pointer
	ld	r22,X+
// save CLA (this is NAD in T1 protocol, we need this for S block - WTX request)
	sts	card_io_NAD,r22
#endif
// test if this ist 1st received frame after ATR (0xff in null_send)
	lds	r23,null_send
	inc	r23
	brne	1f
	sts	null_send,r23	// clear null_send
1:
#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
	cpi	r22,0xff	// test if this is PPSS
	breq	card_io_pps

// no PPS
card_io_pps_end:
#endif
	pop	r29
	pop	r28
	ret

#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
// 1st byte 0xff - PPS from interface device...(ISO7816-3:2006, 6.3.1)
card_io_pps:
// Check, if this is 1st frame after ATR? (ISO7816-3:2006,Figure 4)
	tst	r23
	breq	card_io_pps_parse
// class 0xff is disabled (NAD 0xff is disabled too), ignore this frame
card_io_pps_error:
// signalize error, (size = 0, return value in returned data)
	ldi	r24,2		// PPS error code
	st	Z,r24
// clear returned size (in case of correct PPS size = 0, return value in data = 0xff)
	clr	r24
card_io_pps_ok:
	clr	r25
	rjmp	card_io_pps_end
card_io_pps_parse:
// Table F/D  to timer in 1st page of flash.. no need to use LPM
	ldi	r28,lo8(TA_to_CNT+0x8000)
	ldi	r29,hi8(TA_to_CNT+0x8000)

	set		// flag, remove PPS1

// default F/D (If PPS1 is missing from PPS)
	ldi	r18,lo8((C_ETU_ATR-1))
	ldi	r19,hi8((C_ETU_ATR-1))

	mov	r23,r24		// copy size
	ld	r20,X+		// load PPS0
	eor	r22,r20		// calculate PCK in r22
	swap	r20
#ifdef T1_TRANSPORT
	cpi	r20,0x1f	// protocol 0,1
#else
	cpi	r20,0x0f	// protocol 0
#endif
	brcc	card_io_pps_error // erroneous PPS, unknown protocol, no response
	tst	r25		// length > 255, erroneous PPS, no response
	brne	card_io_pps_error
card_io_pps_PPS1:
	mov	r25,r22		// create copy of PCK, this is PCK for response PPS
	lsr	r20
	brcc	card_io_pps_no_PPS1
	dec	r23		// update size
	ld	r21,X+
	eor	r22,r21		// update PCK for received PPS

// test if we can use PPS1
// if not, remove PPS1 from response, and use recalculated PCK in r25
1:
	ld	r0,Y+
	tst	r0
	breq	2f	// no match found
// load timer values (r18,r19 is set to default if no match is found
// because last value in TA_to_CNT table is default..)
	ld	r19,Y+
	ld	r18,Y+
	cp	r21,r0
	brne	1b
// OK found
	eor	r25,r21	// update PCK for response PPS
	clt		// flag: do not remove PPS1
2:
// r0 == 0 - no TA1 change, other value: r22,r23 = new timer value
card_io_pps_no_PPS1:
	lsr	r20
	brcc	card_io_pps_no_PPS2
	dec	r23
	ld	r21,X+	// load PPS2
	eor	r22,r21	// update PCK for received PPS
	eor	r25,r21	// update PCK for response PPS
card_io_pps_no_PPS2:
	lsr	r20
	brcc	card_io_pps_no_PPS3
	dec	r23
	ld	r21,X+	// load PPS3
	eor	r22,r21	// update PCK for received PPS
	eor	r25,r21	// update PCK for response PPS
card_io_pps_no_PPS3:
	lsr	r20
	brcs	card_io_pps_error	// higest bite in PPS0 shoud be 0 (ISO7816-3/2006 9.2)
	subi	r23,3			// size PPSS,PPS0,LRS
	brne	card_io_pps_error
	ld	r21,X
	eor	r22,r21			// update PCK for received PPS
	brne	card_io_pps_error
//
// PPS frame OK, check if PPS1 must be removed
	brtc	1f

// requested F/D not found, remove PPS1 from response (ISO7816-3:2006 9.2)
	ldd	r21,Z+3
	std	Z+2,r21
	ldd	r21,Z+4
	std	Z+3,r21
// remove bit for PPS1 from PPS0
	ldd	r21,Z+1
	eor	r25,r21	// remove old PCK (from PPS0)
	andi	r21,0xef
	std	Z+1,r21
	eor	r25,r21	// update PCK (response PPS0)
	sbiw	r26,1	// move pointer back
	dec	r24	// reduce size for response PPS
1:
	st	X,r25	// PCK for response PPS

	ldi	r30,lo8(card_io_etu)
	ldi	r31,hi8(card_io_etu)
// new timer value for negotiated F/D
	std	Z+2,r18
	std	Z+3,r19
// negotiated protocol
	std	Z+5,r20
	rjmp	card_io_pps_ok
#endif
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	.global card_io_tx
	.type   card_io_tx, @function

// void card_io_tx(uint8_t * data, uint16_t len)

card_io_tx:
// reprogram timer to correct ETU and clear OVF
	rcall	card_io_stop_null
// save protocol into T
	lds	r20,card_io_proto
	bst	r20,0
// X is now buffer pointer
        movw    r26,r24
// size
	movw	r24,r22
//buffer loop
///////////////////////////////////////////
// TODO limit maximum repeats for one char ? for whole TX buffer?
card_io_tx0_buffer_loop:
// load byte
1:
        ld      r20,X
        rcall   card_io_tx_byte
// 0    - all ok
        tst     r21
//        brne    card_io_tx0_repeat
	brne	1b
// next character ..
        adiw    r26,1
        sbiw    r24,1
	brne    card_io_tx0_buffer_loop
#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
// switch to PPS values
	ldi	r30,lo8(card_io_etu)
	ldi	r31,hi8(card_io_etu)
	ldd	r0,Z+2
	std	Z+0,r0
	ldd	r0,Z+3
	std	z+1,r0
	ldd	r0,Z+5
	std	Z+4,r0
	rjmp	card_io_stop_null
#endif
#ifdef TRANSMISSION_PROTOCOL_MODE_SPECIFIC
	ret
#endif
/*
card_io_tx0_repeat:
	sec
	rcall	send_C	// wait 2 ETU for retransmit!
	sec
	rcall	send_C	//
	rjmp    card_io_tx0_buffer_loop
*/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// this code is called in normal way but is called from ISR too
// beware, ISR does not save whole register set ..

// BYTE is input
// clamped: R20,R21,R22,R23
// R21 output    0 = no error
//               !0 = repeat requested

#define PARITY r22
#define BITCOUNTER r21
#define BYTE   r20
#define TEMP r23
card_io_tx_byte:
#if C_TS == 0x3f
	com	BYTE
#endif
	ldi	BITCOUNTER,8
	sub	PARITY,PARITY
	rcall	send_C		// start bit (carry is cleared)
// character loop
card_io_tx0_ch_loop:
	eor	PARITY,BYTE	// calculate parity (in bit 7 or bit 0)
#if C_TS == 0x3f
	lsl	BYTE
#else
	lsr	BYTE
#endif
	rcall	send_C
	dec	BITCOUNTER
	brne	card_io_tx0_ch_loop

#if C_TS == 0x3f
	com	PARITY
	rol	PARITY
#else
	ror	PARITY
#endif
	rcall	send_C		// send parity bit

// sent 1st stop bit
	sec
	rcall	send_C		// 1st stop bit
// 1st stop bit is already on line, send second stop bit
	sec
	rcall	send_C		// 2nd stop bit
// protocol T1 - no error signaling (r21 is zero)
	brts	1f
// this is T0 code, we need check for byte retransmit
//this is middle point beetwen 1st stop bit and 2nd stop bit, sample I/O here
// TODO, use more samples (3 ? ) here
	in	r21,CARD_IO_IN
	com	r21
	andi	r21,0x10
	breq	1f		// no error
// on error send next (3rd) stop bit
	sec
	rcall	send_C
// r21 is 0x10 = error
1:
// 0 or !0  (tested by tst instruction)
//	swap	r21
	ret

// send Z if carry is set else A
// Z = 1 (pull up)
// A = 0
send_C:
//  while ((TCA0_SINGLE_INTFLAGS & 1) == 0);      // wait clock pulse
	lds	TEMP,0x0A0B
//	sbrs	TEMP, 0
//	rjmp	send_C
	andi	TEMP,1
	breq	send_C

//  TCA0_SINGLE_INTFLAGS = 1;     // clear OVF
//	ldi	TEMP,1			// 1 already in TEMP
	sts	0x0A0B, TEMP

	brcs	1f
//	A (dir  out)
	sbi	CARD_IO_DIR,CARD_IO_BIT
	ret
1:
//	Z (pull up, dir IN)
	cbi	CARD_IO_DIR,CARD_IO_BIT
	ret

#unset PARITY
#unset BITCOUNTER
#unset BYTE
#unset TEMP
/////////////////////////////////////////////////////////////////////////////////////////////////////////

        .global card_io_init
        .type card_io_init, @function


card_io_init:
// initialize I/O
// consider use of  hardware usart .. ?
// ISO 7816 pin
// I/O          to PA4 <= USART2 TX (receive/ transmit)
// CLK          to PA2

// ISO7816 pin CLK - used as clock source for bit transmit/receive
// connect (PIN 32 on TQFP 32 package) PA2 = CLK in, to event system (channel 1)

/////  EVSYS.CHANNEL1 = EVSYS_CHANNEL1_PORTA_PIN2_gc;
	ldi	r24,0x42
	sts	0x0211, r24
// connect channel1 to TCA timer/counter
//////  EVSYS.USERTCA0CNTA = 2;			// channel 1  (channel +1 here, because 0 = no input)
	ldi	r24, 2
	sts	0x023B, r24
// set event counting on TCA ..
//////  TCA0_SINGLE_EVCTRL = 1;       // Input event A, count on positive edge,
	ldi	r24,1
	sts	0x0A09,r24
// TCA setup (ISO7816 CLK to ETU divisor)
	ldi	r18,lo8((C_ETU_ATR-1))
	ldi	r19,hi8((C_ETU_ATR-1))
	ldi	r30,lo8(card_io_etu)
	ldi	r31,hi8(card_io_etu)
	std	Z+0,r18	// etu (ATR)
	std	Z+1,r19
	std	Z+2,r18	// etu (PPS)
	std	Z+3,r19
	std	Z+4,r1	// protocol ATR
	std	z+5,r1	// protocol PPS
// program PER and CNT, disable interrupt from overflow
	rcall	card_io_stop_null
//	sts	0x0A26,r18
//	sts	0x0A27,r19
/////  TCA0_SINGLE_CTRLA = 1;        // enable timer TCA, no clock prescaler ..
	sts	0x0A00,r24
/////  TCA0_SINGLE_CTRLB = 0;        // normal mode
	sts	0x0A01,r1

// we need wait (535) clock cycles and then ATR is sended back to reader
// (min 400, max 40000)
/////  TCA0_SINGLE_CNT = 64000;
	ldi	r18, lo8(64000)
	ldi	r19, hi8(64000)
	sts	0x0A20, r18
	sts	0x0A21, r19
// abowe: card_io_stop_null - CNT was cleared and overflow flag cleared

// PORT setup, open colector (drive port to low, enable pull up, use port
// DIR to transmit 0/1

/////  PORTA.PIN4CTRL = 8;           // enable pull up
/////  PORTA.OUTCLR = (1 << 4);      // if pin is output pin, drive to zero
	ldi	r24,8
	sts	0x0414, r24
	ldi	r24, 0x10
	sts	0x0406, r24
// initial protocol T0
	sts	card_io_proto,r1
// load ATR from FLASH to ram ..
// AVR128DA flash is mapped to 0x8000
// card_io_atr_string is in section .progmem (in 1st 32kiB page)
        ldi     r24,lo8(card_io_atr_string + 0x8000)
        ldi     r25,hi8(card_io_atr_string + 0x8000)
        ldi     r22,ATR_LEN
#ifdef ENABLE_WARM_ATR
// after warm reset different ATR can be sended back ..
	lds	r20,0x40		// load reset source RSTCTRL.RSTFR
	andi	r20,0x10		// test if this is SW reset (SWRF bit)
	sts	0x40,r20		// clear SWRF bit
	breq	1f
// Ok soft reset
        ldi     r24,lo8(card_io_atr_warm_string + 0x8000)
        ldi     r25,hi8(card_io_atr_warm_string + 0x8000)
        ldi     r22,WARM_ATR_LEN
1:
#endif
// map FLASH memory to Data space (bit 5,4 in NVMCTRL.CTRLB)
// here fixed flash page 0 is used
	sts	0x1000+1,r1
	clr	r23
// length in r23,r22, position r25:r24
	rcall	card_io_tx
// mark ATR sent
        ldi     r24,0xff
        sts     null_send,r24
#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
// negotiable mode
	ret
#endif
#ifdef TRANSMISSION_PROTOCOL_MODE_SPECIFIC
// specific mode
// switch speed as defined by Ta1 (specific mode)
	ldi	r18,lo8((C_ETU-1))
	ldi	r19,hi8((C_ETU-1))
	sts	card_io_etu,r18
	sts	card_io_etu+1,r19
// reprogram timer and do return
	rjmp	card_io_stop_null
#endif
// Compact Vector Table is enabled, priority 0 (low priority) vector
//        .global TCA0_OVF_vect
//        .type TCA0_OVF_vect, @function

        .global __vector_3
        .type __vector_3, @function

//TCA0_OVF_vect:
__vector_3:
	push	r0
	in      r0,0x3f
	push	r0
	push	r1
	push	r18
	push	r19
	push	r20
// count overflows
	lds	r18,null_send
	inc	r18
	sts	null_send,r18
// T1 protocol:
// timer is programmed to divide reader clock by 65535, here r20=250 (number
// of overflows). This is 250*65535 clock cycles, for 5MHz reader, this is
// about 3.2 sec. BWT in ATR is set to 6, then 960* 2^6 *372/5MHz, this is
// about 4.5 seconds.
	ldi	r20,250
	lds	r19,card_io_proto
	sbrs	r19,0
// T0 protocol:
// max time .. 960 * WI * FI/f (WI is coded in TC2, if not present WI = 10)
// 372 or 512 from TA1 = Fi, 65536 divisor factor for timer3
// max value for 372 960*10*372/65535 = 54
// max value for 512 960*10*512/65535 = 75

#if (C_ATR_TA1 & 0xF0) == 0x90
	ldi	r20,68
#elif (C_ATR_TA1 & 0xF0) == 0
	ldi	r20,48
#elif (C_ATR_TA1 & 0xF0) == 0x10
	ldi	r20,48
#else
#error Please check TA1 value, Fi is not 512 or 372
#endif
	cp	r20,r18
	breq	vector_null_send
null_send_end:
// clear overflow flag
	ldi	r18,1
	sts     0x0A0B,r18
	pop	r20
	pop	r19
	pop	r18
	pop	r1
	pop	r0
	out	0x3f,r0
	pop	r0
	reti

vector_null_send:
//push rest of not saved registers
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

// this in interrupt handler, clear r1 to allow call ABI functions
	clr	r1
// reprogram timer back to count to ETU
	lds	r20,card_io_etu
	lds	r21,card_io_etu+1
	ldi	r28,0
	ldi	r29,0x0a

	std	Y+0x26,r20
	std	Y+0x27,r21
// TCA0_SINGLE_CNT = 0;
	std	Y+0x20,r1
	std	Y+0x21,r1

// clear timer flag
        ldi     r20,1
	std	Y+0x0b,r20

///////////////////////////////////////////////////////////////////////////////////
// protocol
	bst	r19,0
	brtc	vector_T0
// protocol T1
	lds	r20,card_io_NAD
	swap	r20
	RCALL	card_io_tx_byte
	LDI	R20,0XC3
	RCALL	card_io_tx_byte
	LDI	R20,1
	RCALL	card_io_tx_byte
	LDI	R20,1
	RCALL	card_io_tx_byte
	LDI	R20,0XC3
	RCALL	card_io_tx_byte
// read response
	ldi	r24,lo8(card_io_wtx_response)
	ldi	r25,hi8(card_io_wtx_response)
	ldi	r22,5
	clr	r23
	rcall	card_io_rx
// TODO check response ..
	rjmp	vector_end

vector_T0:
	ldi	r20,0x60
// T flag is cleared (bst r19..) this enabled error signaling for T0 protocol
	rcall   card_io_tx_byte

// maximal two repeats of null byte

// clear overflow flag
	ldi	r20,1
	sts     0x0A0B,r20

        ldi     r20,0x60
        tst     r21
        breq    vector_end
        rcall   card_io_tx_byte
//////////////////////////////////////////////////////////////////////////////////

vector_end:
// timer BASE
	ldi	r28,0
	ldi	r29,0x0a
// timer count from 0 to 0xffff
	ldi	r20,0xff
	std	Y+0x26,r20
	std	Y+0x27,r20
// TCA0_SINGLE_CNT = 0;
	std	Y+0x20,r28
	std	Y+0x21,r28
// clear counter for null send...
	sts	null_send,r28

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
	rjmp	null_send_end

	.global card_io_start_null
	.type card_io_start_null, @function

card_io_start_null:
// timer count from 0 to 0xffff
	ldi	r20,0xff
	ldi	r21,0xff
	rcall	card_io_program_timer
// clear variable - this is counter 0..48/68 then null is send to reader
	sts	null_send,r1
// enable interrupt from timer overflow
// (r20 is set to 1 in card_io_program_timer)
// Z is pointer to timer base
	std	Z+0x0a,r20
	ret

	.global card_io_stop_null
	.type card_io_stop_null, @function

card_io_stop_null:
	lds	r20,card_io_etu
	lds	r21,card_io_etu+1

card_io_program_timer:
	cli
// timer base
	ldi	r30,0
	ldi	r31,0x0a
// disable interrupt from timer
	std	Z+0x0a,r1
// TCA0_SINGLE_PER
	std	Z+0x26,r20
	std	Z+0x27,r21
// clear TCA0  counter
// TCA0_SINGLE_CNT = 0;
	std	Z+0x20,r1
	std	Z+0x21,r1
// disable interrupt from timer overflow
	std	Z+0x0a,r1
// clear overflow
	ldi	r20,1
	std	Z+0x0b,r20
	sei
	ret

	.section .noinit,"aw",@nobits
// multifunction variable
// a) after ATR this is set to 0xff, 1st received frame clear this
//    1st frame is checked for PTS - if yes, this is handled internaly
// b) if null sending mode is requested, this is incremented from 0.. max 68
null_send:
	.skip   1
// do not change order of next variables!
card_io_etu:
	.skip	2	// actual timer value
	.skip	2	// timer value for negotiated baud rate
card_io_proto:
	.skip	1	// actual protocol
	.skip	1	// negotiated protocol (by PPS)
card_io_NAD:
	.skip	1
card_io_wtx_response:
	.skip	5
