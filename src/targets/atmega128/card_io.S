/*
    card_io.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2018,2021 Peter Popovec, popovec.peter@gmail.com

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
//#include <avr/interrupt.h>


	.global	card_io_tx
	.type	card_io_tx, @function
//uint8_t card_io_tx0(uint8_t * data, uint8_t len)

// this enables debugging, errors on receive can be emulated
// in first 8 character received by this code error is generated
// by setting bit in "err" argument

//#define EMULATE_ERRORS
	.global	card_io_rx
	.type	card_io_rx, @function

#ifdef EMULATE_ERRORS
//uint8_t card_io_rx (uint8_t * data, uint8_t len, uint8_t err)
#else
//uint8_t card_io_rx (uint8_t * data, uint8_t len)
#endif

//#define C_TS 0x3f
#define C_TS 0x3b

#define C_ATR_TA1 0x18
#define C_ETU      31
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
#define CARD_IO_IN   _SFR_IO_ADDR(PINB)


#define ETIFR_OFF (ETIFR-ETIFR)
#define ETIMSK_OFF (ETIMSK-ETIFR)
#define OCR_L_OFF (OCR3AL-ETIFR)
#define OCR_H_OFF (OCR3AH-ETIFR)
#define TCNT_L_OFF (TCNT3L-ETIFR)
#define TCNT_H_OFF (TCNT3H-ETIFR)
#define TCCR_A_OFF (TCCR3A-ETIFR)
#define TCCR_B_OFF (TCCR3B-ETIFR)


.macro	send_A
	lds	r23,ETIFR
	andi	r23,0x10
	breq	.-8
	sbi	CARD_IO_DIR,CARD_IO_BIT
	sts	ETIFR,r23
.endm
.macro	send_Z
	lds	r23,ETIFR
	andi	r23,0x10
	breq	.-8
	cbi	CARD_IO_DIR,CARD_IO_BIT
	sts	ETIFR,r23
.endm


// change osccal to maximum, return with cli .. 
card_io_osccal_max:
// calibrate oscilator at maximum
	lds	r23,OSCCAL 
0:
// do not run SEI here, this is called from ISR too .. 
//	sei
	inc	r23
	brne	1f
	cli
	ret
1:
	ori	r23,3
// read atmega errata - after OSCCAL change device 
// may execute some of the subsequent instructions
// incorrectly.
	cli
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

card_io_send_atr:
// init
	cli
// disable pull ups
	ldi	r20,0
	out	CARD_IO_PORT,r20
// all pins input
	out	CARD_IO_DIR,r20
	rcall	card_io_osccal_max
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
// enable RX, and irq from RX complette
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

// clear OCR flag
	ldi	r20,0x10
	sts	ETIFR,r20
// wait minimum one ETU
0:
	lds	r20,ETIFR
	andi	r20,0x10
	breq	0b
	sts	ETIFR,r20
// in next code, one more ETU wait is programmed, ATR must be send
// after 400 ticks after RESET, this guarante minimal 2x 372 ticks
	rcall	card_io_tx
	ldi	r20,lo8((C_ETU-1))
	ldi	r21,hi8((C_ETU-1))
	sts	OCR3AH,r21
	sts	OCR3AL,r20
	ret

// preset r21 for mode 0xf = 4 CTC or 0x7 = NORMAL
// clear TCNT, in r30,r31 timer registers offset (from etifr)
// clear r20
card_io_timer_mode:
	clr	r20
	ldi	r30,lo8(ETIFR)
	ldi	r31,hi8(ETIFR)
	std	Z+TCCR_A_OFF,r20
	std	Z+TCCR_B_OFF,r21
// count from 0
	std	Z+TCNT_H_OFF,r20
	std	Z+TCNT_L_OFF,r20
	ret


card_io_tx_byte:
// parity	
	ldi	r30,0
// bite counter
	ldi	r21,8
// send start bit
	send_A
// character loop
card_io_tx0_ch_loop:
#if C_TS == 0x3f
	rol	r20
	brcc	card_io_tx0_ZERO
// send ONE
	send_A
// parity
	inc	r30
	rjmp	card_io_tx0_next_bite
card_io_tx0_ZERO:
	send_Z
card_io_tx0_next_bite:
#else
	ror	r20
	brcc	card_io_tx0_ZERO
// send ONE
	send_Z
// parity
	inc	r30
	rjmp	card_io_tx0_next_bite
card_io_tx0_ZERO:
	send_A
card_io_tx0_next_bite:
#endif
// decrement bite counter
	dec	r21		
	brne	card_io_tx0_ch_loop
// send parity bit
	ror	r30
#if C_TS == 0x3f
	brcc	card_io_tx0_parity_0
#else
	brcs	card_io_tx0_parity_0
#endif
	send_A
	rjmp	card_io_tx0_parity_bit
card_io_tx0_parity_0:
	send_Z
card_io_tx0_parity_bit:
// prepare two counters, r31:30 count all samples
// r19,18 count "A" value on line
// (safety check, if r31:30 overflow 32767, fail)
	clr	r30
	clr	r31
	movw	r24,r30
// wait for parity bit end, then send 1st stop bit
	send_Z
	ldi	r20,2	// two stop bit
// at this moment stop bit is sending, check retransmit reqest
card_io_tx0_stop:

	sbis	CARD_IO_IN,CARD_IO_BIT
	adiw	r24,1
	adiw	r30,1
	brmi	card_io_tx_byte_fail

	lds	r23,ETIFR
	andi	r23,0x10
	breq	card_io_tx0_stop
	sts	ETIFR,r23
	dec	r20
	brne	card_io_tx0_stop
// two stop bits received
// if r19:18 is over 25% of r31,30, then repeat of byte is requested
	lsr	r31
	rol	r30
	lsr	r31
	rol	r30
	sub	r30,r24
	sbc	r31,r25
	brcs	card_io_tx0_repeat
	clr	r24
	ret
card_io_tx_byte_fail:
	ldi	r24,0xff
	ret
card_io_tx_byte_repeat:
	ldi	r24,1
	ret

#define TX_LEN16
card_io_tx:
#ifdef TX_LEN16
	push	r28
	push	r29
// length
	movw	r28,r22
#endif
	rcall	card_io_osccal_max
	sei

// wait timer overflow 
	lds	r23,ETIFR
	andi	r23,0x10
	breq	.-8
	sts	ETIFR,r23
// X is now buffer pointer
	movw	r26,r24
//buffer loop
///////////////////////////////////////////
card_io_tx0_buffer_loop:
// load byte
	ld	r20,X
	rcall	card_io_tx_byte
// 0    - all ok
// 1    - do retransmit
// 0xff - overrun in parity error signal waiting
	cpi 	r24,1
	breq	card_io_tx0_repeat
	ldi	r25,0xff
	cpi	r24,0xff
	breq	card_io_tx0_fail
// next character .. 
	adiw	r26,1
#ifdef TX_LEN16
	sbiw	r28,1
#else
	dec	r22
#endif
	breq	card_io_tx0_ok
	rjmp	card_io_tx0_buffer_loop

card_io_tx0_repeat:
// wait minimal 2 ETU, then retransmit
	ldi	r20,2
card_io_tx0_repeat_0:
	lds	r23,ETIFR
	andi	r23,0x10
	breq	card_io_tx0_repeat_0
	sts	ETIFR,r23
	dec	r20
	brne	card_io_tx0_repeat_0
	rjmp	card_io_tx0_buffer_loop

card_io_tx0_ok:
card_io_tx0_fail:
#ifdef TX_LEN16
	pop	r29
	pop	r28
#endif
	ret

// uint16_t card_io_rx (uint8_t * data, uint16_t len);
// this function allow only 255 bytes to be read .. 
// define maximum parity error per one character
#define MAX_PARITY_ERR 1
card_io_rx:
	tst	r23
	breq	1f
// > 255 bytes allowed to be read.. clamp this to 255
	ldi	r22,255
1:
	movw	r26, r24
	rcall	card_io_osccal_max
	sei

// preload half ETU, for maximal speed, here value 15 is in r18,r19,
// 21 - working on 3.8/3.7 (wrong on 4.8)
// 20 - working on 4.8,3.7/3.8
// 11 - working on 4.8,3.7,3.8
// 10 - not working on 4.8,3.7,3.8

	ldi	r18,lo8((C_ETU/2))
	ldi	r19,hi8((C_ETU/2))
#ifdef EMULATE_ERRORS
// emulate errors
	mov	r0, r20
#endif
// counter of realy received character
	ldi	r24, 0
// parity error counter (per character)
	ldi	r31,MAX_PARITY_ERR
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
// posible start bit .. sync timer	//
	sts	TCNT3H,r19
	sts	TCNT3L,r18
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
// clear timer compare
	ldi	r23, 0x10
	sts	ETIFR, r23
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
	lds	r23,ETIFR
	andi	r23,0x10
	breq	card_io_bite_loop
// time tick, clear request
	sts	ETIFR,r23
// calculate parity
// load bite from io_filter
	cpi	r20,4
	adc	r30,r1
// rotate bite to register
// load bite from io_filter
	cpi	r20,4
#if C_TS == 0x3f
	rol	r25
#else
	ror	r25
#endif
// decrement bit counter
	dec	r21
	brne	card_io_bite_loop
// 10 bits rotate parity bit to C
#if C_TS == 0x3f
	ror	r25
	inc	r30
#else
	rol	r25
	com	r25
#endif
// handle parity error

// signalize parity error or save character
#ifndef EMULATE_ERRORS
	andi	r30,1
	brne	card_io_no_parity_error
#else
// emulate errors
	lsr	r0
	brcc	card_io_no_parity_error
#endif
//---------------------------------------------------
// wrong parity, check number of parity errors
// per character
	tst	r31			//
	breq	card_io_parity_too_many			// already too many errors

// wait 1st stop bit, imedietly signalize error
// max 9 cpu ticks, min 6 cpu ticks delay ..
card_io_wait_1st_stop:
	lds	r23,ETIFR
	andi	r23,0x10
	breq	card_io_wait_1st_stop
// request retransmition of character
	cbi	CARD_IO_DIR,CARD_IO_BIT
// clear timer compare flag
	sts	ETIFR, r23
// decrement counter of error per character
	dec	r31
// go to wait second stop bit
	rjmp	card_io_wait_2nd_stop
card_io_parity_too_many:

// repeated character received with parity error too
// clear buffer space counter and counter of 
// received characters (RX continues, but all 
// characters are ignored)
#ifndef EMULATE_ERRORS
	clr	r22
	clr	r24
#endif
// clear timer compare flag
	sts	ETIFR, r23
	rjmp	card_io_save_char
// 	rjmp	card_io_wait_2nd_stop
//---------------------------------------------------
// no parity error
// wait 1st stop bit, save character 
card_io_no_parity_error:
	lds	r23,ETIFR
	andi	r23,0x10
	breq	card_io_no_parity_error
// clear timer compare flag
	sts	ETIFR, r23
// renew parity error counter (per character) 
	ldi	r31,MAX_PARITY_ERR
card_io_save_char:
// check if buffer space is available (maximum received chars 255)
	tst	r22
	breq	card_io_wait_2nd_stop
	st	X+,r25
// save char
	dec	r22
	inc	r24

// wait 2nd stop bit 
card_io_wait_2nd_stop:
	lds	r23,ETIFR
	andi	r23,0x10
	breq	card_io_wait_2nd_stop
	sts	ETIFR, r23
// do not drive line (line is input)
	sbi	CARD_IO_IN,CARD_IO_BIT
// wait 3rd stop bit (only if N is set over 1)
card_io_wait_3rd_stop:
	lds	r23,ETIFR
	andi	r23,0x10
	breq	card_io_wait_3rd_stop
	sts	ETIFR, r23

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
	ldi	r25,12
// wait start bit, minimal latency 7 cpu ticks
// maximal 20 cpu ticks
card_io_start2:
// test IO line
	sbic	CARD_IO_IN,CARD_IO_BIT
	rjmp	card_io_idle3
// posible start bit .. sync timer	// 
	sts	TCNT3H,r19
	sts	TCNT3L,r18
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
	lds	r23,ETIFR
	andi	r23,0x10
	breq	card_io_start2
// time tick, clear request
	sts	ETIFR,r23
// decrement stop bit counter
	dec	r25
	brne	card_io_start2

// test if this ist 1st received frame after ATR (0xff in null_send)
	lds	r23,null_send
	inc	r23
	brne	card_io_idle4
	sts	null_send,r23	// clear null_send
#if 0
// specific mode, ignore PPS
// test if this is PTS frame
// X is pointer to frame, r24 is counter of characters
	sub	r26,r24
	subi	r27,0
	movw	r30,r26		// save buffer pointer
	ld	r23,X+		// load CLA
	cpi	r23,0xff
	breq	card_io_pts	// PTS class
#endif
card_io_idle4:
// uint16_ result .. (in future bit 15 protocol T0/T1)
	clr	r25
	ret
#if 0
card_io_pts:
// handle this as PTS, ignore any PTS that does not match correct
// parameters for OsEID

// correct PTS: 0xff 0x10 C_ATR_TA1 checksum
//	      0xff 0x30 C_ATR_TA1 0x02 checksum
//	      0xff 0x50 C_ATR_TA1 0xXX checksum
//	      0xff 0x70 C_ATR_TA1 0x02 0xXX checksum

// minimal PTS is 0xff 0x1X 0xXX checksum (PS1 must be present, because
// missing PS1 is interpreted as Fi=1, D=1 - not correct for OsEID

	cp	r24,4			// check size (minimal PTS size)
	ldi	r25,4			// initial minimum PTS size
	brcs	card_io_ignore_pts	// not enoungh data for PTS
					// size 0 => 256 bytes is not valid
					// for PTS to ..

	clr	r18			// clear buffers for PS2, PS3
	clr	r19

	ld	r20,X			// load INS/PS0
	andi	r20,0x1f		// test protocol, and presence of PS1
	cpi	r20,0x10		//
	brne	card_io_ignore_pts	// protocol != 0, or PS1 not present -> this mean Fi=1, Di=1, reject this PTS

	ld	r20,X+			// reload INS/PS0, count PTS size
	ld	r21,X+			// load PS1
	cpi	r21,C_ATR_TA1
	brne	card_io_ignore_pts	// do not change TA1

	sbrs	r20,5
	rjmp	card_io_pts_no_PS2
	inc	r25
	ld	r18,X+			// load PS2
	cpi	r18,2
	brne	card_io_ignore_pts	// do not change TC1

card_io_pts_no_PS2:
	sbrs	r20,6
	rjmp	card_io_pts_no_PS3
	inc	r25
	ld	r19,X+
card_io_pts_no_PS3:
	cp	r24,r25
	brne	card_io_ignore_pts	// PTS size does not match frame size

// checksum test
	ld	r25,X+			// checksum
	eor	r20,r21
	eor	r20,r18
	eor	r20,r19
	eor	r20,r25
	cpi	r20,0xff		// must match CLA byte
	brne	card_io_ignore_pts
// confirm PTS
	mov	r22,r24			// size
	movw	r24,r30			// PTS pointer (in buffer)
	rcall	card_io_tx		// confirm PTS
card_io_ignore_pts:
	clr	r24			// no byte is received
	clr	r25			// in future bit 15 - protocol T0/T1
	ret
#endif


	.global TIMER3_OVF_vect
	.type TIMER3_OVF_vect, @function
TIMER3_OVF_vect:
	push	r0
	in	r0,0x3f
	push	r20
// count overflows
	lds	r20,null_send
	inc	r20
	sts	null_send,r20
// max time .. 960 * WI * FI/f (WI is coded in TC2, if not present WI = 10)
// 372 or 512 from TA1 = Fi, 65536 divisor factor for timer3
// max value for 372 960*10*372/65535 = 54
// max value for 512 960*10*512/65535 = 75

#if (C_ATR_TA1 & 0xF0) == 0x90
	cpi	r20,68
#elif (C_ATR_TA1 & 0xF0) == 0
	cpi	r20,48
#elif (C_ATR_TA1 & 0xF0) == 0x10
	cpi	r20,48
#else
#error Please check TA1 value, Fi is not 512 or 372
#endif
	brne	null_send_end

// send null byte
// need more registers.. 
	push	r21
	push	r23
	push	r24
	push	r25
	push	r30
	push	r31
	rcall	card_io_osccal_max

// timer mode CTC from 0 to ETU in OCR3A
	ldi	r21,0x0f
	rcall	card_io_timer_mode
// clear OCR request
	ldi	r20,0x10
	std	Z+ETIFR_OFF,r20
// maximal two repeats of null byte 
	ldi	r20,0x60
	rcall	card_io_tx_byte
// clear OCR request
	ldi	r20,0x10
	std	Z+ETIFR_OFF,r20
	ldi	r20,0x60
	tst	r24
	breq	vector_no_repeat
	rcall	card_io_tx_byte
vector_no_repeat:	
// timer into normal mode
	ldi	r21,0x07
	rcall	card_io_timer_mode
	sts	null_send,r20
	pop	r31
	pop	r30
	pop	r25
	pop	r24
	pop	r23
	pop	r21
null_send_end:
	pop	r20
	out	0x3f,r0
	pop	r0
	reti

	.global card_io_start_null
	.type card_io_start_null, @function
card_io_start_null:
	cli
// reprogram timer to normal mode (count from 0 to 0xffff)
// Timer 3 mode CTC TOP 0xffff (mode 0)
// timer source T3, 
// load timer register offset (ETIFR) into Z
	ldi	r21,0x07
	rcall	card_io_timer_mode
	sts	null_send,r20

// clear old request if any, enable interrupt from overflow
	ldi	r20,4
	std	Z+ETIFR_OFF,r20
	std	Z+ETIMSK_OFF,r20		
	sei
	ret

	.global card_io_stop_null
	.type card_io_stop_null, @function
card_io_stop_null:
	cli
// reprogram timer to normal mode (count from 0 to 0xffff)
// Timer 3 mode CTC TOP by OCRA (mode 4)
// timer source T3, 
// load timer register offset (ETIFR) into Z
	ldi	r21,0x0F
	rcall	card_io_timer_mode
//disable all interrupt from timer
	std	Z+ETIMSK_OFF,r20
// clear old request if any
	ldi	r20,4
	std	Z+ETIFR_OFF,r20
	sei
	ret

// card reset
	.global USART0_RX_vect
	.type USART0_RX_vect, @function
USART0_RX_vect:
	jmp 	0


	.global card_io_init
	.type card_io_init, @function

card_io_atr_string:
//     - TS from #define ..
//0xf5 = SEND Ta1..TD1 .. 5 hist. bytes
//     - TA1 from #define .
//0    = TB1 
//2    = TC1 gurad time extended by two bits
//0x10 = TD1 - send TA2
//0x80 = TA2 - only T0 protocol
//hist. bytes OsEID...
// reversed order of bytes in ATR!
#define ATR_LEN 12
	.byte 'D','I','E','s','O',0x80,0x10,2,0,C_ATR_TA1,0xf5,C_TS
.balign 2
card_io_init:
	ldi	r30,lo8(card_io_atr_string)
	ldi	r31,hi8(card_io_atr_string)
	ldi	r23,ATR_LEN
	mov	r22,r23
card_io_init_atr_loop:
// get stack address (as ATR string pointer for card_io_send_atr call)
// (slower but here speed is no problem, save one adiw instruction)
	in	r24,0x3d
	in	r25,0x3e
	lpm	r20,Z+
	push	r20
	dec	r23
	brne	card_io_init_atr_loop
// length in r23,r22, position r25:r24
	rcall	card_io_send_atr
	ldi	r24,0xff
	sts	null_send,r24	// mark ATR sended

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
//    1st frame is checed for PTS - if yes, this is handled internaly
// b) if null sending mode is requested, this is incremented from 0.. max 68
null_send:
	.skip	1
