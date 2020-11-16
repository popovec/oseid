/*
    card_io.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2020 Peter Popovec, popovec.peter@gmail.com
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

//#define C_TS 0x3f
#define C_TS 0x3b

// Warning, 072f:9000 Advanced Card Systems, Ltd ACR38 AC1038-based Smart Card Reader
// fail with this (TA1=0x96) setup ... reader sends with 31 clock cycles per bit
// MyEID 4.0.1 (ATR 3B F5 96 00 00 81 31 FE 45 4D 79 45 49 44 14 )
// is working, but why ? is there some art of autobauding?
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

       .global card_io_rx
        .type   card_io_rx, @function


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

// preload half ETU, for maximal speed, here value 15 is in r18,r19,
// 21 - working on 3.8/3.7 (wrong on 4.8)
// 20 - working on 4.8,3.7/3.8
// 11 - working on 4.8,3.7,3.8
// 10 - not working on 4.8,3.7,3.8

	ldi	r18,lo8((C_ETU/2))
	ldi	r19,hi8((C_ETU/2))
//	ldi	r18,lo8(((C_ETU/2)-1))
//	ldi	r19,hi8(((C_ETU/2)-1))
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

// posible start bit .. sync timer TCA_CNT = C_ETU/2
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
	ldi     r23,1
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

// OK Sat 18 Jul 2020 06:48:23 PM CEST
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
	lds	r23,0x0A0B
	andi	r23,1
	breq	card_io_wait_1st_stop
// request retransmition of characterturn direction to output, PORT  is
// already at 0
	sbi	CARD_IO_DIR,CARD_IO_BIT
// clear timer compare flag
	sts	0x0A0B, r23
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
	sts	0x0A0B, r23
	rjmp	card_io_save_char
// 	rjmp	card_io_wait_2nd_stop
//---------------------------------------------------
// no parity error
// wait 1st stop bit, save character
card_io_no_parity_error:
	lds	r23,0x0A0B
	andi	r23,1
	breq	card_io_no_parity_error
// clear timer compare flag
	sts	0x0A0B, r23
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
//#warning temp return
//	ret

// wait 2nd stop bit
card_io_wait_2nd_stop:
	lds	r23,0x0A0B
	andi	r23,1
	breq	card_io_wait_2nd_stop
	sts	0x0A0B, r23
// do not drive line - DIR input ..
	cbi	CARD_IO_DIR,CARD_IO_BIT
// wait 3rd stop bit (only if N is set over 1)
card_io_wait_3rd_stop:
	lds	r23,0x0A0B
	andi	r23,1
	breq	card_io_wait_3rd_stop
	sts	0x0A0B, r23

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
	dec	r25
	brne	card_io_start2

// test if this ist 1st received frame after ATR (0xff in null_send)
	lds	r23,null_send
	inc	r23
	brne	card_io_idle4
	sts	null_send,r23	// clear null_send

// test if this is PTS frame
// X is pointer to frame, r24 is counter of characters
	sub	r26,r24
	subi	r27,0
	movw	r30,r26		// save buffer pointer
	ld	r23,X+		// load CLA
	cpi	r23,0xff
	breq	card_io_pts	// PTS class
card_io_idle4:
// uint16_ result .. (in future bit 15 protocol T0/T1)
	clr	r25
	ret

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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	.global card_io_tx
	.type   card_io_tx, @function
// uint8_t card_io_tx0(uint8_t * data, uint8_t len)

card_io_tx:
        push    r28
        push    r29
// length
        movw    r28,r22
// clear timer flag
	ldi	r31,1
	sts	0x0A0B,r31

// TODO	clt			// for now only T0 mode (T1 is planed)
// X is now buffer pointer
        movw    r26,r24
//buffer loop
///////////////////////////////////////////
// TODO limit maximum repeats for one char ? for whole TX buffer?
card_io_tx0_buffer_loop:
// load byte
        ld      r20,X
        rcall   card_io_tx_byte
// 0    - all ok
        tst     r24
        brne    card_io_tx0_repeat
// next character ..
        adiw    r26,1
        sbiw    r28,1
	breq    card_io_tx0_ok
	rjmp    card_io_tx0_buffer_loop
card_io_tx0_repeat:
	sec
	rcall	send_C	// wait 2 ETU for retransmit!
	sec
	rcall	send_C	//
	rjmp    card_io_tx0_buffer_loop

card_io_tx0_ok:
        clr     r24
        clr     r25
//card_io_tx0_fail:
        pop     r29
        pop     r28
        ret


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// T bit is used to switch T0/T1 byte sending procedure TODO
// this code is called in normal way but is called from ISR too
// beware, ISR does not save whole register set ..

// BYTE is input
// clamped: R20,R21,R22,R23,R30,R31
// R1 is used as zero!
// R24 output    0 = no error
//               !0 = repeat requested

#define PARITY r22
#define BITCOUNTER r21
#define BYTE   r20
#define TEMP r23
// Warning, R31 must be set to 4 (0x0401, 0x0402 - port address for DIRCLR/DIRSET)
card_io_tx_byte:
	ldi	r31,4
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
	rol	BYTE
#else
	ror	BYTE
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
	rcall	send_C
// TODO	brts	card_io_tx_byte_T1
// this is T0 code, we need check for byte retransmit
// 1st stop bit is already on line, send second stop bit
	sec
	rcall	send_C

//this is middle point beetwen stop bits, sample I/O here
// TODO, use more samples (3 ? ) here
	in	r24,CARD_IO_IN
	com	r24
	andi	r24,0x10
	brne	1f

// send 3rd stop bit
	sec
	rcall	send_C
//this is middle point beetwen stop bits, sample I/O here
// TODO, use more samples (3 ? ) here
	in	r24,CARD_IO_IN
	com	r24
	andi	r24,0x10
1:
	swap	r24
	ret

/*
card_io_tx_byte_T1:
// this is T1 code, no retransmit is checked, clear r24 (no error)
	clr	r24
	ret
*/

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

// port bit position (mask)
	ldi	TEMP, CARD_IO_BIT_MASK
// DIRSET 0x01, DIRCLR 0x02, base port adress 0x04A0

//	sts	0x0401,TEMP	// A
//	sts	0x0402,TEMP	// Z
//
	ldi	r30,0x01
	adc	r30,r1		// if carry Z, else A
	st	Z,TEMP
	ret

#unset PARITY
#unset BITCOUNTER
#unset BYTE
#unset TEMP
/////////////////////////////////////////////////////////////////////////////////////////////////////////

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
#ifdef ENABLE_WARM_ATR
card_io_atr_warm_string:
	.byte 'D','I','E','s','o',0x80,0x10,2,0,C_ATR_TA1,0xf5,C_TS
#define WARM_ATR_LEN 12
#endif
.balign 2

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
/////  TCA0_SINGLE_PER = C_ETU_ATR-1;
	ldi	r18,lo8((C_ETU_ATR-1))
	ldi	r19,hi8((C_ETU_ATR-1))
	sts	0x0A26,r18
	sts	0x0A27,r19
/////  TCA0_SINGLE_CTRLA = 1;        // enable timer TCA, no clock prescaler ..
	sts	0x0A00,r24
/////  TCA0_SINGLE_CTRLB = 0;        // normal mode
	sts	0x0A01,r1

// we need wait (535) clock cycles and then ATR is sended back to reader
// (min 400, max 40000)
/////  TCA0_SINGLE_CNT = 65000;
	ldi	r18, lo8(65000)
	ldi	r19, hi8(65000)
	sts	0x0A20, r18
	sts	0x0A21, r19
/////  TCA0_SINGLE_INTFLAGS = 1;     // clear OVF
	sts	0x0A0B, r24

// PORT setup, open colector (drive port to low, enable pull up, use port
// DIR to transmit 0/1


/////  PORTA.PIN4CTRL = 8;           // enable pull up
/////  PORTA.OUTCLR = (1 << 4);      // if pin is output pin, drive to zero
	ldi	r24,8
	sts	0x0414, r24
	ldi	r24, 0x10
	sts	0x0406, r24

// load ATR from FLASH to ram ..

        ldi     r30,lo8(card_io_atr_string)
        ldi     r31,hi8(card_io_atr_string)
        ldi     r23,ATR_LEN
#ifdef ENABLE_WARM_ATR
// after warm reset different ATR can be sended back ..
	lds	r20,0x40		// load reset source RSTCTRL.RSTFR
	andi	r20,0x10		// test if this is SW reset (SWRF bit)
	sts	0x40,r20		// clear SWRF bit
	breq	1f
// Ok soft reset
        ldi     r30,lo8(card_io_atr_warm_string)
        ldi     r31,hi8(card_io_atr_warm_string)
        ldi     r23,WARM_ATR_LEN
        mov     r22,r23
1:
#endif
        mov     r22,r23
card_io_init_atr_loop:
// get stack address (as ATR string pointer for card_io_send_atr call)
// (slower but here speed is no problem, save one adiw instruction)
        in      r24,0x3d
        in      r25,0x3e
        lpm     r20,Z+
        push    r20
        dec     r23
        brne    card_io_init_atr_loop
// length in r23,r22, position r25:r24
	rcall	card_io_tx
//	sec
//	rcall	send_C
// OK, timer is below 31,  switch speed (ETU 31)
	ldi	r18,lo8((C_ETU-1))
	ldi	r19,hi8((C_ETU-1))
	sts	0x0A26,r18
	sts	0x0A27,r19

// mark ATR sent
        ldi     r24,0xff
        sts     null_send,r24
// renew stack
        in      r24,0x3d
        in      r25,0x3e
        adiw    r24,ATR_LEN
        out     0x3d,r24
        out     0x3e,r25
//1:	rjmp 1b
        ret

// Compact Vector Table is enabled, priority 0 (low priority) vector
//        .global TCA0_OVF_vect
//        .type TCA0_OVF_vect, @function

        .global __vector_3
        .type __vector_3, @function

__vector_3:
//TCA0_OVF_vect:
	push	r0
	in      r0,0x3f
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
// registers used in card_io_tx_byte and send_C
	push	r1
	clr	r1
	push	r21
	push	r22
	push	r23
	push	r24
	push	r30
	push	r31

// reprogram timer back to count to ETU
	ldi	r20,lo8((C_ETU-1))
	ldi	r21,hi8((C_ETU-1))
	sts	0x0A26,r20
	sts	0x0A27,r21
// TCA0_SINGLE_CNT = 0;
	clr	r20
	sts	0x0A20, r20
	sts	0x0A21, r20
// clear timer flag
        ldi     r20,1
        sts     0x0A0B,r20

	ldi	r20,0x60
	rcall   card_io_tx_byte

// maximal two repeats of null byte

// clear overflow flag
	ldi	r20,1
	sts     0x0A0B,r20

        ldi     r20,0x60
        tst     r24
        breq    vector_no_repeat
        rcall   card_io_tx_byte

vector_no_repeat:
// timer count from 0 to 0xffff
	ldi	r20,0xff
	sts	0x0A26,r20
	sts	0x0A27,r20
// TCA0_SINGLE_CNT = 0;
	clr	r20
	sts	0x0A20, r20
	sts	0x0A21, r20
// clear counter for null send...
        sts     null_send,r20


	pop	r31
	pop	r30
	pop	r24
	pop	r23
	pop	r22
	pop	r21
	pop	r1
null_send_end:
// clear overflow flag
	ldi	r20,1
	sts     0x0A0B,r20
	pop	r20
	out	0x3f,r0
	pop	r0
	reti

        .global card_io_start_null
        .type card_io_start_null, @function

card_io_start_null:
	cli
	set
// clear variable - this is counter 0..48/68 then null is send to reader
	sts	null_send,r1
// timer count from 0 to 0xffff
	ldi	r20,0xff
	ldi	r21,0xff
	rjmp	1f

        .global card_io_stop_null
        .type card_io_stop_null, @function

card_io_stop_null:
	cli
	clt
// disable interrupt from timer
	clr	r20
	sts	0xa0A,r20
// reprogram timer back - count to ETU
	ldi	r20,lo8((C_ETU-1))
	ldi	r21,hi8((C_ETU-1))
1:
	sts	0x0A26,r20
	sts	0x0A27,r21
// clear TCA0  counter
// TCA0_SINGLE_CNT = 0;
	sts	0x0A20, r1
	sts	0x0A21, r1
// clear overflow
	ldi	r20,1
	sts     0x0A0B,r20
// check if interrupt from timer must be enabled
	brtc	1f
// enable interrupt  from timer overflow
	sts	0xa0A,r20
1:
	sei
	ret



.section        .noinit,"aw",@nobits

// multifunction variable
// a) after ATR this is set to 0xff, 1st received frame clear this
//    1st frame is checed for PTS - if yes, this is handled internaly
// b) if null sending mode is requested, this is incremented from 0.. max 68
null_send:
        .skip   1
