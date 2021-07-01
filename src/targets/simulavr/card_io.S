/*
    card_io.S - simulavr version

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

    simulavr connector for OsEID

*/
.global card_io_tx
.type card_io_tx, @function

card_io_tx:
	movw	r30,r24
// test if this is PPS response
	lds	r24,card_io_pps
	tst	r24
	breq	1f
// drop PPS response (negotiation is handles in patched simulavr)
	ret
1:
	movw	r26,r22

	ldi	r24,0
	sts	0xff,r24	//reset output fifo
// insert data into buffer (up to 261 bytes..)
card_io_tx_loop:	
	ld	r24,Z+
	sts     0xfe,r24
	sbiw	r26,1
	brne	card_io_tx_loop

	ldi	r24,1
	sts	0xff,r24	//print fifo
	ret

.global card_io_rx
.type card_io_rx, @function

card_io_rx:
	movw	r30,r24
	movw	r26,r22		// length
// clear counter
	clr	r24
	clr	r25

// test, if PPS was generated in previous run
	lds	r21,card_io_pps
	sts	card_io_pps,r1
	tst	r21
	brne	1f

// yes, PPS was sent to card, there is message in buffer
// skip buffer clear and read new message...
	ldi	r22,2
// next instruction waits until input is available
	sts	0xff,r22 	// read line
1:

// read protocol
	lds	r23,0xff
	lds	r21,card_io_proto
	cp	r23,r21
	breq	card_io_rx_loop
// protocol change.. generate PPS
	sts	card_io_proto,r23
// set flag, PPS generated
	sts	card_io_pps,r23
	ldi	r21,0xff
	st	Z+,r21	// PPSS
	andi	r23,1
	st	Z+,r23	// PPS0
	eor	r23,r21
	st	Z+,r23	// PCK
	ldi	r24,3	// PPS len
	ret

card_io_rx_loop:
	lds	r23,0xff
	tst	r23
	breq	1f	// no more characters, skip to end

// in r23 0xF0 or 0xF1 signalize us protocol
// read char
	lds	r0,0xfe
	st	z+,r0
	adiw	r24,1
	sbiw	r26,1
	brne	card_io_rx_loop
// buffer overrun
1:
	ret

.global card_io_start_null
.type card_io_start_null, @function

card_io_start_null:
	ret

.global card_io_init
.type card_io_init, @function

card_io_init:
// ATR is managed in patched simulavr...
	sts	card_io_proto,r1
	sts	card_io_pps,r1

	ret

.global card_io_stop_null
.type card_io_stop_null, @function
card_io_stop_null:
	ret

	.section .noinit,"aw",@nobits
card_io_proto:
	.skip   1
card_io_pps:
	.skip	1
