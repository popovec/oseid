/*
    card_io.S - simulavr version

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015,2017 Peter Popovec, popovec.peter@gmail.com

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
	ldi	r24,0
	sts	0xff,r24	//reset output fifo
card_io_tx_loop:	
	ld	r24,Z+
	sts     0xfe,r24
	dec	r22
	brne	card_io_tx_loop

	ldi	r24,1
	sts	0xff,r24	//print fifo
	ret

.global card_io_rx
.type card_io_rx, @function

card_io_rx:
	movw	r30,r24
card_io_rx_repeat:
	ldi	r24,2
	sts	0xff,r24 	// read line

	lds	r24,0xff	// number of bytes
	tst	r24
	breq	card_io_rx_repeat
	mov	r25,r24
	cp	r22,r25
	brcc	card_io_rx_loop
	mov	r25,r22
//
card_io_rx_loop:
	lds	r0,0xfe
	st	Z+,r0
	dec	r25
	brne	card_io_rx_loop
	ret

.global card_io_start_null
.type card_io_start_null, @function

card_io_start_null:
	ret

.global card_io_init
.type card_io_init, @function

card_io_init:
	ldi	r24,0
	sts	0xff,r24	//reset output fifo

	ldi	r24,0x3f
	sts	0xfe,r24	// out 3f
	ldi	r24,0xf5
	sts	0xfe,r24	// out f5
	ldi	r24,0x18
	sts	0xfe,r24	// out 18
	ldi	r24,0x00
	sts	0xfe,r24	// out 00
	ldi	r24,0x02
	sts	0xfe,r24	// out 02
	ldi	r24,0x10
	sts	0xfe,r24	// out 10
	ldi	r24,0x80
	sts	0xfe,r24	// out 80
	ldi	r24,0x4f
	sts	0xfe,r24	// out 4f
	ldi	r24,0x73
	sts	0xfe,r24	// out 73
	ldi	r24,0x45
	sts	0xfe,r24	// out 45
	ldi	r24,0x49
	sts	0xfe,r24	// out 49
	ldi	r24,0x44
	sts	0xfe,r24	// out 44

	ldi	r24,1
	sts	0xff,r24	// print fifo
	ret

.global card_io_stop_null
.type card_io_stop_null, @function
card_io_stop_null:
	ret

