/*
    card_io.S - simulavr version

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015,2017,2019 Peter Popovec, popovec.peter@gmail.com

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
	movw	r24,r22		// length
	ldi	r22,2
// next instruction waits until input is available
	sts	0xff,r22 	// read line

// clear counter
	clr	r26
	clr	r27

card_io_rx_loop:
	lds	r23,0xff
	tst	r23
	breq	1f	// no more characters, skip to end
// protocol...
	bst	r23,0
	bld	r27,7
// in r23 0xF0 or 0xF1 signalize us protocol
// read char
	lds	r0,0xfe
	st	z+,r0
	adiw	r26,1	// byte counter (bit 15 protocol)
	sbiw	r24,1
	brne	card_io_rx_loop
1:
	movw	r24,r26
// return r25:r24 - length of data (bit 15 is protocol)
	ret

.global card_io_start_null
.type card_io_start_null, @function

card_io_start_null:
	ret

.global card_io_init
.type card_io_init, @function

card_io_init:
// ATR is managed in patched simulavr...
	ret

.global card_io_stop_null
.type card_io_stop_null, @function
card_io_stop_null:
	ret

