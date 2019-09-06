/*
    mem_device.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2019 Peter Popovec, popovec.peter@gmail.com

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

    Same as targets/atmega128/mem_device.S with one difference, memory is
    checked to 16kB - allow simulation on atmega1284 (in patched simulavr)

// FLASH organization:
// 0x00000 .. 0x0FFFF bytes is for program
// 0x10000 .. 0x1FF00 for data
// 0x1FF00 .. 0x1FFFF SPM code

// EEPROM 0x000-0x7ff - constants (used in constants.c)
//        0x800-0xfff - sec memory(pins..)
*/

osccal_min:
		cli
		lds     r18,0x6F
osccal_min_loop:
		cpi     r18,181
		brcs    osccal_min_end
		subi    r18,4
		sts     0x6F,r18
// please read atmega errata anout this nop's
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		rjmp	osccal_min_loop
osccal_min_end:	ret


// return 0 if all ok
// uint8_t sec_device_read_block (void *buffer, uint16_t offset, uint8_t size)
// uint8_t sec_device_read_block (void *buffer, uint8_t offset, uint8_t size)

		.global	sec_device_write_block
		.type	sec_device_write_block, @function

		.global	sec_device_read_block
		.type	sec_device_read_block, @function

sec_device_read_block:
	clt
	rjmp	sec_device_block

sec_device_write_block:
	set
sec_device_block:
	movw	r30,r24		// RAM pointer
	movw	r26,r22		// EEPROM pointer
	ori	r27,0x08	// offset 2048 byte in EEPROM

	mov	r24,r20         //size
	dec	r20
// maximal address is offset + size - 1
	add	r22,r20
	adc	r23,r1
	brcs	4f
	andi	r23,0xfc	// check address below 1023
	brne	4f

// counter and address as uint8_t
// address in range  0-1023
// counter interpreted as 1..256 (0=256)
1:
// set EEPROM address
	out	0x1f,r27
	out	0x1e,r26
// trigger read operation
	sbi	0x1c,0
// increment EEPROM address
	adiw	r26,1
// load data from EEPROM
	in	r19,0x1d
	brts	sec_device_write
// store to RAM
	st	Z+,r19
	rjmp	3f
sec_device_write:
//	load data from RAM
	ld	r0,Z+
// compare, if same do nothing
	cp	r0,r19
	breq	3f
// rewrite eeprom ..
	rcall	osccal_min
	out	0x1d,r0		// EEPROM data register
	sbi	0x1c,2		// master writer
	sbi	0x1c,1		// write
// wait for write end
2:
	sbic	0x1c,1
	rjmp	2b
	sei
3:
	subi	r24,1
	brne	1b
	ret
// raise error
4:
	ldi	r24,1
	ret
///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////


// read max 256 bytes from flash into buffer (size 0 = 256 bytes)
// uint8_t device_read_block (void *buffer, uint16_t offset, uint8_t size);

		.global	device_read_block
		.type	device_read_block, @function

device_read_block:
		call	device_block_check
		movw	r26,r24	// buffer
		movw	r30,r22	// offset
		ldi	r21,1	// rampZ
		out	0x3b,r21
device_read_block_loop:
		elpm	r0,Z+
		st	X+,r0
		dec	r20
		brne	device_read_block_loop
		clr	r24
		ret


		.section	.flash_end,"ax",@progbits
error_trap:
		cli
		rjmp	error_trap

// beware, this function is ABI compatible, but T flag is used too
// if T flag is set, FLASH is set to 0xff
// size on range 1-256, 0 is interpreted as 256

// uint8_t device_update_page (uint16_t flash, uint8_t * ram, uint8_t size);
device_update_page:
// prevent unattended jump here .. check all arguments!
//----------------------------------------------------------------
//
// test interrupt flag - interrupt must be disabled
		brie	error_trap
// test if this is last page of FLASH, if yes, this is error
		cpi	r25,0xff
		breq	error_trap
// test RAM address (must be in range 0x0100 0x10ff for atmega128)
// (0x100 to 0x40ff for atmega1284)
		cpi	r23,0x41
		brcc	error_trap
		and	r23,r23
		breq	error_trap
//----------------------------------------------------------------		
// set Z to page start (aligned)
		mov	r31,r25
		clr	r30
// ram address into X
		movw	r26,r22
// preset rampz
		ldi	r25,1
		out	0x3b,r25	

// in some cases page erase is not needed or page write is not needed
// all bytes for page is AND-ded by r22/r18, if final value is 0xff, no write is needed
		ldi	r22,0xff	// page write test (FLASH)
		ldi	r23,0xff	// page write test (RAM)
// For all bytes from FLASH  do AND by new byte (in buffer), if
// result of AND  ==  new byte for FLASH, no page erase is needed
		ldi	r18,0		// page erase test

// erase page buffer
		rcall	rww

// load data from flash/ram to page buffer
device_update_page_loop:
		rcall	compose_buffer
		mov	r0,r1
		inc	r30
		rcall	compose_buffer
		dec	r30
		ldi	r25,1	// SPMEN
		rcall 	do_spm
// increment by 2
		subi	r30,(-2)
// test if at page end
		brne	device_update_page_loop
//----------------------------------------------------------------
		clr	r1	// ABI
// erase page
		ldi	r25,3	// PGERS,SPMEN
// if r18 == 0, no page erase is needed
		cpi	r18,0
		breq	device_update_page_noerase
// do page erase
		rcall	do_spm
// page is erased, in FLASH some bits are 0, rewrite this bits back
		and	r22,r23
device_update_page_noerase:
// write page
		ldi	r25,5	// PGWRT,SPMEN
// if r22 == 0xff no page write is needed
		inc	r22
		cpse	r22,r1
		rcall	do_spm
#if 1
// reenable rww section, return
		rjmp	rww
#else
#warning there is no space in flash end section for this!
// reenable rww section
		rcall	rww
// remove rest of code, this is for testing only

		mov	r24,r18	// 0 - no page erase or 1 = page erase
		cpse	r22,1	// 0 no page write      2  = page write
		sbci	r24,0xfe

		ret
#endif
//--------- HELPERS ------------------------------------
//r24 is offset in flash buffer for data from ram
//Z flash pointer
//X ram pointer
//r21,20 size
compose_buffer:
// preload from FLASH
		elpm	r1,Z
// conditional .. page write if some old data is not 0xff
		and	r23,r1

// test if old data in FLASH need to be owerwrited by data from RAM
		cpse	r30,r24
		ret
// load data from RAM
		ldi	r19,0xff	// set 0xff
		brts	.+2		// if T is set load 0xff else load data from ram
		ld	r19,X+
// test if page write is needed
		cpse	r1,r19		// FLASH already have same data?
		and	r22,r19		// not, do "and" for page write test
// if and(RAM,FLASH) == RAM, no page erase is needed
		and	r1,r19
		cpse	r19,r1
		ldi	r18,1		// need page erase

		mov	r1,r19
// test if this is last byte from RAM
		dec	r20
		breq	compose_buffer_end
		inc	r24
compose_buffer_end:
		ret

// wait for SPMCSR (for already running SPM to end)
do_spm:
		lds	r19,0x68	// read SPMCR
		sbrc	r19,0		// test SPMEN
		rjmp	do_spm
// wait for EEPROM
		sbic	0x1c,1		// test EEWE
		rjmp	.-4
//
		sts	0x68,r25	// SPMCR
		spm
		ret

//
// reenable RWW secrion
rww:
		ldi	r25,0x11	// RWWSRE SPMEN
		rcall	do_spm
		lds	r25,0x68	// SPMCR
		sbrc	r25,6		// test RWWSB
		rjmp	rww
		ret

///////////////////////////////////////////////////////////////////////////////////////////////////////
// device_write_block (void *ram, uint16_t flash, uint8_t size);
		.global	device_write_block
		.type	device_write_block,@function

device_write_block:
		rcall	device_block_check

		clt			// flag update FLASH
		call	osccal_min
		movw	r18,r24		// save RAM address
		movw	r24,r22		// FLASH address
		movw	r22,r18		// restore RAM address
		rcall	device_update_page

		tst	r20		// test counter, some bytes to next page ?
		breq	1f		// no skip...

		inc	r31		// next page
		movw	r24,r30		// new flash address
		movw	r22,r26		// new RAM addres
		rcall	device_update_page
1:
		clr	r24
		rjmp	device_write_end

///////////////////////////////////////////////////////////////////////////////////////////////////////
// int16_t device_write_ff (uint16_t offset, uint8_t size);

// fill block at offset _offset_ with value 0xff of maximal length _size_
// return number of filled bytes (-1 on error)
// if offset + size is out of memory, clear only to memory end

		.global	device_write_ff
		.type	device_write_ff, @function
device_write_ff:
// check offset - no write after 0xff00...
		cpi	r25,0xff
		brne	1f
// return error (r24 is not needed only set r25 to 0xff = negative number)
//		ldi	r24,0xff
		ldi	r25,0xff
		ret
1:
// expand size to 16 bites value
		mov	r20,r22
		ldi	r21,1
		cpse	r20,r1
		clr	r21

// number of bytes to clear in page (1-256) into r23,r22
		mov	r22,r24
		neg	r22
// expand number of bytes to be erased (write 0xff) in page to 16 bit variable
		ldi	r23,1
		cpse	r22,r1
		clr	r23
// compare calculated size (r23,r22) with real requestet size (r21,r20)
		cp	r20,r22
		cpc	r21,r23
		brcs	1f
// reduce size to requested size
		movw	r20,r22
1:
// save size (as return value)
		push	r20
		push	r21
		call	osccal_min
		ldi	r23,2		// fake RAM address only high byte is tested
//		ldi	r22,3
		set			//FLAG set bytes to 0xff
//r21 is not used, r20 is size in range 1..256 0 = 256
		rcall	device_update_page
// return value 1..256
		pop	r25
		pop	r24
device_write_end:
		sei
		ret

device_block_check:
		mov	r0, r20	// size
		dec	r0	// size -1
		movw	r18,r22	// offset
		add	r18,r0
		adc	r19,r1
		brcs	device_block_check_fail
		cpi	r19,0xff
		brne	device_block_check_ok
device_block_check_fail:
// remove 1st return address, set error into r24 do return
		pop	r0
		pop	r0
		ldi	r24,1
device_block_check_ok:
		ret
