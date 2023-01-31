/*
    mem_device.S

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
// uint8_t sec_device_format()

		.global	sec_device_write_block
		.type	sec_device_write_block, @function

		.global	sec_device_read_block
		.type	sec_device_read_block, @function

		.global	sec_device_format
		.type	sec_device_format, @function

sec_device_format:
	rcall	osccal_min

	ldi	r27,8
	ldi	r26,0

	ldi	r24,0xff
1:
// set EEPROM address
	out	0x1f,r27
	out	0x1e,r26
// write eeprom ..
	out	0x1d,r24	// EEPROM data register
	cli
	sbi	0x1c,2		// master write
	sbi	0x1c,1		// write
	sei
// wait for write end
2:
	sbic	0x1c,1
	rjmp	2b

// inc address
	adiw	r26,1
// test end address
	cpi	r27,0x10
	brne	1b

	clr	r24
	ret

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


device_get_change_counter:
// set EEPROM address
	ldi	r26,0x00	// lo part
	ldi	r27,0x06	// hi part
	out	0x1f,r27
	out	0x1e,r26
// trigger read operation
	sbi	0x1c,0
// increment EEPROM address
	adiw	r26,1
// load data from EEPROM
	in	r25,0x1d
	out	0x1f,r27
	out	0x1e,r26
// trigger read operation
	sbi	0x1c,0
// load data from EEPROM
	in	r24,0x1d
// increment counter (initial value is 0xffff, return 0, this is used in
// update_change_counter code too
	adiw	r24,1
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
		rcall	device_block_check
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

// uint16_t device_get_change_counter()
		.global device_get_change_counter
		.type   device_get_change_counter, @function

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
#ifdef __AVR_ATmega128__
// simulavr, atmgega128
		cpi	r23,0x11
#else
// simulavr1284
		cpi	r23,0x41
#endif
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
		clt			// flag update FLASH

device_write_block2:
		call	device_block_check
		call	osccal_min
		movw	r18,r24		// save RAM address
		movw	r24,r22		// FLASH address
		movw	r22,r18		// restore RAM address
		rcall	device_update_page
		sei
		tst	r20		// test counter, some bytes to next page ?
		breq	1f		// no skip...

		inc	r31		// next page
		movw	r24,r30		// new flash address
		movw	r22,r26		// new RAM addres
		cli
		rcall	device_update_page
		sei
1:
// update change counter
		call	device_get_change_counter
// write back
		rcall	eewrite
		sbiw	r26,1
// write back
	        mov	r24,r25
		rcall	eewrite
// restore return value
		movw	r24,r30
		sei
		ret

eewrite:
		cli
		out	0x1f,r27	// write adress
	        out     0x1e,r26
		out	0x1d,r24	// EEPROM data register
		sbi     0x1c,2          // master writer
		sbi     0x1c,1          // write
		// wait for write end
2:
                sbic    0x1c,1
                rjmp    2b
		sei
		ret

///////////////////////////////////////////////////////////////////////////////////////////////////////
// uint8_t device_write_ff (uint16_t offset, uint8_t size);

		.global	device_write_ff
		.type	device_write_ff, @function
device_write_ff:
		set			// flag clear flash
		mov	r20,r22
		movw	r22,r24
		ldi	r25,0x10	// fake ram address
		rjmp	device_write_block2

// initialize FLASH

		.global	device_format
		.type	device_format, @function
device_format:
		clr	r25
1:
		clr	r22
		clr	r24
		push	r25
		rcall	device_write_ff
		pop	r25
		inc	r25
		cpi	r25,0xff
		brne	1b
		clr	r24
		ret
