/*
    mem_device.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2020 Peter Popovec, popovec.peter@gmail.com

    This is AVR128DA memory subsystem for OsEID project, based on
    other OsEID memory susbsystem for  devices: atmega128, xmega128a4u...
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

    AVR128DA  (512 bytes EEPROM)

// FLASH organization:
// 0x00000 .. 0x0FFFF bytes is for program
// 0x10000 .. 0x1FFFF for data

// EEPROM 0x000-0x1ff
*/

// return 0 if all ok
// uint8_t sec_device_read_block (void *buffer, uint16_t offset, uint8_t size)
// uint8_t sec_device_read_block (void *buffer, uint16_t offset, uint8_t size)


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
//	out     0x3b,r1		// clear RAMPZ
	movw	r26,r24		// RAM pointer
	movw	r30,r22		// EEPROM pointer
	andi	r23,0xfe	// address below 512 ?
	brne	4f		// error
	ori	r31,0x14	// EEPROM block at 0x1400
	mov	r24,r20         //size
	dec	r20
// maximal address is offset + size - 1
	add	r22,r20
	adc	r23,r1
// r23,r22 is max 0x01ff + 0xff, there is no need to check C flag
//	brcs	4f
	andi	r23,0xfe	// check address below 512
	brne	4f

// counter (r24) interpreted as 1..256 (0=256)
// address (r27,r26) in range  0x1400..0x15ff

// wait for NVM (busy)
	cli
1:	lds	r25,0x1002	// NVMCTRL.STATUS
	andi	r25,3
	brne	1b
	sei
// OK NVM is idle, clear NVM errors..
	sts	0x1002,r1

// test write/read
	brts	2f

// eeprom read
1:
	ld	r0,Z+
	st	X+,r0
	dec	r24
	brne	1b
	ret

//eeprom write:
2:
// TODO here only EEERWR mode is used, but there is way to use
// EEWR mode without EEBER to prevent unnecesary erase operation...

// unlock Configuration change protection
//	ldi	r22,0xd8	// KEY for CCP
	ldi	r22,0x9d	// KEY for CCP (self programing)
	ldi	r23,0x13	// EEERWR operation (erase and write)
	out	0x34, r22	// write key to CCP
	sts	0x1000, r23	// write command for NVM
1:
	ld	r0,X+
	st	Z+,r0
	dec	r24
	brne	1b
// wait for NVM (busy), on error newer ending loop
	cli
2:	lds	r25,0x1002	// NVMCTRL.STATUS
	andi	r25,0x73
	brne	2b
	sei


// clear NVM command
// unlock Configuration change protection
//	ldi	r22,0x9d	// KEY for CCP (self programing) - already set
	out	0x34, r22
	sts	0x1000, r1	// NOCMD
// r24 is zero ..
	ret

// raise error
4:
	ldi	r24,1
	ret
///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////


// r20,21 - size
// r22,r23 - offset in device (not FLASH!)
// return: Z - flash address
// on error  skip one return address, return back with r24= bytes to flash end

// here 64kB limit is checked (0x1000..0x1FFFF)
device_block_check:
		ldi	r31,1		// rampZ value
		out	0x3b,r31	// RAMPZ
		movw	r30,r22
		mov	r0, r20	// size
		dec	r0	// size -1
		movw	r18,r30	// offset in flash
		add	r18,r0
		adc	r19,r1
		brcc	device_block_check_ok
// remove 1st return address
		pop	r24
		pop	r24
		ldi	r24,1	// error
device_block_check_ok:
		ret

// read max 256 bytes from flash into buffer (size 0 = 256 bytes)
// uint8_t device_read_block (void *buffer, uint16_t offset, uint8_t size);

		.global	device_read_block
		.type	device_read_block, @function

device_read_block:
		// check range and set FLASH pointer into Z
		rcall	device_block_check
		movw	r26,r24	// buffer
device_read_block_loop:
		elpm	r0,Z+
		st	X+,r0
		dec	r20
		brne	device_read_block_loop
// no error
		clr	r24
		ret

error_trap:
		cli
		rjmp    error_trap

// r20 = nuber of bytes to rewrite (0=256, 1=1... 255=255)
// X - r27,26 = RAM address
// Z - r31,r30 = flash address
device_update_page:
// test RAM address (must be in range 0x4000 0x7fff for AVR128DA)
		movw	r18,r26
		subi	r18,0
		sbci	r19,0x40
		brcs	error_trap
		subi	r18,0
		sbci	r19,0x40
		brcc	error_trap

		push	r28
		push	r29

//----------------------------------------------------------------
// copy flash page to RAM
// allocate page on stack
		in	r28,0x3d	// TODO is this needed (AVR128DA ?)
		in	r29,0x3e
		subi	r29,2
		out	0x3d,r28	// TODO is this needed (AVR128DA ?)
		out	0x3e,r29
// pointer to allocated space in Y
		adiw 	r28,1

// save flash address
		movw	r24,r30
// align flash pointer to page start
		clr	r30
		andi	r31,0xfe
// copy flash page to RAM (stack) - 512 bytes, copy 2 bytes in one step,
// use r1 as counter
1:
		elpm	r0,Z+
		st	Y+,r0
		elpm	r0,Z+
		st	Y+,r0
		dec	r1
		brne	1b
// save position of copy end...
		movw	r22,r28

// update page copy in RAM by real data
		subi	r29,2	// return Y back to copy start
		movw	r30,r24	// renew flash address ..
		andi	r31,1	// remove page number (only offsett in page is needed)
		add	r30,r28	// calculate position in page copy
		adc	r31,r29
//
1:
// load 0xff or RAM data
		ld	r21,X+
		brtc	2f
		ldi	r21,0xff
2:

// load flash data (from page copy)
		ld	r0,Z
// test if erase is needed
		and	r0,r21
		cpse	r0,r21
// r31 is not zero (RAM at 0x4000..0x7fff), can be used to switch r1 to non zero
		or	r1,r31
// update page copy

		st	Z+,r21
// all data copied ?
		dec	r20
		breq	3f
// check page end
		cp	r30,r22
		cpc	r31,r23
		brcs	1b
3:
// renew FLASH address
		movw	r30,r24
// KEY for CCP (SPM)
		ldi	r22,0x9d
// r1 != 0 if page erase is needed
		tst	r1
		breq	device_update_page_W
// perform page erase
// unlock Configuration change protection
		ldi	r23,0x08	// FLPER Flash Page Erase Enable
		out	0x34, r22	// write key to CCP
		sts	0x1000, r23	// write command for NVM

		spm			// perform page erase
#warning check NVM error code
// wait for NVM (busy), on error newer ending loop
	        cli
1:		lds     r23,0x1002      // NVMCTRL.STATUS
	        andi    r23,0x03
	        brne    1b
	        sei
// clear NVM command
// unlock Configuration change protection
		clr	r1
		out     0x34, r22
		sts     0x1000, r1      // NOCMD

device_update_page_W:

// unlock Configuration change protection
		ldi	r23,0x02	// FLWR Flash Write Enable
		out	0x34, r22	// write key to CCP
		sts	0x1000, r23	// write command for NVM

// write page copy in RAM to FLASH

// align flash pointer to page start
		clr	r30
		andi	r31,0xfe
// counter (2x256 bytes)
		clr	r23
// Y = page copy address (RAM)
10:
		ld	r0,Y+
		ld	r1,Y+
// TODO write only if FLASH differ from RAM...
		mov	r21,r0
		and	r21,r1
		inc	r21
		breq	1f
		spm	Z
1:
		adiw	r30,2
		dec	r23
		brne	10b
// wait for NVM (busy), on error newer ending loop
#warning check NVM error code
	        cli
1:		lds     r23,0x1002      // NVMCTRL.STATUS
		out	0x1f,r23	// GPIOR3 .. for debug
	        andi    r23,0x3
	        brne    1b
	        sei
// clear NVM command
// unlock Configuration change protection
		clr	r1		// ABI
		out     0x34, r22
		sts     0x1000, r1      // NOCMD
//
// deallocate page on stack
		in	r18,0x3d	// TODO is this needed (AVR128DA ?)
		in	r19,0x3e
		subi	r19,-2
		out	0x3d,r18	// TODO is this needed (AVR128DA ?)
		out	0x3e,r19

		pop	r29
		pop	r28
		ret

///////////////////////////////////////////////////////////////////////////////////////////////////////

// device_write_block (void *ram, uint16_t flash, uint8_t size);
		.global	device_write_block
		.type	device_write_block,@function

device_write_block:
		clt			// flag update FLASH from RAM
device_write_block2:
		movw	r26,r24		// RAM data pointer
		// check range and set FLASH pointer into Z
		rcall	device_block_check

		rcall	device_update_page

		tst	r20		// test counter, some bytes to next page ?
		breq	1f		// no skip...

		rcall	device_update_page

1:
		brts	1f		// for function "device_write_ff" return  bytes ..
		clr	r24
1:
		ret
///////////////////////////////////////////////////////////////////////////////////////////////////////
// int16_t device_write_ff (uint16_t offset, uint8_t size);

		.global	device_write_ff
		.type	device_write_ff, @function
device_write_ff:
// size into r20 (counter)
		mov	r20,r22
// offset into r22
		movw	r22,r24
// check size
		mov	r0,r20
		dec	r0
		add	r24,r0
		adc	r25,r1
		brcc	1f
// size must be clamped
		mov	r20,r0
		neg	r20
1:
		ldi	r25,0x40	// fake ram address
		set			// flag update FLASH by 0xFF (erase)
		push	r20
		rcall	device_write_block2
// test error code (0=ok)
		tst	r24
		brne	1f
// all OK, return number of bytes ...
// load size back, size in range 1...256 (change 0 to 0x100)
		pop	r24
		ldi	r25,1
		cpse	r24,r1
		ldi	r25,0
		ret
1:
		pop	r0
// negative return value = error
		ldi	r25,0xff
		ret
