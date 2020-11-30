/*
    avr.S

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2020 Peter Popovec, popovec.peter@gmail.com

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

    AVR128DA CPU initialization
*/


	.section .vectors,"ax",@progbits
	.global __vectors
	.type   __vectors, @function

__vectors:
	jmp   __init
	jmp   4
	jmp   __vector_2
	jmp   __vector_3


        .section .init0,"ax",@progbits

__init:
// switch CPU to 24MHz
	ldi	r22,0xd8
	ldi	r23,0x24
	out	0x34,r22	// unlock CCP
	sts	0x68,r23	// switch freq

	ldi	r23,0x1f	// tune oscilator at maximum
	sts	0x69,r23

// do no tallow write to boot/application section, only application data section is allowed to be flashed
	ldi	r23,3		// NVMCTRL.CTRLB, 3
	out	0x34,r22	// unlock CCP
	sts	0x1001,r23

// compact vector table, vector in boot section
	ldi	r23,0x60	// CPUINT.CTRLA,0x60
	out	0x34,r22	// unlock CCP
	sts	0x110,r23

	.section .init2,"ax",@progbits
	clr	r1
	out	0x3f,r1	// clear SREG
// set stack
	ldi	r28,0xff
	ldi	r29,0x7f
	out	0x3d,r28
	out	0x3e,r29

//	out	0x2b,r1	// clear RAMPZ

// do copy data and clear bss is not needed
        .section .init9,"ax",@progbits

// software reset is used (PF6 reset function is disabled by fuse)

// wait for ISO7816 RST == 1

1:

#if 0
	sbis	(0x0+2),3		// VPORTA + 2 = IN from PORTA
	rjmp	1b
#else
	in	r24,0x02                // PORTA IN
	andi	r24,0x08                // PF3
	breq	1b
#endif
// OK, RST is released

// program high priority irq from pin PA3 (5 = level low)
// PORTA.PIN3CTRL = 5;
// 0x400 + 0x10 + 5 = PORTA.PIN3CTRL
        ldi     r24,5	// level low interrupt
        sts     0x0413, r24
// set CPUINT.LVL0PRI
// for PORTA (vector 6, address 0x0c)
	ldi	r22,0xd8	// KEY
	ldi	r23,6		// vector number
	out	0x34,r22	// unlock CCP
	sts	0x113,r23	// CPUINT.LVL1VEC

	sei
	jmp 	main

// Priority 1 level ISR (high)
        .global __vector_2
        .type __vector_2, @function
// do soft reset
__vector_2:
	ldi	r22,0xd8
	ldi	r23,1
	out	0x34,r22	// unlock CCP
	sts	0x41,r23	// run SW reset
// reset seq.  start immediately... ?
	rjmp	1b

#ifdef HW_SERIAL_NUMBER
        .global get_HW_serial_number
        .type   get_HW_serial_number, @function

get_HW_serial_number:
// void get_HW_serial_number (uint8_t *s);
// AVR128DA - serial number address 0x1110 .. 0x111f
// last four bytes = 0
// we need 10 bytes
	ldi	r31,0x11
	ldi	r30,0x12
	movw	r26,r24
	ldi	r24,10
1:
	ld	r0,Z+
	st	X+,r0
	dec	r24
	brne	1b
	ret
#endif

	.section .fuse
__fuse:
	.byte	0	// WDTCFG
	.byte	0	// BODCFG
	.byte	0	// OSCCFG
	.byte	0	// reserved
	.byte	0	// reserved
	.byte	0xc0	// SYSCFG0
	.byte	0	// SYSCFG1
	.byte	0x80	// CODESIZE
	.byte	0x80	// BOOTSIZE


	.section .note.gnu.avr.deviceinfo, "", @note
	.long	4	// long of sring (AVR\0)
	.long 	0x2d
	.long	1	// type
	.asciz	"AVR"
// flash start
	.long 0
	.long 0x20000

// ram start/size
	.long	0x4000
	.long	0x4000
// eeprom start ??? 0x1400 here ???
	.long	0
// eeprom size
	.long	512


.L__stroffsettab_start:
	.long	.L__stroffsettab_end - .L__stroffsettab_start
	.long	.L__device_name_start - .L__strtab_start // offset of device name
.L__stroffsettab_end:
.L__strtab_start:
	.byte 0
.L__device_name_start:
	.asciz	"avr128da32"
//.L__device_name_end:
	.byte 0
.L__strtab_end:
	.balign 4
