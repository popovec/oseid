/*
    avr_os.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2020 Peter Popovec, popovec.peter@gmail.com

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

    CPU initialization and fuses setting for xmega128a4u
    Special: this part of code is responsible for restart of main
    (main must be restarted if card is powered down or on USB suspend etc.)

*/
#include <avr/io.h>
#include <avr/fuse.h>
#include <avr/lock.h>
#include <avr/interrupt.h>
#include "usb.h"
#include "avr_os.h"

#define GCC_VERSION (__GNUC__ * 10000 \
                     + __GNUC_MINOR__ * 100 \
                                          + __GNUC_PATCHLEVEL__)
/* Test for GCC version */
#if GCC_VERSION == 40902
#define X_GCC_OK
#endif
#if GCC_VERSION == 50400
#define X_GCC_OK
#endif

#ifndef X_GCC_OK
#error only AVR GCC version 4.8.1 / 4.9.2 / 5.4.0 are tested to compile this code
#endif


void init_cpu (void) __attribute__((naked))
  __attribute__((section (".init1")));
void
init_cpu (void)
{
  cli ();
  // use PLL - multiply 2MHz RC oscilator to 32MHz
  OSC.PLLCTRL = OSC_PLLSRC_RC2M_gc | (32 / 2);
  OSC.CTRL |= OSC_PLLEN_bm;
  // wait to PLL ready
  while (!(OSC.STATUS & OSC_PLLRDY_bm));
// switch CPU core clock to run from PLL
  {
    asm volatile (		//
		   "ldi	r25,4\n"	//      value (clock source for CPU core..)
		   "ldi	r24,0xd8\n"	//      key
		   "ldi r30,0x40\n"	//      0x0040 = CTRL reg address
		   "ldi	r31,0\n"	//
		   "out 0x3b,r1\n"	//      clear RAMPZ
		   "out 0x34,r24\n"	//      write key to CCP
		   "st  Z,r25\n"	//      write value
		   "ldi r24,0x40\n"	//      delay aproximatly 1ms
		   "ldi r25,0x1f\n"	//
		   "sbiw r24,1\n"	//
		   "brne .-4\n"	//
		   :::);
  }
}

void init_EIND (void) __attribute__((naked))
  __attribute__((section (".init3")));
void
init_EIND (void)
{
//
// https://gcc.gnu.org/onlinedocs/gcc/AVR-Options.html
// 3.19.6.1 EIND and Devices with More Than 128 Ki Bytes of Flash - The compiler never sets EIND.
// this seems to be true but avr-libc sets EIND
//
// $ avr-objdump -d /usr/lib/avr/lib/avrxmega7/crtatxmega128a4u.o
// Disassembly of section .init2:
//
// 00000000 <.init2>:
//    0:   11 24           eor     r1, r1
//    2:   1f be           out     0x3f, r1        ; 63
//    4:   c0 e0           ldi     r28, 0x00       ; 0
//    6:   cd bf           out     0x3d, r28       ; 61
//    8:   d0 e0           ldi     r29, 0x00       ; 0
//    a:   de bf           out     0x3e, r29       ; 62
//    c:   00 e0           ldi     r16, 0x00       ; 0
//    e:   0c bf           out     0x3c, r16       ; 60
//   10:   18 be           out     0x38, r1        ; 56
//   12:   19 be           out     0x39, r1        ; 57
//   14:   1a be           out     0x3a, r1        ; 58
//   16:   1b be           out     0x3b, r1        ; 59
//
// Better way to determine at what value EIND is set is source:
//
// $ dpkg -S /usr/lib/avr/lib/avrxmega7/crtatxmega128a4u.o
// avr-libc: /usr/lib/avr/lib/avrxmega7/crtatxmega128a4u.o
// after unpacking sources (apt source avr-libc .. )
//
// libc/avr-libc/crt1/gcrt1.S:
//
// //#ifdef __AVR_3_BYTE_PC__
// //        ldi     r16, hh8(pm(__vectors))
// //        out     _SFR_IO_ADDR(EIND), r16
// //#endif  /* __AVR_3_BYTE_PC__ */
//
// Unfortunately, EIND is set to 1 in this code, because we using bootloader
// section for vectors.  (We will not speculate why the creators of avr-libc
// chose the EIND setting according to the "vectors" position, it is their
// decision).
//
//
// OsEID code compilled for xmega uses EIND only in one place, file:
// card_os/iso7816.c, line:
//                           return ((c->func) ());
//
// there is no another EICALL/EIJMP instruction in whole code.
// Of course, this is checked after compilation, to prevent unwanted code execution.
// please read Makefile.xmega128a4u, line:
// test `avr-objdump -D build/xmega128a4u/card.elf |egrep "eicall|eijmp"|wc -l` -eq 1
//
// Because whole code affected by EIND is in low 64kiB instruction space
// (there is no jump from application to bootloader space) we need zero in EIND.
//
// here r1 is already cleared (from .init2)
// because this file is device specific, register name is omitted
  asm volatile (		//
		 "out 0x3c,r1\n"	//
		 :::);

}

void init_usb (void) __attribute__((naked))
  __attribute__((section (".init7")));
void
init_usb (void)
{
  // Internal 32MHz oscilator is used for USB.. check USB_Init

  // Interrupt controller - enable LOW, MEDIUM and HIGH level irq
  //PMIC.CTRL = PMIC_LOLVLEN_bm | PMIC_MEDLVLEN_bm | PMIC_HILVLEN_bm;
  // Interrupt controller - enable  HIGH level irq, move vector to bootloader
  // PMIC_IVSEL_bm is protected by CCP ..  enable access first
  CCP = CCP_IOREG_gc;
  PMIC.CTRL = PMIC_IVSEL_bm;
  PMIC.CTRL =
    PMIC_IVSEL_bm | PMIC_LOLVLEN_bm | PMIC_MEDLVLEN_bm | PMIC_HILVLEN_bm;
  //PMIC.CTRL = PMIC_HILVLEN_bm | PMIC_IVSEL_bm;

  sei ();
  USB_Init ();
}

// this code can be used to restart main (or sleep, then restart main)

uint8_t restart_state[2] __attribute__((section (".noinit")));

void restart_main (void) __attribute__((naked))
  __attribute__((section (".init8")));
void
restart_main (void)
{

// save CPU state
  asm volatile (		//
		 "ldi	r30,lo8(%[r_state])\n"	//
		 "ldi	r31,hi8(%[r_state])\n"	//
		 "cli\n"	//
		 "in	r24,0x3d\n"	//
		 "st	Z+,r24\n"	//
		 "in	r24,0x3e\n"	//
		 "st	Z+,r24\n"	//
		 ::[r_state] "m" (restart_state));

// hooks restart main
  asm volatile (		//
		 "rjmp no_sleep\n"	//
		 "do_sleep:\n"	//
		 "cli\n"	//
		 "ldi	r30,lo8(%[sleep_reg])\n"	//
		 "ldi	r31,hi8(%[sleep_reg])\n"	//
		 "ldi	r24,5\n"	// sleep mode PDOWN, enable sleep
		 "st	Z,r24\n"	//
		 "ldi	r24,0\n"	// disable sleep
		 "sei\n"	//
		 "sleep\n"	//
		 "st	Z,r24\n"	//
		 "no_sleep:\n"	//
		 //                   ::[sleep_reg] "m" (SLEEP));        // SLEEP = SLEEP_CTRL
		 ::[sleep_reg] "m" (SLEEP_CTRL)	//
		 :);
// reintialize USB clock/calibration
  USB_Reinit ();
// restore SP for main ..
  asm volatile (		//
		 "ldi	r30,lo8(%[r_state])\n"	//
		 "ldi	r31,hi8(%[r_state])\n"	//
		 "cli\n"	//
		 "ld	r24,Z+\n"	//
		 "out	0x3d,r24\n"	//
		 "ld	r24,Z+\n"	//
		 "out	0x3e,r24\n"	//
		 ::[r_state] "m" (restart_state));
// reinitialize SREG, and RAMP registers

  asm volatile (		//
		 "clr	r1\n"	//
		 "out	0x3f,r1\n"	//
		 "out	%[rampd],r1\n"	//
		 "out	%[rampx],r1\n"	//
		 "out	%[rampy],r1\n"	//
		 "out	%[rampz],r1\n"	//
		 "sei\n"	//
		 ::		//
		 [rampd] "I" (_SFR_IO_ADDR (RAMPD)),	//
		 [rampx] "I" (_SFR_IO_ADDR (RAMPX)),	//
		 [rampy] "I" (_SFR_IO_ADDR (RAMPY)),	//
		 [rampz] "I" (_SFR_IO_ADDR (RAMPZ))	//
		 :);
}

// Next functions force ISR PORTA_INT0_vect (or PORTA_INT1_vect) imedietly
// after any high/midle lewel interrupts are completted.  ISR then owerwrite
// return address on stack and does restart of main from specific address
// (do_sleep or no_sleep)

void
CPU_do_sleep ()
{
  cli ();
//pin4 (normaly connected to ground)
  PORTA.DIRCLR = PIN4_bm;	// INPUT
  PORTA.PIN4CTRL = 3;		// interrupt on LEVEL
  PORTA.INTCTRL = 1;		// low level int
  PORTA.INT0MASK = PIN4_bm;	// pin4
  sei ();
}

//
void
CPU_do_restart_main ()
{
  cli ();
//pin4 (normaly connected to ground)
  PORTA.DIRCLR = PIN4_bm;	// INPUT
  PORTA.PIN4CTRL = 3;		// interrupt on LEVEL
  PORTA.INTCTRL = 4;		// low level int
  PORTA.INT1MASK = PIN4_bm;	// pin4
  sei ();
}

ISR (PORTA_INT0_vect, ISR_NAKED)
{
  // no more interupts
  cli ();
  PORTA.INT0MASK = 0;
  PORTA.INTCTRL = 0;
  PORTA.INTFLAGS = 3;		// clear flags

  asm volatile (		//
		 "pop	r24\n"	//
		 "pop	r24\n"	//
		 "pop	r24\n"	//
		 "ldi       r24,pm_lo8(do_sleep)\n"	//
		 "push      r24\n"	//
		 "ldi       r24,pm_hi8(do_sleep)\n"	//
		 "push      r24\n"	//
		 "ldi       r24,pm_hh8(do_sleep)\n"	//
		 "push      r24\n"	//
		 "sei\n"	//
		 "reti\n"	//
		 ::);
}

ISR (PORTA_INT1_vect, ISR_NAKED)
{
  // no more interupts
  cli ();
  PORTA.INT1MASK = 0;
  PORTA.INTCTRL = 0;
  PORTA.INTFLAGS = 3;		// clear flags

  asm volatile (		//
		 "pop	r24\n"	//
		 "pop	r24\n"	//
		 "pop	r24\n"	//
		 "ldi       r24,pm_lo8(no_sleep)\n"	//
		 "push      r24\n"	//
		 "ldi       r24,pm_hi8(no_sleep)\n"	//
		 "push      r24\n"	//
		 "ldi       r24,pm_hh8(no_sleep)\n"	//
		 "push      r24\n"	//
		 "sei\n"	//
		 "reti\n"	//
		 ::);
}

void
CPU_idle (void)
{
  asm volatile (		//
		 "cli\n"	//
		 "ldi	r30,lo8(%[sleep_reg])\n"	//
		 "ldi	r31,hi8(%[sleep_reg])\n"	//
		 "ldi	r24,1\n"	// sleep mode IDLE, enable sleep
		 "st	Z,r24\n"	//
		 "ldi	r24,0\n"	// disable sleep
		 "sei\n"	//
		 "sleep\n"	//
		 "st	Z,r24\n"	//
		 //                   ::[sleep_reg] "m" (SLEEP));        // SLEEP = SLEEP_CTRL
		 ::[sleep_reg] "m" (SLEEP_CTRL)	//
		 :);
}

#ifdef HW_SERIAL_NUMBER
void
get_HW_serial_number (uint8_t * s)
{
  asm volatile (		//
		 "in	r0,0x3f\n"	//
		 "cli\n"	//
		 "movw	r26,r24\n"	//
		 "adiw	r26,10\n"	// from end - low bits
//
// XMEGA uses several bytes as serial number:
// 1 coorditates on waffer (16 bit X and 16 bit Y)
// 2. wafer number (5 bits)
// 3. LOT number 6 bytes
// we can assume, LOTNUM is ascii...
// https://www.avrfreaks.net/forum/contents-xmega32e5-production-signature-row-question
// https://avrhelp.mcselec.com/index.html?readsig.htm
// https://microchipsupport.force.com/s/article/Serial-number-in-AVR---Mega-Tiny-devices
// https://www.avrfreaks.net/forum/atxmega32e5-serial-number
// and in include file  avr/iox128a4u.h ...  LOTNUM0;  ... Lot Number Byte 0, ASCII
//
// for card we need 10 bytes, use coordinates as low part of serial number
// LOT = 6 bytes - rest of serial number (upper bits).  wafer number is
// distributed to bit 0 of LOT (Original LOT is rotated) bit 7 of LOT chars
// is lost ..  but if this is ascii char, we can assume here is always zero
// in bit 7
//
		 "ldi	r25,2\n"	// NVM_CMD_READ_CALIB_ROW_gc
		 "sts	0x1ca,r25\n"	// NVM.CMD
//
		 "ldi	r30,0x12\n"	//COORDs
		 "ldi	r31,0\n"	//
//
		 "ldi	r22,4\n"	// 4 bytes from coordinates
		 "1:\n"		//
		 "lpm	r24,Z+\n"	//COORDX0, X1, Y0, Y1
		 "st	-X,r24\n"	//
		 "dec	r22\n"	//
		 "brne 1b\n"	//
//
		 "ldi	r30,0x10\n"	// WAFNUM
		 "lpm	r25,Z+\n"	//
//
		 "ldi	r30,8\n"	// LOT0, LOT1 .. LOT5
		 "ldi	r22,6\n"	// 6 bytes from LOTNUMs
		 "1:\n"		//
		 "lpm	r24,Z+\n"	//
		 "ror	r25\n"	//      wafer bit to LOT
		 "rol	r24\n"	//
		 "st	-X,r24\n"	//
		 "dec	r22\n"	//
		 "brne	1b\n"	//
//
		 "sts	0x1ca,r1\n"	// NVM.CMD = NVM_CMD_NO_OPERATION_gc;
		 "out	0x3f,r0\n"	//
		 ::);
}
#endif

FUSES = {
//  .FUSEBYTE1 = 0,     // watchdog - default value
  .FUSEBYTE2 = 0xBF,		// start from bootloader section
//  .FUSEBYTE4 = ,      //
//  .FUSEBYTE5 = ,      //
};


// disable read/write by external programming interface & 0xfc
// disable read/write bootloader section  from application section  &0x3f
// bootloader can access application +application table section
LOCKBITS = (0x3c);
