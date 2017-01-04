#include <stdint.h>
#include <string.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <avr/eeprom.h>
#include <util/atomic.h>
#include "mem_device.h"


#if SELF_SPM
//forward definitions:

void
device_write_page (uint16_t flash, uint8_t * ram, uint8_t * check)
  __attribute__ ((section (".flash_end")));

void
device_write_page (uint16_t flash, uint8_t * ram, uint8_t * check)
{
  asm volatile (		//
  // prevent unattended jump here ..  last two operands must be same
                 "cp    r20,r22\n"      //
                 "brne  5f\n"   //
                 "cp    r21,r23\n"      //
                 "brne  5f\n"   //
//
                 "cli\n"		//
		 "ldi	r20,0x01\n"	// RAMPZ set to 1
		 "out	0x3b, r20\n"	//
		 "movw	r26,r22\n"	// ram pointer to X
		 "clr	r24\n"	// safety clear (clamp to page start)
		 "push	r25\n"
		 "1:\n"		//
		 "lds	r20, 0x01CF\n"	// NVM_STATUS
		 "sbrc	r20, 7\n"	// NVM is busy ?
		 "rjmp	1b\n"	// wait in loop
//
		 "ldi	r21, 0x23\n"	// command LOAD FLASH BUFFER
		 "sts	0x01CA, r21\n"	// set command to NVM_CMD register
// load page
//
                 "2:\n"		//
		 "movw	r30,r24\n" // flash address to Z
		 "ld	r0,X+\n"	// load ram 
		 "ld	r1,X+\n"	//
		 "spm\n"	//
//
		 "adiw	r24,2\n"	// increment flash address
		 "tst	r24\n"	// 256 bytes ?
		 "brne	2b\n"	// loop if page is not fully loaded
//
// erase/write page to flash
                 "pop	r25\n"
                 "clr	r24\n"
//
		 "3:\n"		//
		 "lds	r20, 0x01CF\n"	// NVM_STATUS
		 "sbrc	r20, 7\n"	// NVM is busy ?
		 "rjmp	3b\n"	// wait in loop
//
		 "movw	r30, r24\n"	// flash address to Z
		 "ldi	r21,0x25\n"	// command ERASE_WRITE_APP_PAGE
		 "sts	0x01CA, r21\n"	// write command "ERASE_WRITE_APP_PAGE"
		 "ldi	r20, 0x9D\n"	// unprotect SPM (0xd8 unprotect IO reg)
		 "sts	0x0034, r20\n"	// CCP
		 "spm\n"	//
//
//
		 "4:\n"		//
		 "lds	r20, 0x01CF\n"	// NVM_STATUS
		 "sbrc	r20, 7\n"	// NVM is busy ?
		 "rjmp	4b\n"	// wait in loop
//
 		 "clr	r21\n"		// no command
		 "sts	0x01CA, r21\n"	//
//
                "sei\n"		//
		 "clr	r1\n"	// ABI need r1=0
		 "5:\n"		//
		 :::"r0", "r1", "r20", "r21",
		 "r22", "r23", "r24", "r25", "r26", "r27", "r30", "r31");

}
#else
#warning This code deppend on internal DFU bootloader!!!
/*
This is dissassembled part of DFU loader:
load flash buffer
 call 0x20038
; R18 = RAMPZ
; r16,r17 = address
; r20,21 = data


; R18 = RAMPZ
; r16,r17 = address
; r20,21 = data

 
    20038:       30 91 cf 01     lds     r19, 0x01CF     ;NVM_STATUS
    2003c:       37 fd           sbrc    r19, 7          ;NVM is busy ?
    2003e:       fc cf           rjmp    .-8             ; loop back
; NVR is not busy .. 
    20040:       3b b7           in      r19, 0x3b       ; // save RAMPZ
    20042:       2b bf           out     0x3b, r18       ; // R18 to RAMPZ
    20044:       f8 01           movw    r30, r16
    20046:       20 91 ca 01     lds     r18, 0x01CA     ;NVM_CMD 
    2004a:       13 e2           ldi     r17, 0x23       ;command LOAD FLASH BUFFER
    2004c:       10 93 ca 01     sts     0x01CA, r17     ;NVM_CMD
    20050:       0a 01           movw    r0, r20
    20052:       e8 95           spm
    20054:       20 93 ca 01     sts     0x01CA, r18     ; restore NVM_CMD
    20058:       3b bf           out     0x3b, r19       ; restore RAMPZ
    2005a:       08 95           ret

// write                                                      

call 0x2005c
; R18 = RAMPZ
; r16,r17 = address
; r20 NVM_CMD

    2005c:       3b b7           in      r19, 0x3b       ; save RAMPZ
    2005e:       2b bf           out     0x3b, r18       ; R18 to RAMPZ
    20060:       f8 01           movw    r30, r16
    20062:       20 91 ca 01     lds     r18, 0x01CA     ;NVM_CMD
    20066:       40 93 ca 01     sts     0x01CA, r20
    2006a:       3d e9           ldi     r19, 0x9D       ; unprotect SPM (0xd8 unprotect IO reg)
    2006c:       30 93 34 00     sts     0x0034, r19     ; CCP
    20070:       e8 95           spm
    20072:       20 93 ca 01     sts     0x01CA, r18
    20076:       3b bf           out     0x3b, r19       ; 59
    20078:       08 95           ret

*/

void device_write_page static void
fill_page_buffer (uint16_t address, uint16_t data)
{
  asm volatile (
                "ldi r18,0x01\n"	// RAMPZ
		"movw r26,r22\n"	// ram pointer to X
		"clr r24\n"	// safety clear (clamp to page start)
		"push r25\n"	//
		"1:\n"		//
		"movw r16,r24\n"	// flash address to r16
		"ld   r20,X+\n"	// load ram 
		"ld   r21,X+\n"	//
		"call 0x20038\n"	// store to page buffer
		"adiw r24,2\n"	// increment flash address
		"tst r24\n"	// 256 bytes ?
		"brne 1b\n"	//
		"pop r25\n"	//
		"clr r24\n"	//
		"ldi r18,0x01\n"	// RAMPZ
		"movw r16,r24\n"	//
		"ldi r20,0x25\n"	//ERASE_WRITE_APP_PAGE
		"call 0x2005c\n"	//
		"clr r1\n"	// ABI need r1=0
		:::"r0", "r1", "r16", "r17", "18", "r19", "r20", "r21", "r22",
		"r23", "r24", "r25", "r26", "r27", "r30", "r31");
}


void
device_write_page (uint16_t flash, uint8_t * ram, uint8_t * check)
{
  if (check != ram)
    return;

  ATOMIC_BLOCK (ATOMIC_RESTORESTATE)
  {
    NVM_CMD = 0;
    fill_page_buffer (flash, (uint16_t) ram);
  }
}
#endif

uint8_t
device_write_block (void *buffer, uint16_t offset, uint8_t size)
{
  uint8_t *b = buffer;
  uint16_t p_base;
  uint8_t p_data[256];
  uint16_t s = size;
  uint16_t p_offset;
  uint16_t p_data_size;

  if (s == 0)
    s = 256;

  if ((offset + s) >= 0xFF00 /*FLASHEND - 256 */ )	//last page is used for do_spm code!
    return 1;

  do
    {
      // get page start (aligned)
      p_base = offset & 0xff00;
      // get data position of new data in page
      p_offset = offset & 255;
      // calculate size of new data
      p_data_size = 256 - p_offset;
      if (p_data_size > s)
	p_data_size = s;

      // copy old data (0 - 256)
      device_read_block (p_data, p_base, 0);

      memcpy (p_data + p_offset, b, p_data_size);

      b += p_data_size;
      offset += p_data_size;
      s -= p_data_size;

      // write to flash
      // TODO prevent page erase if not needed..
      device_write_page (p_base, p_data, p_data);
    }
  while (s > 0);
  return 0;
}

// fill block at offset _offset_ with value 0xff of maximal length _size_
// return number of filled bytes (-1 on error)
int16_t
device_write_ff (uint16_t offset, uint16_t size)
{
  uint16_t s;
  uint16_t p_base;
  uint16_t p_offset;

  uint8_t p_data[256];

  if (offset >= 0xFF00 /*FLASHEND - 256 */ )
    return 0;

  // get page start (aligned)
  p_base = offset & 0xff00;
  // get data position of new data in page
  p_offset = offset & 255;

  // copy old data (0 - 256)
  device_read_block (p_data, p_base, 0);

  s = 256 - p_offset;
  if (s > size)
    s = size;

  memset (p_data + p_offset, 0xff, s);

  // write to flash
  device_write_page (p_base, p_data, p_data);
  return s;
}


// read max 256 bytes from flash into buffer (0 = 256)
uint8_t
device_read_block (void *buffer, uint16_t offset, uint8_t size)
{
  asm volatile (		//
		 "movw r26,r24\n"	// buffer
		 "movw r30,r22\n"	// offset
		 "ldi	 r21,1\n"	// value for rampz
		 "out  %[rampz],r21\n"	//
		 "1:"		//
		 "elpm r0,Z+\n"	// load data
		 "st   X+,r0\n"	// store data
		 "dec r20\n"	// counter 
		 "brne 1b\n"	// loop
		 ::		//   
		 [rampz] "i" (_SFR_IO_ADDR (RAMPZ))	//
    );				//
  return 0;
}


// 256 byte for security informations 
uint8_t
sec_device_read_block (void *buffer, uint8_t offset, uint8_t size)
{
  uint16_t eeprom = offset;

  if (eeprom + size > 256)
    return 1;

  eeprom_read_block (buffer, (uint8_t *) (eeprom), size);
  return 0;
}


uint8_t
sec_device_write_block (void *buffer, uint8_t offset, uint8_t size)
{
  uint16_t eeprom = offset;


  if (eeprom + size > 256)
    return 1;

  cli ();
  eeprom_update_block (buffer, (uint8_t *) (eeprom), size);
  eeprom_busy_wait ();
  sei ();

  return 0;
}
