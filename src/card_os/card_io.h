/*
    card_io.h

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


    input/output subsystem for OsEID


    Functions:

    void card_io_init(void)
     - I/O subsystem is initialized and ATR is sent to reader

    void card_io_tx (uint8_t * data, uint16_t len);
     - transmit data from buffer pointed by "data", length is
       defined in "len" variable. Minimal transmit size is 1 byte,
       if len==0 then 65536 bytes are transmitted.

     - for protocol T0, the error signal and character repetition is is used
       as specified in ISO7816-3:2006(E).  The repetition of characters
       should be limited, if the error signal occurs more than (20?) times,
       TX is interrupted.

     uint16_t card_io_rx (uint8_t * data, uint16_t len);

     - pointer "data" must not be NULL and must point to at least 10
       free byte in RAM

     - read data from reader, store to buffer pointed by "data"
       maximal number of received bytes in "len". If reader transmit
       more data as expected in "len", rest of data are discarded.
       (transmit end is detected by timeout after latest received char)
       Discard is not signalized.

     - for protocol T0, the error signal and character repetition is is used
       as specified in ISO7816-3:2006(E).  The repetition of characters
       should be limited, if the error signal occurs more than (20?) times,
       RX continues, but the error signal is no longer generated.  Caller is
       informed about parity error.

     - if len == 0, whole frame is dropped, no byte is stored into buffer.

     - return value corresponds to number of received bytes. this function
       is waiting for data from card reader at least one byte is received.
       (even this byte is wrong i.e. withparity error..)

     - Any special case is signalized by return value 0, in this case,
       the 1st value in buffer is used as error/special code:

     Error codes:
     CARD_IO_PARITY_ERROR - at least one of character was received with
                            parity error.

     Special codes: (only for negotiable mode):
     CARD_IO_PPS - response to PPS is in buffer (used to set T0/T1 protocol)
     CARD_IO_PPS_ERROR - incorrect PPS frame in buffer.

     PPS handling:
     -------------

     IO layer is not responsible to handle 0xff in NAD field or in CLA field.

     If 1st received byte in buffer is 0xff and this is 1st frame after ATR,
     frame is checked, if this is valid PPS frame.

     PPS0 is checked for supported protocols, PPS1 is checked for valid F/D.
     If this frame is not correct PPS or or "PPS" contains values that
     cannot be used, 1st byte in buffer is set to "CARD_IO_PPS_ERROR" and
     returned length is 0.

     For valid PPS frame, the IO layer generates a response frame and this
     frame is returned to caller (1st byte in buffer = CARD_IO_PPS, 2nd
     byte in buffer is length of PPS response frame, returned length = 0).

     Example of data in buffer:

       0xff           4      0xFF   0x11   0x96                      0x78
     [CARD_IO_PPS] [LENGTH] [PPSS] [PPS0] [PPS1] optionally[PPS2,3] [PCK]

     Caller can use protocol value in PPS frame to select T0/1 protocol.
     Caller is responsible to transmit this frame back.  IO layer then
     changes parameters of transmitions to negotiated values.

     void card_io_start_null (void);
     - setup I/O subsystem to transmit NULL bytes / WTX frames.

     void card_io_stop_null (void); (deprecated, should be handles in card_io_tx)
     - setup I/O subsystem to not transmit NULL bytes



     RST handling:

     Cart reset is asynchronous event, IO subsystem can handle this in different ways:

     1. RST pad is connected to microcontroler RESET pin, then no other handling is needed
     2. RST is monitored by interrupt system of microcontroler, microcontroler reset
        is generated if RST is detected
     3. RST is monitored in software, if RST is detected to be active, signal handler
        is called and card is restarted from main (usually by setting setjmp and handler
        then call longjmp. card_os/card.c provide two places for include
        restart.h and restart.c to ensure this task.

*/
#define CARD_IO_PARITY_ERROR 2

#ifdef TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
#define CARD_IO_PPS_ERROR 0xfe
#define CARD_IO_PPS 0xff
#endif

#if !defined (TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE) && !defined(TRANSMISSION_PROTOCOL_MODE_SPECIFIC)
#error TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE or TRANSMISSION_PROTOCOL_MODE_SPECIFIC #define TRANSMISSION_PROTOCOL_MODE_SPECIFIC must be defined
#endif

#if defined (TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE) && defined(TRANSMISSION_PROTOCOL_MODE_SPECIFIC)
#error both TRANSMISSION_PROTOCOL_MODE_NEGOTIABLE and TRANSMISSION_PROTOCOL_MODE_SPECIFIC defined
#endif

#if defined (PROTOCOL_T0) && defined (PROTOCOL_T1) && defined(TRANSMISSION_PROTOCOL_MODE_SPECIFIC)
#error SPECIFIC mode and both T0,T1 protocol defined..
#endif

#if defined (T1_TRANSPORT) && !defined(PROTOCOL_T1)
#error T1_TRANSPORT defined but not PROTOCOL_T1
#endif

#if !defined(__ASSEMBLER__)
void card_io_init (void);
uint16_t card_io_rx (uint8_t * data, uint16_t len);
void card_io_tx (uint8_t * data, uint16_t len);
uint8_t card_io_reset (void);
void card_io_start_null (void);
void card_io_stop_null (void);
#endif
