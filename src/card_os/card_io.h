/*
    card_io.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2017 Peter Popovec, popovec.peter@gmail.com

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
     - I/O subsystem is initialized and ATR is send to reader

    void card_io_tx (uint8_t * data, uint16_t len);
     - transmit data from buffer pointed by "data", length is
       defined in "len" variable. Minimal transmit size is 1 byte,
       if len==0 then 65536 bytes are transmitted.

     uint16_t card_io_rx (uint8_t * data, uint16_t len);
     - read data from reader, store to buffer pointed by "data"
       maximal number of received bytes in "len". If reader transmit
       more data as expected in "len", rest of data are discarded.
       (transmit end is detected by timeout after latest received char)
       Discard is not signalized, for protocol T1 the Le field can be
       dropped silently.
     - if len == 0, no character are stored into buffer (T0 protocol allow
       only 255 character to be transmitted, here 0 is not interpreted as 256)
     - On error return 0, then 1st byte in buffer signalize error:
       1 - parity error (only for T0 transport)
       2 - PPS error (read PPS handling below)

     void card_io_start_null (void);
     - setup I/O subsystem to transmit NULL bytes
       to get CPU for transmiting NULL usualy interrupt subsystem must be used

     void card_io_stop_null (void);
     - setup I/O subsystem to not transmit NULL bytes

     CLASS FFh - card in specific mode (TA2 present in ATR):
	- io layer is not responsible to handle PPS (CLASS FFh / NAD FFh)
        - frame is passed to caller

     CLASS FFh - card in negotiable mode
	- if 1st byte in frame is 0xff, then:
		a) If this is 1st frame after ATR, this is PPS frame (see below)
		   (ISO7816-3:2006,Figure 4)
		b) If this is not 1st frame after ATR, this frame is ignored
                   CLA 0xff is invalid, NAD 0xff is invalid.
		   (ISO7816-3:2006, 6.3.1 NOTE 1)
                   IO layer signalize this as error 2 (see above card_io_rx)


      PPS handling:
        PPS0 is checked for supported protocols, PPS1 is checked for valid F/D. For
        valid PPS IO layer generates a response frame and this frame is returned to
        caller. Caller can use protocol value in PPS frame to select T0/1 protocol.
        Caller is responsible to transmit this frame back. IO layer then
        changes parameters of transmitions to negotiated values.

     RST handling:

     Cart reset is asynchronous event, IO subsystem can handle this in different ways:

     1. RST pad is connected to microcontroler RESET pin, then no other handling is needed
     2. RST is monitored by interrupt system of microcontroler, microcontroler reset
        is generated if RST is detected
     3. RST is monitored in software, if RST is detected to be active, signal handler
        is called and card is restarted from main (usualy by setting setjmp and handler
        then call longjmp. card_os/card.c provide two places for include
        restart.h and restart.c to ensure this task.

*/
void card_io_init (void);
uint16_t card_io_rx (uint8_t * data, uint16_t len);
void card_io_tx (uint8_t * data, uint16_t len);
uint8_t card_io_reset (void);
void card_io_start_null (void);
void card_io_stop_null (void);
