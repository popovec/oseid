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

    uint8_t card_io_tx (uint8_t * data, uint16_t len);
     - transmit data from buffer pointed by "data", length is
       defined in "len" variable. Minimal transmit size is 1 byte,
       if len==0 then 65536 bytes are transmitted.
     - return 255 on error (T0 protocol, reader signalize
       error in parity.. )
     - return 0 - all ok

     uint16_t card_io_rx (uint8_t * data, uint16_t len);
     - read data from reader, store to buffer pointed by "data"
       maximal number of received bytes in "len". If reader transmit
       more data as expected in "len", rest of data are discarded.
       (transmit end is detected by timeout after latest received char)
     - if len == 0, no character are stored into buffer (T0 protocol allow
       only 255 character to be transmitted, here 0 is not interpreted as 256)
     - return numbers of received chars (0..32767), bit 15 is used to signalize protocol T0/1
       Of cource maximal sice is limited by Hw.

     void card_io_start_null (void);
     - setup I/O subsystem to transmit NULL bytes
       to get CPU for transmiting NULL usualy interrupt subsystem must be used

     void card_io_stop_null (void);
     - setup I/O subsystem to not transmit NULL bytes

     uint8_t card_io_reset (void);
     - return 1 if card reset was activated (and ATR was send to reader)
       repeated cals then return 0 until RST is not reactivated.

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
uint8_t card_io_tx (uint8_t * data, uint16_t len);
uint8_t card_io_reset (void);
void card_io_start_null (void);
void card_io_stop_null (void);
