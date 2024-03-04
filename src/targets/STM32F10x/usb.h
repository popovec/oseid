/*
    usb.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2024 Peter Popovec, popovec.peter@gmail.com

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

    USB subsystem for CCID layer - header file (STM32F102 target)

*/

// CCID layer uses this call to transmit data to host:
// endpoint 3 - interrupt
// endpoint 2 - CCID to host
uint8_t USB_send_data_to_host(uint8_t ep, uint8_t * data, uint16_t length);

void USBcommon_Reset(void);

// This is called by HW driver to check if new address for device is available
uint8_t USBcommon_GetAddress(void);

// 0 - device unconfigures, any other value = configuration number
// In this project only configuration 1 is used.
uint8_t USBcommon_GetConfiguration(void);

// This is called after USB hardware is reconfigured to new address
void USBcommon_MarkDeviceAddressed(void);

uint8_t USB_Get_Stall_state(uint8_t ep);

void USB_Configure_ep(uint8_t ep);
void USB_Stall_ep(uint8_t ep);
void USB_Configure_CCID_ep(void);
void USB_Deconfigure_CCID_ep(void);

uint8_t USB_send_data_to_host(uint8_t ep, uint8_t * data, uint16_t length);
// what to do after response:
// OK - nothing
// ZERO_FRAME  - return blank frame (length=0)
// RET_STALL   - stall RX and TX
#define RET_OK          0
#define RET_ZERO_FRAME  20
#define RET_STALL       100
uint8_t USBcommon_ProcessSetupRequest(uint8_t * usb_buffer, uint8_t rec_len);
