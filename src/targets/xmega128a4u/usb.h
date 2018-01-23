/*
    usb.h

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

    xmega USB subsystem for CCID layer - header file

*/
#include <stddef.h>
//////////////////////////////////////////////////////////////////////////
//               CCID support

// CCID part, CCID responses over BULK IN are handled by functions
// isr_CCID_short_message_to_host() and CCID_response_to_host()
// CCID layer normally running in ISR (transaction complete on BULK OUT
// or CONTROL endpoint). If CCID layer can generate response inside this
// ISR and response length is below 64 bytes, response is is synchronously
// sended back by calling isr_CCID_short_message_to_host(). If CCID layer
// receive PC_to_RDR_XfrBlock message:
//
// T0 protocol: message is transferred to card by CCID layer,
// CCID layer then commit response to host, and card software is responsible
// to call CCID_response_to_host() to return data to host.
// CCID layer block any other PC_to_RDR_XfrBlock message to busy slot,
// and slot is unblocked after response is generated.
//
// T1 protocol: message is send to T1 wrapper, T1 wrapper return R frame
// (or any other response if needed). If T1 wrapper can construct full APDU
// for card, CCID layer pass this APDU to card, and if card return response
// T1 wrapper does call CCID_response_to_host() (for 1st 64 bytes of response).
// Rest of response is sended back to host in isr.

void isr_CCID_short_message_to_host (uint8_t * buffer, uint8_t length);
void CCID_response_to_host (uint8_t * buffer, uint16_t length);
// send CCID message to host with seq number "l_seq" to
// request longer working time
void CCID_start_null (uint8_t l_seq);
////////////////////////////////////////////////////////////////////////////

// USB descriptors
//////////////////
// String descriptor
struct Descriptor_String_t
{
//  USB_Descriptor_Header_t Header;
  uint8_t bLength;
  uint8_t bDescriptorType;
  wchar_t UnicodeString[];
//  uint16_t UnicodeString[];
};

// Device descriptor
struct Descriptor_Device_t
{
  uint8_t Size;
  uint8_t Type;

  uint16_t USBSpecification;
  uint8_t Class;
  uint8_t SubClass;
  uint8_t Protocol;
  uint8_t Endpoint0Size;
  uint16_t VendorID;
  uint16_t ProductID;
  uint16_t ReleaseNumber;
  uint8_t ManufacturerStrIndex;
  uint8_t ProductStrIndex;
  uint8_t SerialNumStrIndex;
  uint8_t NumberOfConfigurations;
};

struct Descriptor_Configuration_Header_t
{
  uint8_t bLength;
  uint8_t bDescriptorType;
  uint16_t wTotalLength;
  uint8_t bNumInterfaces;
  uint8_t bConfigurationValue;
  uint8_t iConfiguration;
  uint8_t bmAttributes;
  uint8_t bMaxPower;
};

struct Descriptor_Interface_t
{
  uint8_t bLength;
  uint8_t bDescriptorType;
  uint8_t bInterfaceNumber;
  uint8_t bAlternateSetting;
  uint8_t bNumEndpoints;
  uint8_t bInterfaceClass;
  uint8_t bInterfaceSubClass;
  uint8_t bInterfaceProtocol;
  uint8_t iInterface;
};

struct Descriptor_CCID_Interface_t
{
  uint8_t bLength;		// 0x36
  uint8_t bDescriptorType;	// 0x21
  uint16_t bcdCCID;		// 0x0110
  uint8_t bMaxSlotIndex;	//
  uint8_t bVoltageSupport;
  uint32_t dwProtocols;
  uint32_t dwDefaultClock;
  uint32_t dwMaximumClock;
  uint8_t bNumClockSupported;
  uint32_t dwDataRate;
  uint32_t dwMaxDataRate;
  uint8_t bNumDataRatesSupported;
  uint32_t dwMaxIFSD;
  uint32_t dwSynchProtocols;
  uint32_t dwMechanical;
  uint32_t dwFeatures;
  uint32_t dwMaxCCIDMessageLength;
  uint8_t bClassGetResponse;
  uint8_t bClassEnvelope;
  uint16_t wLcdLayout;
  uint8_t bPINSupport;
  uint8_t bMaxCCIDBusySlots;
};

struct Descriptor_Endpoint_t
{
  uint8_t bLength;
  uint8_t bDescriptorType;
  uint8_t bEndpointAddress;
  uint8_t bmAttributes;
  uint16_t wMaxPacketSize;
  uint8_t bInterval;
};

struct USB_Descriptor_Configuration_t
{
  struct Descriptor_Configuration_Header_t Config;
  struct Descriptor_Interface_t Interface;
  struct Descriptor_CCID_Interface_t CCID_Interface;
  struct Descriptor_Endpoint_t CCID_bulk_out;
  struct Descriptor_Endpoint_t CCID_bulk_in;
  struct Descriptor_Endpoint_t CCID_interrupt;
};
#define CCID_bulk_out_ID 1
#define CCID_bulk_in_ID 2
#define CCID_intr_ID 3

#define ENDPOINT_DIR_OUT                   0x00
#define ENDPOINT_DIR_IN                    0x80

#define CCID_bulk_out_ADDR (ENDPOINT_DIR_OUT | CCID_bulk_out_ID)
#define CCID_bulk_in_ADDR  (ENDPOINT_DIR_IN | CCID_bulk_in_ID)
#define CCID_intr_ADDR      (ENDPOINT_DIR_IN | CCID_intr_ID)

// device independent part

struct USB_Setup_Packet
{
  uint8_t bmRequestType;
  uint8_t bRequest;
  uint16_t wValue;
  uint16_t wIndex;
  uint16_t wLength;
} __attribute__ ((packed));


void USB_Init (void);
void USB_Reinit (void);
uint16_t USB_Device_GetFrameNumber (void)
  __attribute__ ((warn_unused_result));

////////////////////////////////////////////////////
// enumeration and macros for accessing
// device state variable

// device powered only from bus,
// initial state is then DEVICE_STATE_Powered
// bus reset change state to DEVICE_STATE_Default
// then address is set - DEVICE_STATE_Addressed
// and then configured - DEVICE_STATE_Configured

// If device is suspended (DEVICE_STATE_Configured), and then resumed, state
// is derived from configuration number and address of device (powered,
// addressed, configured)

enum USB_Device_States_t
{
  DEVICE_STATE_Powered = 0,
  DEVICE_STATE_Default,
  DEVICE_STATE_Addressed,
  DEVICE_STATE_Configured,
  DEVICE_STATE_Suspended
};
extern volatile uint8_t var_DeviceState;
#define V_SetDeviceState(val) var_DeviceState = val
#define V_GetDeviceState()    var_DeviceState
////////////////////////////////////////////////////

struct __attribute__ ((packed)) USB_EndpointTable_t
{
  struct
  {
    USB_EP_t OUT;
    USB_EP_t IN;
  }
  Endpoints[4];
  uint16_t FrameNum;
};

//__attribute__ ((packed)) USB_EndpointTable_t;
