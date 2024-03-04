/*
    STM32F10x_dev_init.c

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

    USB code - control endpoint

*/
#include <stdint.h>
#include <string.h>
#include "ccid.h"
#include "serial_debug.h"
#include "usb.h"

//////////////////////////////////////////////////////////////////
//
// USB functions for control endpoint, descriptors, function
// for CCID which communicate via the control endpoint
//
//////////////////////////////////////////////////////////////////

// source https://www.usbmadesimple.co.uk/ums_4.htm
// State:
// Default: - GetDescriptor, and SetAddress
// Addressed: - SetConfiguration GetConfiguration SetFeature ClearFeature GetStatus SetDescriptor (optional)
// Configured: after SetConfiguration!, now SetAddress is not valid
//             valid: all + GetInterface, SetInterface, SyncFrame
// 0 for default/addressed
static uint8_t DeviceConfigured __attribute__((section(".noinit")));
// 0 (device in Default mode)
// 1..127 - device is addressed, USB is configured to this address
// 0x80 | address - device reseived address, and this address not yet confirmed
static uint8_t DeviceAddress __attribute__((section(".noinit")));

// Device descriptor
struct __attribute__((packed)) Descriptor_Device_t {
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

struct __attribute__((packed)) Descriptor_Configuration_Header_t {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint16_t wTotalLength;
	uint8_t bNumInterfaces;
	uint8_t bConfigurationValue;
	uint8_t iConfiguration;
	uint8_t bmAttributes;
	uint8_t bMaxPower;
};

struct __attribute__((packed)) Descriptor_Interface_t {
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

struct __attribute__((packed)) Descriptor_CCID_Interface_t {
	uint8_t bLength;	// 0x36
	uint8_t bDescriptorType;	// 0x21
	uint16_t bcdCCID;	// 0x0110
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

struct __attribute__((packed)) Descriptor_Endpoint_t {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint8_t bEndpointAddress;
	uint8_t bmAttributes;
	uint16_t wMaxPacketSize;
	uint8_t bInterval;
};

struct __attribute__((packed)) USB_Descriptor_Configuration_t {
	struct Descriptor_Configuration_Header_t Config;
	struct Descriptor_Interface_t Interface;
	struct Descriptor_CCID_Interface_t CCID_Interface;
	struct Descriptor_Endpoint_t CCID_bulk_out;
	struct Descriptor_Endpoint_t CCID_bulk_in;
	struct Descriptor_Endpoint_t CCID_interrupt;
};

/*
#include <stddef.h>
 wchar_t is 32 bit variable, or 16 (CFLAGS += -fshort-wchar)
 do not use wchar_t here.
 L"Test" - 32 or 16 bit string (depends on wchar_t)
 u"Test" 16 bit
 U"Test" 32 bit

#if SIZEOF_wchar_t > 1
#error 1
#endif
*/

struct __attribute__((packed)) Descriptor_String_t {
	uint8_t bLength;
	uint8_t bDescriptorType;
//      wchar_t UnicodeString[];
	uint16_t UnicodeString[];
};

struct __attribute__((packed)) USB_Request_Header {
	union __attribute__((packed)) {
		struct __attribute__((packed)) {
			uint8_t bmRequestType;
			uint8_t bRequest;
		};
		uint16_t function;
	};
	union __attribute__((packed)) {
		uint16_t wValue;
		struct __attribute__((packed)) {
			uint8_t wValueL;
			uint8_t wValueH;
		};
	};
	union __attribute__((packed)) {
		uint16_t wIndex;
		struct __attribute__((packed)) {
			uint8_t wIndexL;
			uint8_t wIndexH;
		};
	};
	uint16_t wLength;
} __attribute__((packed));

const struct Descriptor_Device_t DeviceDescriptor = {
	.Size = sizeof(struct Descriptor_Device_t),
	.Type = 1,		//DEVICE
	.USBSpecification = 0x0200,
	.Class = 0x00,		//(Defined at Interface level)
	.SubClass = 0x00,
	.Protocol = 0x00,
	.Endpoint0Size = 8,
	.VendorID = 0x08e6,
	.ProductID = 0x3437,
	.ReleaseNumber = 0x0200,
	.ManufacturerStrIndex = 1,
	.ProductStrIndex = 2,
	.SerialNumStrIndex = 3,
	.NumberOfConfigurations = 1,
};

const struct USB_Descriptor_Configuration_t
 ConfigurationDescriptor = {
	.Config = {
		   .bLength = 9,
		   .bDescriptorType = 2,	//configuration
		   .wTotalLength = sizeof(struct USB_Descriptor_Configuration_t),
		   .bNumInterfaces = 1,
		   .bConfigurationValue = 1,
		   .iConfiguration = 0,
		   .bmAttributes = 0xa0,	//reserved
		   .bMaxPower = 25,
		   }
	,.Interface = {
		       .bLength = 9,
		       .bDescriptorType = 4,
		       .bInterfaceNumber = 0,
		       .bAlternateSetting = 0,
		       .bNumEndpoints = 3,
		       .bInterfaceClass = 0x0b,
		       .bInterfaceSubClass = 0,
		       .bInterfaceProtocol = 0,
		       .iInterface = 0,
		       }

	,.CCID_Interface = {
			    .bLength = 0x36,	//CCID
			    .bDescriptorType = 0x21,	//CCID
			    .bcdCCID = 0x0101,	//Version
			    .bMaxSlotIndex = 0,	// one slot
			    .bVoltageSupport = 0x07,	//5V, 3V 1.8V ..
			    .dwProtocols = 0x00000003,	//
			    .dwDefaultClock = 4800,
			    .dwMaximumClock = 4800,
			    .bNumClockSupported = 0,
			    .dwDataRate = 12903,
			    .dwMaxDataRate = 825806,
			    .bNumDataRatesSupported = 53,
			    .dwMaxIFSD = 254,
			    .dwSynchProtocols = 0,
			    .dwMechanical = 0,
			    .dwFeatures = 0x00010230,
			    .dwMaxCCIDMessageLength = 271,
			    .bClassGetResponse = 0,
			    .bClassEnvelope = 0,
			    .wLcdLayout = 0,
			    .bPINSupport = 0,
			    .bMaxCCIDBusySlots = 1}
	,

	.CCID_bulk_out = {
			  .bLength = 7,
			  .bDescriptorType = 5,
			  .bEndpointAddress = 1,
			  .bmAttributes = 2,
			  .wMaxPacketSize = 64,
			  .bInterval = 0,
			  }
	,

	.CCID_bulk_in = {
			 .bLength = 7,
			 .bDescriptorType = 5,
			 .bEndpointAddress = 2 | 0x80,
			 .bmAttributes = 2,
			 .wMaxPacketSize = 64,
			 .bInterval = 0,
			 }
	,

	.CCID_interrupt = {
			   .bLength = 7,
			   .bDescriptorType = 5,
			   .bEndpointAddress = 0x80 | 3,
			   .bmAttributes = 3,
			   .wMaxPacketSize = 8,
			   .bInterval = 16,
			   }
	,
};
/* *INDENT-OFF* */
const struct Descriptor_String_t
     LanguageString = {
	.bLength = 2 + 2 * 1,
	.bDescriptorType = 3,	//String
	.UnicodeString = {0x0409}	// English language
};

const struct Descriptor_String_t
     ManufacturerString = {
	.bLength = 2 + 2 * 7,
	.bDescriptorType = 3,	//String
	.UnicodeString = u"Gemalto"
};

const struct Descriptor_String_t
    ProductSerial = {
	.bLength = 2 + 2 * 8,
	.bDescriptorType = 3,	//String
	.UnicodeString = u"E73C2C85"
};

const struct Descriptor_String_t
    ProductString = {
	.bLength = 2 + 2 * 20,
	.bDescriptorType = 3,	//String
	.UnicodeString = u"USB SmartCard Reader"
};
/* *INDENT-ON* */

#ifdef HW_SERIAL_ID
// external function:
// return max 255 bytes of hardware unique identifier
uint8_t get_HW_serial_id(uint8_t * p, uint8_t max);

static uint32_t crc32(uint32_t crc, uint8_t n)
{
	int j;
	uint32_t mask;

	crc = crc ^ n;
	for (j = 7; j >= 0; j--) {
		mask = -(crc & 1);
		crc = (crc >> 1) ^ (0xEDB88320 & mask);
	}
	return ~crc;
}

static uint8_t charX_from_num(uint8_t n)
{
	n += '0';
	if (n > '9')
		n += 'A' - '9' - 1;
	return n;
}
#endif

static uint8_t USBc_GetDescriptor(struct USB_Request_Header *USB_SetupRequest, uint8_t rec_len)
{
#ifdef HW_SERIAL_ID
	static uint8_t hwserial[18] __attribute__((section(".noinit")));
#endif
	uint8_t type = USB_SetupRequest->wValueH;
	uint8_t index = USB_SetupRequest->wValueL;
	uint16_t r_len = USB_SetupRequest->wLength;
	uint8_t *data = NULL;
	uint16_t len;

	switch (type) {
	case 1:
		// do not test index here, same behavior as on original gemalto reader
		data = (uint8_t *) (&DeviceDescriptor);
		len = sizeof(struct Descriptor_Device_t);
		break;

	case 2:
		// do not test index here, same behavior as on original gemalto reader
		data = (uint8_t *) (&ConfigurationDescriptor);
		len = sizeof(struct USB_Descriptor_Configuration_t);
		break;
	case 3:
		if (index == 0) {
			data = (uint8_t *) (&LanguageString);
			len = LanguageString.bLength;
		} else if (index == 1) {
			data = (uint8_t *) (&ManufacturerString);
			len = ManufacturerString.bLength;
		} else if (index == 2) {
			data = (uint8_t *) (&ProductString);
			len = ProductString.bLength;
		} else if (index == 3) {
#ifdef HW_SERIAL_ID
			uint32_t crc = 0xffffffff;
			uint8_t buffer[32];
			int i;
			memset(buffer, 0, 32);
			len = get_HW_serial_id(buffer, 32);
			len -= 1;
			i = 1;
			while (len--)
				crc = crc32(crc, buffer[i++]);
			memset(hwserial, 0, sizeof(hwserial));
			hwserial[0] = 18;
			hwserial[1] = 3;
			hwserial[2] = charX_from_num(((buffer[0] >> 4) & 15) + (crc & 3));
			crc >>= 2;
			hwserial[4] = charX_from_num(((buffer[0] >> 0) & 15));
			for (i = 6; i < 18; i += 2) {
				hwserial[i] = charX_from_num(crc & 0x1f);
				crc >>= 5;
			}

			data = hwserial;
			len = 18;
#else
			data = (uint8_t *) (&ProductSerial);
#endif
			len = ProductSerial.bLength;
		}
		break;
/*
       case 4: Interface                       Not directly accessible
       case 5: Endpoint                        Not directly accessible
       case 6: Device Qualifier                for high speed capable devices
       case 7: Other Speed Configuration       for high speed capable devices
       case 8: Interface Power                 Obsolete
       case 9: OTG
       case 10: DEBUG

*/
	}

	if (data) {
		if (len > r_len)
			len = r_len;
		return USB_send_data_to_host(0, data, len);
	}
	return RET_STALL;
}

static const uint8_t clock_freq[] = {
	0x67, 0x32, 0x00, 0x00, 0xCE, 0x64, 0x00, 0x00,
	0x9D, 0xC9, 0x00, 0x00, 0x3A, 0x93, 0x01, 0x00,
	0x74, 0x26, 0x03, 0x00, 0xE7, 0x4C, 0x06, 0x00,
	0xCE, 0x99, 0x0C, 0x00, 0xD7, 0x5C, 0x02, 0x00,
	0x11, 0xF0, 0x03, 0x00, 0x34, 0x43, 0x00, 0x00,
	0x69, 0x86, 0x00, 0x00, 0xD1, 0x0C, 0x01, 0x00,
	0xA2, 0x19, 0x02, 0x00, 0x45, 0x33, 0x04, 0x00,
	0x8A, 0x66, 0x08, 0x00, 0x0B, 0xA0, 0x02, 0x00,
	0x73, 0x30, 0x00, 0x00, 0xE6, 0x60, 0x00, 0x00,
	0xCC, 0xC1, 0x00, 0x00, 0x99, 0x83, 0x01, 0x00,
	0x32, 0x07, 0x03, 0x00, 0x63, 0x0E, 0x06, 0x00,
	0xB3, 0x22, 0x01, 0x00, 0x7F, 0xE4, 0x01, 0x00,
	0x06, 0x50, 0x01, 0x00, 0x36, 0x97, 0x00, 0x00,
	0x04, 0xFC, 0x00, 0x00, 0x53, 0x28, 0x00, 0x00,
	0xA5, 0x50, 0x00, 0x00, 0x4A, 0xA1, 0x00, 0x00,
	0x95, 0x42, 0x01, 0x00, 0x29, 0x85, 0x02, 0x00,
	0xF8, 0x78, 0x00, 0x00, 0x3E, 0x49, 0x00, 0x00,
	0x7C, 0x92, 0x00, 0x00, 0xF8, 0x24, 0x01, 0x00,
	0xF0, 0x49, 0x02, 0x00, 0xE0, 0x93, 0x04, 0x00,
	0xC0, 0x27, 0x09, 0x00, 0x74, 0xB7, 0x01, 0x00,
	0x6C, 0xDC, 0x02, 0x00, 0xD4, 0x30, 0x00, 0x00,
	0xA8, 0x61, 0x00, 0x00, 0x50, 0xC3, 0x00, 0x00,
	0xA0, 0x86, 0x01, 0x00, 0x40, 0x0D, 0x03, 0x00,
	0x80, 0x1A, 0x06, 0x00, 0x48, 0xE8, 0x01, 0x00,
	0xBA, 0xDB, 0x00, 0x00, 0x36, 0x6E, 0x01, 0x00,
	0x24, 0xF4, 0x00, 0x00, 0xDD, 0x6D, 0x00, 0x00,
	0x1B, 0xB7, 0x00, 0x00
};

static uint8_t ccid_control_request(struct USB_Request_Header *USB_SetupRequest, uint8_t rec_len)
{
// check wValue, wIndex, a1 03 00 00 00 00 d4 00
	if (USB_SetupRequest->wValue != 0 || USB_SetupRequest->wIndex != 0)
		return RET_STALL;

	if (USB_SetupRequest->bRequest == 2)	// clock freq
	{
		return USB_send_data_to_host(0, NULL, 0);
	} else if (USB_SetupRequest->bRequest == 3)	// data rates
	{
		uint16_t len = sizeof(clock_freq);
		if (USB_SetupRequest->wLength < len) {
			len = USB_SetupRequest->wLength;
			len &= 0xffc0;
		}
		return USB_send_data_to_host(0, (uint8_t *) clock_freq, len);
	} else {
		return RET_STALL;
	}
}

static uint8_t USBc_Feature(struct USB_Request_Header *USB_SetupRequest, uint8_t rec_len)
{
	if (DeviceAddress == 0)
		return RET_STALL;

	if (USB_SetupRequest->wLength)
		return RET_STALL;

	// recipient endpoint:
	if (USB_SetupRequest->wValue == 0) {
		// all EP configured or only control?
		if (DeviceConfigured) {
			if (USB_SetupRequest->wIndex > 3)
				return RET_STALL;
		} else {
			if (USB_SetupRequest->wIndex)
				return RET_STALL;
		}
		if (USB_SetupRequest->bRequest == 1) {
			// control endpoint remains always configured
			USB_Configure_ep(USB_SetupRequest->wIndex & 3);
			// Fall-through
		} else if (USB_SetupRequest->bRequest == 7) {
			// control endpoint is functional even if stalled
			USB_Stall_ep(USB_SetupRequest->wIndex & 3);
			// Fall-through
		} else
			return RET_STALL;
	}
	// recipient device - ignore
	return RET_ZERO_FRAME;
}

static uint8_t USBc_GetStatus(struct USB_Request_Header *USB_SetupRequest, uint8_t rec_len)
{
// static is not needed, USB_send_data_to_host crete a copy (up to endpoint size)
	uint8_t status[2] = { 0, 0 };

	if (DeviceAddress == 0)
		return RET_STALL;

//      wValue, wIndex, wLength
// dev   0        0       2
// int   0       interf   2
// endp  0      endpoint  2
//      uint8_t bmRequestType = USB_SetupRequest->bmRequestType;
//      uint8_t recipient = bmRequestType & 0x1f;

	if (USB_SetupRequest->wLength != 2 || USB_SetupRequest->wValue)
		return RET_STALL;

	switch (USB_SetupRequest->bmRequestType & 3) {
	case 0:		// Device
	case 1:		// Interface
// alloved only 0 (only one interface is used in this project
		if (USB_SetupRequest->wIndex)
			return RET_STALL;
		return USB_send_data_to_host(0, (uint8_t *) (&status), 2);
	case 2:
// this project uses endpoints 0,1,2,3 ..
		if (USB_SetupRequest->wIndex > 3)
			return RET_STALL;

		// bit 0 if halted
		status[0] = USB_Get_Stall_state(USB_SetupRequest->wIndex);
		return USB_send_data_to_host(0, (uint8_t *) (&status), 2);
	default:
		return RET_STALL;
	}
}

static uint8_t USBc_SetConfiguration(struct USB_Request_Header *USB_SetupRequest, uint8_t rec_len)
{
	if (DeviceAddress == 0)
		return RET_STALL;
	if (USB_SetupRequest->wLength || USB_SetupRequest->wIndex)
		return RET_STALL;
	if (USB_SetupRequest->wValue == 0) {
		// deconfigure endpoints..(except control endpoint)
		USB_Deconfigure_CCID_ep();
		DeviceConfigured = 0;
		return RET_ZERO_FRAME;
	} else if (USB_SetupRequest->wValue == 1) {
		DeviceConfigured = 1;
		// configure endpoints.. (control ep is already configured)
		USB_Configure_CCID_ep();
		CCID_notify();
		return RET_ZERO_FRAME;
	} else
		return RET_STALL;

}

static uint8_t USBc_GetConfiguration(struct USB_Request_Header *USB_SetupRequest, uint8_t rec_len)
{
	if (DeviceAddress == 0)
		return RET_STALL;
	if (USB_SetupRequest->wLength != 1 || USB_SetupRequest->wValue || USB_SetupRequest->wIndex)
		return RET_STALL;
	return USB_send_data_to_host(0, &DeviceConfigured, 1);
}

static uint8_t USBc_SetAddress(struct USB_Request_Header *USB_SetupRequest, uint8_t rec_len)
{
// invalid if configuration is selected

	if (DeviceConfigured)
		return RET_STALL;
	if (USB_SetupRequest->wLength || USB_SetupRequest->wIndex || USB_SetupRequest->wValueH)
		return RET_STALL;
	if (USB_SetupRequest->wValueL & 0x80)
		return RET_STALL;
	DeviceAddress = USB_SetupRequest->wValueL | 0x80;
	return RET_ZERO_FRAME;
}

/*
https://www.usbmadesimple.co.uk/ums_4.htm
Standard USB Requests:
			DEVICE			INTERFACE		ENDPOINT
GET_STATUS		(80 00)			(81 00)			(82 00) Partial
GET_CONFIGURATION	(80 08)
GET_DECRIPTOR		(80 06)			not directly accessible	not directly accessible
GET_INTERFACE					(81 0a)
SET_INTERFACE					(01 0b)

CLEAR_FEATURE		(00 01)			(01 01)			(02 01)
SET_FEATURE		(00 03)			(01 03)			(02 03)
SET_ADDRESS		(00 05) OK
SET_DESCRIPTOR		(00 07) OK
SET_CONFIGURATIN	(00 09) OK
SYNC_FRAME								(02 12)

*/

uint8_t USBcommon_ProcessSetupRequest(uint8_t * usb_buffer, uint8_t rec_len)
{
	struct USB_Request_Header *USB_SetupRequest = (struct USB_Request_Header *)usb_buffer;
	uint16_t function = USB_SetupRequest->function;

	uint8_t ret = RET_STALL;

	if (rec_len != 8)
		return ret;
	if (USB_SetupRequest->bmRequestType < 3)
		ret = USBc_Feature((struct USB_Request_Header *)usb_buffer, rec_len);
	if (function == 0x0680)
		ret = USBc_GetDescriptor((struct USB_Request_Header *)usb_buffer, rec_len);
	if (function == 0x0880)
		ret = USBc_GetConfiguration((struct USB_Request_Header *)usb_buffer, rec_len);
	if (function == 0x0900)
		ret = USBc_SetConfiguration((struct USB_Request_Header *)usb_buffer, rec_len);
	if ((function & 0xfffc) == 0x0080)
		ret = USBc_GetStatus((struct USB_Request_Header *)usb_buffer, rec_len);
	if (function == 0x0500)
		ret = USBc_SetAddress((struct USB_Request_Header *)usb_buffer, rec_len);

	// CCID specific
	if (function == 0x03a1)
		ret = ccid_control_request((struct USB_Request_Header *)usb_buffer, rec_len);

// CCID class descriptor ?
// a0 06 00 29 00 00 0d 00
// resp 09 29 02 0a 00 01 00 00 ff
//      if (function == 0x06a0)
//              USB_send_data_to_host(0, 0, 0);
	return ret;
}

uint8_t USBcommon_GetAddress(void)
{
	return DeviceAddress;
}

uint8_t USBcommon_GetConfiguration(void)
{
	return DeviceConfigured;
}

void USBcommon_MarkDeviceAddressed(void)
{
	DeviceAddress &= 0x7f;
}

void USBcommon_Reset()
{
	DeviceAddress = 0;
	DeviceConfigured = 0;
}
