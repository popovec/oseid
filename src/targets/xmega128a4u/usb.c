/*
    usb.c

    This is part of OsEID (Open source Electronic ID)

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

    xmega USB subsystem for CCID layer

*/
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <avr/io.h>
#include <util/atomic.h>
#include <avr/pgmspace.h>
#include <util/delay.h>
#include <avr/sleep.h>

#include "ccid.h"
#include "usb.h"
#include "LED.h"
#include "avr_os.h"
#include "serial_debug.h"

// do not use __flashN  and not use pgm_read_byte_far ..
// all USB related data are located in bootloader section
// use this macro to access data:
#define pgm_read_byte_bloader(addr)        \
(__extension__({                    \
    uint16_t __addr16 = (uint16_t)(addr); \
    uint8_t __result;               \
    __asm__ __volatile__            \
    (                               \
        "ldi r30,2\n"			\
        "out %2, r30" "\n\t"        \
        "movw r30, %1" "\n\t"       \
        "elpm %0, Z+" "\n\t"        \
        : "=r" (__result)           \
        : "r" (__addr16),           \
          "I" (_SFR_IO_ADDR(RAMPZ)) \
        : "r30", "r31"	       \
    );                              \
    __result;                       \
}))


#define INTERNAL_ERROR(t) {cli();for(;;){LED1_BUSY();_delay_ms(t);}}


#define CONTROL_REQTYPE_DIRECTION  0x80
//#define CONTROL_REQTYPE_TYPE       0x60
#define CONTROL_REQTYPE_RECIPIENT  0x1F
#define REQDIR_HOSTTODEVICE        (0 << 7)
#define REQDIR_DEVICETOHOST        (1 << 7)
#define REQTYPE_STANDARD           (0 << 5)
//#define REQTYPE_CLASS              (1 << 5)
//#define REQTYPE_VENDOR             (2 << 5)
#define REQREC_DEVICE              (0 << 0)
#define REQREC_INTERFACE           (1 << 0)
#define REQREC_ENDPOINT            (2 << 0)
//#define REQREC_OTHER               (3 << 0)

// define some macros for USB hardware
#define M_Controller_Reset() USB.CTRLA &= ~USB_ENABLE_bm;USB.CTRLA |= USB_ENABLE_bm
#define M_SetSpeedLow() USB.CTRLA &= ~USB_SPEED_bm
#define M_SetSpeedFull() USB.CTRLA |= USB_SPEED_bm
#define M_Attach() USB.CTRLB |= USB_ATTACH_bm
#define M_GetAddress() USB.ADDR
#define M_SetAddress(val) USB.ADDR = val
#define M_DisableIRQ()	USB.INTCTRLA &= USB_INTLVL_gm;USB.INTCTRLB = 0;
#define M_ClearIRQ()    USB.INTFLAGSACLR = 0xFF;USB.INTFLAGSBCLR = 0xFF;

// USB interrupts flags macros
#define F_IRQ_SUSPEND()  (USB.INTFLAGSACLR & USB_SUSPENDIF_bm)
#define F_CLEAR_SUSPEND() (USB.INTFLAGSACLR = USB_SUSPENDIF_bm)
#define F_IRQ_RESUME()  (USB.INTFLAGSACLR & USB_RESUMEIF_bm)
#define F_CLEAR_RESUME() (USB.INTFLAGSACLR = USB_RESUMEIF_bm)
#define F_IRQ_RESET()  (USB.INTFLAGSACLR & USB_RSTIF_bm)
#define F_CLEAR_RESET() (USB.INTFLAGSACLR = USB_RSTIF_bm)
#define F_IRQ_SOFI()  (USB.INTFLAGSACLR & USB_SOFIF_bm)
#define F_CLEAR_SOFI() (USB.INTFLAGSACLR = USB_SOFIF_bm)

#define F_SET_BUSEVENT_IE()   USB.INTCTRLA |= USB_BUSEVIE_bm;
#define F_SET_BUSEVENT_SOF()  USB.INTCTRLA |= USB_SOFIE_bm;


// internal variables and some macros for USB variables read/write/check state (initialized in USB_Init())
struct USB_EndpointTable_t USB_EndpointTable __attribute__((aligned (2)))
  __attribute__((section (".noinit")));

// macros for accessing this variable in usb.h ..  (initialized in USB_Init())
volatile uint8_t var_DeviceState __attribute__((section (".noinit")));

// (initialized in USB_Init())
uint8_t var_ConfigurationNumber __attribute__((section (".noinit")));
#define V_SetConfigurationNumber(val) var_ConfigurationNumber = val
#define V_GetConfigurationNumber()    var_ConfigurationNumber

struct USB_Setup_Packet USB_Setup_Packet __attribute__((section (".noinit")));
// buffers
uint8_t control_out[8] __attribute__((section (".noinit")));	// buffer for control endpoint (from host)
uint8_t control_in[8] __attribute__((section (".noinit")));
uint8_t ccid_interrupt[8] __attribute__((section (".noinit")));
uint8_t ccid_in[64] __attribute__((section (".noinit")));
uint8_t ccid_out[64] __attribute__((section (".noinit")));


typedef struct
{
  uint8_t bmRequestType;
  uint8_t bRequest;
  uint16_t wValue;
  uint16_t wIndex;
  uint16_t wLength;
} __attribute__((packed)) USB_Request_Header_t;


enum USB_Control_Request_t
{
  REQ_GetStatus = 0,
  REQ_ClearFeature = 1,
  REQ_SetFeature = 3,
  REQ_SetAddress = 5,
  REQ_GetDescriptor = 6,
  REQ_SetDescriptor = 7,
  REQ_GetConfiguration = 8,
  REQ_SetConfiguration = 9,
  REQ_GetInterface = 10,
  REQ_SetInterface = 11,
  REQ_SynchFrame = 12,
};

enum USB_Feature_Selectors_t
{
  FEATURE_SEL_EndpointHalt = 0,
  FEATURE_SEL_DeviceRemoteWakeup = 1,
  FEATURE_SEL_TestMode = 2,
};


const struct Descriptor_Device_t
  __attribute__((used, section (".bootloader"))) DeviceDescriptor = {
  .Size = sizeof (struct Descriptor_Device_t),
  .Type = 1,			//DEVICE
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
  __attribute__((used, section (".bootloader"))) ConfigurationDescriptor = {
  .Config = {
	     .bLength = 9,
	     .bDescriptorType = 2,	//configuration
	     .wTotalLength = sizeof (struct USB_Descriptor_Configuration_t),
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
		    .bEndpointAddress = CCID_bulk_out_ADDR,
		    .bmAttributes = 2,
		    .wMaxPacketSize = 64,
		    .bInterval = 0,
		    }
  ,

  .CCID_bulk_in = {
		   .bLength = 7,
		   .bDescriptorType = 5,
		   .bEndpointAddress = CCID_bulk_in_ADDR,
		   .bmAttributes = 2,
		   .wMaxPacketSize = 64,
		   .bInterval = 0,
		   }
  ,

  .CCID_interrupt = {
		     .bLength = 7,
		     .bDescriptorType = 5,
		     .bEndpointAddress = (ENDPOINT_DIR_IN | 3),
		     .bmAttributes = 3,
		     .wMaxPacketSize = 8,
		     .bInterval = 16,
		     }
  ,
};

const struct Descriptor_String_t
  __attribute__((used, section (".bootloader"))) LanguageString = {
  .bLength = 2 + 2 * 1,
  .bDescriptorType = 3,		//String
  .UnicodeString = {0x0409}	// English language
};

const struct Descriptor_String_t
  __attribute__((used, section (".bootloader"))) ManufacturerString = {
  .bLength = 2 + 2 * 7,
  .bDescriptorType = 3,		//String
  .UnicodeString = L"Gemalto"
};

const struct Descriptor_String_t
  __attribute__((used, section (".bootloader"))) ProductSerial = {
  .bLength = 2 + 2 * 8,
  .bDescriptorType = 3,		//String
  .UnicodeString = L"E73C2C84"
};

const struct Descriptor_String_t
  __attribute__((used, section (".bootloader"))) ProductString = {
  .bLength = 2 + 2 * 20,
  .bDescriptorType = 3,		//String
  .UnicodeString = L"USB SmartCard Reader"
};


#define ENDPOINT_EPNUM_MASK                     0x0F

USB_Request_Header_t USB_ControlRequest __attribute__((section (".noinit")));

void
ccid_notify (uint8_t data)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

// if previous packet is not send, do nothing
  if (!(usb->Endpoints[CCID_intr_ID].IN.STATUS & USB_EP_BUSNACK0_bm))
    return;

// inform CCID layer - card state (from argument)
  ccid_interrupt[0] = 0x50;
  ccid_interrupt[1] = data;

  DEBUG_print_string ("notify:");
  DEBUG_dump_block (ccid_interrupt, 2);

// send interrupt paket
  usb->Endpoints[CCID_intr_ID].IN.CNT = 2;
  usb->Endpoints[CCID_intr_ID].IN.STATUS &=
    ~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);
}

static void
ReconfigureEndpoints (uint8_t configuration)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  // first disable all endpoints except control endpoint
  usb->Endpoints[CCID_bulk_out_ID].OUT.CTRL = 0;
  usb->Endpoints[CCID_bulk_in_ID].IN.CTRL = 0;
  usb->Endpoints[CCID_intr_ID].IN.CTRL = 0;

  if (configuration == 0)
    return;

  usb->Endpoints[CCID_bulk_out_ID].OUT.STATUS = 0;
  usb->Endpoints[CCID_bulk_out_ID].OUT.CTRL = USB_EP_TYPE_BULK_gc | USB_EP_INTDSBL_bm | 3;	// bulk, 64 bit buffer, no interrupt
  usb->Endpoints[CCID_bulk_out_ID].OUT.CNT = 0;
  usb->Endpoints[CCID_bulk_out_ID].OUT.DATAPTR = (intptr_t) ccid_out;

  usb->Endpoints[CCID_bulk_in_ID].IN.STATUS = USB_EP_BUSNACK0_bm;	// NACK IN request (no data.. )
  usb->Endpoints[CCID_bulk_in_ID].IN.CTRL = USB_EP_TYPE_BULK_gc | USB_EP_INTDSBL_bm | 3;	// bulk, 64 bit buffer, no interrupt
  usb->Endpoints[CCID_bulk_in_ID].IN.CNT = 0;
  usb->Endpoints[CCID_bulk_in_ID].IN.DATAPTR = (intptr_t) ccid_in;

  usb->Endpoints[CCID_intr_ID].IN.STATUS = USB_EP_BUSNACK0_bm;	// NACK IN request (no data.. )
  usb->Endpoints[CCID_intr_ID].IN.CTRL = USB_EP_TYPE_BULK_gc | USB_EP_INTDSBL_bm | 3;	// bulk/interrupt, 8 bit buffer, no interrupt
  usb->Endpoints[CCID_intr_ID].IN.CNT = 0;
  usb->Endpoints[CCID_intr_ID].IN.DATAPTR = (intptr_t) ccid_interrupt;
}

static void
ConfigureControlEndpoint (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

// disable all endpoints
  for (uint8_t EPNum = 0; EPNum < 4; EPNum++)
    {
      ((struct USB_EndpointTable_t *) USB.EPPTR)->Endpoints[EPNum].IN.CTRL =
	0;
      ((struct USB_EndpointTable_t *) USB.EPPTR)->Endpoints[EPNum].OUT.CTRL =
	0;
    }

  usb->Endpoints[0].IN.STATUS = USB_EP_BUSNACK0_bm;	// NACK IN request (no data.. )
  usb->Endpoints[0].IN.CTRL = USB_EP_INTDSBL_bm | USB_EP_TYPE_CONTROL_gc;
  usb->Endpoints[0].IN.CNT = 0;
  usb->Endpoints[0].IN.DATAPTR = (intptr_t) control_in;

  usb->Endpoints[0].OUT.STATUS = 0;
  usb->Endpoints[0].OUT.CTRL = USB_EP_INTDSBL_bm | USB_EP_TYPE_CONTROL_gc;
  usb->Endpoints[0].OUT.CNT = 0;
  usb->Endpoints[0].OUT.DATAPTR = (intptr_t) control_out;
}


static void USB_init_variables (void);
void
USB_Reinit ()
{
  DEBUG_init ();
  // Start the 32MHz internal RC oscillator and start the DFLL to increase it to 48MHz using the USB SOF as a reference
  OSC.CTRL |= OSC_RC32MEN_bm;
  while (!(OSC.STATUS & OSC_RC32MRDY_bm));

  // change freq to 48MHz PLL reference  from USB SOF
  uint16_t DFLLCompare = (48000000 / 1024);
  // reference for PLL: 0=internal 32kHz, 1=external 32kHz
  // 2 = SOF  3 = reserved
  OSC.DFLLCTRL |= (2 << OSC_RC32MCREF_gp);
  DFLLRC32M.COMP1 = (DFLLCompare & 0xFF);
  DFLLRC32M.COMP2 = (DFLLCompare >> 8);

  // use NVM to read calibration (USB OSCILATOR)
  ATOMIC_BLOCK (ATOMIC_RESTORESTATE)
  {
    NVM.CMD = NVM_CMD_READ_CALIB_ROW_gc;
    DFLLRC32M.CALA =
      pgm_read_byte (offsetof (NVM_PROD_SIGNATURES_t, USBRCOSCA));
    DFLLRC32M.CALB =
      pgm_read_byte (offsetof (NVM_PROD_SIGNATURES_t, USBRCOSC));
    NVM.CMD = NVM_CMD_READ_CALIB_ROW_gc;
  }
  DFLLRC32M.CTRL = DFLL_ENABLE_bm;

  // use NVM to read calibration (USBCAL)
  ATOMIC_BLOCK (ATOMIC_RESTORESTATE)
  {
    NVM.CMD = NVM_CMD_READ_CALIB_ROW_gc;
    USB.CAL0 = pgm_read_byte (offsetof (NVM_PROD_SIGNATURES_t, USBCAL0));
    USB.CAL1 = pgm_read_byte (offsetof (NVM_PROD_SIGNATURES_t, USBCAL1));
    NVM.CMD = NVM_CMD_NO_OPERATION_gc;
  }
}

void
USB_Init (void)
{
  USB_Reinit ();
  CCID_Init ();
  USB.EPPTR = (intptr_t) & USB_EndpointTable;
  // total 4 endpoints (control, ccid in/out/interrupt)
  USB.CTRLA = (USB_STFRNUM_bm | (3 << USB_MAXEP_gp));
  // USB busevent priority high
  USB.INTCTRLA = (3 << USB_INTLVL_gp);

  // no divisor for fullspeed
  CLK.USBCTRL = 0 << CLK_USBPSDIV_gp;
  // usb clock from 32MHz oscilator (tuned by SOF)
  CLK.USBCTRL |= (CLK_USBSRC_RC32M_gc | CLK_USBSEN_bm);
  M_DisableIRQ ();
  M_ClearIRQ ();
  M_Controller_Reset ();

  // device is powered only from bus
  V_SetDeviceState (DEVICE_STATE_Powered);
  V_SetConfigurationNumber (0);
  M_SetSpeedFull ();

  ConfigureControlEndpoint ();
// enable bus event interupts
  F_SET_BUSEVENT_IE ();
// and SOF events (this is now handled by event subsystem and timer)
// F_SET_BUSEVENT_SOF ();
// enable trans.complette and setup interrupt
  USB.INTCTRLB = USB_TRNIE_bm | USB_SETUPIE_bm;

// route SOF to TIMER
  EVSYS.CH0MUX = 0x0a;
// configure timer to generate interrupt from SOF in 0.5 sec interval
  TCC0.CTRLA = 8;		// timer source event 0
  TCC0.CTRLB = 0;		//
  TCC0.PER = 1000;		// count from 0 to 1000
  TCC0.INTCTRLA = 3;		//high priority interrupt on overflow

  USB.ADDR = 0;
  USB_init_variables ();

  M_Attach ();
}

uint16_t
USB_Device_GetFrameNumber (void)
{
  return ((struct USB_EndpointTable_t *) USB.EPPTR)->FrameNum;
}

///////////////////////////////////////////////////////////////////////////////////////////////
static void
Endpoint_ClearSETUP (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  usb->Endpoints[0].OUT.STATUS &=
    ~(USB_EP_SETUP_bm | USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm |
      USB_EP_OVF_bm);

  usb->Endpoints[0].OUT.STATUS |= USB_EP_TOGGLE_bm;
  usb->Endpoints[0].IN.STATUS |= USB_EP_TOGGLE_bm;
}

static void
Endpoint_ClearStatusStage_in (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  while (!(usb->Endpoints[0].OUT.STATUS & USB_EP_TRNCOMPL0_bm))
    {
      if (V_GetDeviceState () == DEVICE_STATE_Powered)
	return;
    }
  usb->Endpoints[0].OUT.STATUS &=
    ~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);
}

static void
Endpoint_ClearStatusStage_out (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  while (!(usb->Endpoints[0].IN.STATUS & USB_EP_BUSNACK0_bm))
    {
      if (V_GetDeviceState () == DEVICE_STATE_Powered)
	return;
    }
  usb->Endpoints[0].IN.CNT = 0;
  usb->Endpoints[0].IN.STATUS &=
    ~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);
}

ISR (USB_BUSEVENT_vect)
{
  if (F_IRQ_SOFI ())
    {
      // this is now handled by timer ..
      //isr_CCID_NULL ();
      F_CLEAR_SOFI ();
    }
  if (F_IRQ_SUSPEND ())
    {
      F_CLEAR_SUSPEND ();
      // suspend only if device is already addressed
      if (V_GetDeviceState () == DEVICE_STATE_Powered)
	return;
      LED2_SUSPEND ();
      LED1_OFF ();
      V_SetDeviceState (DEVICE_STATE_Suspended);
      // CPU sleep is sheduled after high level USB interrupt is at end
      CPU_do_sleep ();
      return;
    }

  if (F_IRQ_RESUME ())
    {
      LED2_RUN ();
      LED1_IDLE ();
      F_CLEAR_RESUME ();
      if (V_GetConfigurationNumber ())
	{
	  V_SetDeviceState (DEVICE_STATE_Configured);
	  ccid_notify (3);	// card present no change
	}
      else
	{
	  if (M_GetAddress ())
	    V_SetDeviceState (DEVICE_STATE_Addressed);
	  else
	    V_SetDeviceState (DEVICE_STATE_Powered);
	}
    }

  if (F_IRQ_RESET ())
    {
      F_CLEAR_RESET ();
      V_SetDeviceState (DEVICE_STATE_Default);
      V_SetConfigurationNumber (0);
      M_SetAddress (0);

      ConfigureControlEndpoint ();
    }
}

static void Endpoint_Write_Descriptor
  (const void *const Buffer, uint16_t Length)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  uint8_t *DataStream = ((uint8_t *) Buffer);

  if (Length > USB_ControlRequest.wLength)
    Length = USB_ControlRequest.wLength;

  if (!(Length))
    {
      usb->Endpoints[0].IN.CNT = 0;
      usb->Endpoints[0].IN.STATUS &=
	~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);
    }

  DEBUG_print_string ("control to host:");

  for (;;)
    {
      uint8_t USB_DeviceState_LCL = V_GetDeviceState ();
      if (USB_DeviceState_LCL == DEVICE_STATE_Suspended)
	return;
      else if (usb->Endpoints[0].OUT.STATUS & USB_EP_SETUP_bm)
	return;
      else if (usb->Endpoints[0].OUT.STATUS & USB_EP_TRNCOMPL0_bm)
	break;


      if (usb->Endpoints[0].IN.STATUS & USB_EP_BUSNACK0_bm)
	{
	  uint8_t *here = control_in;
	  if (Length > 8)
	    {
	      for (uint8_t i = 0; i < 8; i++, here++)
		*here = pgm_read_byte_bloader (DataStream++);
	      usb->Endpoints[0].IN.CNT = 8;
	      DEBUG_dump_block (control_in, 8);
	      Length -= 8;
	    }
	  else if (Length)
	    {
	      for (uint8_t i = 0; i < Length; i++, here++)
		*here = pgm_read_byte_bloader (DataStream++);
	      usb->Endpoints[0].IN.CNT = Length;
	      DEBUG_dump_block (control_in, Length);
	      Length = 0;
	    }
	  else
	    usb->Endpoints[0].IN.CNT = 0;

	  usb->Endpoints[0].IN.STATUS &=
	    ~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);
	}
    }
  return;
}

void
USB_Device_GetDescriptor (void)
{
  const uint8_t DescriptorType = (USB_ControlRequest.wValue >> 8);
  const uint8_t DescriptorNumber = (USB_ControlRequest.wValue & 0xFF);
  void *Address = NULL;
  uint16_t Size = 0;

  switch (DescriptorType)

    {
    case 1:			// DEVICE
      Address = (void *) &DeviceDescriptor;
      Size = sizeof (struct Descriptor_Device_t);
      break;
    case 2:			//configuration
      Address = (void *) &ConfigurationDescriptor;
      Size = sizeof (struct USB_Descriptor_Configuration_t);
      break;
    case 3:			// string
      switch (DescriptorNumber)

	{
	case 0x00:
	  DEBUG_print_string ("Language string\n");
	  Address = (void *) &LanguageString;
	  Size = pgm_read_byte_bloader (&LanguageString.bLength);
	  break;
	case 0x01:
	  DEBUG_print_string ("Manufacturer string\n");
	  Address = (void *) &ManufacturerString;
	  Size = pgm_read_byte_bloader (&ManufacturerString.bLength);
	  break;
	case 0x02:
	  DEBUG_print_string ("Product string\n");
	  Address = (void *) &ProductString;
	  Size = pgm_read_byte_bloader (&ProductString.bLength);
	  break;
	case 0x03:
	  DEBUG_print_string ("Serial string\n");
	  Address = (void *) &ProductSerial;
	  Size = pgm_read_byte_bloader (&ProductSerial.bLength);
	  break;
	}
      break;
    case 4:			//Interface
      Address = (void *) &ConfigurationDescriptor.Interface;
      Size = 9;
      break;
// CCID descriptor, seems to host newer read this directly
//  why sizeof (struct Descriptor_Endpoint_t) ?
// and not sizeof (struct ConfigurationDescriptor.CCID_Interface) ??
/*
    case 0x21:
      Address = (void *) &ConfigurationDescriptor.CCID_Interface;
      Size = sizeof (struct Descriptor_Endpoint_t);
      break;
*/
    case 5:			// endpoint

      switch (DescriptorNumber)
	{
	case 0:
	  Address = (void *) &ConfigurationDescriptor.CCID_bulk_in;
	  Size = sizeof (struct Descriptor_Endpoint_t);
	  break;
	case 1:
	  Address = (void *) &ConfigurationDescriptor.CCID_bulk_out;
	  Size = sizeof (struct Descriptor_Endpoint_t);
	  break;
	case 2:
	  Address = (void *) &ConfigurationDescriptor.CCID_interrupt;
	  Size = sizeof (struct Descriptor_Endpoint_t);
	  break;
	}
    }
  Endpoint_ClearSETUP ();
  Endpoint_Write_Descriptor (Address, Size);
  Endpoint_ClearStatusStage_in ();
}

static void
USB_Device_SetAddress (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  uint8_t DeviceAddress = (USB_ControlRequest.wValue & 0x7F);

  DEBUG_print_string ("USB_Device_SetAddress\n");

  Endpoint_ClearSETUP ();
  Endpoint_ClearStatusStage_out ();

  while (!(usb->Endpoints[0].IN.STATUS & USB_EP_BUSNACK0_bm));

  M_SetAddress (DeviceAddress);
  if (DeviceAddress)
    V_SetDeviceState (DEVICE_STATE_Addressed);
  else
    V_SetDeviceState (DEVICE_STATE_Default);
}

static void
USB_Device_SetConfiguration (void)
{
  if ((uint8_t) USB_ControlRequest.wValue > 1)
    return;

  Endpoint_ClearSETUP ();

  DEBUG_print_string ("USB_Device_SetConfiguration\n");

  V_SetConfigurationNumber ((uint8_t) USB_ControlRequest.wValue);

  Endpoint_ClearStatusStage_out ();

  if (V_GetConfigurationNumber ())
    {
      V_SetDeviceState (DEVICE_STATE_Configured);
      ReconfigureEndpoints (1);	// 1st configuration
      ccid_notify (3);		// card present, change
    }
  else
    {
      if (M_GetAddress ())
	V_SetDeviceState (DEVICE_STATE_Addressed);
      else
	V_SetDeviceState (DEVICE_STATE_Powered);
    }
}

static void
USB_Device_GetConfiguration (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  Endpoint_ClearSETUP ();
  DEBUG_print_string ("USB_Device_GetConfiguration\n");

  control_in[0] = V_GetConfigurationNumber ();
  usb->Endpoints[0].IN.CNT = 1;
  usb->Endpoints[0].IN.STATUS &=
    ~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);
  Endpoint_ClearStatusStage_in ();
}

static USB_EP_t *
USB_Endpoint_ptr ()
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  uint8_t address =
    USB_ControlRequest.wIndex & (ENDPOINT_DIR_OUT | ENDPOINT_DIR_IN |
				 ENDPOINT_EPNUM_MASK);

  switch (address)
    {
    case ENDPOINT_DIR_OUT | 0:	// CONTROL out
      return &(usb->Endpoints[0].OUT);
    case ENDPOINT_DIR_IN | 0:	// CONTROL in
      return &(usb->Endpoints[0].IN);
    case ENDPOINT_DIR_OUT | CCID_bulk_out_ID:
      return &(usb->Endpoints[CCID_bulk_out_ID].OUT);
    case ENDPOINT_DIR_IN | CCID_bulk_in_ID:
      return &(usb->Endpoints[CCID_bulk_in_ID].IN);
    case ENDPOINT_DIR_IN | CCID_intr_ID:
      return &(usb->Endpoints[CCID_intr_ID].IN);
    }
  return NULL;
}

static void
USB_Device_GetStatus (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;
  USB_EP_t *usb_endpoint;

  DEBUG_print_string ("USB_Device_GetStatus\n");

  uint8_t CurrentStatus = 0;
  switch (USB_ControlRequest.bmRequestType)
    {
    case (REQDIR_DEVICETOHOST | REQTYPE_STANDARD | REQREC_DEVICE):
      break;
    case (REQDIR_DEVICETOHOST | REQTYPE_STANDARD | REQREC_ENDPOINT):
// What to do if not configured endpoint status is requested ?
      usb_endpoint = USB_Endpoint_ptr ();
      if (usb_endpoint)
	{
	  CurrentStatus = usb_endpoint->CTRL & USB_EP_STALL_bm ? true : false;
	  break;
	}
    default:
      return;
    }

  Endpoint_ClearSETUP ();

  control_in[0] = CurrentStatus & 0xff;
  control_in[1] = CurrentStatus >> 8;

  usb->Endpoints[0].IN.CNT = 2;
  usb->Endpoints[0].IN.STATUS &=
    ~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);
  Endpoint_ClearStatusStage_in ();
}

static void
USB_Device_ClearSetFeature (void)
{
  USB_EP_t *usb_endpoint;

  DEBUG_print_string ("USB_Device_ClearSetFeature\n");

  switch (USB_ControlRequest.bmRequestType & CONTROL_REQTYPE_RECIPIENT)
    {
    case REQREC_ENDPOINT:
      if ((uint8_t) USB_ControlRequest.wValue == FEATURE_SEL_EndpointHalt)
	{
	  usb_endpoint = USB_Endpoint_ptr ();
	  if (!usb_endpoint)
	    return;

	  if (USB_ControlRequest.bRequest != REQ_SetFeature)
	    {
	      usb_endpoint->CTRL &= ~USB_EP_STALL_bm;
	      usb_endpoint->STATUS &= ~USB_EP_TOGGLE_bm;
	    }
	  else
	    usb_endpoint->CTRL |= USB_EP_STALL_bm;
	}
      break;
    default:
      return;
    }
  Endpoint_ClearSETUP ();
  Endpoint_ClearStatusStage_out ();
}

const uint8_t __attribute__((used, section (".bootloader"))) clock_freq[] = {
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

static void
ccid_control_request ()
{
  DEBUG_print_string ("ccid control ");
  if (USB_ControlRequest.bRequest == 2)	// clock freq
    {
      DEBUG_print_string ("clock\n");
      Endpoint_ClearSETUP ();
      Endpoint_Write_Descriptor (clock_freq, 53 * 4);
      Endpoint_ClearStatusStage_in ();
    }
  else if (USB_ControlRequest.bRequest == 3)	// data rates
    {
      DEBUG_print_string ("rates\n");
      Endpoint_ClearSETUP ();
      Endpoint_Write_Descriptor (NULL, 0);
      Endpoint_ClearStatusStage_in ();
    }
}

static void
USB_Device_ProcessControlRequest (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  if (!(usb->Endpoints[0].OUT.STATUS & USB_EP_SETUP_bm))
    return;

  DEBUG_print_string ("control from host:");
  DEBUG_dump_block (control_out, sizeof (struct USB_Setup_Packet));

  memcpy ((void *) &USB_ControlRequest, control_out,
	  sizeof (struct USB_Setup_Packet));


  uint8_t bmRequestType = USB_ControlRequest.bmRequestType;

  DEBUG_print_string ("bmRequestType = ");
  DEBUG_dump_block (&bmRequestType, 1);
// specific ccid request (GET_CLOCK_FREQUENCIES, GET_DATA_RATES)
  if (bmRequestType == 0xa1)
    ccid_control_request ();


  switch (USB_ControlRequest.bRequest)
    {
    case REQ_GetStatus:
      if ((bmRequestType ==
	   (REQDIR_DEVICETOHOST | REQTYPE_STANDARD | REQREC_DEVICE))
	  || (bmRequestType ==
	      (REQDIR_DEVICETOHOST | REQTYPE_STANDARD | REQREC_ENDPOINT)))
	{
	  USB_Device_GetStatus ();
	}

      break;
    case REQ_ClearFeature:
    case REQ_SetFeature:
      if ((bmRequestType ==
	   (REQDIR_HOSTTODEVICE | REQTYPE_STANDARD | REQREC_DEVICE))
	  || (bmRequestType ==
	      (REQDIR_HOSTTODEVICE | REQTYPE_STANDARD | REQREC_ENDPOINT)))
	{
	  USB_Device_ClearSetFeature ();
	}

      break;
    case REQ_SetAddress:
      if (bmRequestType ==
	  (REQDIR_HOSTTODEVICE | REQTYPE_STANDARD | REQREC_DEVICE))
	USB_Device_SetAddress ();
      break;
    case REQ_GetDescriptor:
      if ((bmRequestType ==
	   (REQDIR_DEVICETOHOST | REQTYPE_STANDARD | REQREC_DEVICE))
	  || (bmRequestType ==
	      (REQDIR_DEVICETOHOST | REQTYPE_STANDARD | REQREC_INTERFACE)))
	{
	  USB_Device_GetDescriptor ();
	}

      break;
    case REQ_GetConfiguration:
      if (bmRequestType ==
	  (REQDIR_DEVICETOHOST | REQTYPE_STANDARD | REQREC_DEVICE))
	USB_Device_GetConfiguration ();
      break;
    case REQ_SetConfiguration:
      if (bmRequestType ==
	  (REQDIR_HOSTTODEVICE | REQTYPE_STANDARD | REQREC_DEVICE))
	USB_Device_SetConfiguration ();
      break;
    default:
      break;
    }

  if (usb->Endpoints[0].OUT.STATUS & USB_EP_SETUP_bm)
    {
      Endpoint_ClearSETUP ();
      // stall control IN/OUT
      usb->Endpoints[0].IN.STATUS |= USB_EP_STALL_bm;
      usb->Endpoints[0].OUT.STATUS |= USB_EP_STALL_bm;
    }
}

/***********************************************************

         CCID  BULK IN/BULK OUT support function

***********************************************************/
// this is used by CCID layer for responses
uint8_t CCID_short_response[63] __attribute__((section (".noinit")));

volatile uint16_t CCID_message_to_host_count
  __attribute__((section (".noinit")));
uint8_t *CCID_message_to_host_position __attribute__((section (".noinit")));

uint8_t CCID_message_from_host[271] __attribute__((section (".noinit")));
volatile uint16_t CCID_message_from_host_count
  __attribute__((section (".noinit")));

volatile uint8_t bulk_in_reserved __attribute__((section (".noinit")));
volatile uint16_t send_null __attribute__((section (".noinit")));
volatile uint8_t seq __attribute__((section (".noinit")));

////////////////////////////////////////////
// CCID BULK IN endpoint
////////////////////////////////////////////

// send short (<63 bytes) response to host
// this can be called only from ISR
void
isr_CCID_short_response_to_host (uint8_t * buffer, uint8_t length)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  // safety check, if oversized, return only CCID header
  if (length > 63)
    length = 10;
  // safety check, if BULK IN is reseved, this is internal error
  // short message can be generated only from two ISR:
  // - transaction complette
  // - timer ISR for generating time extension (null byte)
  // both ISRs must check if BULK IN endpoint is already reserved

  if (bulk_in_reserved)
    {
      INTERNAL_ERROR (200);
      return;
    }

  DEBUG_print_string ("short response:");
  DEBUG_dump_block (buffer, length);

  // wait for BULK IN endpoint if busy
  while ((usb->Endpoints[CCID_bulk_in_ID].IN.STATUS & USB_EP_BUSNACK0_bm) ==
	 0);

  // prepare transfer
  memcpy (ccid_in, buffer, length);
  usb->Endpoints[CCID_bulk_in_ID].IN.CNT = length;

  // send packet
  usb->Endpoints[CCID_bulk_in_ID].IN.STATUS &=
    ~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);

}

// this is used in ISR normaly but 1st part of message is
// send by this procedure from non ISR context
void
isr_CCID_message_to_host (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;
  uint16_t lcount;

  // is USB endpoint free ?
  if ((usb->Endpoints[CCID_bulk_in_ID].IN.STATUS & USB_EP_BUSNACK0_bm) == 0)
    return;

  // have some data to send ?
  if (!CCID_message_to_host_position)
    return;

  lcount = CCID_message_to_host_count;

  if (lcount > 64)
    lcount = 64;

  if (lcount)
    memcpy (ccid_in, CCID_message_to_host_position, lcount);

  CCID_message_to_host_position += lcount;
  CCID_message_to_host_count -= lcount;
  usb->Endpoints[CCID_bulk_in_ID].IN.CNT = lcount;

  // last message not 64 bytes ?
  if (lcount < 64)
    {
      // no more data to send
      CCID_message_to_host_position = NULL;
      // clear reservation of BULK IN
      bulk_in_reserved = 0;
    }
  // send packet
  usb->Endpoints[CCID_bulk_in_ID].IN.STATUS &=
    ~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);
}

void
CCID_start_null (uint8_t l_seq)
{
  seq = l_seq;
  send_null = 1;
  TCC0.CNT = 0;
}

// this is called from ISR
ISR (TCC0_OVF_vect)
{
  uint8_t msg[11];

  // is null sending mode active?
  if (!send_null)
    return;
  // is bulk in reserved?
  if (bulk_in_reserved)
    {
      // bulk in is reserved, turn off sending null
      // (response from card is already transmited to host)
      send_null = 0;
      return;
    }
  memset (msg, 0, 11);
  msg[0] = 0x80;		//
  msg[1] = 1;
  msg[6] = seq;
  msg[7] = 0x80;		//
  msg[8] = 1;			// multiplier for BWT/WWT
  LED1_BUSY ();
  isr_CCID_short_response_to_host (msg, 10);
}

// send long message to host (with reservation of BULK IN endpoint)
// this call block until BULK IN is busy!
void
CCID_response_to_host (uint8_t * buffer, uint16_t length)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  // safety check, if bulk in is reseved, this is internal error if yes
  // long message can be generated only for PC_to_RDR_XfrBlock message
  // and there is no way to run two instances of PC_to_RDR_XfrBlock
  // services

  if (bulk_in_reserved)
    {
      INTERNAL_ERROR (1000);
      return;
    }

  DEBUG_print_string ("to host:");
  DEBUG_dump_block (buffer, length);

  ATOMIC_BLOCK (ATOMIC_RESTORESTATE)
  {
    while ((usb->Endpoints[CCID_bulk_in_ID].IN.STATUS & USB_EP_BUSNACK0_bm) ==
	   0)
      {
	// unblock interrupts if endpoint is not free
	NONATOMIC_BLOCK (NONATOMIC_FORCEOFF);
      }
    bulk_in_reserved = 1;
    send_null = 0;
    CCID_message_to_host_count = length;
    CCID_message_to_host_position = buffer;
    isr_CCID_message_to_host ();
  }

}

////////////////////////////////////////////
// CCID BULK OUT endpoint
////////////////////////////////////////////
void
isr_CCID_message_from_host (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;
  uint16_t cnt;
  int8_t ret;

  // data from host ?
  if (!(usb->Endpoints[CCID_bulk_out_ID].OUT.STATUS & USB_EP_TRNCOMPL0_bm))
    return;

  // If CCID layer need to send > 63 bytes message to host
  // CCID layer must "reserve" BULK IN endpoint. If BULK IN is reserved,
  // any processing of BULK OUT messages must wait. One exception ist
  // CCID "ABORT" message, but this is handled in CONTROL endpoint
  // service routine. If BULK IN transmit end with transaction complette,
  // this isr (isr_CCID_message_from_host) is re-called.
  //

  if (bulk_in_reserved)
    return;

  cnt = usb->Endpoints[CCID_bulk_out_ID].OUT.CNT;

  // check message size, do not write out of buffer!
  if (CCID_message_from_host_count + cnt < 271)
    if (cnt)
      memcpy (CCID_message_from_host + CCID_message_from_host_count,
	      ccid_out, cnt);

  CCID_message_from_host_count += cnt;
  LED1_RUN ();

  DEBUG_print_string ("from host:");
  DEBUG_dump_block (CCID_message_from_host, CCID_message_from_host_count);

  ret =
    parse_command (CCID_message_from_host, CCID_message_from_host_count,
		   CCID_short_response);
  if (ret != -1)
    {
      // CCID BULK OUT is complette,
      if (ret)
	{
	  LED1_IDLE ();

	  // send response back
	  if (ret < 64)
	    isr_CCID_short_response_to_host (CCID_short_response, ret);
	  else
	    {
	      // this is internal error, CCID parser return size must be below 64
	      INTERNAL_ERROR (800);
	    }
	}
      CCID_message_from_host_count = 0;
    }
  // confirm BULK IN transfer, read new message part
  usb->Endpoints[CCID_bulk_out_ID].OUT.STATUS &=
    ~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);
}

ISR (USB_TRNCOMPL_vect)
{
  if (V_GetDeviceState () != DEVICE_STATE_Powered)
    USB_Device_ProcessControlRequest ();
  if (V_GetDeviceState () == DEVICE_STATE_Configured)
    {
      isr_CCID_message_from_host ();
      isr_CCID_message_to_host ();
    }


  USB.FIFORP = 0;		// any value to FIFORP/WP to clear TCIF
  USB.INTFLAGSBCLR = 0xff;	// clear interrupts
}

static void
USB_init_variables (void)
{
  CCID_message_from_host_count = 0;
  CCID_message_to_host_count = 0;
  CCID_message_to_host_position = 0;
  bulk_in_reserved = 0;
  send_null = 0;
}
