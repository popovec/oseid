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
struct USB_EndpointTable_t USB_EndpointTable __attribute__ ((aligned (2)))
  __attribute__ ((section (".noinit")));

// macros for accessing this variable in usb.h ..  (initialized in USB_Init())
volatile uint8_t var_DeviceState __attribute__ ((section (".noinit")));

// (initialized in USB_Init())
uint8_t var_ConfigurationNumber __attribute__ ((section (".noinit")));
#define V_SetConfigurationNumber(val) var_ConfigurationNumber = val
#define V_GetConfigurationNumber()    var_ConfigurationNumber

struct USB_Setup_Packet USB_Setup_Packet
  __attribute__ ((section (".noinit")));
// buffers
uint8_t control_out[8] __attribute__ ((section (".noinit")));	// buffer for control endpoint (from host)
uint8_t control_in[8] __attribute__ ((section (".noinit")));
uint8_t ccid_interrupt[8] __attribute__ ((section (".noinit")));
uint8_t ccid_in[64] __attribute__ ((section (".noinit")));
uint8_t ccid_out[64] __attribute__ ((section (".noinit")));


typedef struct
{
  uint8_t bmRequestType;
  uint8_t bRequest;
  uint16_t wValue;
  uint16_t wIndex;
  uint16_t wLength;
} __attribute__ ((packed)) USB_Request_Header_t;


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


const struct Descriptor_Device_t PROGMEM DeviceDescriptor = {
  .Size = sizeof (struct Descriptor_Device_t),
  .Type = 1,			//DEVICE
  .USBSpecification = 0x0110,
  .Class = 0x00,		//(Defined at Interface level)  
  .SubClass = 0x00,
  .Protocol = 0x00,
  .Endpoint0Size = 8,
  .VendorID = 0x03EB,
//  .VendorID = 0xF3EB,
  .ProductID = 0x6011,
  .ReleaseNumber = 0x0000,
  .ManufacturerStrIndex = 0x01,
  .ProductStrIndex = 0x02,
  .SerialNumStrIndex = 0,
  .NumberOfConfigurations = 1,
};

const struct USB_Descriptor_Configuration_t PROGMEM ConfigurationDescriptor = {
  .Config = {
	     .bLength = 9,
	     .bDescriptorType = 2,	//configuration
	     .wTotalLength = sizeof (struct USB_Descriptor_Configuration_t),
	     .bNumInterfaces = 1,
	     .bConfigurationValue = 1,
	     .iConfiguration = 0,
	     .bmAttributes = 0x80,	//reserved
	     .bMaxPower = 50,
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
		      .bcdCCID = 0x0100,	//Version
		      .bMaxSlotIndex = 0,	// one slot
		      .bVoltageSupport = 0x07,	//5V, 3V 1.8V ..
		      .dwProtocols = 0x00000003,	//
		      .dwDefaultClock = 4000000,
		      .dwMaximumClock = 4000000,
		      .bNumClockSupported = 0,
		      .dwDataRate = 10752,
		      .dwMaxDataRate = 344064,
		      .bNumDataRatesSupported = 0,
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
		     .bInterval = 10,
		     }
  ,
};

const struct Descriptor_String_t PROGMEM LanguageString = {
  .bLength = 2 + 2 * 1,
  .bDescriptorType = 3,		//String
  .UnicodeString = {0x0409}	// English language
};


const struct Descriptor_String_t PROGMEM ManufacturerString = {
  .bLength = 2 + 2 * 5,
  .bDescriptorType = 3,		//String
  .UnicodeString = L"Atmel"
};

const struct Descriptor_String_t PROGMEM ProductString = {
  .bLength = 2 + 2 * 21,
  .bDescriptorType = 3,		//String
  .UnicodeString = L"USB Smart Card Reader"
};


#define ENDPOINT_EPNUM_MASK                     0x0F

USB_Request_Header_t USB_ControlRequest __attribute__ ((section (".noinit")));

void
ccid_notify (uint8_t data)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

// if previous packet is not send, do nothing
  if (!(usb->Endpoints[3].IN.STATUS & USB_EP_BUSNACK0_bm))
    return;

// inform CCID layer - card state (from argument)
  ccid_interrupt[0] = 0x50;
  ccid_interrupt[1] = data;

// send interrupt paket
  usb->Endpoints[3].IN.CNT = 2;
  usb->Endpoints[3].IN.STATUS &=
    ~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);
}

static void
ReconfigureEndpoints (uint8_t configuration)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  // first disable all endpoints except control endpoint  
  usb->Endpoints[1].OUT.CTRL = 0;
  usb->Endpoints[2].IN.CTRL = 0;
  usb->Endpoints[3].IN.CTRL = 0;

  if (configuration == 0)
    return;

  usb->Endpoints[1].OUT.STATUS = 0;
  usb->Endpoints[1].OUT.CTRL = USB_EP_TYPE_BULK_gc | USB_EP_INTDSBL_bm | 3;	// bulk, 64 bit buffer, no interrupt
  usb->Endpoints[1].OUT.CNT = 0;
  usb->Endpoints[1].OUT.DATAPTR = (intptr_t) ccid_out;

  usb->Endpoints[2].IN.STATUS = USB_EP_BUSNACK0_bm;	// NACK IN request (no data.. )
  usb->Endpoints[2].IN.CTRL = USB_EP_TYPE_BULK_gc | USB_EP_INTDSBL_bm | 3;	// bulk, 64 bit buffer, no interrupt
  usb->Endpoints[2].IN.CNT = 0;
  usb->Endpoints[2].IN.DATAPTR = (intptr_t) ccid_in;

  usb->Endpoints[3].IN.STATUS = USB_EP_BUSNACK0_bm;	// NACK IN request (no data.. )
  usb->Endpoints[3].IN.CTRL = USB_EP_TYPE_BULK_gc | USB_EP_INTDSBL_bm | 3;	// bulk/interrupt, 8 bit buffer, no interrupt
  usb->Endpoints[3].IN.CNT = 0;
  usb->Endpoints[3].IN.DATAPTR = (intptr_t) ccid_interrupt;
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
	  ccid_notify (1);	// card present no change
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
		*here = pgm_read_byte (DataStream++);
	      usb->Endpoints[0].IN.CNT = 8;
	      Length -= 8;
	    }
	  else if (Length)
	    {
	      for (uint8_t i = 0; i < Length; i++, here++)
		*here = pgm_read_byte (DataStream++);
	      usb->Endpoints[0].IN.CNT = Length;
	    }
	  else
	    usb->Endpoints[0].IN.CNT = 0;

	  usb->Endpoints[0].IN.STATUS &=
	    ~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);
	}
    }
  return;
}

static void
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
	  Address = (void *) &LanguageString;
	  Size = pgm_read_byte (&LanguageString.bLength);
	  break;
	case 0x01:
	  Address = (void *) &ManufacturerString;
	  Size = pgm_read_byte (&ManufacturerString.bLength);
	  break;
	case 0x02:
	  Address = (void *) &ProductString;
	  Size = pgm_read_byte (&ProductString.bLength);
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
  if (Size == 0)
    return;
  Endpoint_ClearSETUP ();
  Endpoint_Write_Descriptor (Address, Size);
  Endpoint_ClearStatusStage_in ();
}

static void
USB_Device_SetAddress (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  uint8_t DeviceAddress = (USB_ControlRequest.wValue & 0x7F);

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
    case ENDPOINT_DIR_OUT | 1:	// CCID BULK out
      return &(usb->Endpoints[1].OUT);
    case ENDPOINT_DIR_IN | 2:	// CCID BULK in
      return &(usb->Endpoints[2].IN);
    case ENDPOINT_DIR_IN | 3:	// CCID INTR in
      return &(usb->Endpoints[3].IN);
    }
  return NULL;
}

static void
USB_Device_GetStatus (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;
  USB_EP_t *usb_endpoint;

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

static void
USB_Device_ProcessControlRequest (void)
{
  struct USB_EndpointTable_t *usb = (struct USB_EndpointTable_t *) USB_EPPTR;

  if (!(usb->Endpoints[0].OUT.STATUS & USB_EP_SETUP_bm))
    return;

  memcpy ((void *) &USB_ControlRequest, control_out,
	  sizeof (struct USB_Setup_Packet));

// TODO check if this is specific CCID request .. 

  uint8_t bmRequestType = USB_ControlRequest.bmRequestType;
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
uint8_t CCID_short_response[63] __attribute__ ((section (".noinit")));

volatile uint16_t CCID_message_to_host_count
  __attribute__ ((section (".noinit")));
uint8_t *CCID_message_to_host_position __attribute__ ((section (".noinit")));

uint8_t CCID_message_from_host[271] __attribute__ ((section (".noinit")));
volatile uint16_t CCID_message_from_host_count
  __attribute__ ((section (".noinit")));

volatile uint8_t bulk_in_reserved __attribute__ ((section (".noinit")));
volatile uint16_t send_null __attribute__ ((section (".noinit")));
volatile uint8_t seq __attribute__ ((section (".noinit")));

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
  // wait for BULK IN endpoint if busy 
  while ((usb->Endpoints[2].IN.STATUS & USB_EP_BUSNACK0_bm) == 0);

  // prepare transfer
  memcpy (ccid_in, buffer, length);
  usb->Endpoints[2].IN.CNT = length;

  // send packet       
  usb->Endpoints[2].IN.STATUS &=
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
  if ((usb->Endpoints[2].IN.STATUS & USB_EP_BUSNACK0_bm) == 0)
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
  usb->Endpoints[2].IN.CNT = lcount;

  // last message not 64 bytes ?
  if (lcount < 64)
    {
      // no more data to send
      CCID_message_to_host_position = NULL;
      // clear reservation of BULK IN
      bulk_in_reserved = 0;
    }
  // send packet
  usb->Endpoints[2].IN.STATUS &=
    ~(USB_EP_TRNCOMPL0_bm | USB_EP_BUSNACK0_bm | USB_EP_OVF_bm);
}

uint8_t ccid_timeout;

void
CCID_timeout (uint8_t t_out)
{
  ccid_timeout = t_out;
}

void
CCID_start_null (uint8_t l_seq)
{
  seq = l_seq;
  send_null = 1;
  ccid_timeout = 255;
  TCC0.CNT = 0;
}

// this is called from ISR
ISR (TCC0_OVF_vect)
{
  uint8_t msg[11];

  if (ccid_timeout)
    {
      ccid_timeout--;
      if (ccid_timeout == 0)
	{
	  send_null = 0;
	  CPU_do_restart_main ();
	}
    }

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
  msg[6] = seq;
  msg[7] = 0x80;		//  
  msg[0] = 0x80;		//
  msg[1] = 1;
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

  ATOMIC_BLOCK (ATOMIC_RESTORESTATE)
  {
    while ((usb->Endpoints[2].IN.STATUS & USB_EP_BUSNACK0_bm) == 0)
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
  if (!(usb->Endpoints[1].OUT.STATUS & USB_EP_TRNCOMPL0_bm))
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

  cnt = usb->Endpoints[1].OUT.CNT;

  // check message size, do not write out of buffer!
  if (CCID_message_from_host_count + cnt < 271)
    if (cnt)
      memcpy (CCID_message_from_host + CCID_message_from_host_count,
	      ccid_out, cnt);

  CCID_message_from_host_count += cnt;
  LED1_RUN ();
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
  usb->Endpoints[1].OUT.STATUS &=
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
  ccid_timeout = 0;
}
