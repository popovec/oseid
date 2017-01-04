#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>

#include "card_io.h"
#include "ccid.h"
#include "usb.h"
#include "LED.h"
#include "avr_os.h"

#define C_RDR_to_PC_DataBlock  0x80
#define C_RDR_to_PC_SlotStatus 0x81
#define C_RDR_to_PC_Parameters 0x82
#define C_RDR_to_PC_Escape     0x83
#define C_RDR_to_PC_DataRateAndClockFrequency 0x84

/////////////////////////////////////////////////////////////////
// TPDU T0  handling code
//
/////////////////////////////////////////////////////////////////

uint8_t SlotError __attribute__ ((section (".noinit")));

//slot status:
union Slot_Status_Register
{
  struct
  {
    uint8_t bmICCStatus:2;
    uint8_t RFU:4;
    uint8_t bmCommandStatus:2;
  };
  uint8_t SlotStatus;
} Status __attribute__ ((section (".noinit")));

uint8_t ATR[33] __attribute__ ((section (".noinit")));
uint8_t ATRlen __attribute__ ((section (".noinit")));;

enum TPDU_states
{
  T_IDLE,
  T_WAIT_RESPONSE,
  T_WAIT_PROCEDURE_BYTE,
  T_WAIT_STATUS,
};

volatile uint8_t TPDU_state __attribute__ ((section (".noinit")));

uint8_t card_ins __attribute__ ((section (".noinit")));

// card IO buffers/variables
// 0  no data for card, or data len
volatile uint8_t card_rx_len __attribute__ ((section (".noinit")));
uint8_t CCID_card_buffer[271] __attribute__ ((section (".noinit")));
uint8_t *card_rx_buffer __attribute__ ((section (".noinit")));
// response from card (256 bytes of response + status 2 bytes)
uint8_t card_response[271] __attribute__ ((section (".noinit")));
uint16_t card_response_len __attribute__ ((section (".noinit")));

// NOT called from ISR
uint8_t
card_io_rx (uint8_t * data, uint8_t len)
{
  uint8_t l_len;
  // wait for data from CCID layer
  while (!card_rx_len);
  // copy data to card ..
  memcpy (data, card_rx_buffer, card_rx_len);

  l_len = card_rx_len;
  card_rx_len = 0;
  return l_len;
}


// NOT called from ISR
uint8_t
card_io_tx (uint8_t * data, uint8_t len)
{
  uint8_t p_byte;

  p_byte = data[0];

  switch (TPDU_state)
    {
    case T_IDLE:
      // no data is expected from card .. drop data    
      return 0;
    case T_WAIT_RESPONSE:
      {
	// only copy data from card, then wait for status, 
	// send this to host in one message
	// send response to host
	memcpy (card_response + card_response_len, data, len);
	card_response_len += len;

	TPDU_state = T_WAIT_STATUS;
	return 0;
      }

    case T_WAIT_PROCEDURE_BYTE:
      if (p_byte == 0xc0)	// data from card (no other check for OsEID)
	{
	  TPDU_state = T_WAIT_RESPONSE;
	  return 0;
	}
      if (p_byte == card_ins)	// for OsEID no need to handle ~ins, ins+1, ~(ins+1), 0x60
	{
	  // rest of APDU to card (only if data len >0)
	  if (CCID_card_buffer[14])
	    {
	      card_rx_buffer = CCID_card_buffer + 15;
	      card_rx_len = CCID_card_buffer[14];
	      TPDU_state = T_WAIT_STATUS;
	      return 0;
	    }
	  // protocol error ? or return 1 byte status ?   
	  // No data for this APDU, return one byte response 
	  // back to host (fall through to T_WAIT_STATUS:)
	  card_response[card_response_len] = card_ins;
	  card_response_len++;
	}
      p_byte &= 0xf0;
      // len 1 for 0x90  is ok ? 
      if (p_byte != 0x60 && p_byte != 0x90 && len > 2)
	{
	  // protocol error
	  card_response[1] = 0;
	  card_response[2] = 0;
	  card_response[7] = Status.SlotStatus = 1;
	  card_response[8] = SlotError = 0xf4;
	  CCID_response_to_host (card_response, card_response_len);
	  TPDU_state = T_IDLE;
	  return 0;
	}
      // fall through, send
    case T_WAIT_STATUS:
      // send response to host
      // TODO check length .. 
      memcpy (card_response + card_response_len, data, len);
      card_response_len += len;
      card_response[1] = (card_response_len - 10) & 0xff;
      card_response[2] = (card_response_len - 10) >> 8;
      CCID_response_to_host (card_response, card_response_len);
      TPDU_state = T_IDLE;
      return 0;
    }
  return 0;
}

void
card_io_start_null ()
{
  CCID_start_null (card_response[6]);	//seq number
  return;
}

void
card_io_stop_null ()
{
  return;
}

///////////////////////////////////////////////////////////////////////////////////
//            CCID part
//
// this is called from CCID layer (in ISR) for PC_to_RDR_XfrBlock in ISR
// 0 - all ok, data deliviering to card
// 1 - error
static int8_t
run_card (uint8_t * ccid_command)
{
  // create copy
  memcpy (CCID_card_buffer, ccid_command, 271);
  if (ccid_command[2] == 0)
    {
      // if command is below 4 bytes return error
      if (ccid_command[1] < 4)
	{
	  Status.bmCommandStatus = 1;	// error
	  SlotError = 1;	// wrong len
	  return 1;
	}
      // normal command, no data
      if (ccid_command[1] < 5)
	{
	  // append LC
	  ccid_command[1] = 5;
	  ccid_command[14] = 0;
	}
    }
  card_ins = ccid_command[11];
// check if command is correct
  Status.bmCommandStatus = 1;
  SlotError = 11;		// wrong command
/*
Allow reader to send odd command as defined in ISO
card is responsible to handle errors or disable odd commands (T0 proto)
*/
#if 0
  if (card_ins & 1)
    return 1;
#endif
  if ((card_ins & 0xf0) == 0x60)
    return 1;
  if ((card_ins & 0xf0) == 0x90)
    return 1;

// send command to card (card software wait for card_rx_len in busy loop)

  card_rx_buffer = CCID_card_buffer + 10;
  card_rx_len = 5;
  TPDU_state = T_WAIT_PROCEDURE_BYTE;
// CCID header is already prepared, set only status/error
  Status.bmCommandStatus = 0;	// command ok
  Status.bmICCStatus = 0;	//ICC present, active
  Status.SlotStatus = 0;	// no error

  card_response[7] = 0;		//Status.SlotStatus
  card_response[8] = SlotError;

  // offset for response
  card_response_len = 10;
  return 0;

// TODO: if card  main() get locked (by sw error etc), here timer must be
// started and main must be restarted by CPU_do_restart_main() (timeout
// message from ccid layer must be sended too)

}

//////////////////////////////////////////////////////////////////////////

// parse command
#define PC_to_RDR_IccPowerOn 0x62
#define PC_to_RDR_IccPowerOff 0x63
#define PC_to_RDR_GetSlotStatus 0x65
#define PC_to_RDR_XfrBlock 0x6f
#define PC_to_RDR_GetParameters 0x6c
#define PC_to_RDR_ResetParameters 0x6d
#define PC_to_RDR_SetParameters  0x61
#define PC_to_RDR_Escape  0x6b
#define PC_to_RDR_IccClock 0x6e
#define PC_to_RDR_T0APDU  0x6a
#define PC_to_RDR_Secure  0x69
#define PC_to_RDR_Mechanical 0x71
#define PC_to_RDR_Abort 0x72
#define PC_to_RDR_SetDataRateAndClockFrequency 0x73


static int8_t
RDR_to_PC_DataBlock_wrong_slot (uint8_t * l_response)
{
  l_response[7] = 0x42;		// No ICC present, command failed error in error reg
  l_response[8] = 5;		// slot does not exist;
  return 10;			// CCID header length
}


static int8_t
RDR_to_PC_DataBlock_busy_slot (uint8_t * response)
{
  Status.bmCommandStatus = 1;
  response[7] = Status.SlotStatus;
  response[8] = 0xe0;		// slot busy;
  return 10;			// CCID header length
}

//static void RDR_to_PC_DataBlock_busy_slot(uint8_t *l_responsel) __attribute__((alias ("RDR_to_PC_SlotStatus_busy_slot")));
static int8_t RDR_to_PC_SlotStatus_busy_slot (uint8_t * l_responsel)
  __attribute__ ((alias ("RDR_to_PC_DataBlock_busy_slot")));

static int8_t
func_PC_to_RDR_IccPowerOn (uint8_t * command, uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);

  CPU_do_restart_main ();
// ATR is always available
#ifdef Infineon
#warning TODO emulation of Infineon fail, Infineon need T1 protocol
#define C_ATR_LEN 15
  ATR[0] = 0x3b;
  ATR[1] = 0xf5;
  ATR[2] = 0x96;
  ATR[3] = 0x00;
  ATR[4] = 0x00;
  ATR[5] = 0x80;
  ATR[6] = 0x31;
  ATR[7] = 0xfe;
  ATR[8] = 0x45;
  ATR[9] = 0x4d;		//M
  ATR[10] = 0x79;		//y
  ATR[11] = 0x45;		//E
  ATR[12] = 0x49;		//I
  ATR[13] = 0x44;		//D
  ATR[14] = 0x15;
#else
// normal OsEID ATR
// 3b:f7:18:00:02:10:80:4f:73:45:49:44
#define C_ATR_LEN  12
#define C_ATR_HIST 5
  ATR[0] = 0x3b;
  ATR[1] = 0xf0 | C_ATR_HIST;
  ATR[2] = 0x18;
  ATR[3] = 0x00;
  ATR[4] = 0x02;
  ATR[5] = 0x10;
  ATR[6] = 0x80;

  ATR[7] = 0x4f;		//O
  ATR[8] = 0x73;		//s
  ATR[9] = 0x45;		//E
  ATR[10] = 0x49;		//I
  ATR[11] = 0x44;		//D
#endif
  ATRlen = C_ATR_LEN;
  //copy ATR to respone  
  memcpy (response + 10, ATR, ATRlen);

  Status.bmCommandStatus = 0;	// command ok
  Status.bmICCStatus = 0;	//ICC present, active

  response[1] = ATRlen;		// set response length  
  response[7] = Status.SlotStatus;
  response[8] = SlotError;
  CPU_do_restart_main ();
  return ATRlen + 10;
}

static int8_t
func_PC_to_RDR_GetSlotStatus (uint8_t * command, uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);

  if (TPDU_state != T_IDLE)
    {
      Status.bmCommandStatus = 1;
      return RDR_to_PC_SlotStatus_busy_slot (response);
    }
  Status.bmCommandStatus = 0;	// command ok
  Status.bmICCStatus = 0;	//ICC present, active
  response[7] = Status.SlotStatus;
  response[8] = SlotError;
  return 10;
}


static int8_t
func_PC_to_RDR_ResetParameters (uint8_t * command, uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);

  Status.bmCommandStatus = 1;
  response[7] = Status.SlotStatus;

  if (TPDU_state != T_IDLE)
    return RDR_to_PC_SlotStatus_busy_slot (response);

  if (command[1] != 0 && command[2] != 0)
    {
      response[8] = 1;		// slot error = wrong length
      return 10;
    }
  Status.bmCommandStatus = 0;	// command OK
  response[7] = Status.SlotStatus;
  response[1] = 5;		// response data len

  response[10] = ATR[1];
  if (ATR[0] == 0x3b)
    response[11] = 0;		// direct
  else
    response[11] = 2;		// inverrse conversion
  response[12] = 2;		// guard time
  response[13] = 10;		// WI
  response[14] = 0;		// Stopping the Clock is not allowed
  return 15;
}

static int8_t
func_PC_to_RDR_SetDataRateAndClockFrequency (uint8_t * command,
					     uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);

  Status.bmCommandStatus = 1;
  response[7] = Status.SlotStatus;

  if (TPDU_state != T_IDLE)
    return RDR_to_PC_SlotStatus_busy_slot (response);

  if (command[1] != 8 || command[2] != 0)
    {
      response[8] = 1;		// slot error = wrong length
      return 10;
    }
  if (command[7] != 0)
    {
      response[8] = 7;		// slot error = srong parameter
      return 10;
    }
  if (command[8] != 0)
    {
      response[8] = 8;		// slot error = srong parameter
      return 10;
    }
  if (command[9] != 0)
    {
      response[8] = 9;		// slot error = srong parameter
      return 10;
    }
// ignore forced parameters, return "real" values

  Status.bmCommandStatus = 0;	// command OK
  response[7] = Status.SlotStatus;
  response[1] = 8;		// response data len

// 4MHz is reported in descriptor -> max baud = 129032
  response[10] = 4000L & 255;
  response[11] = (4000L >> 8) & 255;
  response[12] = (4000L >> 16) & 255;
  response[13] = (4000L >> 24) & 255;
  response[14] = (129032 >> 8) & 255;
  response[15] = (129032 >> 8) & 255;
  response[16] = (129032 >> 8) & 255;
  response[17] = (129032 >> 8) & 255;

  return 18;
}


static int8_t
func_PC_to_RDR_SetParameters (uint8_t * command, uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);

  Status.bmCommandStatus = 1;
  response[7] = Status.SlotStatus;

  if (TPDU_state != T_IDLE)
    return RDR_to_PC_SlotStatus_busy_slot (response);

  if (command[2] != 0)
    {
      response[8] = 1;		// slot error = wrong length
      return 10;
    }
  if (command[7] != 0)		// only T0 protocol
    {
      response[8] = 7;		// wrong protocol
      return 10;
    }
  if (command[1] != 5)
    {
      response[8] = 1;		// wrong len
      return 10;
    }
  // command is OK, parse parameters, signalize wrong
  // values, but do not return error

  Status.bmCommandStatus = 0;	// command OK
  response[7] = Status.SlotStatus;
  response[1] = 5;		// response data len

  response[10] = ATR[1];
  if (ATR[0] == 0x3b)
    response[11] = 0;		// direct
  else
    response[11] = 2;		// inverrse conversion
  response[12] = 2;		// guard time
  response[13] = 10;		// WI
  response[14] = 0;		// Stopping the Clock is not allowed

  if (response[10] != command[10])
    response[8] = 10;
  if (response[11] != command[11])
    response[8] = 11;
  if (response[10] != command[12])
    response[8] = 12;
  if (response[10] != command[13])
    response[8] = 13;
  if (response[14] != command[14])
    response[8] = 14;

  return 15;
}

static int8_t
func_PC_to_RDR_IccPowerOff (uint8_t * command, uint8_t * response)
{
  // power off card in slot 0
  if (command[5] == 0)
    {
      if (TPDU_state != T_IDLE)
	CPU_do_restart_main ();
      Status.bmICCStatus = 1;	//ICC present, inactive
      Status.bmCommandStatus = 0;	// command ok
      response[7] = Status.SlotStatus;
      response[8] = SlotError;
      return 10;
    }
  return func_PC_to_RDR_GetSlotStatus (command, response);
}


static int8_t
func_Unsupported (uint8_t * command, uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);
  if (TPDU_state != T_IDLE)
    {
      Status.bmCommandStatus = 1;
      return RDR_to_PC_SlotStatus_busy_slot (response);
    }
  Status.bmCommandStatus = 1;
  Status.bmICCStatus = 0;
  SlotError = 0;		//not supported command
  response[7] = Status.SlotStatus;
  response[8] = SlotError;
  return 10;
}


static int8_t
func_PC_to_RDR_XfrBlock (uint8_t * command, uint8_t * response)
{
  if (command[5] != 0)		// wrong slot
    return RDR_to_PC_DataBlock_wrong_slot (response);
  if (TPDU_state != T_IDLE)
    {
      Status.bmCommandStatus = 1;
      return RDR_to_PC_DataBlock_busy_slot (response);
    }
  // slot idle, prepare response
  memcpy (card_response, response, 10);
  // handle PTS
  // TODO, PTS is allowed only after ATR..
  if (command[2] == 0 && command[1] > 2)	//minimal 0xff,xxx,checksum
    if (command[10] == 0xff)
      {
	uint8_t bytes = 3;

	if (command[11] & 0x40)
	  bytes++;
	if (command[11] & 0x20)
	  bytes++;
	if (command[11] & 0x10)
	  bytes++;
	if (bytes == command[1])
	  {
	    // seems to be PTS ..
	    uint8_t sum = 0, i, len = bytes + 10;
	    for (i = 10; i < len; i++)
	      sum ^= command[i];
	    if (sum == 0)
	      {
		// send back nothing ..
		Status.bmCommandStatus = 0;	// command ok
		Status.bmICCStatus = 0;	//ICC present, active
		Status.SlotStatus = 0;	// no error
		response[1] = 0;
		response[7] = 0;	//Status.SlotStatus
		response[8] = SlotError;
		return 10;
	      }
	    else
	      {
		// wrong checksum
		Status.bmCommandStatus = 1;
		SlotError = 10;	// wrong PTS
		response[7] = Status.SlotStatus;
		response[8] = SlotError;
		return 10;
	      }
	  }
	else
	  {
	    // wrong len of PTS
	    Status.bmCommandStatus = 1;	// error
	    SlotError = 1;	// wrong len
	    response[7] = Status.SlotStatus;
	    response[8] = SlotError;
	    return 10;
	  }
      }



  if (0 == run_card (command))
    return 0;
  // wrong CARD command
  Status.bmCommandStatus = 1;
  Status.bmICCStatus = 0;	//ICC present, active
  SlotError = 11;		// wrong command
  response[7] = Status.SlotStatus;
  response[8] = SlotError;
  return 10;
}


// check if CCID command is correct (return 0 if not)
static uint8_t
CCID_check_command (uint8_t command)
{
  switch (command)
    {
    case PC_to_RDR_IccPowerOn:
      return C_RDR_to_PC_DataBlock;
    case PC_to_RDR_IccPowerOff:
      return C_RDR_to_PC_SlotStatus;
    case PC_to_RDR_GetSlotStatus:
      return C_RDR_to_PC_SlotStatus;
    case PC_to_RDR_XfrBlock:
      return C_RDR_to_PC_DataBlock;
    case PC_to_RDR_GetParameters:
      return C_RDR_to_PC_Parameters;
    case PC_to_RDR_ResetParameters:
      return C_RDR_to_PC_Parameters;
    case PC_to_RDR_SetParameters:
      return C_RDR_to_PC_Parameters;
    case PC_to_RDR_Escape:
      return C_RDR_to_PC_Escape;
    case PC_to_RDR_IccClock:
      return C_RDR_to_PC_SlotStatus;
    case PC_to_RDR_T0APDU:
      return C_RDR_to_PC_SlotStatus;
    case PC_to_RDR_Secure:
      return C_RDR_to_PC_DataBlock;
    case PC_to_RDR_Mechanical:
      return C_RDR_to_PC_SlotStatus;
    case PC_to_RDR_Abort:
      return C_RDR_to_PC_SlotStatus;
    case PC_to_RDR_SetDataRateAndClockFrequency:
      return C_RDR_to_PC_DataRateAndClockFrequency;

    default:
      return 0;
    }
}


// CCID parser, maximal length of data 271 bytes

// return 0 or number of bytes to send back to host over BULK IN endpoint
// return can specify 1-63 bytes message only! 
// -1 is used to signalize more data needed (incomplette message)
// return codes 64..127 and -128..-2 reserved
int8_t
parse_command (uint8_t * command, uint16_t count, uint8_t * ccid_response)
{
  // TODO TODO checking of CCID BULK OUT mesage is not fully
  // implemented due incomplette documentation of CCID class

  // ignore short message (below CCID header size)
  // this handle ZLP too..
  if (count == 0)
    return -1;

  // fill CCID response header
  ccid_response[1] = 0;
  ccid_response[2] = 0;
  ccid_response[3] = 0;
  ccid_response[4] = 0;
  ccid_response[5] = command[5];	//copy slot number
  ccid_response[6] = command[6];	//copy seq number
  ccid_response[7] = 0x40;	// command failed
  ccid_response[8] = 0;		// slot error = unsupported command
  ccid_response[9] = 0;


  ccid_response[0] = CCID_check_command (command[0]);
  // check if CCID command is in message
  if (ccid_response[0] == 0)
    {
      // no signalize error
      ccid_response[0] = C_RDR_to_PC_SlotStatus;
      return 10;
    }
  if ((count < 10) ||
      ((command[1] + (command[2] << 8)) > 261) ||
      (command[3] != 0) || (command[4] != 0))
    {
      ccid_response[8] = 1;	// slot error = wrong length
      return 10;
    }
  // check if message data part correspond to data size in ccid header
  {
    uint16_t len = 10 + command[1] + (command[2] << 8);

    if (count < len)
      {
	// BULK OUT message not complette (receiving in chunk of 64 bytes)
	if ((count % 64) == 0)
	  return -1;
	// this is definitively short BULK OUT message (size in header
	// not correspond to real received data size)
	// TODO how handle this ? 
	// now reporting wrong size 
	ccid_response[8] = 1;	// slot error = wrong length
	return 10;
      }
    // TODO   
    // zeroize oversized data or report error?
    //  
    if (len < count)
      {
	memset (command + len, 0, 271 - len);
	count = len;
      }
  }
  // OK, CCID BULK OUT seems to be correct, proceed command

  switch (command[0])
    {
////////////////////////////////////////////////////////////////
    case PC_to_RDR_IccPowerOn:
      return func_PC_to_RDR_IccPowerOn (command, ccid_response);
////////////////////////////////////////////////////////////////
    case PC_to_RDR_IccPowerOff:
      return func_PC_to_RDR_IccPowerOff (command, ccid_response);
////////////////////////////////////////////////////////////////
    case PC_to_RDR_SetParameters:
      return func_PC_to_RDR_SetParameters (command, ccid_response);
////////////////////////////////////////////////////////////////
    case PC_to_RDR_ResetParameters:
      return func_PC_to_RDR_ResetParameters (command, ccid_response);
////////////////////////////////////////////////////////////////
    case PC_to_RDR_GetSlotStatus:
      return func_PC_to_RDR_GetSlotStatus (command, ccid_response);
////////////////////////////////////////////////////////////////
    case PC_to_RDR_SetDataRateAndClockFrequency:
      return
	func_PC_to_RDR_SetDataRateAndClockFrequency (command, ccid_response);
////////////////////////////////////////////////////////////////
    case PC_to_RDR_XfrBlock:
      return func_PC_to_RDR_XfrBlock (command, ccid_response);
////////////////////////////////////////////////////////////////
    default:
      return func_Unsupported (command, ccid_response);
    }
}


/** Configures the board hardware and chip peripherals for the demo's functionality. */
void
card_io_init (void)
{
// ccid layer init
  ATRlen = 0;
  TPDU_state = T_IDLE;
  SlotError = 5;		// slot does not exist;
  Status.SlotStatus = 0x42;	// No ICC present, command failed error in error reg

// Reader LEDs
  LED1_INIT ();
  LED1_IDLE ();
  LED2_INIT ();
  LED2_RUN ();
}
