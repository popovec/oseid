/*
    serial.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2016,2019 Peter Popovec, popovec.peter@gmail.com

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

    linux serial port I/O for OsEID simulator

*/


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <errno.h>
#include <ifdhandler.h>
#include <PCSC/debuglog.h>


#include "serial.h"

// communication timeout in seconds
#define COMM_TIMEOUT 120

#define RET_OK 0
#define RET_FAIL 1


int reader_fd;
char *reader_device;

static void
FlushPort ()
{
  fd_set fdset;
  int fd = reader_fd;
  struct timeval t;
  uint8_t byte;
  int i;

  Log1 (PCSC_LOG_DEBUG, "doing flush");

  for (;;)
    {
      FD_ZERO (&fdset);
      FD_SET (fd, &fdset);

      // 115200 serial speed, approximately 87uS per character
      // timeout for two chars ..
      t.tv_sec = 0;
      t.tv_usec = 200;

      i = select (fd + 1, &fdset, NULL, NULL, &t);
      if (i < 1)
	break;
      if (1 != read (fd, &byte, 1))
	break;
    }
}

//=======================================================================================

RESPONSECODE
WritePort (DWORD lun, DWORD length, PUCHAR buffer)
{
  int rv;

  FlushPort ();

  log_xxd (PCSC_LOG_DEBUG, "sending:", buffer, length);
  rv = write (reader_fd, buffer, length);
  if (rv < 0)
    {
      Log2 (PCSC_LOG_CRITICAL, "write error: %s", strerror (errno));
      return RET_FAIL;
    }
  return RET_OK;
}

//=======================================================================================


RESPONSECODE
ReadPort (DWORD lun, PDWORD length, PUCHAR buffer)
{
  uint8_t r_buffer[261 * 3];
  uint8_t byte, flag = 0;
  int rv, already_read;
  int i;

  fd_set fdset;
  int fd = reader_fd;
  struct timeval t;

  // error by default */
  *length = 0;

  // Read loop */
  for (already_read = 0; already_read < 261 * 3;)
    {
      FD_ZERO (&fdset);
      FD_SET (fd, &fdset);
      t.tv_sec = COMM_TIMEOUT;
      t.tv_usec = 0;

      i = select (fd + 1, &fdset, NULL, NULL, &t);
      if (i == -1)
	{
	  Log2 (PCSC_LOG_CRITICAL, "select: %s", strerror (errno));
	  return RET_FAIL;
	}
      else if (i == 0)
	{
	  log_xxd (PCSC_LOG_DEBUG, "serial read: ", r_buffer, already_read);
	  Log2 (PCSC_LOG_DEBUG, "Timeout! (%d sec)", COMM_TIMEOUT);
	  return RET_FAIL;
	}

      rv = read (fd, &byte, 1);
      if (rv < 0)
	{
	  log_xxd (PCSC_LOG_DEBUG, "serial read:", r_buffer, already_read);
	  Log2 (PCSC_LOG_DEBUG, "read error: %s", strerror (errno));
	  return RET_FAIL;
	}
      if (rv == 0)
	continue;
//      fprintf(stderr,"%c",byte);

      // start parsing input after '<' ...
      if (byte == '<')
	{
	  flag = 1;
	  continue;
	}
      if (flag)
	{
	  r_buffer[already_read++] = byte;
	  if (byte == 0x0d)
	    break;
	  if (byte == 0x0a)
	    break;
	}
    }
// very tolerant hex to binary  converter
//(max 256 bytes)
  {
    uint8_t byte = 0;
    uint8_t flag = 0;

    for (i = 1; i < already_read; i++)
      {
	if (*length < 256)
	  {
	    if (!isxdigit (r_buffer[i]))
	      {
		if (flag)
		  {
		    // no hex digit but some hex digit already parsed
		    // save byte
		    buffer[*length] = byte;
		    byte = 0;
		    flag = 0;
		    (*length)++;
		  }
		if (r_buffer[i] == 0x0d)
		  break;
		if (r_buffer[i] == 0x0a)
		  break;
		continue;
	      }
	    else
	      {
		flag++;
		if (flag == 3)
		  {
		    // save byte
		    buffer[*length] = byte;
		    byte = 0;
		    flag = 0;
		    (*length)++;
		  }
		r_buffer[i] -= '0';
		if (r_buffer[i] > 9)
		  r_buffer[i] -= 7;
		if (r_buffer[i] > 9)
		  r_buffer[i] -= 32;
		byte *= 16;
		byte += r_buffer[i];
		continue;
	      }
	  }
	else
	  break;
      }
    return RET_OK;
  }
  return RET_FAIL;
}


//=======================================================================================

RESPONSECODE
OpenGBP (DWORD lun, LPSTR dev_name)
{
  struct termios sparam;

  reader_fd = open (dev_name, O_RDWR | O_NOCTTY);
  if (reader_fd < 0)
    {
      Log3 (PCSC_LOG_CRITICAL, "open %s: %s", dev_name, strerror (errno));
      return RET_FAIL;
    }

  reader_device = strdup (dev_name);

  if (tcflush (reader_fd, TCIOFLUSH))
    Log2 (PCSC_LOG_INFO, "tcflush() function error: %s", strerror (errno));

  // get config attributes */
  if (tcgetattr (reader_fd, &sparam) == -1)
    {
      Log2 (PCSC_LOG_INFO, "tcgetattr() function error: %s",
	    strerror (errno));
      close (reader_fd);
      reader_fd = -1;
      return RET_FAIL;
    }

/* ************************************************************************************ */
  //default
  sparam.c_cflag = 0;
  //set control flags (use only POSIX declared values!!!)

  sparam.c_cflag &= ~CSIZE;	// clear character size  bits
  sparam.c_cflag |= CS8;	// set 8 bits per character
  sparam.c_cflag &= ~CSTOPB;	// one stop bit
  sparam.c_cflag &= ~PARODD;	// even parity (but parity is not used .. line below)
  sparam.c_cflag &= ~PARENB;	// no parity
  sparam.c_cflag |= CREAD;	// enable receiver
  sparam.c_cflag |= CLOCAL;	// Ignore modem control lines.
  sparam.c_cflag |= HUPCL;	// hang up after close (lower modem control lines)

  sparam.c_cflag |= B115200;

  //set baudrate (separately for in/out or  same for in/out
  //cfsetispeed (&sparam.ts, sparam.speed);
  //cfsetospeed (&sparam.ts, sparam.speed);
  //cfsetspeed (&sparam.ts, sparam.speed);

  /* ************************************************************************************ */
  // set input processing

  //sparam.c_iflag &= IGNBRK;
  //sparam.c_iflag &= BRKINT;
  //sparam.c_iflag &= IGNPAR;
  //sparam.c_iflag &= PARMRK;
  //sparam.c_iflag &= INPCK;         //do not check input parity
  //sparam.c_iflag &= ISTRIP;        //do not strip 8 bit
  //sparam.c_iflag &= INLCR;         //do not  translate input NL to CR
  //sparam.c_iflag &= IGNCR;         //do not ignore CR
  //sparam.c_iflag &= ICRNL;         //do not translate CR to NL
  //sparam.c_iflag &= IXON;          //turn off XON/XOFF on output
  //sparam.c_iflag &= IXOFF;         //turn off XON/XOFF on input
  //sparam.c_iflag &= IXANY;         //input character does not restart output
  ///*sparam.c_iflag &= IUTF8;*/     //not POSIX!!!, linux specific ..


  // disable all input processing

  sparam.c_iflag = 0;

  /* ************************************************************************************ */
  //set output processing

  // POSIX values, without _BSD_SOURCE, _SVID_SOURCE or _XOPEN_SOURCE
  //sparam.c_oflag &= OPOST; // disable output postprocessing
  //sparam.c_oflag &= ONLCR; // do not remap NL to CR-NL
  //sparam.c_oflag &= OCRNL; // do not map  CR to NL
  //sparam.c_oflag &= ONOCR; // do output of CR  on column 0
  //sparam.c_oflag &= ONLRET;        // do not  filter CR
  //sparam.c_oflag &= OFILL; // use timed delay, do not send fill characters
  // this need _BSD_SOURCE or SVID_SOURCE or _XOPEN_SOURCE
  //sparam.c_oflag |= (NL0 | CR0 | TAB0 | BS0 | VT0 | FF0); //nop delay for outputs

  //disable all output processing
  sparam.c_oflag = 0;

  /* ************************************************************************************ */
  //sparam.c_lflag &= ISIG;
  //sparam.c_lflag &= ICANON;
  //sparam.c_lflag &= XCASE;
  //sparam.c_lflag &= ECHO;
  //sparam.c_lflag &= ECHOE;
  //sparam.c_lflag &= ECHOK;
  //sparam.c_lflag &= ECHONL;
  //sparam.c_lflag &= NOFLSH;
  //sparam.c_lflag &= TOSTOP;
  //sparam.c_lflag &= IEXTEN;

  //disable all
  sparam.c_lflag = 0;

  /* ************************************************************************************ */
  /*
     VEOF  //not needed, ICANON is off
     VEOL  //not needed, ICANON is off
     VERASE //not needed, ICANON is off
     VINTR //not needed, ISIG is off
     VKILL //not needed, ICANON is off
     VQUIT //not needed, ISIG is off
     VSTART //not needed, IXON is off
     VSTOP //not needed, IXON is off
     VSUSP //not needed, ISIG is off
   */

  sparam.c_cc[VTIME] = 0;
  sparam.c_cc[VMIN] = 1;	//block read  if no character is received

  /* ************************************************************************************ */


  //change immediately all parameters
  tcsetattr (reader_fd, TCSANOW, &sparam);
  //alternate call ioctl(sparam.fd, TCSETS, &sparam)
  /* ************************************************************************************ */


  return RET_OK;
}

//=======================================================================================

RESPONSECODE
CloseGBP (DWORD lun)
{
  close (reader_fd);
  reader_fd = -1;
  free (reader_device);
  reader_device = NULL;
  return RET_OK;
}

//=======================================================================================

RESPONSECODE
OpenPortByName (DWORD lun, LPSTR dev_name)
{
  if (OpenGBP (lun, dev_name) != RET_OK)
    {
      Log1 (PCSC_LOG_CRITICAL, "Open failed");
      return IFD_COMMUNICATION_ERROR;
    }
  return IFD_SUCCESS;
}

//=======================================================================================

RESPONSECODE
OpenPort (DWORD lun, DWORD channel)
{
  char dev_name[FILENAME_MAX];

  if (channel > 0)
    return IFD_COMMUNICATION_ERROR;

  sprintf (dev_name, "/dev/pcscd-test%d", (int) channel);

  return OpenPortByName (lun, dev_name);
}

//=======================================================================================

RESPONSECODE
ClosePort (DWORD lun)
{
  if (CloseGBP (lun) != RET_OK)
    return IFD_COMMUNICATION_ERROR;

  return IFD_SUCCESS;
}
