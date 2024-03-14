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

    STM32F102CB/STM32F103CB/MH2103CBT6 initialization code + USB code

*/
#include <stdint.h>
#include <string.h>
#include "ccid.h"
#include "serial_debug.h"
#include "flash_cow_dev.h"
#include "LED.h"
#include "usb.h"
#include "os.h"
//////////////////////////////////////////////////////////////////
//
// USB functions hardware dependent code
//
//////////////////////////////////////////////////////////////////

#define PERIPH_BASE	0x40000000U
#define APB1PERIPH_BASE       PERIPH_BASE
#define APB2PERIPH_BASE       (PERIPH_BASE + 0x00010000U)
#define AHBPERIPH_BASE        (PERIPH_BASE + 0x00020000U)
#define FLASH_R_BASE          (AHBPERIPH_BASE + 0x00002000U)
#define USB_BASE              (APB1PERIPH_BASE + 0x00005C00U)	/*!< USB_IP Peripheral Registers base address */
#define USB_PMAADDR           (APB1PERIPH_BASE + 0x00006000U)	/*!< USB_IP Packet Memory Area base address */

#define GPIOA_BASE	0x40010800U
#define GPIOB_BASE      0x40010C00U
#define RCC_BASE	0x40021000U

// GPIOA clock on APB2
static void enable_GPIOA_clock()
{
	volatile uint32_t *address;

	address = (uint32_t *) (RCC_BASE);
	address[0x18 / 4] |= 4;
}

#ifndef CORE_FREQ
#define CORE_FREQ 72
#endif
#if CORE_FREQ == 48
static void __attribute__((unused)) RCC_setup()
{
/*
	PLL is running on 48MHz (from HSE xtal 8MHz)
	1 is division factor for USB (48MHz)

	APB1 max = 24MHz
	APB2 max = 48MHz
	AHB max - 48MHz
	ADC max is 14MHz, from APB2 ->divisor 4, -> 12MHz
*/

	volatile uint32_t *address = (uint32_t *) (RCC_BASE);

	// enable XTAL oscillator (8MHz)
	address[0] |= (1 << 16);	//RCC_RC |= HSEON
	// wait for HSE stable
	while (!(address[0] & (1 << 17))) ;	// RCC_RC, HSERDY

	// PLL source HSE (PLLSRC)
	address[1] = (1 << 16);
	// set pll factor (6x8=48MHz)
	address[1] |= (4 << 18);
	// enable PLL
	address[0] |= (1 << 24);	//RCC_RC |= PLL_ON
	// wait for PLL stable
	while (!(address[0] & (1 << 25))) ;

	// APB1 prescaler = 2
	address[1] |= (4 << 8);

	// ADC clock - 48MHz / 4 -> 12MHz
	address[1] |= (1 << 14);

	// for 24..48MHz two wait states for flash
	address = (uint32_t *) (FLASH_R_BASE);
	address[0] |= 1;	// FLASH_ACR register, bit 2,1,0 = latency

	// switch system to PLL clock
	address = (uint32_t *) (RCC_BASE);
	address[1] |= 2;

	// usb clock divisor = 1
	address[1] |= (1 << 22);

	// wait for system clock switch to PLL
	while ((address[1] & 0x0c) != 8) ;

	// enable TIM2 clock
	address[0x1c / 4] |= (1 << 0);

	// enable USB clock
	address[0x1c / 4] |= (1 << 23);

	// reset USB clock
//      address[0x10 / 4] |= (1 << 23);
//      address[0x10 / 4] &= ~(1 << 23);

	// enable ADC1 clock (ADC is used for random generator)
	address[0x18 / 4] = (1 << 9);

}
#elif CORE_FREQ == 96
static void RCC_setup()
{
/*
	APB1 max = 108MHz
	APB2 max = 216MHz
	AHB max = 216HHz
	ADC max = 14MHz, from APB2
	// 108..216 1 wait state

	PLL is running on 96MHz (from HSE xtal 8MHz)
	2 is division factor for USB (48MHz)

	APB1 max = 48MHz
	APB2 max = 96MHz
	AHB max - 96HHz
	ADC max is 14MHz, from APB2 ->divisor 8, -> 12MHz
*/

	volatile uint32_t *address = (uint32_t *) (RCC_BASE);

	// enable XTAL oscillator (8MHz)
	address[0] |= (1 << 16);	//RCC_RC |= HSEON
	// wait for HSE stable
	while (!(address[0] & (1 << 17))) ;	// RCC_RC, HSERDY

	// PLL source HSE (PLLSRC)
	address[1] = (1 << 16);
	// set pll factor (12x8=96MHz)
	address[1] |= 0x00280000;	// 96MHz
	// USB 96MHz /2
	address[1] |= 0x00C00000;

	// enable PLL
	address[0] |= (1 << 24);	//RCC_RC |= PLL_ON
	// wait for PLL stable
	while (!(address[0] & (1 << 25))) ;

	// APB1 prescaler = 2
	address[1] |= (4 << 8);

	// ADC clock - 96MHz / 8 -> 12MHz
	address[1] |= 0x0000C000;

	// for 108.. 216 z two wait states for flash
	address = (uint32_t *) (FLASH_R_BASE);
	address[0] |= 1;	// FLASH_ACR

	// switch system to PLL clock
	address = (uint32_t *) (RCC_BASE);
	address[1] |= 2;

	// wait for system clock switch to PLL
	while ((address[1] & 0x0c) != 8) ;

	// enable TIM2 clock
	address[0x1c / 4] |= (1 << 0);

	// enable USB clock
	address[0x1c / 4] |= (1 << 23);

	// reset USB clock
//      address[0x10 / 4] |= (1 << 23);
//      address[0x10 / 4] &= ~(1 << 23);

	// enable ADC1 clock (ADC is used for random generator)
	address[0x18 / 4] = (1 << 9);

}
#else
static void RCC_setup()
{
/*
	PLL is running on 72MHz (from HSE xtal 8MHz)
	1.5 is division factor for USB (48MHz)

	APB1 max = 36MHz
	APB2 max = 72MHz
	AHB max - 72MHz
	ADC max is 14MHz, from APB2 ->divisor 6, -> 12MHz
*/

	volatile uint32_t *address = (uint32_t *) (RCC_BASE);

	// enable XTAL oscillator (8MHz)
	address[0] |= (1 << 16);	//RCC_RC |= HSEON
	// wait for HSE stable
	while (!(address[0] & (1 << 17))) ;	// RCC_RC, HSERDY

	// PLL source HSE (PLLSRC)
	address[1] = (1 << 16);
	// set pll factor (9x8=72MHz)
	address[1] |= (7 << 18);
	// enable PLL
	address[0] |= (1 << 24);	//RCC_RC |= PLL_ON
	// wait for PLL stable
	while (!(address[0] & (1 << 25))) ;

	// APB1 prescaler = 2
	address[1] |= (4 << 8);

	// ADC clock - 72MHz / 6 -> 12MHz
	address[1] |= (2 << 14);

	// for 48..72MHz two wait states for flash
	address = (uint32_t *) (FLASH_R_BASE);
	address[0] |= 2;	// FLASH_ACR register, bit 2,1,0 = latency

	// switch system to PLL clock
	address = (uint32_t *) (RCC_BASE);
	address[1] |= 2;

	// wait for system clock switch to PLL
	while ((address[1] & 0x0c) != 8) ;

	// enable TIM2 clock
	address[0x1c / 4] |= (1 << 0);

	// enable USB clock
	address[0x1c / 4] |= (1 << 23);

	// reset USB clock
//      address[0x10 / 4] |= (1 << 23);
//      address[0x10 / 4] &= ~(1 << 23);

	// enable ADC1 clock (ADC is used for random generator)
	address[0x18 / 4] = (1 << 9);

}
#endif
//// USB
#define EP0R (0/4)
#define EP1R (4/4)
#define EP2R (8/4)
#define EP3R (12/4)
// 4,5,6,7 unused
#define CNTR (0x40/4)
#define ISTR (0x44/4)
#define DADDR (0x4c/4)
#define BTABLE (0x50/4)

static void NVIC_EnableIRQ(int IRQn)
{
	volatile uint32_t *address;
	address = (uint32_t *) (0xE000E100);	// NVIC ISER
	// select register and set bit ..
	address[IRQn / 32] = (1 << ((uint32_t) (IRQn) & 0x1F));
}

void usbInit(void)
{
	uint16_t counter;

	volatile uint32_t *USB_reg = (uint32_t *) (USB_BASE);

	// activate reset
	USB_reg[CNTR] = 1;
	// delay (about 1uS  t_STARTUP), but not over 10mS
	for (counter = 0; counter < 1500; counter++)
		asm volatile ("nop\n");
	// clear interrupt status
	USB_reg[ISTR] = 0;
	// deactivate RESET and enable interrupts
	// 15 Correct transfer interrupt mask
	// 12 Wakeup interrupt mask
	// 11 Suspend mode interrupt mask
	// 10 USB reset interrupt mask
	// 9 SOF
	USB_reg[CNTR] = 0 | (1 << 15) | (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9);

// NVIC lines: RM0008 Rev 21, page 625
// 19 = USB HP  2) USB high-priority interrupt (Channel 19): Triggered only by a correct transfer event for isochronous and double-buffer bulk transfer to reach the highest possible transfer rate.
// 20 = USB LP  1) USB low-priority interrupt (Channel 20): Triggered by all USB events  (Correct transfer, USB reset, etc.). The firmware has to check the interrupt source before serving the interrupt.
// 42 USB Wakeup  3) USB wakeup interrupt (Channel 42): Triggered by the wakeup event from the USB Suspend mode (EXTI line 18).
	NVIC_EnableIRQ(20);
	NVIC_EnableIRQ(42);
}

/// USB PMA buffer manipulation (RM0008 Rev 21, page 650,651)
static uint16_t USB_calculate_USB_COUNT(uint16_t size)
{
	uint32_t ret = 0;

	// block size = 2, round up ... or block size 32
	if (size > 62) {
		// BL_SIZE = 1
		ret = 0x8000;
		size /= 32;
	} else
		size = (size + 1) / 2;
	return ret | (size << 10);
}

static uint32_t *USB_get_ep_buffer_to_host_address(uint8_t ep)
{
	uint32_t *USB_reg = (uint32_t *) (USB_PMAADDR + ep * 16);
	uint32_t address = *USB_reg * 2 + USB_PMAADDR;

	return (uint32_t *) address;
}

static void USB_init_ep_buffer_to_host(uint8_t ep, uint16_t offset, uint16_t size)
{
	uint32_t *USB_reg = (uint32_t *) (USB_PMAADDR + ep * 16);
	USB_reg[0] = offset;
	USB_reg[1] = 0;
}

static void USB_ep_set_data_len_to_host(uint8_t ep, uint16_t len)
{
	uint32_t *USB_reg = (uint32_t *) (USB_PMAADDR + ep * 16 + 4);
	*USB_reg = len & 0x3ff;
}

static uint32_t *USB_get_ep_buffer_from_host_address(uint8_t ep)
{
	uint16_t *USB_reg = (uint16_t *) (USB_PMAADDR + ep * 16 + 8);
	return (uint32_t *) (*(USB_reg) * 2 + USB_PMAADDR);
}

static void USB_init_ep_buffer_from_host(uint8_t ep, uint16_t offset, uint16_t size)
{
	uint32_t *USB_reg = (uint32_t *) (USB_PMAADDR + ep * 16 + 8);
	USB_reg[0] = offset;
	USB_reg[1] = USB_calculate_USB_COUNT(size);
}

static uint16_t USB_ep_get_data_len_from_host(uint8_t ep)
{
	uint32_t *USB_reg = (uint32_t *) (USB_PMAADDR + 12 + ep * 16);
	return *USB_reg & 0x3ff;
}

static void USB_PMA2ram(uint8_t * pma, uint8_t * ram, uint16_t len)
{
	uint32_t *l_pma = (uint32_t *) pma;
	uint16_t *l_ram = (uint16_t *) ram;
	// round up, transfer 16 bit at once
	len = (len + 1) / 2;
	while (len--)
		*(l_ram++) = *(l_pma++);
}

static uint16_t USB_read_from_host(uint8_t ep, uint8_t * ram)
{
	uint32_t *pma = USB_get_ep_buffer_from_host_address(ep);
	uint16_t len = USB_ep_get_data_len_from_host(ep);

	USB_PMA2ram((uint8_t *) pma, ram, len);
	return len;
}

static void USB_write_to_host(uint8_t ep, uint8_t * ram, uint16_t len)
{
	uint32_t *pma = USB_get_ep_buffer_to_host_address(ep);
	uint16_t *l_ram = (uint16_t *) ram;
	len = (len + 1) / 2;
	while (len--)
		*(pma++) = *(l_ram++);
}

#define EP_RX_DISS_ (0<<12)
#define EP_RX_STALL_ (1<<12)
#define EP_RX_NAK_ (2<<12)
#define EP_RX_VALID_ (3<<12)
#define EP_TX_DISS_ (0<<4)
#define EP_TX_STALL_ (1<<4)
#define EP_TX_NAK_ (2<<4)
#define EP_TX_VALID_ (3<<4)

#define USB_ep_set_rx(ep,state) USB_ep_set_status(ep,1,state)
#define USB_ep_set_tx(ep,state) USB_ep_set_status(ep,0,state)

static uint8_t data_for_host_status[4] __attribute__((section(".noinit")));
static uint8_t *data_for_host[4] __attribute__((section(".noinit")));
static uint16_t data_for_host_len[4] __attribute__((section(".noinit")));

#define EP_TO_HOST_FREE 0
#define EP_TO_HOST_LAST 1
#define EP_TO_HOST_BUSY 2

static void USB_ep_set_status(uint8_t ep, uint8_t rx, uint16_t state)
{
	volatile uint32_t *USB_reg = (uint32_t *) (USB_BASE);
	uint32_t val, togg;

	val = USB_reg[ep];
	togg = val;
	// clear "toggle" bits
	val &= ~((1 << 14) | (3 << 12) | (1 << 6) | (3 << 4));
	// if bit does not match result, set it in "togg"
	togg ^= state;
	// mask only toggled bits
	if (rx) {
		togg &= (3 << 12);
		val &= ~(1 << 15);	// clear CTR_RX
	} else {
		togg &= (3 << 4);
		val &= ~(1 << 7);	// clear CTR TX
	}
	// toggle to match final value
	val ^= togg;
	USB_reg[ep] = val;
}

void USB_Deconfigure_CCID_ep(void)
{
	USB_ep_set_rx(1, EP_RX_DISS_);
	USB_ep_set_tx(1, EP_TX_DISS_);
	USB_ep_set_rx(2, EP_RX_DISS_);
	USB_ep_set_tx(2, EP_TX_DISS_);
	USB_ep_set_rx(2, EP_RX_DISS_);
	USB_ep_set_tx(3, EP_TX_DISS_);
}

void USB_reset()
{
	volatile uint32_t *USB_reg = (uint32_t *) (USB_BASE);
	uint32_t val;

	data_for_host_status[0] = EP_TO_HOST_FREE;
	data_for_host_status[1] = EP_TO_HOST_FREE;
	data_for_host_status[2] = EP_TO_HOST_FREE;
	data_for_host_status[3] = EP_TO_HOST_FREE;

	USBcommon_Reset();

	// after reset only endpoint0 is active..
	USB_Deconfigure_CCID_ep();

	// disable device
	USB_reg[DADDR] = 0;
	USB_reg[BTABLE] = 0;

	// endpoint, offset in PMA, allocated size
	USB_init_ep_buffer_to_host(0, 64, 64);
	USB_init_ep_buffer_from_host(0, 128, 64);

	// allocate buffers for CCID (both direction, even only one is used)
	// OUT
	USB_init_ep_buffer_to_host(1, 256, 64);
	USB_init_ep_buffer_from_host(1, 320, 64);

	// IN
	USB_init_ep_buffer_to_host(2, 384, 64);
	USB_init_ep_buffer_from_host(2, 448, 64);
	// INTERRUPT
	USB_init_ep_buffer_to_host(3, 160, 8);
	USB_init_ep_buffer_from_host(3, 192, 8);

	// unknown state, clear USB_EP0R, set endpoint type CONTROL
	for (int i = 0; i < 4; i++) {
		val = USB_reg[i];
		val &= 0x70007000;
		USB_reg[i] = val;
	}

	// unknown state, clear USB_EP0R, set endpoint type CONTROL
	val = USB_reg[0];
	val &= 0x70007000;
	// EP_TYPE = 1
	val |= (1 << 9);
	USB_reg[0] = val;

	USB_ep_set_rx(0, EP_RX_VALID_);
	USB_ep_set_tx(0, EP_TX_NAK_);

// set EF bit in DADDR to enable function
	USB_reg[DADDR] = 0x80;
	return;
}

uint8_t USB_Get_Stall_state(uint8_t ep)
{
	volatile uint32_t *USB_reg = (uint32_t *) (USB_BASE);
	uint32_t val;
	if (ep > 3)
		return 0;
	val = USB_reg[ep];
	val &= 0x3030;
	if (val == 0x1010)
		return 1;
	return 0;
}

void USB_Stall_ep(uint8_t ep)
{
	if (ep > 3)
		return;
	USB_ep_set_rx(ep, EP_RX_STALL_);
	USB_ep_set_tx(ep, EP_TX_STALL_);
}

void USB_Configure_ep(uint8_t ep)
{
	volatile uint32_t *USB_reg = (uint32_t *) (USB_BASE);
	uint32_t val;
	if (ep == 1) {
		// BULK OUT
		val = USB_reg[1];
		val &= 0x70007000;
		val |= 1;
		USB_reg[1] = val;
		USB_ep_set_rx(1, EP_RX_VALID_);
		USB_ep_set_tx(1, EP_TX_DISS_);
	}
	if (ep == 2) {
		// BULK IN
		val = USB_reg[2];
		val &= 0x70007000;
		val |= 2;
		USB_reg[2] = val;
		USB_ep_set_rx(2, EP_RX_DISS_);
		USB_ep_set_tx(2, EP_TX_NAK_);
	}
	if (ep == 3) {
		// INTERRUPT
		val = USB_reg[3];
		val &= 0x70007000;
		val |= (3 << 9);
		val |= 3;
		USB_reg[3] = val;
		USB_ep_set_rx(3, EP_RX_VALID_);
		USB_ep_set_tx(3, EP_TX_NAK_);
	}
}

void USB_Configure_CCID_ep(void)
{
	USB_Configure_ep(1);
	USB_Configure_ep(2);
	USB_Configure_ep(3);
}

static void init_GPIOA_pins()
{
	volatile uint32_t *gpioa;
	gpioa = (uint32_t *) GPIOA_BASE;

// clear PA9 mode
	gpioa[4 / 4] &= 0xFFFFFF0F;
#ifdef SERIAL_DEBUG
	gpioa[4 / 4] |= 0x00A0;	// alternate ..  USART 1 TX
#endif
}

#ifndef SERIAL_DEBUG
int led1, led2;
static void ledx()
{
	volatile uint32_t *gpioa = (uint32_t *) GPIOA_BASE;
	if (led1 == 0 && led2 == 0) {
		// clear PA9 mode
		gpioa[4 / 4] &= 0xFFFFFF0F;
	} else {
		gpioa[4 / 4] |= 0x0010;	// PA9 push pull, 10MHz
		if (led1)
			gpioa[0x10 / 4] = (1 << 9);
		else
			gpioa[0x10 / 4] = (1 << (9 + 16));
	}
}

void led1_on()
{
	led1 = 1;
	ledx();
}

void led1_off()
{
	led1 = 0;
	ledx();
}

void led1_toggle()
{
	led1 ^= 1;
	ledx();
}

void led2_on()
{
	led2 = 1;
	ledx();
}

void led2_off()
{
	led2 = 0;
	ledx();
}
#endif
static void USB_Send_Data_Handler(uint8_t ep)
{
	volatile uint32_t *USB_reg = (uint32_t *) (USB_BASE);
	uint32_t val;
	uint16_t len;
	uint16_t blen = 8;

	// TODO buffer size from PMA, for now 0,3 size =8 1,2 = 64
	if (ep == 1 || ep == 2)
		blen = 64;

	len = blen;
	// is there some data for host ?
	if (data_for_host_status[ep] == EP_TO_HOST_LAST) {
		data_for_host_status[ep] = EP_TO_HOST_FREE;
	}
	if (data_for_host_status[ep] == EP_TO_HOST_FREE) {
		uint8_t address = USBcommon_GetAddress();
		// new address from host ?
		if (address & 0x80) {
			DEBUG_print_string("Addr");
			// bit 7 must remain set, it is used to enable the USB function
			USB_reg[DADDR] = address;
			USBcommon_MarkDeviceAddressed();
			DEBUG_print_hex(address);
			DEBUG_putchar('\n');
		}
		// clear TX status
		val = USB_reg[ep];
		val &= ~((1 << 14) | (3 << 12) | (1 << 6) | (3 << 4));
		val &= ~(1 << 7);
		USB_reg[ep] = val;

// debug interrupt endpoint
		if (ep == 3) {
			val = USB_reg[ep];
			DEBUG_print_hex16(val);
			DEBUG_putchar('%');
		}
		return;
	}

	if (data_for_host_len[ep] < len)
		len = data_for_host_len[ep];

	data_for_host_len[ep] -= len;

	USB_write_to_host(ep, data_for_host[ep], len);
	data_for_host[ep] += len;
	USB_ep_set_data_len_to_host(ep, len);
	USB_ep_set_tx(ep, EP_TX_VALID_);

	// last chunk ?
	if (len < blen)
		data_for_host_status[ep] = EP_TO_HOST_LAST;
	return;
}

uint8_t USB_send_data_to_host(uint8_t ep, uint8_t * data, uint16_t length)
{
	// error endpoint is busy
	if (data_for_host_status[ep] != EP_TO_HOST_FREE) {
		DEBUG_print_string("ERR");
		DEBUG_print_hex(ep);
		DEBUG_print_string("\n");
		return 1;
	}
	data_for_host[ep] = data;
	data_for_host_len[ep] = length;
	data_for_host_status[ep] = EP_TO_HOST_BUSY;

	USB_Send_Data_Handler(ep);
	return 0;
}

void USB_endpoint_Handler(uint32_t status)
{
// handle only received data from host (OUT /SETUP) for now
	volatile uint32_t *USB_reg = (uint32_t *) (USB_BASE);
	uint32_t ep_status;
	uint8_t usb_buffer[64];
	uint16_t rec_len;
	uint8_t ep = 0;
	uint8_t ret = RET_OK;

	ep = status & 0x0f;

	ep_status = USB_reg[ep];
	// correct transfer ?
	if (ep_status & (1 << 15)) {
		rec_len = USB_read_from_host(ep, usb_buffer);
		if (ep_status & (1 << 11)) {
			ret = USBcommon_ProcessSetupRequest(usb_buffer, rec_len);
		} else {
			if (ep == 1) {
				CCID_Handler_from_host(usb_buffer, rec_len);
			}
			ret = RET_OK;
		}
		if (ret == RET_STALL) {
			USB_ep_set_rx(ep, EP_RX_STALL_);
			USB_ep_set_tx(ep, EP_TX_STALL_);
		} else {
			if (ret == RET_ZERO_FRAME)
				USB_send_data_to_host(ep, 0, 0);
			// RET_OK or RET_ZERO_FRAME
			USB_ep_set_rx(ep, EP_RX_VALID_);
		}
	}

	// test if some data for host are deliviered:
	if (ep_status & (1 << 7)) {
// debug, interrupt endpoint..
		if (ep == 3)
			DEBUG_putchar('!');
		USB_Send_Data_Handler(ep);
	}
//      DEBUG_putchar('\n');
}

void CCID_send_null(void);

void USB_ISR()
{
	volatile uint32_t *USB_reg = (uint32_t *) (USB_BASE);
	uint32_t istr;
	for (;;) {
		istr = USB_reg[0x44 / 4];
		if (!(istr & 0xff00))
			break;
		// clear all requests (CTR is cleared in endpoints registers below)
		USB_reg[0x44 / 4] = 0;
		// endpoint test CTR bit
		if (istr & (1 << 15)) {
			// MH2103A workaround
			for (int i = 0; i < 8; i++) {
				uint32_t wk = USB_reg[i];
				if (wk & (1 << 15)) {
					istr |= (i | (1 << 4));
					break;
				}
				if (wk & (1 << 7)) {
					istr |= i;
					break;
				}
			}
			USB_endpoint_Handler(istr);
		}
		// RESET
		if (istr & (1 << 10)) {
			DEBUG_print_string("R\n");
			USB_reset();
		}
		// SOF
		if (istr & (1 << 9)) {
			CCID_send_null();
		}
		// suspend
		if (istr & (1 << 11)) {
			LED1_OFF();
			LED2_SUSPEND();
			DEBUG_print_string("Suspend\n");
			USB_reg[0x40 / 4] |= (1 << 3);	// set suspend flag
			USB_reg[0x40 / 4] |= (1 << 2);	// Low Power..
			// after return from ISR this ends in CPU_Idle()...
			// (because card in waiting for data)
			// TODO: check power consumption, maybe it is necessary to
			// turn off other functions of the processor and the clock
		}
		// resume
		if (istr & (1 << 12)) {
			LED2_RUN();
			LED1_IDLE();
			DEBUG_print_string("Wakeup 20\n");
			USB_reg[0x40 / 4] &= ~(1 << 2);	// clear low power flag
			USB_reg[0x40 / 4] &= ~(1 << 3);	// clear suspend flag
			if (USBcommon_GetConfiguration() == 1)
				CCID_notify();
		}
	}
}

void __attribute__((interrupt(20))) USB_LP_handler()
{
	USB_ISR();
}

void __attribute__((interrupt(42))) USBWakeup_handler()
{
	volatile uint32_t *USB_reg = (uint32_t *) (USB_BASE);
	uint32_t istr = USB_reg[0x44 / 4];

	if (istr & (1 << 12)) {
		USB_reg[0x44 / 4] &= ~(1 << 12);	// clear ISR flag
		USB_reg[0x40 / 4] &= ~(1 << 3);	// remove Force suspend flag
	}
	DEBUG_print_string("Wakeup 42\n");
}

////////////////////////////////////////////////////////////////////////////
void CPU_idle()
{
	asm volatile ("wfi\n");
}

// timer ISR is used to switch SP from MSP to PSP
#define TIM2_BASE 0x40000000
void timer_init(void)
{
	volatile uint32_t *timer = (uint32_t *) TIM2_BASE;
// prescaler 1
	timer[0x28 / 4] = 0;
// CNT
	timer[0x10 / 4] = 10;
// count down and enable timer, stop on update
	timer[0] = (1 << 4) | (1 << 0) | (1 << 3);
// enable interrupt on update
	timer[0x0c / 4] = 1;
	NVIC_EnableIRQ(28);
}

void __attribute__((interrupt(28))) __attribute__((naked)) TIM2_handler()
{
	asm volatile (		//
// unblock interrupt request from timer2
			     "mov   r3, 0x40000000\n"	//
			     "movs    r2, #0\n"	//
			     "str     r2, [r3, #16]\n"	//
// switch to psp stack
			     "mov r0,#4\n"	//
			     "orrs lr,r0\n"	//
			     "bx      lr\n");
}

void main_exit()
{
	for (;;) ;
}

extern uint32_t _user_stack;
void init_card_task()
{
	asm volatile (		//
			     "ldr r0, =_user_stack\n"	//
			     "msr psp, r0\n"	//
			     "ldr r1,=main_exit\n"	//      return from main here
			     "str r1,[r0,#20]\n"	//      lr
			     "ldr r1,=main\n"	//              main
			     "str r1,[r0,#24]\n"	//      pc
			     "mov r1,0x21000000\n"	//      initial psr value
			     "str r1,[r0,#28]\n"	//      psr
			     :::"r0", "r1");
}

// this is called only in USB ISR
void CPU_do_restart_main()
{
// There is only one level of ISR enabled, no nested ISR are used
// only "main" can be interrupted .. Reinit main psp and structure on stack..
	DEBUG_print_string("attempt to restart main\n");
	init_card_task();
}

// external function:
// return max 255 bytes of hardware unique identifier
uint8_t get_HW_serial_id(uint8_t * p, uint8_t max)
{
	volatile uint32_t *s = (uint32_t *) 0x1FFFF7E8;
	uint8_t buffer[12];
	uint32_t val;

	val = *(s++);
	buffer[0] = (val >> 8) & 0xff;
	buffer[1] = (val >> 0) & 0xff;
	buffer[2] = (val >> 8) & 0xff;
	buffer[3] = (val >> 0) & 0xff;
	val = *(s++);
	buffer[4] = (val >> 24) & 0xff;
	buffer[5] = (val >> 16) & 0xff;
	buffer[6] = (val >> 8) & 0xff;
	buffer[7] = (val >> 0) & 0xff;
	val = *(s++);
	buffer[8] = (val >> 24) & 0xff;
	buffer[9] = (val >> 16) & 0xff;
	buffer[10] = (val >> 8) & 0xff;
	buffer[11] = (val >> 0) & 0xff;
	memcpy(p, buffer, max > 12 ? 12 : max);
	return max > 12 ? 12 : max;
}

static uint64_t crc64(uint64_t crc, uint8_t n)
{
	int j;
	uint64_t mask;

	crc = crc ^ n;
	for (j = 7; j >= 0; j--) {
		mask = -(crc & 1);
		crc = (crc >> 1) ^ (0xC96C5795D7870F42 & mask);
	}
	return ~crc;
}

// return exact 10 bytes (card serial number)
void get_HW_serial_number(uint8_t here[10])
{
	uint8_t buffer[32];
	int len, i = 0;
	uint64_t crc = 1U;
	uint8_t b, *h = here;

	len = get_HW_serial_id(buffer, 32);
	while (len--)
		crc = crc64(crc, buffer[i++]);
	memset(here, 0, 10);
// remove non decimal chars (warning, this is not real
// conversion to decadic number!)
	h += 9;
	for (i = 0; i < 20;) {
		b = crc & 0xf;
		if (b > 9) {
			crc += b;
			continue;
		}
		crc >>= 4;
		if (i & 1) {
			*h |= (b << 4);
			h--;
		} else {
			*h = b;
		}
		i++;
	}
}

static void nostart()
{
// RED led ON
	volatile uint32_t *gpioa = (uint32_t *) GPIOA_BASE;
	// clear PA9 mode
	gpioa[4 / 4] &= 0xFFFFFF0F;
	gpioa[4 / 4] |= 0x0010;	// PA9 push pull, 10MHz
	gpioa[0x10 / 4] = (1 << (9 + 16));
// stop here if PB12 /SWDIO/ is grouned
	// GPIOB...
	volatile uint32_t *address;
	address = (uint32_t *) (RCC_BASE);
	address[0x18 / 4] |= 8;
	address = (uint32_t *) GPIOB_BASE;
	address[1] = 0x48484444;
	// activate pull-up
	address[0x10 / 4] = (1 << 12) | (1 << 14);
	// read state
	while (!(address[0x8 / 4] & (1 << 12))) ;
}

void init_stm()
{
	RCC_setup();
	enable_GPIOA_clock();
	nostart();
	init_GPIOA_pins();
	DEBUG_init();
	CCID_Init();
	usbInit();
	DEBUG_print_string("Init OK, starting main\n");
	init_card_task();
	timer_init();
// we shouldn't come back here (ISR switches SP to PSP)
	for (;;) ;
}

// libc ...
#if 0
void *memcpy(void *dest, const void *src, size_t n)
{
	char *d = (char *)dest;
	char *s = (char *)src;
	while (n--)
		*d++ = *s++;
	return dest;
}
#else
void *memcpy(void *dest, const void *src, size_t n)
{
	uint32_t *d32 = (uint32_t *) dest;
	uint32_t *s32 = (uint32_t *) src;

	while (n >= 4) {
		*d32++ = *s32++;
		n -= 4;
	}

	char *d = (char *)d32;
	char *s = (char *)s32;
	while (n--)
		*d++ = *s++;
	return dest;
}
#endif
#if 0
void *memset(void *s, int c, size_t n)
{
	uint8_t *here = s;
	uint8_t byte = c & 0xff;
	while (n--)
		*(here++) = byte;
	return s;
}
#else
void *memset(void *s, int c, size_t n)
{
	uint32_t *here32 = s;
	uint8_t byte = c & 0xff;
	uint32_t b32 = (byte << 24) | (byte << 16) | (byte << 8) | (byte);

	while (n >= 4) {
		*(here32++) = b32;
		n -= 4;
	}

	uint8_t *here = (uint8_t *) here32;

	while (n--)
		*(here++) = byte;
	return s;
}
#endif

int memcmp(const void *s1, const void *s2, size_t n)
{
	unsigned char *mem1 = (unsigned char *)s1;
	unsigned char *mem2 = (unsigned char *)s2;

	while (n--) {
		if (*mem1 != *mem2)
			return *mem1 - *mem2;
		mem1++;
		mem2++;
	}
	return 0;
}
