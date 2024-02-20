/*
    STM32F10x_init.S

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

    STM32F102 reset handler + vector table

*/

.syntax unified
.cpu cortex-m3
.fpu softvfp
.thumb

	.global vtable
	.type vtable, %object
	.section .vector_table,"a",%progbits
vtable:
// cortex-M3
	.word	_estack
	.word	Reset_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
// 0x10
//MemManage BusFault UsageFault Reserved ...
	.word	default_interrupt_handler, default_interrupt_handler, default_interrupt_handler,  default_interrupt_handler
// 0x20
	.word   default_interrupt_handler, default_interrupt_handler, default_interrupt_handler
// 0x2c SVCall
	.word	default_interrupt_handler
// 0x30 Debug Monitor
	.word   default_interrupt_handler
// 0x34 reserved
	.word   default_interrupt_handler
// 0x38 PendSV
	.word	default_interrupt_handler
// 0x3c SysTick
	.word	default_interrupt_handler

// STM32F102 specific
// 0x40 WWDG
	.word	default_interrupt_handler
// PVD
	.word	default_interrupt_handler
// TAMPER
	.word	default_interrupt_handler
// RTC
	.word	default_interrupt_handler
// 0x50 FLASH
	.word	default_interrupt_handler
// RCC
	.word	default_interrupt_handler
// EXTI0
	.word	default_interrupt_handler
// EXTI1
	.word	default_interrupt_handler
// 0x60 EXTI2
	.word	default_interrupt_handler
// EXTI3
	.word	default_interrupt_handler
// EXTI4
	.word	default_interrupt_handler
// DMA1_Channel1
	.word	default_interrupt_handler
// 0x70 DMA1_Channel2
	.word	default_interrupt_handler
// DMA1_Channel3
	.word	default_interrupt_handler
// DMA1_Channel4
	.word	default_interrupt_handler
// DMA1_Channel5
	.word	default_interrupt_handler
// 0x80 DMA1_Channel6
	.word	default_interrupt_handler
// DMA1_Channel7
	.word	default_interrupt_handler
// ADC1_2
	.word	default_interrupt_handler
// USB_HP
	.word	USB_HP_handler
// 0x90 USB_LP
	.word	USB_LP_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
// 0xa0
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
// 0xb0
	.word	TIM2_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
// 0xc0
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
// 0xd0
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
// 0xe0
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	USBWakeup_handler
	.word	default_interrupt_handler
// 0xf0
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
// 0x100
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
// 0x110
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
// 0x120
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler
	.word	default_interrupt_handler

// 0x130 .. free flash ..

	.weak USBWakeup_handler
	.thumb_set USBWakeup_handler,default_interrupt_handler

        .weak USB_HP_handler
        .thumb_set USB_HP_handler,default_interrupt_handler

        .weak USB_LP_handler
        .thumb_set USB_LP_handler,default_interrupt_handler

        .weak TIM2_handler
        .thumb_set TIM2_handler,default_interrupt_handler

	.section .text.default_interrupt_handler,"ax",%progbits
	.global default_interrupt_handler
	.type default_interrupt_handler, %function

default_interrupt_handler:
	b	.

	.size default_interrupt_handler, .-default_interrupt_handler



	.global Reset_handler
	.type Reset_handler, %function

Reset_handler:
// init stack pointer
	ldr	r0, =_estack
	mov	sp, r0

// init RAM variables
	movs	r0, #0
	ldr	r1, =_sdata
	ldr	r2, =_edata
	ldr	r3, =_sidata
	b	2f

1:
	ldr	r4, [r3, r0]
	str	r4, [r1, r0]
	adds	r0, r0, #4

2:
	adds	r4, r0, r1
	cmp	r4, r2
	bcc	1b

// clear BSS
	movs	r0, #0
	ldr	r1, =_sbss
	ldr	r2, =_ebss
	b	2f

1:
	str	r0, [r1]
	adds	r1, r1, #4

2:
	cmp	r1, r2
	bcc	1b

	bl	init_stm
// do not call main, main is maintained in init_stm() as user task
//	bl    main
	b	.
	.align 	4
	.size Reset_handler, .-Reset_handler
