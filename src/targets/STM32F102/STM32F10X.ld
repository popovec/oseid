ENTRY(Reset_handler)

/* flash size is specified in Makefile (depends on MCU) */

MEMORY
{
    FLASH ( rx )          : ORIGIN = 0x08000000, LENGTH = CFG_CODE_SIZE
    RAM ( rxw )           : ORIGIN = 0x20000000, LENGTH = CFG_RAM_SIZE
}

_ram_end_ = ORIGIN(RAM) + LENGTH(RAM) -1 ;
_estack = (_ram_end_ - 7);
_estack &= 0xfffffff8;
_user_stack = _estack;
_user_stack -= 1024;

SECTIONS
{
  .vector_table :
  {
    . = ALIGN(4);
    KEEP (*(.vector_table))
    . = ALIGN(4);
  } >FLASH

  .text :
  {
    . = ALIGN(4);
    *(.text)
    *(.text*)
    . = ALIGN(4);
  } >FLASH

  .ARM.extab :
  {
    *(.ARM.extab* .gnu.linkonce.armextab.*)
  } > FLASH
  exidx_start = .;

  .ARM.exidx :
    {
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > FLASH
    __exidx_end = .;

  .rodata :
  {
    . = ALIGN(4);
    *(.rodata)
    *(.rodata*)
    . = ALIGN(4);
  } >FLASH

  _sidata = .;
  .data : AT(_sidata)
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data)
    *(.data*)
    _edata = .;
    . = ALIGN(4);
  } >RAM

  .bss :
  {
    . = ALIGN(4);
    _sbss = .;
    *(.bss)
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } >RAM

  end = . ;
  _end =  . ;
}
