/*
    bn_lib.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2021 Peter Popovec, popovec.peter@gmail.com

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

    big number arithmetics

    All functions are "generic", able to run on 8 bit CPU.  It is assumed,
    all these functions are in ASM for target architecture, therefore all
    functions are weak.  Use this code only for debug/test purposes, or if
    target architecture does not have optimized functions.

    lot of routines use "mod_len" variable) to get actual length of big number
    please  use only 8 bytes steps in bn length (ASM optimized routines uses
    step in length 64 bits)

   please write this code for you platform in ASM/C to prevent side channel
   attack (timing.. ), this code must run in constant time


*/
#include "rsa.h"
#ifndef __BN_LIB__
#define __BN_LIB__

// set arithmetics length (number of bits)
uint8_t bn_set_bitlen(uint16_t blen);

void  bn_swap(void *a, void*b);
uint8_t __attribute__ ((weak)) bn_is_zero (void * k);
uint8_t __attribute__ ((weak)) bn_neg (void *a);

uint8_t __attribute__ ((weak)) bn_add_v (void * r, void * a, uint8_t len, uint8_t carry );
uint8_t __attribute__ ((weak)) bn_add (void * r, void * a );

uint8_t __attribute__ ((weak)) bn_sub_v (void * r, void * a, void *b, uint8_t len );
uint8_t __attribute__ ((weak)) bn_sub (void * r, void * a,void *b );
uint8_t __attribute__ ((weak)) bn_sub_long (void *r, void *a, void *b);

uint8_t  __attribute__ ((weak)) bn_cmpGE (void * c, void * d);
uint8_t __attribute__ ((weak)) bn_abs_sub (void *r, void *a, void *b);

void __attribute__ ((weak)) bn_add_mod (void * r, void * a, void * mod);
void __attribute__ ((weak)) bn_sub_mod (void * r, void * a, void * mod);


uint8_t __attribute__ ((weak)) bn_shift_L_v (void * r, uint8_t len);
uint8_t __attribute__ ((weak)) bn_shiftl (void * r);

uint8_t __attribute__ ((weak)) bn_shift_R_v_c (void *r, uint8_t len, uint8_t carry);
uint8_t __attribute__ ((weak)) bn_shiftr (void *r);
uint8_t __attribute__ ((weak)) bn_shiftr_long (void *r);
uint8_t __attribute__ ((weak)) bn_shiftr_c (void *r, uint8_t carry);
uint8_t __attribute__((weak)) bn_shift_R_signed (void *r);

void __attribute__ ((weak)) bn_mul_v (void * r, void * a, void * b, uint8_t len);

void __attribute__ ((weak)) bn_mod (void *result, void *mod);
void __attribute__ ((weak)) bn_mod_half (void *result, void *mod);

uint8_t __attribute__ ((weak)) bn_inv_mod (void * r, void * c, void * p);

#ifndef __BN_LIB_SELF__
extern uint8_t mod_len;
extern uint16_t bn_real_bit_len;
extern uint8_t bn_real_byte_len;
#endif


uint16_t __attribute__((weak)) bn_count_bits (void *n);
uint8_t __attribute__((weak)) bn_shift_R_v_signed (void *r, uint8_t len);

#endif
