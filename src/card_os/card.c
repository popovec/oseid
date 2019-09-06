/*
    card.c

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

    main

*/
#include <stdint.h>
#include <stdlib.h>
#include "rnd.h"
#include "card_io.h"
#include "iso7816.h"
#include "myeid_emu.h"
#include "fs.h"

#ifdef CARD_RESTART
#include "restart.h"
#endif

int
main (void)
{
#ifdef CARD_RESTART
#include "restart.c"
#endif

  //initialize filesystem
  fs_init ();
  //initialize random number generator
  rnd_init ();
  //initialize myeid emulation (not valid security env)
  security_env_set_reset (NULL);
  // initialize iso part of card
  response_clear ();
  // initialize card IO and send ATR
  card_io_init ();

  for (;;)
    card_poll ();
  return 0;
}
