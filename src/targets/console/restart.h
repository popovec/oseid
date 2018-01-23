/*
    targets/console/restart.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2017 Peter Popovec, popovec.peter@gmail.com

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

    handler - restart of OsEID main

*/
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>

sigjmp_buf JumpBuffer;
void INThandler (int);

void
INThandler (int sig)
{
  signal (sig, INThandler);
  printf ("CTRL-C, card reset (type 'quit' to exit)\n");
  siglongjmp (JumpBuffer, 1);
}
