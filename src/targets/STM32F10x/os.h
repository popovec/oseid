/*
    os.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015-2024 Peter Popovec, popovec.peter@gmail.com

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

    Various functions related to power management, task management...

*/

// called from main task if waiting for data from interrupt
void CPU_idle(void);

// this is used by CCID layer to restart card task
void CPU_do_restart_main(void);
