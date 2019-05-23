#!/bin/bash
#
#    targets/console/pcscd/OsEIDsim/run_pcscd.sh
#
#    This is part of OsEID (Open source Electronic ID)
#
#    Copyright (C) 2015-2019 Peter Popovec, popovec.peter@gmail.com
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    connect pcscd daemon to simulavr with OsEID card (generic simualtion,
#    not in simulavr)
#

mkdir -p tmp
DEV=$1
if [ $? -lt 1 ]; then
	socat -d -d pty,link=tmp/OsEIDsim.socket,raw,echo=0 "exec:build/console/console ...,pty,raw,echo=0" &
	DEV=`pwd`/tmp/OsEIDsim.socket
fi
sleep 0.2
echo 'FRIENDLYNAME      "OsEIDsim"' > tmp/reader.conf
echo 'DEVICENAME        '$DEV >> tmp/reader.conf
echo 'LIBPATH           '`pwd`/build/console/libOsEIDsim.so.0.0.1  >>tmp/reader.conf
echo 'CHANNELID         1' >>  tmp/reader.conf

/usr/sbin/pcscd -d -f -c `pwd`/tmp/reader.conf

