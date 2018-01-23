#!/bin/bash
#
#    targets/simulavr/run_pcscd.sh
#
#    This is part of OsEID (Open source Electronic ID)
#
#    Copyright (C) 2015,2017 Peter Popovec, popovec.peter@gmail.com
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
#    connect pcscd daemon to simulavr with OsEID card
#
if [ `id -u` -ne 0 ]; then
	echo "Sorry, this work only for root user"
	exit 1
fi
mkdir -p `pwd`tmp
touch `pwd`/tmp/OsEIDsim.socket
DEV=$1
if [ $? -lt 1 ]; then
	if [ -x targets/simulavr/simulavr-oseid ]; then
	  socat -d -d pty,link=tmp/OsEIDsim.socket,raw,echo=0 "exec:'targets/simulavr/simulavr-oseid -g -d OsEID128',pty,raw,echo=0" &
	else
	  which simulavr-oseid
	  if [ $? -ne 0 ]; then
		echo "Unable to execute simulavr-oseid, please read targets/simulavr/Readme"
		exit 1
	  fi
	  socat -d -d pty,link=tmp/OsEIDsim.socket,raw,echo=0 "exec:'simulavr-oseid -g -d OsEID128',pty,raw,echo=0" &
	fi
	DEV=`pwd`/tmp/OsEIDsim.socket
fi
sleep 1
echo 'FRIENDLYNAME      "OsEIDsim"' > `pwd`/tmp/reader.conf
echo 'DEVICENAME        '$DEV >> `pwd`/tmp/reader.conf
echo 'LIBPATH           '`pwd`/build/console/libOsEIDsim.so.0.0.1  >>`pwd`/tmp/reader.conf
echo 'CHANNELID         1' >>  tmp/reader.conf

/usr/sbin/pcscd -d -f -c `pwd`/tmp/reader.conf
