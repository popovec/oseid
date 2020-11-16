#!/bin/bash
#
#    targets/simulavr/run_pcscd.sh
#
#    This is part of OsEID (Open source Electronic ID)
#
#    Copyright (C) 2015,2019 Peter Popovec, popovec.peter@gmail.com
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

GDB=0

echo $#
if [ $# -ge 1 ]; then
	if [ $1 == "gdb" ]; then
		GDB=1
	fi
fi

if [ `id -u` -ne 0 ]; then
	echo "Sorry, this work only for root user"
	exit 1
fi


OsEID_DIR=`pwd`

mkdir -p "${OsEID_DIR}/tmp"
touch "${OsEID_DIR}/tmp/OsEIDsim.socket"
DEV=$1
if [ $? -lt 1 ]; then
	if [ -x "${OsEID_DIR}/targets/simulavr/simulavr-oseid" ]; then
	  if [ $GDB -eq 0 ]; then
		socat -d -d pty,link=${OsEID_DIR}/tmp/OsEIDsim.socket,raw,echo=0 "exec:'${OsEID_DIR}/targets/simulavr/simulavr-oseid -d OsEID128 -e build/simulavr/card.eeprom.bin build/simulavr/card.bin',pty,raw,echo=0" &
	  else
		socat -d -d pty,link=${OsEID_DIR}/tmp/OsEIDsim.socket,raw,echo=0 "exec:'${OsEID_DIR}/targets/simulavr/simulavr-oseid -g -d OsEID128',pty,raw,echo=0" &
	  fi
	else
	  which simulavr-oseid
	  if [ $? -ne 0 ]; then
		echo "Unable to execute simulavr-oseid, please read targets/simulavr/Readme"
		exit 1
	  fi
	  if [ $GDB -eq 0 ]; then
		socat -d -d pty,link=${OsEID_DIR}/tmp/OsEIDsim.socket,raw,echo=0 "exec:'simulavr-oseid -d OsEID128 -e build/simulavr/card.eeprom.bin build/simulavr/card.bin',pty,raw,echo=0" &
	  else
		socat -d -d pty,link=${OsEID_DIR}tmp/OsEIDsim.socket,raw,echo=0 "exec:'simulavr-oseid -g -d OsEID128',pty,raw,echo=0" &
	  fi
	fi
	DEV="${OsEID_DIR}/tmp/OsEIDsim.socket"
fi
sleep 1
echo 'FRIENDLYNAME      "OsEIDsim"' > "${OsEID_DIR}/tmp/reader.conf"
echo 'DEVICENAME        '$DEV >> "${OsEID_DIR}/tmp/reader.conf"
echo 'LIBPATH           '${OsEID_DIR}/build/console/libOsEIDsim.so.0.0.1  >> "${OsEID_DIR}/tmp/reader.conf"
echo 'CHANNELID         1' >>  "${OsEID_DIR}/tmp/reader.conf"

/usr/sbin/pcscd -d -f -c "${OsEID_DIR}/tmp/reader.conf"
