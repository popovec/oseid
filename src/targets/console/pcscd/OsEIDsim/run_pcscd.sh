#!/bin/bash

DEV=$1
if [ $? -lt 1 ]; then
	socat -d -d pty,link=tmp/OsEIDsim.socket,raw,echo=0 "exec:build/console/console ...,pty,raw,echo=0" &
	DEV=`pwd`/tmp/OsEIDsim.socket
fi
sleep 0.2
mkdir -p tmp
echo 'FRIENDLYNAME      "OsEIDsim"' > tmp/reader.conf
echo 'DEVICENAME        '$DEV >> tmp/reader.conf
echo 'LIBPATH           '`pwd`/build/console/libOsEIDsim.so.0.0.1  >>tmp/reader.conf
echo 'CHANNELID         1' >>  tmp/reader.conf

/usr/sbin/pcscd -d -f -c `pwd`/tmp/reader.conf

