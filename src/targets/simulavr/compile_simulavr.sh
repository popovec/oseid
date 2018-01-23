#!/bin/bash
set -e
(
mkdir -p build/simulavr
cp targets/simulavr/oseid-simulavr.patch build/simulavr/oseid-simulavr.patch
cd build/simulavr
rm -rf simulavr*
apt-get source simulavr
cd simulavr-0.1.2.2
find .|grep Makefile.in|xargs rm
rm aclocal.m4
rm configure
aclocal
echo "9" > debian/compat
patch -p 1 < ../oseid-simulavr.patch
touch NEWS
sed 's/YFLAGS/AM_YFLAGS/g' < src/disp-vcd/Makefile.am >  src/disp-vcd/Makefile.am.tmp
mv src/disp-vcd/Makefile.am.tmp src/disp-vcd/Makefile.am
sed 's/LFLAGS/AM_LFLAGS/g' < src/disp-vcd/Makefile.am >  src/disp-vcd/Makefile.am.tmp
mv src/disp-vcd/Makefile.am.tmp src/disp-vcd/Makefile.am
sed 's/YFLAGS/AM_YFLAGS/g' < src/disp-vcd/Makefile.am >  src/disp-vcd/Makefile.am.tmp
mv src/disp-vcd/Makefile.am.tmp src/disp-vcd/Makefile.am
sed 's/LFLAGS/AM_LFLAGS/g' < src/disp-vcd/Makefile.am >  src/disp-vcd/Makefile.am.tmp
mv src/disp-vcd/Makefile.am.tmp src/disp-vcd/Makefile.am
sed 's/CFLAGS/AM_CFLAGS/g' < Makefile_AVR_Rules >  Makefile_AVR_Rules.tmp
mv Makefile_AVR_Rules.tmp Makefile_AVR_Rules
automake --add-missing
autoconf
fakeroot debian/rules binary
)
cp build/simulavr/simulavr-0.1.2.2/src/simulavr targets/simulavr/simulavr-oseid
