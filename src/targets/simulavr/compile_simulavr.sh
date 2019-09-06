#!/bin/bash
set -e
(
mkdir -p build/simulavr-oseid
cp targets/simulavr/oseid-simulavr.patch build/simulavr-oseid/oseid-simulavr.patch
cd build/simulavr-oseid
rm -rf simulavr*
apt-get source simulavr/stretch
cd simulavr-0.1.2.2
find .|grep Makefile.in|xargs rm
rm aclocal.m4
rm configure
echo "9" > debian/compat
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
sed 's/INCLUDES/AM_CPPFLAGS/g' < Makefile_AVR_Rules > Makefile_AVR_Rules.tmp
mv Makefile_AVR_Rules.tmp Makefile_AVR_Rules
sed 's/AC_DEFUN(TROTH_ENABLE_TESTS,\[/AC_DEFUN(\[TROTH_ENABLE_TESTS\],\[/g' < configure.ac > configure.ac.tmp
mv configure.ac.tmp configure.ac

patch -p 1 < ../oseid-simulavr.patch


aclocal
automake --add-missing
autoconf
fakeroot debian/rules binary
)
cp build/simulavr-oseid/simulavr-0.1.2.2/src/simulavr targets/simulavr/simulavr-oseid
