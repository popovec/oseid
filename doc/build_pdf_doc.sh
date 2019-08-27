#!/bin/bash

git clone https://github.com/popovec/popovec.github.io
mv popovec.github.io/OsEID/images/ .
rm -rf popovec.github.io
a2x -vv -a revnumber="pdfdraft" -a revdate="`date`" -f pdf doc.txt
