EESchema Schematic File Version 4
LIBS:OsEID-cache
EELAYER 26 0
EELAYER END
$Descr A4 11693 8268
encoding utf-8
Sheet 1 1
Title "OsEID (AVR128DA32)"
Date "2020-08-13"
Rev "V1.0"
Comp "<popovec.peter@gmail.com>"
Comment1 ""
Comment2 ""
Comment3 ""
Comment4 ""
$EndDescr
Text GLabel 7600 3700 0    60   Input ~ 0
IO
Text GLabel 8550 3700 2    60   Input ~ 0
CLK
Text GLabel 8550 3500 2    60   Input ~ 0
Ucc
Text GLabel 8800 3600 2    60   Input ~ 0
Reset
Text GLabel 7650 3500 0    60   Input ~ 0
Gnd
Text GLabel 7400 3600 0    60   Input ~ 0
Vpp
Wire Wire Line
	7400 3600 7700 3600
Wire Wire Line
	8550 3500 8500 3500
Wire Wire Line
	8500 3600 8800 3600
Wire Wire Line
	8550 3700 8500 3700
Text GLabel 4150 1900 0    60   Input ~ 0
Vpp
Text GLabel 4650 5850 0    60   Input ~ 0
Gnd
Text GLabel 5100 1600 2    60   Input ~ 0
Ucc
Text GLabel 6150 2750 2    60   Input ~ 0
IO
Text GLabel 6150 2650 2    60   Input ~ 0
Reset
Text GLabel 6150 2550 2    60   Input ~ 0
CLK
Wire Wire Line
	7700 3500 7650 3500
Wire Wire Line
	7700 3700 7600 3700
$Comp
L OsEID_AVR_v1.0:CONN_3X2 P1
U 1 1 5F343A5E
P 8100 3650
F 0 "P1" H 8100 4000 50  0000 C CNN
F 1 "ISO7816-3_pads_6" H 8100 3916 40  0000 C CNN
F 2 "OsEID_footprints:ISO7816-3_pads_6" H 8050 3450 60  0001 C CNN
F 3 "" H 8100 3650 60  0000 C CNN
	1    8100 3650
	1    0    0    -1  
$EndComp
Wire Wire Line
	4150 1900 4750 1900
Wire Wire Line
	4750 1900 4750 2050
Wire Wire Line
	5100 1600 5000 1600
Wire Wire Line
	5000 1600 5000 2050
Wire Wire Line
	4800 5650 4800 5850
Wire Wire Line
	4800 5850 4650 5850
NoConn ~ 5650 5250
NoConn ~ 5650 5150
NoConn ~ 5650 5050
NoConn ~ 5650 4950
NoConn ~ 5650 4850
NoConn ~ 5650 4750
NoConn ~ 5650 4650
NoConn ~ 5650 3550
NoConn ~ 5650 2350
NoConn ~ 5650 2450
NoConn ~ 5650 2850
NoConn ~ 5650 3850
NoConn ~ 5650 4450
NoConn ~ 5650 4350
NoConn ~ 5650 4250
NoConn ~ 5650 4150
NoConn ~ 5650 4050
NoConn ~ 5650 3950
NoConn ~ 5650 3750
$Comp
L OsEID_AVR_v1.0:AVR128DA32-EPT U1
U 1 1 5F349ACB
P 5050 3850
F 0 "U1" H 4520 3896 50  0000 R CNN
F 1 "AVR128DA32-EPT" H 4520 3805 50  0000 R CNN
F 2 "OsEID_footprints:TQFP-32_7x7mm_P0.8mm" H 5100 6050 50  0001 C CIN
F 3 "" H 5050 3850 50  0001 C CNN
	1    5050 3850
	1    0    0    -1  
$EndComp
NoConn ~ 5650 3350
NoConn ~ 5650 3450
Wire Wire Line
	5650 2750 6150 2750
Wire Wire Line
	6150 2650 5650 2650
Wire Wire Line
	5650 2550 6150 2550
NoConn ~ 5650 2950
NoConn ~ 5650 3050
NoConn ~ 5650 3250
$Comp
L OsEID_AVR_v1.0:Conn_01x03-Connector_Generic J1
U 1 1 5F3ED353
P 5100 6250
F 0 "J1" V 4973 6430 50  0000 L CNN
F 1 "Conn_01x03-Connector_Generic" V 5064 6430 50  0000 L CNN
F 2 "OsEID_footprints:PIN_ARRAY_3X1" H 5100 6250 50  0001 C CNN
F 3 "" H 5100 6250 50  0001 C CNN
	1    5100 6250
	0    1    1    0   
$EndComp
Wire Wire Line
	5000 6050 5000 5650
Text GLabel 5400 5850 2    60   Input ~ 0
Ucc
Text GLabel 5400 5950 2    60   Input ~ 0
Vpp
Wire Wire Line
	5100 6050 5100 5850
Wire Wire Line
	5100 5850 5400 5850
Wire Wire Line
	5400 5950 5200 5950
Wire Wire Line
	5200 5950 5200 6050
Text Notes 5275 1900 0    50   ~ 0
AVDD and VDD are internally connected together \nsource: preliminary datasheet AVR128DA\nmicrochip doc,  40002183A.pdf,  page 14
$EndSCHEMATC
