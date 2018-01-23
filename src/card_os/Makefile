#-------------------------------------------------------------------
# card_os files
#-------------------------------------------------------------------
COMMON_TARGETS= $(BUILD)iso7816.o $(BUILD)myeid_emu.o $(BUILD)fs.o $(BUILD)ec.o $(BUILD)rsa.o $(BUILD)card.o $(BUILD)constants.o $(BUILD)aes.o $(BUILD)des.o $(BUILD)bn_lib.o

$(BUILD)iso7816.o:	card_os/iso7816.c
	$(CC) $(CFLAGS) $(HAVE) -o $(BUILD)iso7816.o -c card_os/iso7816.c -Icard_os

$(BUILD)myeid_emu.o:	card_os/myeid_emu.c
	$(CC) $(CFLAGS) $(HAVE) -o $(BUILD)myeid_emu.o -c card_os/myeid_emu.c -Icard_os

$(BUILD)fs.o:	card_os/fs.c
	$(CC) $(CFLAGS) $(HAVE) -o $(BUILD)fs.o -c card_os/fs.c -Icard_os

$(BUILD)ec.o:	card_os/ec.c
	$(CC) $(CFLAGS) $(HAVE) -o $(BUILD)ec.o -c card_os/ec.c -Icard_os

$(BUILD)rsa.o:	card_os/rsa.c card_os/rsa.h
	$(CC) $(CFLAGS) $(HAVE) -o $(BUILD)rsa.o -c card_os/rsa.c -Icard_os

$(BUILD)aes.o:	card_os/aes.c card_os/aes.h
	$(CC) $(CFLAGS) $(HAVE) -o $(BUILD)aes.o -c card_os/aes.c -Icard_os

$(BUILD)des.o:	card_os/des.c card_os/des.h
	$(CC) $(CFLAGS) $(HAVE) -o $(BUILD)des.o -c card_os/des.c -Icard_os

$(BUILD)card.o:	card_os/card.c
	$(CC) $(CFLAGS) -o $(BUILD)card.o -c card_os/card.c -Icard_os

$(BUILD)constants.o:	card_os/constants.h card_os/constants.c
	$(CC) $(CFLAGS) $(HAVE) -o $(BUILD)constants.o -c card_os/constants.c -Icard_os

$(BUILD)bn_lib.o:	card_os/bn_lib.h lib/generic/bn_lib.c
	$(CC) $(CFLAGS) $(HAVE) -o $(BUILD)bn_lib.o -c lib/generic/bn_lib.c -Icard_os

