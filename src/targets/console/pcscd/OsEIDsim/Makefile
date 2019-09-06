# use a correct default CFLAGS
ifeq ($(CFLAGS),)
CFLAGS = -O2 -g -Wall -fPIC -I.  `pkg-config libpcsclite --cflags`
else
CFLAGS += -Wall -fPIC -I. `pkg-config libpcsclite --cflags`
endif

version="0.0.1"

targets =  hex2bytes.c serial.c ifdhandler.c

all: libOsEIDsim.so

libOsEIDsim.so:  $(targets)
	rm -f $@
	$(CC) -shared $(CFLAGS) $(LDFLAGS) $(targets)  -o $@
	chmod -x $@
	mv $@ $@.$(version)

clean:
	rm -f $(targets)
	rm -f libOsEIDsim.so*
	rm -f Makefile.bak
	rm -f config.log
	rm -f *~

.PHONY: all clean
