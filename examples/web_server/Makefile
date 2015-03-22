# Copyright (c) 2015 Cesanta Software
# All rights reserved

PROG = web_server

POLARSSL_PATH = /usr/local
POLARSSL_INCPATH = $(POLARSSL_PATH)/include
POLARSSL_LIBPATH = $(POLARSSL_PATH)/lib
POLARSSL_LIBNAME = mbedtls

INCDIR = -I./../../ -I$(POLARSSL_INCPATH)
SOURCES = $(PROG).c mongoose.c ../../polarssl_compat.c
CFLAGS = -W -Wall -I../.. -pthread -g -O0 $(CFLAGS_EXTRA) -DNS_ENABLE_SSL $(INCDIR)
LDFLAGS = -L$(POLARSSL_LIBPATH) -l$(POLARSSL_LIBNAME)
#

$(PROG): $(SOURCES)
	$(CC) -o $(PROG) $(SOURCES) $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf $(PROG) *.exe *.dSYM *.obj *.exp .*o *.lib
