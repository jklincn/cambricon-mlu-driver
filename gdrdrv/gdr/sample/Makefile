# note that pkg-config respects PKG_CONFIG_PATH, which can be used
# to pick libcheck from a user-defined path

NEUWARE_HOME ?= /usr/local/neuware

GDRAPI_INC	:= ../gdrlib
GDRAPI_LIB	:= ../gdrlib

COMMONCFLAGS := -O2
CFLAGS	+= $(COMMONCFLAGS)
CFLAGS	+= -I $(NEUWARE_HOME)/include -I $(GDRAPI_INC)
LDFLAGS += -L $(NEUWARE_HOME)/lib64 -L $(GDRAPI_LIB)
LIBS	:= -lcndrv -lpthread -lgdrapi

all: copybw copylat

copybw: copybw.o
	$(CC) -o $@ $^ $(LIBS) $(LDFLAGS)

copylat: copylat.o
	$(CC) -o $@ $^ $(LIBS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -c $< -o $@

clean:
	rm -f *.o $(EXES) *~ core.*
	rm -f copybw
	rm -f copylat
.PHONY: clean all
