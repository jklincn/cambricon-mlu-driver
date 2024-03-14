CROSS_CC_PREFIX = $(__BUILDING_OPTS__)
CC  = $(CROSS_CC_PREFIX)gcc

all : ipcm_server
LDLIBS += -lpthread
LDLIBS += -lcndrv

CFLAGS += $(TARGET_CAMBRICON_CFLAGS)
LDFLAGS += $(TARGET_CAMBRICON_LDFLAGS)

ccflags-y += -Wall -Werror

DAEMON_SRC = \
	ipcm_server.c

ipcm_server:
	$(CC) $(CFLAGS) $(LDFLAGS) $(DAEMON_SRC) -o ipcm_server $(LDLIBS)

clean:
	rm -rf ipcm_server
