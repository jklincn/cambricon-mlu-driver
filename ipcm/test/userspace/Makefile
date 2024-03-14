CROSS_CC_PREFIX = $(__BUILDING_OPTS__)
CC  = $(CROSS_CC_PREFIX)gcc

all : ipcm_test
LDLIBS += -lpthread
LDLIBS += -lcndrv

CFLAGS += $(TARGET_CAMBRICON_CFLAGS)
LDFLAGS += $(TARGET_CAMBRICON_LDFLAGS)

TEST_SRC = \
	ipcm_test_arm.c

ipcm_test:
	$(CC) $(CFLAGS) $(LDFLAGS) $(TEST_SRC) -o ipcm_test $(LDLIBS)

clean:
	rm -rf ipcm_test
