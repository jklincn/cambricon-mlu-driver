ccflags-y += -D_FILE_OFFSET_BITS=64 -O2 -g -Wall  -Wextra  -Wwrite-strings \
		-Wno-unused-result -Wno-int-in-bool-context -Wno-sign-compare \
		-ffunction-sections -fdata-sections -Wl,-gc-sections -D_GNU_SOURCE -std=c99

CUR_DIR=.

NUMA_DISABLE=1
ifeq ($(NUMA_DISABLE),1)
CFLAGS += -DNUMA_DISABLE
else
LDFLAGS += -lnuma
endif

CC ?= gcc
LDFLAGS += -pthread
CFLAGS += -I ../../core \
          -I ../../include

all : bw_sample p2p_sample
.PHONY : clean

bw_sample : bw_sample.o common.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o bw_sample bw_sample.o common.o

p2p_sample : p2p_sample.o common.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o p2p_sample p2p_sample.o common.o

clean:
	@-rm -f bw_sample
	@-rm -f p2p_sample
	@find . -type f -name '*.o' -delete
