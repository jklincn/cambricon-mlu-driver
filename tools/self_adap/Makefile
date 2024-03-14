ccflags-y += -D_FILE_OFFSET_BITS=64 -O2 -g -Wall  -Wextra  -Wwrite-strings \
		-Wno-unused-result -Wno-int-in-bool-context -Wno-sign-compare \
		-ffunction-sections -fdata-sections -Wl,-gc-sections -D_GNU_SOURCE -std=c99

CUR_DIR=.

CC ?= gcc
LDFLAGS += -pthread
CFLAGS += -I ../../core \
          -I ../../include \
          -I ../bw_sample

all : pcie_copy d2d_copy p2p_copy complex

.PHONY : clean

pcie_copy : pcie_copy.o ../bw_sample/common.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o pcie_copy pcie_copy.o ../bw_sample/common.o

d2d_copy : d2d_copy.o ../bw_sample/common.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o d2d_copy d2d_copy.o ../bw_sample/common.o

p2p_copy : p2p_copy.o ../bw_sample/common.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o p2p_copy p2p_copy.o ../bw_sample/common.o

complex : complex.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o complex complex.o

clean:
	@-rm -f pcie_copy
	@-rm -f d2d_copy
	@-rm -f p2p_copy
	@-rm -f complex  rcd*.log
	@find . -type f -name '*.o' -delete
