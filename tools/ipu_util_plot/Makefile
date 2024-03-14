ccflags-y += -D_FILE_OFFSET_BITS=64 -O2 -g -Wall  -Wextra  -Wwrite-strings \
		-Wno-unused-result -Wno-int-in-bool-context -Wno-sign-compare \
		-ffunction-sections -fdata-sections -Wl,-gc-sections -D_GNU_SOURCE -std=c99

CUR_DIR=.
CC ?= gcc

all : ipu_util_plot
.PHONY : clean

ipu_util_plot: ipu_util_plot.o
	$(CC) *.c -o ipu_util_plot

clean:
	@-rm -f ipu_util_plot
	@find . -type f -name '*.o' -delete
