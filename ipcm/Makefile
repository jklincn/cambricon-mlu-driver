
$(warning "BOARD_NAME: "$(BOARD_NAME))
ifneq (,$(filter $(BOARD_NAME), c30s c50 c50s))
KERN_DIR ?=
PWD :=$(shell pwd)
OUTPUT_DIR ?= $(PWD)

ifneq ($(PWD),$(OUTPUT_DIR))
$(shell mkdir -p $(OUTPUT_DIR) && touch $(OUTPUT_DIR)/Makefile)
endif

MOD_DIR = $(PWD)
TEST_DIR = $(PWD)/test/userspace/
DAEMON_DIR = $(PWD)/daemon/
TEST_KERNEL = $(PWD)/test/kernelspace

KBUILD_PARAMS ?=
KBUILD_PARAMS += ARCH=arm64
KBUILD_PARAMS += CROSS_COMPILE=aarch64-linux-gnu-
KBUILD_PARAMS += PRE_COMPILE_CC=aarch64-linux-gnu-gcc

all:
	$(OPTION) $(MAKE) $(FLAG) $(KBUILD_PARAMS) -C $(KERN_DIR) M=$(OUTPUT_DIR) src=$(PWD) modules
	cd $(TEST_KERNEL) && $(MAKE)
	$(STRIP) -S $(OUTPUT_DIR)/ipcm_drv.ko
	cd $(DAEMON_DIR) && $(MAKE) && cd $(TEST_DIR) && $(MAKE) && cd $(MOD_DIR)

clean:
	$(MAKE) $(KBUILD_PARAMS) -C $(KERN_DIR) M=$(OUTPUT_DIR) src=$(PWD) clean
	cd $(TEST_KERNEL) && $(MAKE) clean
	cd $(DAEMON_DIR) && $(MAKE) clean && cd $(TEST_DIR) && $(MAKE) clean && cd $(MOD_DIR)

else
all:
	@echo "skip build ipcm drv/lib/bin"
clean:
	@echo "skip build ipcm drv/lib/bin"
endif
