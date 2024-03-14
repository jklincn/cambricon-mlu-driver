KERN_DIR ?=

ifneq ($(KERNELRELEASE),)
obj-m := rpmsg_ipc_demo.o
else

OUTPUT_DIR ?= $(PWD)

ifneq ($(PWD),$(OUTPUT_DIR))
$(shell mkdir -p $(OUTPUT_DIR) && touch $(OUTPUT_DIR)/Makefile)
endif

ccflags-y += -I$(PWD)/../../

KBUILD_PARAMS ?=
KBUILD_PARAMS += ARCH=arm64
KBUILD_PARAMS += CROSS_COMPILE=aarch64-linux-gnu-
KBUILD_PARAMS += PRE_COMPILE_CC=aarch64-linux-gnu-gcc

PHONY +=ipcm_ipc_demo

ipcm_ipc_demo:
	$(OPTION) $(MAKE) $(TARGET_CAMBRICON_CFLAGS) $(FLAG) $(KBUILD_PARAMS) -C $(KERN_DIR) M=$(OUTPUT_DIR) src=$(PWD) modules && $(STRIP) -S $(OUTPUT_DIR)/rpmsg_ipc_demo.ko

PHONY += clean
clean:
	rm -rf *.ko
	@find . -type f -name '*.o' -delete
	@find . -type f -name '*.mod' -delete
	@find . -type f -name '*.cmd' -delete
	rm -rf *.mod.c
	@rm -f Module.symvers
	@rm -f modules.order

.PHONY: $(PHONY)

endif
