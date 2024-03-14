PWD :=$(shell pwd)
ifndef TOP_DIR
	TOP_DIR	:= $(PWD)
endif
include $(TOP_DIR)/config
OUTPUT_DIR ?= $(PWD)

ifneq ($(PWD),$(OUTPUT_DIR))
$(shell mkdir -p $(OUTPUT_DIR) && touch $(OUTPUT_DIR)/Makefile)
endif

#KBUILD_PARAMS need to distinguish platform
ifeq ($(CONFIG_CNDRV_PCIE_PLATFORM),y)
  #insmod cndrv_host in host of pcie platform.
  KERNEL_UNAME ?=$(shell uname -r)
  KERNEL_MODLIB ?= /lib/modules/$(KERNEL_UNAME)
  KERNEL_SOURCES ?= $(shell test -d $(KERNEL_MODLIB)/source && echo $(KERNEL_MODLIB)/source || echo $(KERNEL_MODLIB)/build)
  ARCH ?= $(shell uname -m | sed -e 's/i.86/i386/' \
    -e 's/armv[0-7]\w\+/arm/' \
    -e 's/aarch64/arm64/' \
    -e 's/ppc64le/powerpc/' \
  )

  #################################################################
  # cross compile example:
  # make ARCH=xxx CROSS_COMPILE=xxx KERN_DIR=xxx KERNEL_SOURCES=xxx
  #################################################################
  KERN_DIR ?= $(KERNEL_MODLIB)/build
  KBUILD_PARAMS += ARCH=$(ARCH)
  KBUILD_PARAMS += KERNEL_OUTPUT=$(KERN_DIR)
  KBUILD_PARAMS += KERNEL_SOURCES=$(KERNEL_SOURCES)
  ifdef CROSS_COMPILE
    KBUILD_PARAMS += PRE_COMPILE_CC=$(CROSS_COMPILE)gcc
    STRIP := $(CROSS_COMPILE)strip
  else
    KBUILD_PARAMS += PRE_COMPILE_CC=cc
    STRIP := strip
  endif

else ifeq ($(CONFIG_CNDRV_EDGE_PLATFORM),y)
  #insmod cndrv_host in device of edge platform.
  ifneq (,$(filter $(BOARD_NAME), c20e_soc ce3226_soc))
    KBUILD_PARAMS ?=
    KBUILD_PARAMS += ARCH=arm64
    KBUILD_PARAMS += CROSS_COMPILE=aarch64-linux-gnu-
    KBUILD_PARAMS += PRE_COMPILE_CC=aarch64-linux-gnu-gcc
  else ifneq (,$(filter $(BOARD_NAME), ce3225_soc))
    KBUILD_PARAMS ?=
    KBUILD_PARAMS += ARCH=arm64
    KBUILD_PARAMS += CROSS_COMPILE=aarch64-linux- #gcc9.3
    KBUILD_PARAMS += PRE_COMPILE_CC=aarch64-linux-gcc
  endif
  KERNEL_SOURCES ?= $(KERN_DIR)
  KBUILD_PARAMS += KERNEL_OUTPUT=$(KERN_DIR)
  KBUILD_PARAMS += KERNEL_SOURCES=$(KERNEL_SOURCES)

else ifeq ($(CONFIG_CNDRV_PCIE_ARM_PLATFORM),y)
  #insmod cndrv_host in device of pcie platform.
  KERNEL_SOURCES ?= $(KERN_DIR)
  KBUILD_PARAMS ?=
  KBUILD_PARAMS += ARCH=arm64
  KBUILD_PARAMS += CROSS_COMPILE=aarch64-linux-gnu-
  KBUILD_PARAMS += PRE_COMPILE_CC=aarch64-linux-gnu-gcc
  KBUILD_PARAMS += KERNEL_OUTPUT=$(KERN_DIR)
  KBUILD_PARAMS += KERNEL_SOURCES=$(KERNEL_SOURCES)
endif

ifeq ($(COVERAGE_ENABLE),1)
    ccflags-y += -fprofile-arcs -ftest-coverage
endif

all:
	@env BOARD_NAME=$(BOARD_NAME) $(MAKE) -j EXTRA_CFLAGS=-g $(KBUILD_PARAMS) -C $(KERN_DIR) M=$(OUTPUT_DIR) src=$(PWD) modules && $(STRIP) -g $(OUTPUT_DIR)/cambricon-drv.ko

clean:
	rm -rf *.ko
	@find . -type f -name '*.o' -delete
	@find . -type f -name '*.mod' -delete
	@find . -type f -name '*.cmd' -delete
	@find . -type f -name '*.o.ur-safe' -delete
	@find . -type f -name '*.o.d' -delete
	rm -rf *.mod.c
	@rm -f Module.symvers
	@rm -f modules.order
	@rm -rf pre_compile
