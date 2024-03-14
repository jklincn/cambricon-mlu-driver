###########################################################
# Set the include-path according to the defined interface.
###########################################################
include $(src)/config

ccflags-y += $(addprefix -D,$(foreach i,$(LIST),$(if $(findstring y,$($(i))),$(i))))
ccflags-y += -I$(src)/include -I$(src)/core -I$(src)/plat \
	-I$(src)/ \
	-I$(src)/plat/common/include \
	-I$(src)/monitor \
	-I$(src)/mm \
	-I$(src)/mm/include \
	-I$(src)/proc \
	-I$(src)/commu	\
	-I$(src)/log	\
	-I$(src)/commu/commu/	\
	-I$(src)/domain	\
	-I$(src)/domain/include	\
	-I$(src)/mig \
	-I$(src)/binn \
	-I$(src)/host_mcu_trans \
	-I$(obj)/pre_compile \
	-I$(src)/smlu \
	-I$(src)/gdma \
	-I$(src)/gdma/ce_api \
	-I$(src)/gdma/host_api \
	-I$(src)/gdma/rpc

ccflags-y += -Wall -Werror
ccflags-y += -Wno-array-bounds

ifeq ($(BUILD_MODE),debug)
ccflags-y += -D BASE_BOOT_MAX_TIME=720000
else
ccflags-y += -D BASE_BOOT_MAX_TIME=300
endif

BUILD_VERSION ?= 5.10.1

ccflags-y += -D DRV_MAJOR_VER=$(word 1,$(subst ., ,$(BUILD_VERSION)))
ccflags-y += -D DRV_MINOR_VER=$(word 2,$(subst ., ,$(BUILD_VERSION)))
ccflags-y += -D DRV_PATCH_VER=$(word 3,$(subst ., ,$(BUILD_VERSION)))

###########################################################
# Define build targets and what files to include.
###########################################################
TARGET_MODULE := cambricon-drv
obj-m += $(TARGET_MODULE).o

obj-$(CONFIG_GDRDRV_MODULE) += cambricon-gdrdrv.o
cambricon-gdrdrv-y = gdrdrv/gdrdrv.o

obj-$(CONFIG_PEERMEM_MODULE) += cambricon-peermem.o
cambricon-peermem-y = mlu_peer_memory/mlu_peer_mem.o

obj-$(CONFIG_UTIL_DRV_MODULE) += cambricon-util_drv.o
util_drv := $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/smlu/drv/*.c)))
cambricon-util_drv-y = $(util_drv)

module-y ?=
###########################################################
# Define bus layer
###########################################################
module-y += $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/plat/*.c)))

###########################################################
# Define core layer
###########################################################
module-y += $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/core/*.c)))

###########################################################
# Define cap sub-module
###########################################################
module-y += $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/cap/*.c)))

###########################################################
# Define pcie sub-module
###########################################################
module-$(CONFIG_CNDRV_PCIE) += \
	plat/pcie/mlu220_mlu270/cndrv_pci.o \
	plat/pcie/mlu290_ce3226/cndrv_pci.o \
	plat/pcie/mlu500/cndrv_pci.o \
	plat/pcie/mlu500/helmtia/plat_c50/cndrv_pci_c50.o \
	plat/pcie/mlu500/helmtia/plat_c50/cndrv_pci_c50_vf.o \
	plat/pcie/mlu370_pigeon/cndrv_pci.o \
	plat/pcie/mlu370_pigeon/haikouichthys/plat_c30s/cndrv_pci_c30s.o \
	plat/pcie/mlu370_pigeon/haikouichthys/plat_c30s/cndrv_pci_c30s_vf.o \
	plat/pcie/mlu370_pigeon/haikouichthys/plat_pigeon/cndrv_pci_pigeon.o \
	plat/pcie/mlu370_pigeon/haikouichthys/plat_pigeon/fw_manager_pigeon.o \
	plat/pcie/mlu290_ce3226/haikouichthys/plat_c20/cndrv_pci_c20.o \
	plat/pcie/mlu290_ce3226/haikouichthys/plat_c20/cndrv_pci_c20_vf.o \
	plat/pcie/mlu290_ce3226/hallucigenia/plat_ce3226/cndrv_pci_ce3226.o \
	plat/pcie/mlu290_ce3226/hallucigenia/plat_ce3226/fw_manager_ce3226.o \
	plat/pcie/mlu220_mlu270/hallucigenia/plat_c20l/cndrv_pci_c20l.o \
	plat/pcie/mlu220_mlu270/hallucigenia/plat_c20l/cndrv_pci_c20l_vf.o \
	plat/pcie/mlu220_mlu270/hallucigenia/plat_c20e/cndrv_pci_c20e.o

###########################################################
# Define cnhost_dev sub-module
###########################################################
module-y += $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/device/*.c)))

###########################################################
# Define mm sub-module
###########################################################
mm_src := $(src)/mm $(src)/mm/fa_mem $(src)/mm/delay_free $(src)/mm/mem_lib \
	  $(src)/mm/host_mem $(src)/mm/mem_rpc $(src)/mm/mem_compat $(src)/mm/mem_pgretire \
	  $(src)/mm/mem_vmm $(src)/mm/mem_perf
module-y += $(subst $(src)/,,$(patsubst %.c,%.o,$(foreach n,$(mm_src),$(wildcard $(n)/*.c))))

module-y += mm/hal/hal_llc/llc_common.o mm/hal/hal_smmu/smmu_common.o mm/hal/cn_mem_hal.o mm/mem_tools/camb_mm_tools.o mm/mem_tools/camb_mm_cp.o
module-${CONFIG_CNDRV_PCIE} += \
	mm/hal/hal_llc/llc_220.o \
	mm/hal/hal_llc/llc_270.o \
	mm/hal/hal_llc/llc_290.o \
	mm/hal/hal_llc/llc_370.o \
	mm/hal/hal_llc/llc_590.o \
	mm/hal/hal_smmu/smmu_220.o \
	mm/hal/hal_smmu/smmu_270.o \
	mm/hal/hal_smmu/smmu_290.o \
	mm/hal/hal_smmu/smmu_370.o \
	mm/hal/hal_smmu/smmu_3226.o \
	mm/hal/hal_smmu/smmu_590.o \
	mm/hal/hal_smmu/smmu_5223.o

module-${CONFIG_CNDRV_C20E_SOC} += mm/hal/hal_llc/llc_220.o
module-${CONFIG_CNDRV_PIGEON_SOC} += mm/hal/hal_llc/llc_5223.o

module-${CONFIG_CNDRV_EDGE} += \
	mm/mem_lib/camb_asm_cache.o \
	mm/mem_tools/camb_kern_test.o \
	mm/mem_ext/camb_mm_ext.o \
	mm/mem_ext/camb_mm_ext_remap.o \
	mm/mem_ext/camb_mm_kern_ext.o
###########################################################
# Define sbts sub-module
###########################################################
sbts_src := $(src)/sbts $(src)/sbts/idc $(src)/sbts/tcdp $(src)/sbts/task_topo
module-$(CONFIG_CNDRV_SBTS) += $(subst $(src)/,,$(patsubst %.c,%.o,$(foreach n,$(sbts_src),$(wildcard $(n)/*.c))))

###########################################################
# Define mig and binn sub-module
###########################################################
module-$(CONFIG_CNDRV_MIG) += $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/mig/*.c)))
module-y += $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/binn/*.c)))

###########################################################
# Define lpm sub-module
###########################################################
module-y += lpm/cndrv_lpm.o

###########################################################
# Define ctx sub-module
###########################################################
module-y += ctx/cndrv_ctx_ioctl.o

###########################################################
# Define gdma sub-module
###########################################################
gdma_src := $(src)/gdma $(src)/gdma/rpc $(src)/gdma/ce_api
module-y += $(subst $(src)/,,$(patsubst %.c,%.o,$(foreach n,$(gdma_src),$(wildcard $(n)/*.c))))

gdma_api_src := \
	$(src)/gdma/host_api \
	$(src)/gdma/host_api/plat/mlu370 \
	$(src)/gdma/host_api/plat/mlu500 \
	$(src)/gdma/host_api/plat/pigeon
module-$(CONFIG_CNDRV_HOST_GDMA) += \
	$(subst $(src)/,,$(patsubst %.c,%.o,$(foreach n,$(gdma_api_src),$(wildcard $(n)/*.c))))

###########################################################
# Define fw sub-module
###########################################################
module-y += fw/serv_stat.o

fw_src := $(src)/fw $(src)/fw/plat
module-$(CONFIG_CNDRV_FW) += \
	$(subst $(src)/,,$(patsubst %.c,%.o,$(foreach n,$(fw_src),$(wildcard $(n)/*.c))))

###########################################################
# Define monitor sub-module
###########################################################
monitor_common := $(src)/monitor $(src)/monitor/pmu_version $(src)/monitor/xid $(src)/monitor/time
module-y += $(subst $(src)/,,$(patsubst %.c,%.o,$(foreach n,$(monitor_common),$(wildcard $(n)/*.c))))
module-y += \
	monitor/axi_monitor/cndrv_axi_monitor.o			\
	monitor/highrate/cndrv_monitor_highrate.o		\
	monitor/highrate/cndrv_monitor_common.o			\
	monitor/cndev/cndev_server.o 					\
	monitor/cndev/cndev_device.o 					\
	monitor/cndev/cndev_common.o

module-$(CONFIG_CNDRV_PCIE) +=						\
	monitor/highrate/cndrv_mlu370_highrate.o		\
	monitor/highrate/cndrv_mlu500_highrate.o		\
	monitor/highrate/cndrv_mlu580_highrate.o		\
	monitor/highrate/cndrv_mlu590_highrate.o		\
	monitor/axi_monitor/cndrv_axi_monitor_mlu200.o	\
	monitor/axi_monitor/cndrv_axi_monitor_mlu270.o	\
	monitor/axi_monitor/cndrv_axi_monitor_mlu220.o	\
	monitor/axi_monitor/cndrv_axi_monitor_mlu290.o	\
	monitor/axi_monitor/cndrv_axi_monitor_mlu370.o	\
	monitor/axi_monitor/cndrv_axi_monitor_mlu580.o	\
	monitor/axi_monitor/cndrv_axi_monitor_mlu590.o	\
	monitor/cndev/cndev_mlu270.o					\
	monitor/cndev/cndev_mlu220.o					\
	monitor/cndev/cndev_mlu290.o					\
	monitor/cndev/cndev_mlu590.o					\
	monitor/cndev/cndev_mlu580.o					\
	monitor/cndev/cndev_mlu370.o

module-$(CONFIG_CNDRV_C20E_SOC) += 					\
	monitor/axi_monitor/cndrv_axi_monitor_mlu200.o	\
	monitor/axi_monitor/cndrv_axi_monitor_mlu220.o	\
	monitor/cndev/cndev_mlu220.o

module-$(CONFIG_CNDRV_CE3226_SOC) += 				\
	monitor/highrate/cndrv_ce3226_highrate.o 		\
	monitor/axi_monitor/cndrv_axi_monitor_ce3226.o	\
	monitor/cndev/cndev_ce3226.o

module-$(CONFIG_CNDRV_PIGEON_SOC) += 				\
	monitor/highrate/cndrv_pigeon_highrate.o 		\
	monitor/axi_monitor/cndrv_axi_monitor_pigeon.o	\
	monitor/cndev/cndev_pigeon.o

module-$(CONFIG_CNDRV_PCIE_ARM_PLATFORM) +=			\
	monitor/cndev/cndev_mlu590.o					\
	monitor/cndev/cndev_mlu580.o					\
	monitor/cndev/cndev_mlu370.o

###########################################################
# Define exception management sub-module
###########################################################
module-$(CONFIG_CNDRV_MNT) += $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/expmnt/*.c)))

###########################################################
# Define mcu sub-module
###########################################################
module-y += mcu/cndrv_mcu_main.o \
         mcu/cndrv_mcu_info.o

module-$(CONFIG_CNDRV_PCIE) += 	\
	mcu/cndrv_mcu_mlu270.o		\
	mcu/cndrv_mcu_mlu220.o		\
	mcu/cndrv_mcu_mlu290.o		\
	mcu/cndrv_mcu_mlu590.o		\
	mcu/cndrv_mcu_mlu580.o		\
	mcu/cndrv_mcu_mlu370.o

module-$(CONFIG_CNDRV_C20E_SOC) += mcu/cndrv_mcu_mlu220.o
module-$(CONFIG_CNDRV_CE3226_SOC) += mcu/cndrv_mcu_ce3226.o
module-$(CONFIG_CNDRV_PIGEON_SOC) += mcu/cndrv_mcu_pigeon.o

###########################################################
# Define qos sub-module
###########################################################
module-y += noc/qos.o noc/qos_info.o

###########################################################
# Define attr sub-module
###########################################################
module-y += attr/cndrv_attr.o	\
	attr/cndrv_attr_ioctl.o

module-$(CONFIG_CNDRV_PCIE) += 	\
	attr/cndrv_attr_mlu220.o	\
	attr/cndrv_attr_mlu270.o	\
	attr/cndrv_attr_mlu290.o	\
	attr/cndrv_attr_mlu590.o	\
	attr/cndrv_attr_mlu580.o	\
	attr/cndrv_attr_mlu370.o

module-$(CONFIG_CNDRV_C20E_SOC) += attr/cndrv_attr_mlu220.o
module-$(CONFIG_CNDRV_CE3226_SOC) += attr/cndrv_attr_ce3226.o
module-$(CONFIG_CNDRV_PIGEON_SOC) += attr/cndrv_attr_pigeon.o

###########################################################
# Define mcc sub-module
###########################################################
mcc_src := $(src)/mcc $(src)/mcc/host_mcu_trans
module-$(CONFIG_CNDRV_MCC) += $(subst $(src)/,,$(patsubst %.c,%.o,$(foreach n,$(mcc_src),$(wildcard $(n)/*.c))))

###########################################################
# Define proc sub-module
###########################################################
module-$(CONFIG_CNDRV_PROC) += $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/proc/*.c)))

###########################################################
# Define platform sub-module
###########################################################
module-${CONFIG_CNDRV_EDGE} += \
	plat/platform/cndrv_edge.o	\
	plat/platform/cndrv_edge_async.o\
	plat/platform/cndrv_edge_dma.o  \

module-${CONFIG_CNDRV_C20E_SOC} += plat/platform/cndrv_edge_c20e.o
module-${CONFIG_CNDRV_CE3226_SOC} += plat/platform/cndrv_edge_ce3226.o
module-${CONFIG_CNDRV_PIGEON_SOC} += plat/platform/cndrv_edge_pigeon.o
module-${CONFIG_CNDRV_PCIE_ARM_PLATFORM} += plat/platform/cndrv_edge_pcie_arm_dev.o

###########################################################
# Define commu sub-module
###########################################################
module-y += commu/commu_napi.o

commu_src := $(src)/commu $(src)/commu/commu
module-$(CONFIG_CNDRV_COMMU) += $(subst $(src)/,,$(patsubst %.c,%.o,$(foreach n,$(commu_src),$(wildcard $(n)/*.c))))

###########################################################
# Define ipcm sub-module
###########################################################
include $(src)/ipcm/config.host
module-$(CONFIG_CNDRV_IPCM) += $(HOST_IPCM_SRC)

###########################################################
# Define domain sub-module
###########################################################
domain_src := $(src)/domain $(src)/domain/dmlib $(src)/domain/test $(src)/domain/resource
module-y += $(subst $(src)/,,$(patsubst %.c,%.o,$(foreach n,$(domain_src),$(wildcard $(n)/*.c))))

###########################################################
# Define vuart sub-module
###########################################################
module-$(CONFIG_CNDRV_VUART) += $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/log/*.c)))

###########################################################
# Define i2c sub-module
###########################################################
module-$(CONFIG_CNDRV_I2C) += $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/i2c/*.c)))

###########################################################
# Define smlu sub-module
###########################################################
module-$(CONFIG_CNDRV_SMLU) += $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/smlu/*.c)))

###########################################################
# Define norflash sub-module
###########################################################
module-$(CONFIG_CNDRV_NOR) += $(subst $(src)/,,$(patsubst %.c,%.o,$(wildcard $(src)/nor/*.c)))

# add all module-y to objs
$(TARGET_MODULE)-objs += $(module-y)

###########################################################
# IB build for kernel symbols
###########################################################
OFA_DIR := /usr/src/ofa_kernel
OFA_CANDIDATES = $(OFA_DIR)/$(ARCH)/$(KERNELRELEASE) $(OFA_DIR)/$(KERNELRELEASE) $(OFA_DIR)/default /var/lib/dkms/mlnx-ofed-kernel
MLNX_OFED_KERNEL := $(shell for d in $(OFA_CANDIDATES); do \
                              if [ -d "$$d" ]; then \
                                echo "$$d"; \
                                exit 0; \
                              fi; \
                            done; \
                            echo $(OFA_DIR) \
                     )

ifneq ($(shell test -d $(MLNX_OFED_KERNEL) && echo "true" || echo "" ),)
    ccflags-y += -I$(MLNX_OFED_KERNEL)/include -I$(MLNX_OFED_KERNEL)/include/rdma
    KBUILD_EXTRA_SYMBOLS := $(MLNX_OFED_KERNEL)/Module.symvers
endif

###########################################################
# Precompile adapts to various kernel versions
###########################################################
CN_PRECOMPILE_SCRIPT := $(src)/tools/pre_compile.sh
CN_PRECOMPILE_CMD := /bin/sh $(CN_PRECOMPILE_SCRIPT)
CN_PRECOMPILE_CFLAGS := $(shell $(CN_PRECOMPILE_CMD) build_cflags \
  '$(PRE_COMPILE_CC)' '$(ARCH)' '$(KERNEL_SOURCES)' '$(KERNEL_OUTPUT)' \
  '$(CONFIG_CNDRV_PCIE_PLATFORM)')

CN_PRECOMPILE_TEST_HEADERS := $(obj)/pre_compile/macros.h
CN_PRECOMPILE_TEST_HEADERS += $(obj)/pre_compile/functions.h
CN_PRECOMPILE_TEST_HEADERS += $(obj)/pre_compile/symbols.h
CN_PRECOMPILE_TEST_HEADERS += $(obj)/pre_compile/types.h
CN_PRECOMPILE_TEST_HEADERS += $(obj)/pre_compile/generic.h

##################################################################################
# Generate a header file for a single pre_compile compile test. Each compile test
# header depends on pre_compile.sh, as well as the generated pre_compile/headers.h
# file, which is included in the compile test preamble.
##################################################################################
$(obj)/pre_compile/compile-tests/%.h: $(CN_PRECOMPILE_SCRIPT)
	@mkdir -p $(obj)/pre_compile/compile-tests
	@echo "  PRECOMPILE: $(notdir $*)"
	@$(CN_PRECOMPILE_CMD) compile_tests '$(PRE_COMPILE_CC)' '$(CN_PRECOMPILE_CFLAGS)'\
	 '$(ARCH)' '$(KERNEL_OUTPUT)'\
	 $(notdir $*) > $@

#################################################################################
# Concatenate a pre_compile/*.h header from its constituent compile test headers
#
# $(1): The name of the concatenated header
# $(2): The list of compile tests that make up the header
#################################################################################
define CN_GENERATE_COMPILE_TEST_HEADER
 $(obj)/pre_compile/$(1).h: $(addprefix $(obj)/pre_compile/compile-tests/,$(addsuffix .h,$(2)))
	@mkdir -p $(obj)/pre_compile
	@# concatenate /dev/null to prevent cat from hanging when $$^ is empty
	@cat $$^ /dev/null > $$@
endef

################################################################################
# Generate the pre_compile compile test headers from the lists of compile tests
# provided by the module-specific Kbuild files.
################################################################################
CN_PRECOMPILE_FUNCTION_COMPILE_TESTS += get_user_pages \
					get_user_pages_remote \
					vm_map_ram \
					mmap_read_lock \
					mmap_write_lock \
					map_vm_area \
					fcheck \
					llist_reverse_order \
					pci_cleanup_aer_uncorrect_error_status \
					time64_to_tm \
					ioremap_wc \
					cpumask_clear_cpu \
					uart_handle_sysrq_char \
					kernel_read
CN_PRECOMPILE_GENERIC_COMPILE_TESTS ?=
CN_PRECOMPILE_MACRO_COMPILE_TESTS += access_ok \
					topology_sibling_cpumask
CN_PRECOMPILE_SYMBOL_COMPILE_TESTS += ib_peer_memory_symbols
CN_PRECOMPILE_TYPE_COMPILE_TESTS ?=

$(eval $(call CN_GENERATE_COMPILE_TEST_HEADER,functions,$(CN_PRECOMPILE_FUNCTION_COMPILE_TESTS)))
$(eval $(call CN_GENERATE_COMPILE_TEST_HEADER,generic,$(CN_PRECOMPILE_GENERIC_COMPILE_TESTS)))
$(eval $(call CN_GENERATE_COMPILE_TEST_HEADER,macros,$(CN_PRECOMPILE_MACRO_COMPILE_TESTS)))
$(eval $(call CN_GENERATE_COMPILE_TEST_HEADER,symbols,$(CN_PRECOMPILE_SYMBOL_COMPILE_TESTS)))
$(eval $(call CN_GENERATE_COMPILE_TEST_HEADER,types,$(CN_PRECOMPILE_TYPE_COMPILE_TESTS)))

# For any object files that depend on pre_compile, declare the dependency here.
$(addprefix $(obj)/,$($(TARGET_MODULE)-objs) gdrdrv/gdrdrv.o mlu_peer_memory/mlu_peer_mem.o $(util_drv)): | $(CN_PRECOMPILE_TEST_HEADERS)
