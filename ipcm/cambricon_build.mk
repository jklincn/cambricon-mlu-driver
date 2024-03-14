$(warning "BOARD_NAME: "$(BOARD_NAME))
CAMBRICON_BUILD_MAKE_OPTS =     \
         __BUILDING_OPTS__=aarch64-linux-gnu-

CAMBRICON_BUILD_FOR_COMPILING_HEADERS = ./cambr_ipcm.h

ifneq (,$(filter $(BOARD_NAME), c30s c50 c50s))
CAMBRICON_BUILD_DEPENDENCIES = linux driver-api #need by ipcm_server/ipcm_test

CAMBRICON_BUILD_INSTALL_MODULES = ./ipcm_drv.ko
CAMBRICON_BUILD_INSTALL_EXECS = ./daemon/ipcm_server
CAMBRICON_BUILD_INSTALL_TEST_EXECS = ./test/userspace/ipcm_test
CAMBRICON_BUILD_INSTALL_TEST_MODULES = ./test/kernelspace/rpmsg_ipc_demo.ko
endif

$(eval $(cambricon-cambricon-generic-package))
