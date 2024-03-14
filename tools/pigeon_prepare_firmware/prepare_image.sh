#!/bin/bash

#
# pack config original file IS "tools/fw_cfg_sample.xml"
#

#------Parameter parse
param_force_unzip_tar_pack=0
param_version="4.21.3"
param_upgrade_img=0
param_make_img=0
param_build_host_driver=0
param_load_host_driver=0
param_load_host_driver=0
param_load_host_driver_user_setting=""
load_host_driver_param_tbl=()

drv_major="4"
drv_minor="21"
drv_build="3"

VERSION=$drv_major.$drv_minor.$drv_build

function set_version()
{
	drv_build=${param_version##*.}
	drv_major=${param_version%%.*}
	drv_minor=${param_version#*.}
	drv_minor=${drv_minor%.*}

	VERSION=$drv_major.$drv_minor.$drv_build
	echo driver: ${VERSION}

	pushd ../../ > /dev/null
	sed -i "s/^#define DRV_MAJOR.*/#define DRV_MAJOR ($drv_major)/g" ./core/version.h
	sed -i "s/^#define DRV_MINOR.*/#define DRV_MINOR ($drv_minor)/g" ./core/version.h
	sed -i "s/^#define DRV_BUILD.*/#define DRV_BUILD ($drv_build)/g" ./core/version.h
	popd > /dev/null
}

function make_firmware_img()
{
	if [ $param_make_img -eq 0 ]; then
		return
	fi
	# 1. if the "firmware_image" exist, then it will no be updated.
	images_pkg=./firmware_image

	if [ $param_force_unzip_tar_pack -ne 0 ]; then
		echo "FORCE clean and reunzip tar pack ..."
		if [ -d $images_pkg ]; then
			rm -rf $images_pkg
		fi
	fi

	if [ ! -d ${images_pkg} ]; then
		echo "extra bsp & drv..."
		mkdir ${images_pkg}
		if [ ! -f release*.tar.bz2 ] || [ ! -f base_driver-*.tar.gz ]; then
			echo "ERROR: not bsp package or base_driver pakage"
			exit -1
		fi

		echo "prepare bsp ..."
		tar xf release*.tar.bz2
		cp release/images/* ${images_pkg}
		rm -rf release

		echo "prepeare base_drver ..."
		mkdir base_drv
		tar xf base_driver-*.tar.gz -C base_drv/
		./tools/make_ext4fs -b 1024 -l 64M base_drv.img base_drv/
		cp base_drv.img ${images_pkg}
		rm -rf base_drv/
		rm -rf base_drv.img

		echo "done ..."
		# Show the sub-imamges
		ls -al ${images_pkg}

	elif [ ! -f ${images_pkg}/Image ] || [ ! -f ${images_pkg}/cambr-ce3225v100-emmc.dtb ] || [ ! -f ${images_pkg}/bl31.bin ] || [ ! -f ${images_pkg}/rootfs_ext4.img ] || [ ! -f ${images_pkg}/base_drv.img ]; then
		echo "ERROR: Please check ${images_pkg} have all correct images List: Image cambr-ce325v100-emmc.dtb bl31.bin rootfs_ext4.img base_drv.img"
		exit -1;
	else
		echo "previous firmware_image exist and it's ok. if you need to update, please rm -rf ${images_pkg} & rerun $0"
	fi

	#........ Packing
	./tools/fw_pack --dir ${images_pkg} --config firmware_cfg.xml --output firmware_sys.img --version ${VERSION}

	#
	# Store back one
	#
	mkdir -p  lib
	mkdir -p  lib/firmware
	mkdir -p  lib/firmware/cambricon
	mkdir -p  lib/firmware/cambricon/ce3225
	cp firmware_sys.img  lib/firmware/cambricon/ce3225
}

function upgrade_firmware_img()
{
	if [ $param_upgrade_img -ne 0 ]; then
		if [ ! -d "/lib/firmware/cambricon/ce3225" ]; then
			sudo mkdir /lib/firmware/cambricon || exit 1
			sudo mkdir /lib/firmware/cambricon/ce3225 || exit 1
			sudo chmod 0777 /lib/firmware/cambricon/ce3225 || exit 1
		fi

		echo "upgrade firmware_sys.img ..."
		if [ ! -f firmware_sys.img ]; then
			if [ ! -f  lib/firmware/cambricon/ce3225/firmware_sys.img ]; then
				echo "Please make firmware_sys.img first!!!"
				exit 1
			fi
			cp lib/firmware/cambricon/ce3225/firmware_sys.img .
		fi
		sudo cp -rdf firmware_sys.img /lib/firmware/cambricon/ce3225/
		rm -rf firmware_sys.img
	fi
}

function build_host_driver()
{
	pushd ../../ > /dev/null
	if [ $param_build_host_driver -ne 0 ];then
		echo "build driver..."
		make clean && make
	fi
	popd > /dev/null
}

function prepare_host_driver_param_tbl()
{
	local tmp=""
	local next=""
	local i=0

	if [[ "$param_load_host_driver_user_setting" == "" ]]; then
		return 0
	fi
	tmp=$param_load_host_driver_user_setting
	next=$param_load_host_driver_user_setting
	while true
	do
		tmp=${tmp%;*}
		next=${next#*;}
		load_host_driver_param_tbl[$i]="$tmp"
		if [[ "$tmp" == "$next" ]]; then
			break
		fi
		tmp="$next"
		let "i+=1"
	done
}
function load_host_driver()
{
	if [ $param_load_host_driver -ne 0 ];then
		echo "load driver... < ${load_host_driver_param_tbl[@]} >"
		if [[ "`lsmod | grep camb`" != "" ]]; then
			echo "pre to unload cambricon_drv ..."
			sudo rmmod cambricon_drv
		fi
		sudo insmod cambricon-drv.ko $*
	fi
}


function usage()
{
	echo ""
	echo "Usage"
	echo ""
	echo "	-h|--help ....................... Show help information"
	echo "	-v|--version X.Y.Z .............. Set driver version"
	echo "	-m|--make 0/1 ................... To make firmware_sys.img (1 make. 0 Not)"
	echo "	-u|--upgrade 0/1 ................ Let upgrade firmware_sys.img (1 upgrade. 0 Not)"
	echo "	-f|--force ...................... FORCE make firmware_sys.img with reunziping tar pack forced!!!"
	echo "	-b|--build 0/1 .................. To build host driver (1 build host driver. 0 Not)"
	echo "	-l|--load 0/1 ................... To load host driver (1 load. 0 Not)(load host driver with param if needed)"
	echo "	-p|--param \"param1;param2\" .................. Set user setting parameter for load driver"
	echo "	EXP: \"isr_type=\"msix\"..NOTE: Attention to string param!!!"
	echo ""
}


#-------------------------------------------------------
#------------------------------------------------------- MAIN
#-------------------------------------------------------
ARGS=`getopt -o v:u:m:b:l:p:fh -l version:,upgrade:,make:,build:,load:,param:,force,help -n 'example.sh' -- "$@"`
eval set -- "${ARGS}"
while true
do
	case "$1" in
		-h|--help)
			usage
			exit 0
			;;
		-v|--version)
			param_version=$2
			echo "param_version : $param_version"
			shift 2
			;;
		-u|--upgrade)
			param_upgrade_img=$2
			echo "will upgrade image : $param_upgrade_img"
			shift 2
			;;
		-m|--make)
			param_make_img=$2
			echo "will make image : $param_make_img"
			shift 2
			;;
		-b|--build)
			param_build_host_driver=$2
			echo "will build host driver : $param_build_host_driver"
			shift 2
			;;
		-l|--load)
			param_load_host_driver=$2
			echo "Will load host dirver : $param_load_host_driver"
			shift 2
			;;
		-f|--force)
			param_force_unzip_tar_pack=1
			shift
			;;
		-p|--param)
			param_load_host_driver_user_setting="$2"
			echo "Load host dirver with param : ${param_load_host_driver_user_setting}"
			shift 2
			;;
		--)
			shift
			break
			;;
		*)
			echo "Invalid param"
			usage
			exit 1
			;;
		esac
done

#...... Update version
set_version

#....... Make Dir for firmware image
make_firmware_img

#........ Upgrade firmware_sys.img
upgrade_firmware_img

#........ make host driver
build_host_driver

#........ load host driver
prepare_host_driver_param_tbl
load_host_driver
