#!/bin/bash

dev=$1

if [ -z "$dev" ]; then
	echo "Error: no device specified"
	exit 1
fi

if [ ! -e "/sys/bus/pci/devices/$dev" ]; then
	dev="0000:$dev"
fi

if [ ! -e "/sys/bus/pci/devices/$dev" ]; then
	echo "Error: device $dev not found"
	exit 1
fi

port=$(basename $(dirname $(readlink "/sys/bus/pci/devices/$dev")))

if [ ! -e "/sys/bus/pci/devices/$port" ]; then
	echo "Error: device $port not found"
	exit 1
fi

while [ -e "/sys/bus/pci/devices/$port" ]
do
	echo "device $port be found"
	#acs=$(setpci -s $port ECAP_ACS+6.w)
	sleep 1
	#setpci -s $port ECAP_ACS+6.w=$(printf "%04x" $(("0x$acs" | 0x40)))
	setpci -s $port ECAP_ACS+6.w=0x0
	port=$(basename $(dirname $(readlink "/sys/bus/pci/devices/$port")))
done
