#!/bin/bash
#example 15:00.0
dev=$1
#range A value = 1 or 2 (50 μs to 100 μs / 1 ms to 10 ms)
#range B value = 5 0r 6 (16 ms to 55 ms / 65 ms to 210 ms)
#range C value = 9 or 10 (260 ms to 900 ms / 1 s to 3.5 s)
#range D value = 13 0r 14 (4 s to 13 s / 17 s to 64 s)
value=$2
if [ -z "$dev" ]; then
	echo "Error: no device specified"
	exit 1
fi
if [ -z $value ]; then
	echo "default value 0"
	value=0
fi
if [ ! -e "/sys/bus/pci/devices/$dev" ]; then
	dev="0000:$dev"
fi

if [ ! -e "/sys/bus/pci/devices/$dev" ]; then
	echo "Error: device $dev not found"
	exit 1
fi

devctl=$(setpci -s $dev CAP_EXP+28.w)

setpci -s $dev CAP_EXP+28.w=$(printf "%04x" $value)
setpci -s $dev CAP_EXP+28.w
lspci -vvs $dev |grep completion -i
