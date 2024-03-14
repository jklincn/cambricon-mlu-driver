#!/bin/bash

#process is a function for single 'ep to rc', setting aer and error report.
process(){
	dev=$1
	if [ ! -e "/sys/bus/pci/devices/$dev" ]; then
		echo "Error: device $dev not found"
		exit 1
	fi
	#find the previous port.
	port=$(basename $(dirname $(readlink "/sys/bus/pci/devices/$dev")))

	if [ ! -e "/sys/bus/pci/devices/$port" ]; then
		echo "Error: device $port not found"
		exit 1
	fi

	tag=0
	while [ -e "/sys/bus/pci/devices/$port" ]
	do
		tag=$[tag+1]
		if [ $tag -eq 1 ]; then
			echo "EP: device $dev be found"
			#open aer of EP
			setpci -s $dev ECAP_AER+8.L=00000000
			setpci -s $dev ECAP_AER+14.L=00000000
			#close error report of EP
			temp1=$(setpci -s $dev 88.B)
			setpci -s $dev 88.B=$[temp1&0xF0]

			echo "DSP: device $port be found"
			#open aer of DSP
			setpci -s $port ECAP_AER+8.L=00000000
			setpci -s $port ECAP_AER+14.L=00000000
			#close error report of DSP
			temp2=$(setpci -s $port CAP_EXP+8.B)
			setpci -s $port CAP_EXP+8.B=$[temp2&0xF0]
		fi
		port_last=$port 
		port=$(basename $(dirname $(readlink "/sys/bus/pci/devices/$port")))
	done
	echo "RC: device $port_last be found"
	#close aer of RC
	setpci -s $port_last ECAP_AER+8.L=FFFFFFFF
}



if [ -z "$1" ]; then
	#if no parameter, auto find all card BDF with domain
	raw=$(lspci -D | grep cabc)
else
	#if has parameter, find this BDF with domain
	raw=$(lspci -Ds $1)
fi

if [ -z "$raw" ]; then
	echo "Error: no EP"
	exit 1
fi

count=0
for i in $raw
do
	if [ $[count%5] -eq 0 ]; then
		process $i
		echo '------------'
	fi
	count=$[count+1]
done


