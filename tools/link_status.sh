#!/bin/bash

#process is a function for single 'ep to rc', setting aer and error report.
process(){
	dev=$1
	if [ ! -e "/sys/bus/pci/devices/$dev" ]; then
		echo "Error: device $dev not found"
		exit 1
	fi
	topo=$(readlink "/sys/bus/pci/devices/$dev")
	topo=${topo#*pci} && topo=${topo#*/}
	echo '(RC)'${topo//'/'/-->}'(EP)'
	topo=${topo//'/'/' '}
	for bdf in $topo
	do
		echo '----'$bdf
		lnkcap=$(sudo lspci -s $bdf -vvv | grep -i width | grep -i lnkcap)
		lnksta=$(sudo lspci -s $bdf -vvv | grep -i width | grep -i lnksta)
		info=$(sudo lspci -s $bdf -vvv | grep -i maxreadreq)
		maxpayload=${info%%,*} && maxpayload=$(echo ${maxpayload/MaxPayload/MaxPayload:})
		maxreadreq=${info#*,} && maxreadreq=${maxreadreq/MaxReadReq/MaxReadReq:}
		echo '   '$lnkcap
		echo '   '$lnksta
		echo '    '$maxpayload
		echo '   '$maxreadreq
	done
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
		echo '----------------'
	fi
	count=$[count+1]
done
