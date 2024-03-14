#!/bin/bash
iova=$1
input_param_count=$#
iomem_list=`cat /proc/iomem`

#variable flag represents if iova is in iomem range
flag=n

line=`echo "${iomem_list}" | wc -l`
addr_start_list=`echo "${iomem_list}" | awk -F '-' '{print $1}' | awk '{print $1}'`
addr_end_list=`echo "${iomem_list}" | awk -F '-' '{print $2}' | awk '{print $1}'`

function is_in_interval(){
	if [ $((16#${iova})) -ge $((16#${addr_start})) ] &&
		[ $((16#${iova})) -le $((16#${addr_end})) ]
	then
		tmp=0
	else
		tmp=1
	fi
}

function para_check(){
	if [ ${input_param_count} -ne 1 ]; then
		echo "invalid input parameters"
		echo "usage: sudo $0 [iova]"
		exit 1
	fi
}

function para_normalization(){
	prefix=${iova:0:2}
	if [ ${prefix} == "0x" ] || [ ${prefix} == "0X" ]; then
		iova_tmp=${iova:2}
		iova=${iova_tmp}
	fi
}

#check if input parameters are valid
para_check

#normalization input addr with 0x or 0X
para_normalization

#check if iova is in range of iomem
for i in `seq 1 $line`
do
	addr_start=`echo "${addr_start_list}" | sed -n "${i}p"`
	addr_end=`echo "${addr_end_list}" | sed -n "${i}p"`

	#check if iova is in [addr_start, addr_end]
	is_in_interval
	if [ ${tmp} -eq 0 ]; then
		flag=y
		echo "${iomem_list}" | sed -n "${i}p"
	fi
done

if [ ${flag} == "n" ]; then
	echo "${iova} is not in iomem range"
fi
