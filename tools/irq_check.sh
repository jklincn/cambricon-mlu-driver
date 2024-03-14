#!/bin/bash

VERSION="0.9.2"

secondry_handle_en=0
try_use_secondry_handle=0

MAX_SPT=128
sel_id=255
sel_bdf=""
specify=0
msix_en=0
res_to_rtn=0

check_ret=()

curt_numa_online=0
curt_numa_begin=0
curt_numa_end=0

function init_ret()
{
	local i

	for((i=0;i<$MAX_SPT;i++))
	do
		check_ret[$i]="PASS"
	done
}

function show_ret()
{
	local i

	echo ""
	echo "check result:"
	echo "....................................."
	for ((i=0;i<$mlu_cnt;i++))
	do
		if [ $specify -ne 0 ]; then
			if [ $sel_id -ne $i ] && [ "$sel_bdf" != "${cabc_dev_bdf_list[$i]}" ]; then
				continue
			fi
		fi
		echo "card $i [${cabc_dev_bdf_list[$i]}] : ${check_ret[$i]}"
		if [ "${check_ret[$i]}" = "FAILED" ]; then
			let "res_to_rtn=$res_to_rtn+1"
		fi
	done
	echo ""
}

#-------NUMA INFO
numa_node_cnt=0
numa_node_info_tbl=()
function get_cpu_numa_info()
{
	local numa_node_cnt_tmp=0
	local numa_begin=0
	local numa_end=0
	local numa_node_info=""
	local i=0

	#NOTE: The lscpu maybe not work well on all Machine - old method in v0.9.
	#numa_node_cnt_tmp=`lscpu | grep 'NUMA node('`
	#numa_node_cnt_tmp=${numa_node_cnt_tmp##* }
	#numa_node_cnt=$numa_node_cnt_tmp

	#NOTE Here we treat the numa only have one continus group. In future complex machine can put improvement here.
	numa_node_cnt_tmp=`cat /sys/devices/system/node/online`
	curt_numa_online=$numa_node_cnt_tmp
	echo "numa cnt = $numa_node_cnt_tmp"
	numa_begin=${numa_node_cnt_tmp%%-*}
	numa_end=${numa_node_cnt_tmp##*-}
	curt_numa_begin=$numa_begin
	curt_numa_end=$numa_end
	echo "numa : node-$numa_begin -----> node-$node-$numa_end"
	if [ $numa_begin -eq $numa_end ]; then
		echo ">>>>>>> NUMA Node LessEqual 1, Not need check! <<<<<<<<"
		exit 3
	fi

	for((i=$numa_begin;i<=$numa_end;i++))
	do
	{
		#NOTE: The lscpu maybe not work well on all Machine - old method in v0.9.
		#numa_node_info=`lscpu | grep "NUMA node$i CPU"`

		numa_node_info=`cat /sys/devices/system/node/node$i/cpulist`
		numa_node_info=${numa_node_info##* }
		numa_node_info_tbl[$i]="$numa_node_info"
		echo "numa_$i : ${numa_node_info_tbl[$i]}"
	}
	done
}

#-----------DEVICE INFO
mlu_cnt=0
mlu_locate_info_tbl=()
cabc_dev_bdf_list=()
cabc_dev_name_list=()
mlu_locate_info_cpulist_tbl=()

function prepare_cabc_devices()
{
	local dst="00:00.0"
	local i=0
	local j=0
	local IFS_OLD=$IFS

	IFS=$'\n'

	lspci | grep cabc > tmp_pci_cbac

	for line in `cat tmp_pci_cbac`
	do
		echo "<$line>"
		cabc_dev_bdf_list[$i]=${line%% Processing*}
		cabc_dev_name_list[$i]=${line##*Device }
		let "i=$i+1"
	done
	for((j=0;j<$i;j++))
	do
		echo "${cabc_dev_bdf_list[$j]} <> ${cabc_dev_name_list[$j]}"
	done
	rm tmp_pci_cbac
	IFS=$IFS_OLD

	return $i
}

function get_mlu_numa_location()
{
	local i=0
	local mlu_locate_tmp=0
	local bdf=0
	local bus=0
	local device=0
	local function=0
	local DM_BDF=""

	prepare_cabc_devices
	mlu_cnt=$?

	for((i=0;i<$mlu_cnt;i++))
	do
	{

		#NOTE: The lscpu maybe not work well on all Machine - old method in v0.9.
		#mlu_locate_tmp=`lspci -s ${cabc_dev_bdf_list[$i]} -vv | grep "NUMA node"`

		bdf=${cabc_dev_bdf_list[$i]}
		bus=${bdf%:*}
		bdf=${bdf#*:}
		device=${bdf%.*}
		bdf=${bdf#*.}
		function=${bdf%.*}
		DM_BDF="0000:$bus:$device.$function"
		mlu_locate_tmp=`cat /sys/bus/pci/devices/${DM_BDF}/numa_node`
		mlu_locate_tmp=${mlu_locate_tmp##* }
		mlu_locate_info_tbl[$i]=$mlu_locate_tmp
		echo "ID_$i [${cabc_dev_name_list[$i]} ${cabc_dev_bdf_list[$i]}] node  :  ${mlu_locate_info_tbl[$i]}"

		#NOTE some machine maybe have no correct numa info, this cpulist is secondry handle.
		if [ $secondry_handle_en -ne 0 ]; then
			mlu_locate_info_cpulist_tbl[$i]=`cat /sys/bus/pci/devices/${DM_BDF}/local_cpulist`
		fi
	}
	done

}

#-----------------DEVICE'irq INFO
mlu_irq_info_tbl=()
mlu_irq_locate_info_tbl=()
function get_mlu_irq_num()
{
	local i=0
	local head=0
	local mlu_irq_tmp=""

	for((i=0;i<$mlu_cnt;i++))
	do
	{
		#THIS CAN NOT COVER MSIX MODE
		#mlu_irq_tmp=`lspci -vvv -s ${cabc_dev_bdf_list[$i]} | grep "Interrupt:"`
		#mlu_irq_tmp=${mlu_irq_tmp##* }

		if [ $msix_en -eq 0 ]; then
			mlu_irq_tmp=`cat /sys/bus/pci/devices/0000:${cabc_dev_bdf_list[$i]}/irq`
		else
			ls /sys/bus/pci/devices/0000:${cabc_dev_bdf_list[$i]}/msi_irqs > tmp_irqs
			local IFS_OLD=$IFS
			IFS=$'\n'
			head=1
			for line in `cat tmp_irqs`
			do
				if [ $head -eq 1 ]; then
					mlu_irq_tmp="$line"
					head=0
				else
					mlu_irq_tmp="$mlu_irq_tmp ""$line"
				fi
			done
			IFS=$IFS_OLD
			rm tmp_irqs
		fi
		mlu_irq_info_tbl[$i]=$mlu_irq_tmp
		echo "ID_$i'irq [${cabc_dev_name_list[$i]} ${cabc_dev_bdf_list[$i]}]  =  <${mlu_irq_info_tbl[$i]}>"
	}
	done
}

function get_mlu_irq_location()
{
	local i=0
	local mlu_irq_locate_tmp=""
	local irq_num=""
	local last_irqs_num=""
	local head_begin=0

	for((i=0;i<$mlu_cnt;i++))
	do
	{
		irq_num=${mlu_irq_info_tbl[$i]}
		head_begin=1
		while true
		do
			last_irqs_num=${irq_num#* }
			irq_num=${irq_num%% *}
			echo "---irq_num $irq_num    ...last_irqs_num $last_irqs_num"
			mlu_irq_locate_tmp=`cat /proc/irq/$irq_num/smp_affinity_list`
			if [ $head_begin -eq 1 ]; then
				mlu_irq_locate_info_tbl[$i]="$mlu_irq_locate_tmp"
			else
				mlu_irq_locate_info_tbl[$i]="${mlu_irq_locate_info_tbl[$i]};""$mlu_irq_locate_tmp"
			fi
			echo "ID_$i'irq_${mlu_irq_info_tbl[$i]} [${cabc_dev_name_list[$i]} ${cabc_dev_bdf_list[$i]}] cpu group  :  ${mlu_irq_locate_info_tbl[$i]}"
			if [ "$irq_num" = "$last_irqs_num" ]; then
				break
			fi
			head_begin=0
			irq_num=$last_irqs_num
		done
	}
	done
}

#--------------------Check Handle
group_p=()
group_p_cnt=0
group_s=()
group_s_cnt=0
function to_compare()
{
	local left_p=0
	local right_p=0
	local left_s=0
	local right_s=0
	local i=0
	local j=0
	local covered=0

	for((i=0;i<$group_s_cnt;i++))
	do
		left_s=${group_s[$i]}
		right_s=${group_s[$i]}
		left_s=${left_s%-*}
		right_s=${right_s#*-}
		echo "	Son : [$left_s $right_s] <<< ${group_s[$i]} @ $i"
		if [ "$right_s" = "" ]; then
			right_s=$left_s
		fi
		covered=0
		for((j=0;j<$group_p_cnt;j++))
		do
			left_p=${group_p[$j]}
			right_p=${group_p[$j]}
			left_p=${left_p%-*}
			right_p=${right_p#*-}
			echo "	Parent : [$left_p $right_p] <<< ${group_p[$j]} @ $j"
			if [ "$right_p" = "" ]; then
				right_p=$left_p
			fi
			echo "		[$left_s $right_s] s.VS.p [$left_p  $right_p]"
			if [ $left_s -ge $left_p ] && [ $right_s -le $right_p ]; then
				covered=1
				break
			fi

		done
		if [ $covered -eq 0 ]; then
			return 1
		fi
	done

	return 0
}
function is_mlu_node_include_mluirq_node()
{
	local mlu_id=$1
	local mlu_node=$2
	local mluirq_node_cpu=$3
	local pre=""
	local next=""
	local group_p=()
	local group_s=()
	local i=0
	local ret=0
	local cpu_grp=""
	local last_cpu_grps=""

	echo "------------------------------------------------------------"
	echo "[mlu : $mlu_id] at node ($mlu_node)"
	echo ""
	if [ $mlu_node -lt $curt_numa_begin ] || [ $mlu_node -gt $curt_numa_end ]; then
		if [ $secondry_handle_en -ne 0 ]; then
			echo "mlu_node(${mlu_node})_cpu : ${mlu_locate_info_cpulist_tbl[$mlu_id]}  --- cpulist secondry handle when no node info."
			try_use_secondry_handle=1
		else
			echo "mlu_node(${mlu_node})_cpu : NULL."
		fi
	else
		echo "mlu_node(${mlu_node})_cpu : ${numa_node_info_tbl[$mlu_node]}"
	fi
	echo ""
	echo "mluirq_node_cpu : $mluirq_node_cpu"
	echo ""

	if [ $mlu_node -lt $curt_numa_begin ] || [ $mlu_node -gt $curt_numa_end ]; then
		echo "The MLU Do not have correct NUMA node($mlu_node) information(beyong <$curt_numa_begin $curt_numa_end>)"
		if [ $try_use_secondry_handle -ne  0 ] ;then
			echo "The next will use cpulist as secondry handle..."
		else
			echo ""
			return 255
		fi
	fi

	i=0
	if [ $try_use_secondry_handle -ne 0 ]; then
		cpu_info=${mlu_locate_info_cpulist_tbl[$mlu_id]}
	else
		cpu_info=${numa_node_info_tbl[$mlu_node]}
	fi
	while true
	do
		pre=${cpu_info%,*}
		next=${cpu_info#*,}
		group_p[$i]=$pre
		echo "	mlu cpu : $i = ${group_p[$i]}   [$cpu_info  $pre  $next]"
		let "i=$i+1"
		if [ "$next" = "$pre" ]; then
			break
		fi
		cpu_info=$next
	done
	group_p_cnt=$i

	cpu_grp=$mluirq_node_cpu
	while true
	do
		last_cpu_grps=${cpu_grp#*;}
		cpu_grp=${cpu_grp%%;*}

		i=0
		cpu_info=$cpu_grp
		while true
		do
			pre=${cpu_info%,*}
			next=${cpu_info#*,}
			group_s[$i]=$pre
			echo "	mluirq cpu : $i = ${group_s[$i]}   [$cpu_info  $pre  $next]"
			let "i=$i+1"
			if [ "$next" = "$pre" ]; then
				break
			fi
			cpu_info=$next
		done
		group_s_cnt=$i

		to_compare
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "Meet fail mark"
			break
		fi
		if [ "$last_cpu_grps" = "$cpu_grp" ]; then
			break
		fi
		cpu_grp="$last_cpu_grps"
	done
	return $ret
}
function check_mlu_irq_banding_relation()
{
	local i=0
	local is_incnlude=0

	echo ""
	echo "Checking......"

	for((i=0;i<$mlu_cnt;i++))
	do
	{
		if [ $specify -ne 0 ]; then
			if [ $sel_id -ne 255 ]; then
				if [ $sel_id -ne $i ]; then
					continue
				fi
			else
				if [ "$sel_bdf" != "${cabc_dev_bdf_list[$i]}" ]; then
					continue
				fi
			fi
		fi
		is_mlu_node_include_mluirq_node  $i  "${mlu_locate_info_tbl[$i]}"  "${mlu_irq_locate_info_tbl[$i]}"
		if [ $? -ne 0 ]; then
			echo "FAILED CHECK"
			check_ret[$i]="FAILED"
		else
			echo "PASS CHECK"
		fi
	}
	done
	echo ""
}

function usage()
{
	echo ""
	echo "Version $VERSION"
	echo "Usage:"
	echo "sudo $0 -h|--help ------------------------- get help"
	echo "sudo $0 -b|--bdf B:D.F -------------------- check one card via its B:D.F"
	echo "sudo $0 -i|--id  Index -------------------- check one card via its ID"
	echo "sudo $0 -t|--typeisr intx/msi/msix -------- set the isr type of device uses"
	echo "sudo $0 -a|--assist Number ---------------- set 'Number' handle which is as assister when node is fail"
	echo "sudo $0 ----------------------------------- No parameter will let it check all devices"
	echo "NOTE:"
	echo "	   -i/-b which is last will have greater effect."
	echo "	   intx/msi have same check logic and msix is complex, defualt is msi."
	echo "	   -a/--assist Number will enable a pathc handle for get cpu info, Default is Disable. The Nuber can be 2."
	echo ""
}
########################################################  MAIN

USER=`whoami`
if [ $USER != 'root' ]; then
	echo ">>>>>>> Need sudo run irq check <<<<<<<"
	exit 1
fi

lsmod | grep cambricon_drv >> /dev/null
if [ $? -ne 0 ]; then
	echo ">>>>>>> Please install mlu driver first <<<<<<<<"
	exit 2
fi

ARGS=`getopt -o b:i:t:a:h -l bdf:,id:,typeisr:,assist:,help -n 'example.sh' -- "$@"`

eval set -- "${ARGS}"

while true
do
	case "$1" in
		-h|--help)
			usage
			exit 0
			;;
		-b|--bdf)
			echo "set bdf [$2]"
			sel_bdf=$2
			if [ $sel_id -ne 255 ]; then
				echo "Use sel_bdf"
				sel_id=255
			fi
			specify=1
			shift 2
			;;
		-i|--id)
			echo "set card id [$2]"
			sel_id=$2
			if [ "$sel_bdf" != "" ]; then
				echo "Use sel_id"
				sel_bdf=""
			fi
			specify=1
			shift 2
			;;
		-t|--typeisr)
			echo "set isr type [$2]"
			if [ "$2" = "msix" ]; then
				msix_en=1
			fi
			shift 2
			;;
		-a|--assist)
			echo "set assister enable [$2]"
			if [ $2 -eq 2 ]; then
				secondry_handle_en=1
			fi
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

if [ $specify -ne 0 ]; then
	echo ""
	echo "Select One"
	echo "sel_bdf : $sel_bdf"
	echo "sel_id  : $sel_id"
	echo ""
fi

echo ""
echo "......................Start to check with msix[$msix_en].................."
echo ""

init_ret

echo "==============NUMA INFO============="
get_cpu_numa_info
echo ""

echo "==============MLU's NUMA LOCATION INFO============="
get_mlu_numa_location
echo ""


echo "==============MLU's IRQ CPU LOCATION INFO============="
get_mlu_irq_num
get_mlu_irq_location
echo ""

echo "==============CHECK MLU NUMA(CPU List) with MLU's IRQ CPU============="
check_mlu_irq_banding_relation
echo ""

show_ret

exit $res_to_rtn
