#!/bin/bash

PATH="/sbin:/usr/sbin:$PATH"

# check if tar\awk is support
RECORD_CMD=`which tar 2> /dev/null`
if [ $? -ne 0 ]; then
	echo "tar is needed"
	exit 1
fi

RECORD_CMD=`which awk 2> /dev/null`
if [ $? -ne 0 ]; then
	echo "awk is needed"
	exit 1
fi

BASE_LOG_FILENAME="cambricon-bug-report"
TEMP_DIR="cambricon_log"
RECORD_CMD="cat"
BASE_FILENAME=$TEMP_DIR/baseinfo
SYSLOG_FILENAME=$TEMP_DIR/systemlog
DMESG_FILENAME=$TEMP_DIR/dmesg
SYSINFO_FILENAME=$TEMP_DIR/sysinfo
ACPI_FILENAME=$TEMP_DIR/acpi
DEV_FILENAME=$TEMP_DIR/devinfo
IPMI_FILENAME=$TEMP_DIR/ipmi

set_filename() {
    LOG_FILENAME="$BASE_LOG_FILENAME.tar.gz"
    OLD_LOG_FILENAME="$BASE_LOG_FILENAME.old.tar.gz"
}

if [ -d /proc/driver/cambricon ]; then
    proc_module_dirs="."
    module_names="cambricon_drv"
fi

usage_bug_report_message() {
    echo "Please include the '$LOG_FILENAME' log file when reporting"
    echo "your bug via the CAMBRICON Linux forum (see www.cambricon.com)."
    echo ""
    echo "By delivering '$LOG_FILENAME' to CAMBRICON, you acknowledge"
    echo "and agree that personal information may inadvertently be included in"
    echo "the output.  Notwithstanding the foregoing, CAMBRICON will use the"
    echo "output only for the purpose of investigating your reported issue."
}

usage() {
    echo ""
    echo "$(basename $0): CAMBRICON Linux MLU Driver bug reporting shell script."
    echo ""
    usage_bug_report_message
    echo ""
    echo "$(basename $0) [OPTION]..."
    echo "    -h / --help"
    echo "        Print this help output and exit."
    echo "    --output-file <file>"
    echo "        Write output to <file>. If gzip is available, the output file"
    echo "        will be automatically compressed, and \".tar.gz\" will be appended"
    echo "        to the filename. Default: write to cambricon-bug-report.tar.gz."
    echo "    --safe-mode"
    echo "        Disable some parts of the script that may hang the system."
    echo "    --extra-system-data"
    echo "        Enable additional data collection that may aid in the analysis"
    echo "        of certain classes of bugs. Output file maybe large depend on the system log."
    echo "        If running the script without the --safe-mode option hangs the system,"
    echo "        consider using this option to help identify stuck kernel software."
    echo "    --device-only [cardid1,cardid2]"
    echo "        only collect device logs and some basic info, no root permissions required."
    echo "    -v / --version"
    echo "        show current version."
    echo ""
}

CAMBRICON_BUG_REPORT_VERSION='0.4'
CAMBRICON_BUG_REPORT_CHANGE='$Change: 20230706 $'
CAMBRICON_BUG_REPORT_VERSIONDATE=`echo "$CAMBRICON_BUG_REPORT_CHANGE" | tr -c -d "[:digit:]"`

# Set the default filename so that it won't be empty in the usage message
set_filename

# Parse arguments: Optionally set output file, run in safe mode, include extra
# system data, or print help
BUG_REPORT_SAFE_MODE=0
BUG_REPORT_EXTRA_SYSTEM_DATA=0
BUG_REPORT_DEVICE_ONLY=0
SAVED_FLAGS=$@
while [ "$1" != "" ]; do
    case $1 in
        -o | --output-file )    if [ -z $2 ]; then
                                    usage
                                    exit 1
                                elif [ "$(echo "$2" | cut -c 1)" = "-" ]; then
                                    echo "Warning: Questionable filename"\
                                         "\"$2\": possible missing argument?"
                                fi
                                BASE_LOG_FILENAME="$2"
                                # override the default filename
                                set_filename
                                shift
                                ;;
        --safe-mode )           BUG_REPORT_SAFE_MODE=1
                                ;;
        --extra-system-data )   BUG_REPORT_EXTRA_SYSTEM_DATA=1
                                ;;
        --device-only )         BUG_REPORT_DEVICE_ONLY=1
                                if [ $2 ] && [ "$(echo "$2" | cut -c 1)" != "-" ];then
                                    echo "DEVICE_ID=$2"
                                    BUG_REPORT_DEVICE_ID=$2
				    shift
				fi
				;;
        -h | --help )           usage
                                exit
                                ;;
        -v | --version )        echo $CAMBRICON_BUG_REPORT_VERSION
                                exit
                                ;;
        * )                     usage
                                exit 1
    esac
    shift
done


#
#Get PCIE config of whole chain From EP to RC
#
get_config_of_whole_chain()
{
	local place=$1
	local DM_B_D_F=$2
	local port="$DM_B_D_F"
	local level=0

	place="${place}/whole_chain_pcie_config"
	mkdir -p "${place}"
	while [ -e "/sys/bus/pci/devices/$port" ]
	do
		lspci -s $port -vvv > ${place}/${port}_lvl${level}.conf
		let "level+=1"
		port=$(basename $(dirname $(readlink "/sys/bus/pci/devices/$port")))
	done
}

#
# echo_metadata() - echo metadata of specified file
#
echo_metadata() {
    printf "*** ls: "
    /bin/ls -l --full-time "$1" 2> /dev/null

    if [ $? -ne 0 ]; then
        # Run dumb ls -l. We might not get one-second mtime granularity, but
        # that is probably okay.
        ls -l "$1" 2>&1
    fi
}

#
# append() - append the contents of the specified file to the log
#
append() {
    (
        echo "____________________________________________"
        echo ""

        if [ ! -f "$1" ]; then
            echo "*** $1 does not exist"
        elif [ ! -r "$1" ]; then
            echo "*** $1 is not readable"
        else
            echo "*** $1"
            echo_metadata "$1"
            cat  "$1"
        fi
        echo ""
    ) | $RECORD_CMD >> $2
}

#
# append_silent() - same as append(), but don't print anything
# if the file does not exist
#
append_silent() {
    (
        if [ -f "$1" -a -r "$1" ]; then
            echo "____________________________________________"
            echo ""
            echo "*** $1"
            echo_metadata "$1"
            cat  "$1"
            echo ""
        fi
    ) | $RECORD_CMD >> $2
}

#
# append_glob() - use the shell to expand a list of files, and invoke
# append() for each of them
#
append_glob() {
    for append_glob_iterator in `ls $1 2> /dev/null;`; do
        append "$append_glob_iterator"
    done
}

#
# append_file_or_dir_silent() - if $1 is a regular file, append it; otherwise,
# if $1 is a directory, append all files under it.  Don't print anything if the
# file does not exist.
#
append_file_or_dir_silent() {
    if [ -f "$1" ]; then
        append "$1"
    elif [ -d "$1" ]; then
        append_glob "$1/*"
    fi
}

#
# append_binary_file() - Encode a binary file into a ascii string format
# using 'base64' and append the contents output to the log file
#
append_binary_file() {
    (
        base64=`which base64 2> /dev/null | head -n 1`

        if [ $? -eq 0 -a -x "$base64" ]; then
                if [ -f "$1" -a -r "$1" ]; then
                    echo "____________________________________________"
                    echo ""
                    echo "base64 \"$1\""
                    echo ""
                    base64 "$1" 2> /dev/null
                    echo ""
                fi
        else
            echo "Skipping $1 output (base64 not found)"
            echo ""
        fi

    ) | $RECORD_CMD >> $2
}

#
# append_command() - append the output of the specified command to the log
#
append_command() {
    if [ -n "$1" ]; then
        echo "$1"
        echo ""
        $1
        echo ""
    fi
}

#
# append_command_backgroud() - append the output of the specified command to the log
#
append_command_backgroud() {
    if [ -n "$1" ]; then
        echo "$1"
        echo ""
        $1 &
        pid=$!
        total_timeout=10
        query_interval=1
        waited_time=0
        while :
        do
            if ! kill -0 $pid >/dev/null 2>&1 ; then
                break
            fi
            if [ $waited_time -ge $total_timeout ]; then
                echo "timeout detect"
                kill -9 $pid &
                break
            fi
            sleep $query_interval
            waited_time=$((waited_time + query_interval))
        done
        echo ""
    fi
}

#
# search_string_in_logs() - search for string $2 in log file $1
#
search_string_in_logs() {
    if [ -f "$1" ]; then
        echo ""
        if [ -r "$1" ]; then
            echo "  $1:"
            grep $2 "$1" 2> /dev/null
            return 0
        else
            echo "$1 is not readable"
        fi
    fi
    return 1
}

#
# print_package_for_file() - Print the package that owns the file $1
#
print_package_for_file()
{
    # Try to figure out which package manager we should use, and print which
    # package owns a file.

    pkgcmd=`which dpkg-query 2> /dev/null | head -n 1`
    if [ $? -eq 0 -a -n "$pkgcmd" ]; then
        pkgoutput=`"$pkgcmd" --search "$1" 2> /dev/null`
        if [ $? -ne 0 -o "x$pkgoutput" = "x" ] ; then
            echo No package found for $1
            return
        fi

        pkgname=$(echo "$pkgoutput" | sed -e 's/:[[:space:]].*//')
        if [ "x$pkgname" = "x" ] ; then
            echo Can\'t parse package result: $pkgoutput
            return
        fi
        "$pkgcmd" --show --showformat='    Package: ${Package}:${Architecture} ${Version}\n' $pkgname

        return
    fi

    pkgcmd=`which pacman 2> /dev/null | head -n 1`
    if [ $? -eq 0 -a -n "$pkgcmd" ]; then
        pkgoutput=`"$pkgcmd" --query --owns "$1" 2> /dev/null`
        if [ $? -ne 0 -o "x$pkgoutput" = "x" ] ; then
            echo No package found for $1
            return
        fi
        echo "$pkgoutput"

        return
    fi

    pkgcmd=`which rpm 2> /dev/null | head -n 1`
    if [ $? -eq 0 -a -n "$pkgcmd" ]; then
        "$pkgcmd" -q -f "$1" 2> /dev/null
        return
    fi
}

get_bdf_from_devid() {
    cardnum=$1
    cnmon info -c $cardnum > camb_tmp.txt

    startline=`cat camb_tmp.txt | grep "Domain ID" -n | awk -F ':' '{print $1}'`

    pcie_domain=`cat camb_tmp.txt | awk -F ':' -v start=$startline '/'"Domain ID"'/{if(NR>=start){$2=$2;print $2; exit}}'`
    pcie_bus=`cat camb_tmp.txt | awk -F ':' -v start=$startline '/'"Bus num"'/{if(NR>=start){$2=$2;print $2; exit}}'`
    pcie_device=`cat camb_tmp.txt | awk -F ':' -v start=$startline '/'"Device"'/{if(NR>=start){$2=$2;print $2; exit}}'`
    pcie_func=`cat camb_tmp.txt | awk -F ':' -v start=$startline '/'"Function"'/{if(NR>=start){$2=$2;print $2; exit}}'`
    pcie_domain=${pcie_domain// /}
    pcie_bus=${pcie_bus// /}
    pcie_device=${pcie_device// /}
    pcie_func=${pcie_func// /}

    rm camb_tmp.txt
    echo "$pcie_domain:$pcie_bus:$pcie_device.$pcie_func"
}

#
# Start of script
#


# check that we are root (needed for `lspci -vxxx`, ipmitool and potentially for
# accessing kernel log files)
if [ `id -u` -ne 0 ] && [ $BUG_REPORT_DEVICE_ONLY -ne 1 ]; then
    echo "ERROR: Please run $(basename $0) as root."
    exit 1
fi


# move any old log file (zipped) out of the way
if [ -f $LOG_FILENAME ]; then
    mv $LOG_FILENAME $OLD_LOG_FILENAME
fi


# make sure what we can write to the log file
touch $LOG_FILENAME 2> /dev/null
if [ $? -ne 0 ]; then
    echo
    echo "ERROR: Working directory is not writable; please cd to a directory"
    echo "       where you have write permission so that the $LOG_FILENAME"
    echo "       file can be written."
    echo
    exit 1
fi
mkdir $TEMP_DIR

# print a start message to stdout
echo ""
echo "cambricon-bug-report.sh will now collect information about your"
echo "system and create the file '$LOG_FILENAME' in the current"
echo "directory.  It may take several seconds to run.  In some"
echo "cases, it may hang trying to capture data generated dynamically"
echo "by the Linux kernel and/or the CAMBRICON kernel module.  While"
echo "the bug report log file will be incomplete if this happens, it"
echo "may still contain enough data to diagnose your problem."
echo ""
if [ $BUG_REPORT_SAFE_MODE -eq 0 ]; then
    echo "If cambricon-bug-report.sh hangs, consider running with the --safe-mode"
    echo "and --extra-system-data command line arguments."
    echo ""
fi
usage_bug_report_message
echo ""
echo -n "Running $(basename $0)...";


# print prologue to the log file
(
    echo "____________________________________________"
    echo ""
    echo "Start of CAMBRICON bug report log file.  Please include this file, along"
    echo "with a detailed description of your problem, when reporting a mlus"
    echo "driver bug via the CAMBRICON Linux forum (see www.cambricon.com)."
    echo ""
    echo "cambricon-bug-report.sh Version: $CAMBRICON_BUG_REPORT_VERSION"
    echo "cambricon-bug-report.sh Change Date: $CAMBRICON_BUG_REPORT_VERSIONDATE"
    echo ""
    echo "Date: `date +%Y.%m.%d_%H:%M:%S`"
    echo "uname: `uname -a`"
    echo "command line flags: $SAVED_FLAGS"
    echo ""
) | $RECORD_CMD >> $BASE_FILENAME


# append OPAL (IBM POWER system firmware) messages
append_silent "/sys/firmware/opal/msglog" $BASE_FILENAME

# append useful files
append "/etc/issue" $BASE_FILENAME
append_silent "/etc/redhat-release" $BASE_FILENAME
append_silent "/etc/redhat_version" $BASE_FILENAME
append_silent "/etc/fedora-release" $BASE_FILENAME
append_silent "/etc/slackware-release" $BASE_FILENAME
append_silent "/etc/slackware-version" $BASE_FILENAME
append_silent "/etc/debian_release" $BASE_FILENAME
append_silent "/etc/debian_version" $BASE_FILENAME
append_silent "/etc/mandrake-release" $BASE_FILENAME
append_silent "/etc/yellowdog-release" $BASE_FILENAME
append_silent "/etc/sun-release" $BASE_FILENAME
append_silent "/etc/release" $BASE_FILENAME
append_silent "/etc/gentoo-release" $BASE_FILENAME
append "/var/log/cambricon-installer.log" $BASE_FILENAME
append_silent "/var/log/cambricon-uninstall.log" $BASE_FILENAME
append "/etc/modprobe.d/cambricon-drv.conf" $BASE_FILENAME

# Append any config files found in home directories
cat /etc/passwd \
    | cut -d : -f 6 \
    | sort | uniq \
    | while read DIR; do
        append_file_or_dir_silent "$DIR/.cn/cambricon-application-profiles-rc" $BASE_FILENAME
        append_file_or_dir_silent "$DIR/.cn/cambricon-application-profiles-rc.backup" $BASE_FILENAME
        append_silent "$DIR/.cn/cambricon-application-profile-globals-rc" $BASE_FILENAME
    done

# Capture global app profile configs
append_file_or_dir_silent "/etc/cambricon/cambricon-application-profiles-rc" $BASE_FILENAME

# append system library info
(
    echo "____________________________________________"
    echo ""

	echo "*** ldconfig system info"
    ldconfig -N -v -p 2> /dev/null
    echo ""

) | $RECORD_CMD >> $BASE_FILENAME


# lspci information
(
    echo "____________________________________________"
    echo ""

    lspci=`which lspci 2> /dev/null | head -n 1`

    if [ $? -eq 0 -a -x "$lspci" ]; then
        # Capture CAMBRICON devices
        echo "$lspci -d \"cabc:*\" -v -xxx"
        echo ""
        $lspci -vvv -xxxx 2> /dev/null
        echo ""
        echo "____________________________________________"
        echo ""
        echo "$lspci -tv"
        echo ""
        $lspci -tv 2> /dev/null
        echo ""
        echo "____________________________________________"
        echo ""
        echo "$lspci -nn"
        echo ""
        $lspci -nn 2> /dev/null
    else
        echo "Skipping lspci output (lspci not found)"
        echo ""
    fi
) | $RECORD_CMD >> $BASE_FILENAME

# NUMA information
(
    echo "____________________________________________"
    echo ""

    numactl=`which numactl 2> /dev/null | head -n 1`

    if [ $? -eq 0 -a -x "$numactl" ]; then
	# Get hardware NUMA configuration
	echo "$numactl -H"
	echo ""
	$numactl -H
    fi

    # Get additional NUMA information
    filelist="/sys/devices/system/node/has_cpu \
    	      /sys/devices/system/node/has_memory \
	      /sys/devices/system/node/has_normal_memory \
	      /sys/devices/system/node/online \
	      /sys/devices/system/node/possible"

    # Get MLU NUMA information
    lspci=`which lspci 2> /dev/null | head -n 1`
    if [ $? -eq 0 -a -x "$lspci" ]; then
	mlus=`$lspci -d "cabc:*" -s ".0" | awk '{print $1}'`
	for mlu in $mlus; do
	    filelist="$filelist \
	    	      /sys/bus/pci/devices/*$mlu/local_cpulist \
		      /sys/bus/pci/devices/*$mlu/numa_node"
	done
    fi

    for file in $filelist; do
	echo "____________________________________________"
	if [ ! -f "$file" ]; then
	    echo "*** $file does not exist"
	elif [ ! -r "$file" ]; then
	    echo "*** $file is not readable"
	else
	    echo "*** $file"
	    echo_metadata "$file"
	    cat "$file"
	fi
	echo ""
    done
) | $RECORD_CMD >> $BASE_FILENAME

# lsusb information
(
    echo "____________________________________________"
    echo ""

    lsusb=`which lsusb 2> /dev/null | head -n 1`

    if [ $? -eq 0 -a -x "$lsusb" ]; then
        echo "$lsusb"
        echo ""
        $lsusb 2> /dev/null
        echo ""
    else
        echo "Skipping lsusb output (lsusb not found)"
        echo ""
    fi
) | $RECORD_CMD >> $BASE_FILENAME

# dmidecode
(
    echo "____________________________________________"
    echo ""

    dmidecode=`which dmidecode 2> /dev/null | head -n 1`

    if [ $? -eq 0 -a -x "$dmidecode" ]; then
        echo "$dmidecode"
        echo ""
        $dmidecode 2> /dev/null
        echo ""
    else
        echo "Skipping dmidecode output (dmidecode not found)"
        echo ""
    fi
) | $RECORD_CMD >> $BASE_FILENAME

# module version magic
(
    echo "____________________________________________"
    echo ""

    modinfo=`which modinfo 2> /dev/null | head -n 1`

    if [ $? -eq 0 -a -x "$modinfo" ]; then
        for name in $module_names; do
            echo "$modinfo $name | grep vermagic"
            echo ""
            ( $modinfo $name | grep vermagic ) 2> /dev/null
            echo ""
        done
    else
        echo "Skipping modinfo output (modinfo not found)"
        echo ""
    fi
) | $RECORD_CMD >> $BASE_FILENAME

# get any relevant kernel messages
(
    echo "____________________________________________"
    echo ""
    echo "Scanning kernel log files for CAMBRICON kernel messages:"

    grep_args="-e CN -e cambricon- -e cnrm-cnlog -e camb"
    logfound=0

    journalctl=`which journalctl 2> /dev/null | head -n 1`
    if [ $? -eq 0 -a -x "$journalctl" ]; then
        logfound=1
        cnrmfound=0

        for boot in -2 -1 -0; do
            #if (journalctl -b $boot | grep ${grep_args}) > /dev/null 2>&1; then
                echo ""
                echo "  journalctl -b $boot:"
                (journalctl -b $boot) 2> /dev/null
                cnrmfound=1
            #fi
        done

        if [ $cnrmfound -eq 0 ]; then
            echo ""
            echo "No CAMBRICON kernel messages found in recent systemd journal entries."
        fi
    else
        search_string_in_logs /var/log/messages "$grep_args" && logfound=1
        search_string_in_logs /var/log/syslog "$grep_args" && logfound=1
        search_string_in_logs /var/log/kern.log "$grep_args" && logfound=1
        search_string_in_logs /var/log/kernel.log "$grep_args" && logfound=1
    fi

    if [ $logfound -eq 0 ]; then
        echo ""
        echo "No suitable log found."
    fi

    echo ""
) | $RECORD_CMD >> $SYSLOG_FILENAME

# If extra data collection is enabled, dump all active CPU backtraces to be
# picked up in dmesg, and get more syslog
if [ $BUG_REPORT_EXTRA_SYSTEM_DATA -ne 0 ]; then
    (
        echo "____________________________________________"
        echo ""
        echo "Triggering SysRq backtrace on active CPUs (see dmesg output)"
        sysrq_enabled=`cat /proc/sys/kernel/sysrq`
        if [ "$sysrq_enabled" -ne "1" ]; then
            echo 1 > /proc/sys/kernel/sysrq
        fi

        echo l > /proc/sysrq-trigger

        if [ "$sysrq_enabled" -ne "1" ]; then
            echo $sysrq_enabled > /proc/sys/kernel/sysrq
        fi
    ) | $RECORD_CMD >> $BASE_FILENAME

    (
        pushd /var/log/ 2>&1 > /dev/null
        logs=`ls messages* 2> /dev/null`
        popd 2>&1 > /dev/null
        for log in $logs; do
            tail -c 100M /var/log/$log > $TEMP_DIR/$log
        done

        pushd /var/log/ 2>&1 > /dev/null
        logs=`ls log* 2> /dev/null`
        popd 2>&1 > /dev/null
        for log in $logs; do
            tail -c 100M /var/log/$log > $TEMP_DIR/$log
        done
    )
fi

# append dmesg output
(
    echo "____________________________________________"
    echo ""
    echo "dmesg:"
    echo ""
    dmesg 2> /dev/null
) | $RECORD_CMD >> $DMESG_FILENAME

# print gcc & g++ version info
(
    which gcc >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "____________________________________________"
        echo ""
        gcc -v 2>&1
    fi

    which g++ >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "____________________________________________"
        echo ""
        g++ -v 2>&1
    fi
) | $RECORD_CMD >> $BASE_FILENAME

# append useful /proc files
append "/proc/cmdline" $BASE_FILENAME
append "/proc/cpuinfo" $BASE_FILENAME
append "/proc/interrupts" $BASE_FILENAME
append "/proc/meminfo" $BASE_FILENAME
append "/proc/modules" $BASE_FILENAME
append "/proc/version" $BASE_FILENAME
append "/proc/pci" $BASE_FILENAME
append "/proc/iomem" $BASE_FILENAME
append "/proc/mtrr" $BASE_FILENAME

# ipmi information
(
    ipmitool=`which ipmitool 2> /dev/null | head -n 1`

    if [ $? -eq 0 -a -x "$ipmitool" ]; then
        echo "____________________________________________"
        $ipmitool sel elist 2> /dev/null
        echo ""
        echo "____________________________________________"
        $ipmitool sdr elist 2> /dev/null
    else
        echo "Skipping ipmitool output (ipmitool not found)"
        echo ""
    fi
) | $RECORD_CMD >> $IPMI_FILENAME

#acpi dump
(
    acpidump=`which acpidump 2> /dev/null | head -n 1`

    if [ $? -eq 0 -a -x "$acpidump" ]; then

        base64=`which base64 2> /dev/null | head -n 1`

        if [ $? -eq 0 -a -x "$base64" ]; then

            TEMP_FILENAME="acpidump-temp$$.log"

            echo "$acpidump -o"
            echo ""
            $acpidump -o $TEMP_FILENAME 2> /dev/null

            # make sure if data file is created
            if [ -f "$TEMP_FILENAME" ]; then
                (
		$base64 $TEMP_FILENAME 2> /dev/null
                echo ""
		) | $RECORD_CMD >> $ACPI_FILENAME
                # remove the temporary file when complete
                rm $TEMP_FILENAME 2> /dev/null
            else
                echo "Skipping acpidump output (can't create data file $TEMP_FILENAME)"
                echo ""
                # do not fail here, continue
            fi
        else
            echo "Skipping acpidump output (base64 not found)"
            echo ""
        fi
    fi
)

# List the sysfs entries for all CAMBRICON device functions
# This info is useful to debug dynamic power management issues
#
# NOTE: We need to query this before other things in this script,
# because other operations may alter the power management
# state of the MLU(s).
for subdir in `ls /sys/bus/pci/devices/ 2> /dev/null`; do
    vendor_id=`cat /sys/bus/pci/devices/$subdir/vendor 2> /dev/null`
    if [ "$vendor_id" = "0xcabc" ]; then
        append "/sys/bus/pci/devices/$subdir/power/control" $DEV_FILENAME
        append "/sys/bus/pci/devices/$subdir/power/runtime_status" $DEV_FILENAME
        append "/sys/bus/pci/devices/$subdir/power/runtime_usage" $DEV_FILENAME
    fi
done

#detect card health status
drop_card=`lspci -d cabc: | grep ff | wc -l`
num_card=`lspci -d cabc: | grep -v 'cabc:...[16]' | wc -l`
running_card=`ls /dev/cambricon_dev* | grep -v mi | wc -l`
if [ $drop_card -ne 0 ] || [ $running_card -lt $num_card ]; then
    echo  ""
    echo  "[Warning]Some cards are in unstable state:$drop_card, $num_card, $running_card"
    echo  "[Warning]if this program stuck for a long time, use safe mode instead"
fi

# disable these when safemode is requested
if [ $BUG_REPORT_SAFE_MODE -eq 0 ]; then
    # cnmon
    CNDEV_LOG_FILE="cambricon-cndev-temp$$.log"
    touch $CNDEV_LOG_FILE 2>/dev/null
    if [ -w $CNDEV_LOG_FILE ]; then
        export __CNDEV_DBG_FILE=${CNDEV_LOG_FILE} __CNDEV_DBG_APPEND=1 __CNDEV_DBG_LVL=DEBUG
    fi

    (
        echo "____________________________________________"
        echo ""

        cnmon=`which cnmon 2> /dev/null | head -n 1`

        if [ $? -eq 0 -a -x "$cnmon" ]; then
            append_command_backgroud "$cnmon info"
            append_command_backgroud "$cnmon mlulink"
        else
            echo "Skipping cnmon output (cnmon not found)"
            echo ""
        fi
    ) | $RECORD_CMD >> $DEV_FILENAME

    if [ -f $CNDEV_LOG_FILE ]; then
        append_binary_file $CNDEV_LOG_FILE $DEV_FILENAME
        rm -f $CNDEV_LOG_FILE
        unset __CNDEV_DBG_FILE __CNDEV_DBG_APPEND __CNDEV_DBG_LVL
    fi

    if [ -v BUG_REPORT_DEVICE_ID ]; then
        oldIFS=$IFS
        IFS=','
        for devid in $BUG_REPORT_DEVICE_ID; do
            bdf=`get_bdf_from_devid $devid`
            bdfs="$bdf $bdfs"
        done
        IFS=$oldIFS
    fi

    old_path=''
    for MLU in `ls /proc/driver/cambricon/mlus/ 2> /dev/null`; do
        if [ -v bdfs ]; then
            if ! echo $bdfs | grep -q "$MLU"; then
	            continue
            fi
        fi
        DEV_DIR=$PWD/$TEMP_DIR/cambricon/$MLU

        if [ -e /proc/driver/cambricon/mlus/$MLU/report ]; then
            if [ old_path != '' ]; then
                old_path=`cat /proc/driver/cambricon/mlus/$MLU/report | grep path= | awk -F '=' '{print $2}'`
                if [ -e $old_path ]; then
                    cp -r $old_path $TEMP_DIR/cambricon_log_old
                fi
            fi
            if [ ! -e $DEV_DIR ];then
                mkdir -p $DEV_DIR
            fi
            echo path $PWD/$TEMP_DIR/cambricon/ > /proc/driver/cambricon/mlus/$MLU/report
            echo report on > /proc/driver/cambricon/mlus/$MLU/report
        else
            if [ ! -e $DEV_DIR ];then
                mkdir -p $DEV_DIR
            fi
        fi
        append "/proc/driver/cambricon/mlus/$MLU/mlumsg" $DEV_DIR/mlumsg
        append "/proc/driver/cambricon/mlus/$MLU/cn_mem" $DEV_DIR/mlumsg
        append "/proc/driver/cambricon/mlus/$MLU/pinned_mem" $DEV_DIR/mlumsg
        append "/proc/driver/cambricon/mlus/$MLU/bootinfo" $DEV_DIR/mlumsg
        append "/proc/driver/cambricon/mlus/$MLU/stat" $DEV_DIR/mlumsg
        append "/proc/driver/cambricon/mlus/$MLU/power" $DEV_DIR/power
        append "/proc/driver/cambricon/mlus/$MLU/information" $DEV_DIR/information
        append "/proc/driver/cambricon/mlus/$MLU/bootinfo" $DEV_DIR/bootinfo

        get_config_of_whole_chain $DEV_DIR $MLU
    done

    #wait for report done
    if [ X$old_path != X'' ]; then
        loop=0
        for MLU in `ls /proc/driver/cambricon/mlus/ 2> /dev/null`; do
            if [ -e /proc/driver/cambricon/mlus/$MLU/report ]; then
            out=`cat /proc/driver/cambricon/mlus/$MLU/report | grep state=0`
            if [ $? != 0 ];then
                while ((loop<30)); do
                    out=`cat /proc/driver/cambricon/mlus/$MLU/report | grep state=0`
                    if [ $? -eq 0 ];then
                        break;
                    else
                        ((loop++));
                        sleep 1;
                    fi
                done
            fi
            if ((loop>=30));then
                append "/proc/driver/cambricon/mlus/$MLU/mlumsg" $DEV_DIR/mlumsg
            fi
            echo path $old_path > /proc/driver/cambricon/mlus/$MLU/report
            fi
        done
    fi
else
    (
        echo "Skipping cnmon, cambricon-debugdump due to --safe-mode argument."
        echo ""
    ) | $RECORD_CMD >> $DEV_FILENAME
fi

(
    echo "____________________________________________"

    # print epilogue to log file

    echo ""
    echo "End of CAMBRICON bug report log file."
) | $RECORD_CMD >> $BASE_FILENAME

sync > /dev/null 2>&1

tar czf $LOG_FILENAME $TEMP_DIR 2> /dev/null
rm -rf $TEMP_DIR
# Done

echo " complete."
echo ""
