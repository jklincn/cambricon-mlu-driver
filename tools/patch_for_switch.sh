#!/bin/bash

#scan the cambricon device
cam_dev_list=`lspci -dcabc:|awk '{print $1}'`
if [ -z "$cam_dev_list" ]; then
  echo "Error: no device specified"
  exit 1
fi

for card in ${cam_dev_list[@]}
do
  card="0000:$card"
  port=$(basename $(dirname $(readlink "/sys/bus/pci/devices/$card")))
  echo cambricon_card $card
  while [ -e "/sys/bus/pci/devices/$port" ]
  do
    up_stream=`lspci -vvv -s $port|grep "Upstream Port"`
    if [ -z "$up_stream" ]; then
      port=$(basename $(dirname $(readlink "/sys/bus/pci/devices/$port")))
      continue;
    fi

    switch_9797=$(lspci -n -s $port|grep "10b5:9797")
    if [ -n "$switch_9797" ];then
      echo "    The $port is PLX 9797"
      switch_9797=$(lspci -vvv -s $port|grep "Region 0:"|grep "Memory at"|grep 16M)
      if [ -n "$switch_9797" ];then
        devmem2_exist=`which devmem2`
        if [ -z "$devmem2_exist" ]; then
          echo "Please install devmem2 and reboot"
        else
          bar0_addr=0x`echo ${switch_9797#*"Memory at "}|awk '{print $1}'`
          for ((i=0;i<=6;i++))
          do
            waddr=`printf "0x%x" $(($bar0_addr+0x760+i*0x4000))`
            old_value=`devmem2 $waddr w`
            old_value=${old_value##*": "}
            new_value=`printf "0x%x" $((old_value|0x200000))`
            w_res=`devmem2 $waddr w $new_value`
            echo "        $waddr old_value:$old_value new_value:$new_value"
          done
        fi
      fi
    fi

    switch_f60=$(lspci -n -s $port|grep "10b5:")$(lspci -n -s $port|grep "1000:c030")
    if [ -n "$switch_f60" ]; then
      rdata=0x$(setpci -s $port f63.B)
      wdata=`echo "obase=16;$(($rdata|0x04))"|bc`
      echo "    The card $port f60 rdata:$rdata wdata:$wdata"
      echo ""
      setpci -s $port f63.B=$wdata
    fi

    port=$(basename $(dirname $(readlink "/sys/bus/pci/devices/$port")))
  done
done
