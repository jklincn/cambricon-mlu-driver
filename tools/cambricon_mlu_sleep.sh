#!/bin/sh

case $1/$2 in
	pre/*)
		modprobe -r cambricon_drv
		echo "Going to $2..."
		;;
	post/*)
		echo "Waking up from $2..."
		modprobe cambricon_drv
		;;
esac
