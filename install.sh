#!/bin/sh
SYSTABLE=$(cat /boot/System.map-`uname -r` | grep -i "sys_call_table" -m1 | cut -d' ' -f1)
/sbin/insmod progger.ko SYSTABLE=0x$SYSTABLE 
