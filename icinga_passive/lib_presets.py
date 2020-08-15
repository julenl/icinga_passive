#! /usr/bin/env python
"""
Useful command presets to retrieve metrics on a system to be monitored.
The "pre" dictionaries keys are the preset name.
Each preset name contains a 'Description' and a 'Command'.
The Command is a shell snippet that returns an integer or a float
Optionally, it can contain a UOM (Unit Of Measurement), described here:
 https://nagios-plugins.org/doc/guidelines.html#PLUGOUTPUT   
"""

pre = {}

pre['root_disk'] = {}
pre['root_disk']['Description'] = 'The the amount of used bytes on the main/root partition'
pre['root_disk']['Command'] = "df |grep '/$' | awk '{print $3}'"
pre['root_disk']['UOM'] = "B"

pre['total_cpu'] = {}
pre['total_cpu']['Description'] = 'Total percentage of CPU capacity used'
pre['total_cpu']['Command'] = "grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage }'"
pre['total_cpu']['UOM'] = "%"

pre['total_mem'] = {}
pre['total_mem']['Description'] = 'Total memory RAM in "active" state'
pre['total_mem']['Command'] = """awk '/MemTotal/ {total=$2} /MemFree/ {free=$2} /Buffers/ {buffers=$2} $1 ~ /^Cache/ {cached=$2} /SReclaimable/ {reclaim=$2} /Shmem:/ {shmem=$2} END {printf "%.0f\\n", ((total - free) - (buffers + cached)) / 1024}' /proc/meminfo"""
pre['total_mem']['UOM'] = "B"

pre['lm_cpu_temp'] = {}
pre['lm_cpu_temp']['Description'] = 'CPU temperature in Celsius from lm-sensors'
pre['lm_cpu_temp']['Command'] = "sensors -u | grep -A1 'Package id 0:' |tail -1 | awk '{print $NF}'"

pre['bytes_sent'] = {}
pre['bytes_sent']['Description'] = 'Bytes sent on the primary network interface'
pre['bytes_sent']['Command'] = "grep 1 /sys/class/net/*/carrier 2> /dev/null |grep -v '/lo/' |xargs -I % sh -c 'cat $(dirname %)/statistics/rx_bytes' | tail -1"
pre['bytes_sent']['UOM'] = "c"

pre['bytes_recv'] = {}
pre['bytes_recv']['Description'] = 'Bytes received on the primary network interface'
pre['bytes_recv']['Command'] = "grep 1 /sys/class/net/*/carrier 2> /dev/null |grep -v '/lo/' |xargs -I % sh -c 'cat $(dirname %)/statistics/tx_bytes' | tail -1"
pre['bytes_recv']['UOM'] = "c"


#pre[''] = {}
#pre['']['Description'] = ''
#pre['']['Command'] = ""

def get_presets():
    return pre
