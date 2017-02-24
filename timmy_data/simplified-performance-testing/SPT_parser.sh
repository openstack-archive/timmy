#!/bin/bash

results=${1:-"/tmp/timmy/info"}
glance_create="glance-1-image-create.sh"
glance_download="glance-2-image-download.sh"
cinder_volume="cinder-VM-volume-write.sh"
iperf_vm="network-VM-to-VM-iperf-tests.sh"
iperf_host="iperf-client.sh"
res_glance_create=`find $results -name $glance_create`
res_glance_download=`find $results -name $glance_download`
res_cinder=`find $results -name $cinder_volume`
res_iperf_vm=`find $results -name $iperf_vm`
res_iperf_host="$(find $results -name "${iperf_host}*")"
res_iperf_node_dir="$(find $results -name "client" -type d)"
[ -n "$res_iperf_node_dir" ] && res_iperf_node="$(ls $res_iperf_node_dir)" || res_iperf_node=""

function print_result() {
	[ -n "$2" ] && printf "$2" || printf "n/a"
	echo -e "\t<-- $1"
}

function a() {
	[ -n "$1" ] && printf "$1\t" || printf "n/a\t"
}

function b() {
	word=`echo $1 | grep -o '[a-zA-Z/]\+'`
	number=`echo $1 | grep -o '[0-9.]\+'`
	python -c '
import sys
word = sys.argv[1]
number = sys.argv[2]
if word == "Gbits/sec":
    sys.stdout.write(str(int(float(number)*1000000000)))
elif word == "Mbits/sec":
    sys.stdout.write(str(int(float(number)*1000000)))
elif word == "Kbits/sec":
    sys.stdout.write(str(int(float(number)*1000)))
elif word == "bits/sec":
    sys.stdout.write(str(int(number)))
' $word $number 2> /dev/null
}

function c() {
	echo $1 | python -c 'import sys; print(float(sys.stdin.read())/1000000000)' 2> /dev/null
}

function d() {
	word=`echo $1 | grep -o '[a-zA-Z/]\+'`
	number=`echo $1 | grep -o '[0-9.]\+'`
	python -c '
import sys
word = sys.argv[1]
number = sys.argv[2]
if word == "GB/s":
    sys.stdout.write(str(int(float(number)*1000)))
elif word == "MB/s":
    sys.stdout.write(str(float(number)))
elif word == "kB/s":
    sys.stdout.write(str(int(float(number)/1000)))
' $word $number 2> /dev/null
}

if [ -n "$res_glance_create" ]
then
	res_gc=`head -n 4 $res_glance_create | grep '^[0-9.]\+$' | \
                python -c 'import sys; print("%.2fMB/s" % (4000/float(sys.stdin.read(),)))' 2> /dev/null`
fi
print_result "Glance upload" $res_gc

if [ -n "$res_glance_download" ]
then
	res_gd=`head -n 1 $res_glance_download | grep '^[0-9.]\+$' | \
                python -c 'import sys; print("%.2fMB/s" % (4000/float(sys.stdin.read(),)))' 2> /dev/null`
fi
print_result "Glance download" $res_gd

if [ -n "$res_cinder" ]
then
	res_4k=`grep 'DD_TEST_1' $res_cinder | grep copied | rev | awk '{print $1$2}' | rev`
	res_1m=`grep 'DD_TEST_2' $res_cinder | grep copied | rev | awk '{print $1$2}' | rev`
	res_1g=`grep 'DD_TEST_3' $res_cinder | grep copied | rev | awk '{print $1$2}' | rev`
fi
print_result "Block Storage Write 4k" $res_4k
print_result "Block Storage Write 1M" $res_1m
print_result "Block Storage Write 1G" $res_1g

[ -n "$res_iperf_node" ] && nnum="$(wc -l <<< "$res_iperf_node")" && print_result "Number of nodes (during iperf HW to HW tests)" $nnum

if [ -n "$res_iperf_host" ]
then
	res_t1=""
	res_t10=""
	for i in $res_iperf_host
	do
		res_t1="$(echo "$res_t1"; b $(head -n 7 $i | tail -n 1 | grep '^\[.*sec' | rev | awk '{print $1$2}' | rev | sed 's/ //g'))"
                res_t1="$(echo "$res_t1" | grep -v '^$' | sort -n | tail -n 1)"
		res_t10="$(echo "$res_t10"; b $(head -n 33 $i | tail -n 1 | grep '^\[SUM.*sec' | rev | awk '{print $1$2}' | rev | sed 's/ //g'))"
                res_t10="$(echo "$res_t10" | grep -v '^$' | sort -n | tail -n 1)"
       done
fi
res_t1=`echo "$res_t1" | python -c 'import sys; print(float(sys.stdin.read())/1000000000)' 2> /dev/null`
res_t10=`echo "$res_t10" | python -c 'import sys; print(float(sys.stdin.read())/1000000000)' 2> /dev/null`
print_result "HW to HW (best)" $res_t1
print_result "HW to HW (best) - 10 Threads" $res_t10

if [ -n "$res_iperf_host" ]
then
	res_mt1=""
	res_mt10=""
	for i in $res_iperf_host
	do
		res_mt1="$(echo "$res_mt1"; b $(head -n 7 $i | tail -n 1 | grep '^\[.*sec' | rev | awk '{print $1$2}' | rev | sed 's/ //g'))"
                res_mt1="$(echo "$res_mt1" | grep -v '^$' | sort -n | head -n 1)"
		res_mt10="$(echo "$res_mt10"; b $(head -n 33 $i | tail -n 1 | grep '^\[SUM.*sec' | rev | awk '{print $1$2}' | rev | sed 's/ //g'))"
                res_mt10="$(echo "$res_mt10" | grep -v '^$' | sort -n | head -n 1)"
	done
fi
res_mt1=`echo "$res_mt1" | python -c 'import sys; print(float(sys.stdin.read())/1000000000)' 2> /dev/null`
res_mt10=`echo "$res_mt10" | python -c 'import sys; print(float(sys.stdin.read())/1000000000)' 2> /dev/null`
print_result "HW to HW (worst)" $res_mt1
print_result "HW to HW (worst) - 10 Threads" $res_mt10

if [ -n "$res_iperf_vm" ]
then
	res1=`head -n 8 $res_iperf_vm | tail -n 1 | grep '^\[.*sec' | rev | awk '{print $1$2}' | rev | sed 's/ //g'`
	res2=`head -n 17 $res_iperf_vm | tail -n 1 | grep '^\[.*sec' | rev | awk '{print $1$2}' | rev | sed 's/ //g'`
	res3=`head -n 44 $res_iperf_vm | tail -n 1 | grep '^\[SUM.*sec' | rev | awk '{print $1$2}' | rev | sed 's/ //g'`
	res4=`head -n 52 $res_iperf_vm | tail -n 1 | grep '^\[.*sec' | rev | awk '{print $1$2}' | rev | sed 's/ //g'`
	res5=`head -n 61 $res_iperf_vm | tail -n 1 | grep '^\[.*sec' | rev | awk '{print $1$2}' | rev | sed 's/ //g'`
fi
print_result "VM to VM - VMs on same node - via Private IP - 1 thread" $res1
print_result "VM to VM - VMs on different HW nodes - via Private IP - 1 thread" $res2
print_result "VM to VM - VMs on different HW nodes - via Private IP - MILTI 10 thread" $res3
print_result "VM to VM - via Floating IP and VMs are on different nodes - 1 thread" $res4
print_result "VM to VM - diff nodes, VMs connected to separate networks connected by vRouter - via Private IP - 1 thread" $res5


echo "--------------------------"
a `d $res_gc`
a `d $res_gd`
a `d $res_4k`
a `d $res_1m`
a `d $res_1g`
a $nnum
a $res_t1
a $res_t10
a $res_mt1
a $res_mt10
a $(c `b $res1`)
a $(c `b $res2`)
a $(c `b $res3`)
a $(c `b $res4`)
a $(c `b $res5`)
echo 
