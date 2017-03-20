#!/bin/bash

set -x

# this test requires fully functional dd in VM, cirros (busybox) version will not work
# this test requires sudo and pkill in VM

SPT_FLOATING_NET=${SPT_FLOATING_NET:-"admin_floating_net"}
SPT_FLAVOR=${SPT_FLAVOR:-"m1.small"}
SPT_IMAGE=${SPT_IMAGE:-"xenial"}
SPT_VM_USER=${SPT_VM_USER:-"ubuntu"}
SPT_VM_COOLDOWN=${SPT_VM_COOLDOWN:-"120"}
DD_OPTIONS=${DD_OPTIONS:-"oflag=direct"}
DD_TIMEOUT=${DD_TIMEOUT:-"10"}
SSH_OPTS="-q -n -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -l $SPT_VM_USER"
VM_BOOT_TIMEOUT_MINUTES=${VM_BOOT_TIMEOUT_MINUTES:-"5"}

vm_boot_check_tries=$(($VM_BOOT_TIMEOUT_MINUTES*2))
vm_boot_check_delay=30
vm_active_check_tries=10
vm_active_check_delay=10
vm_volume_available_check_tries=10
vm_volume_available_check_delay=30
vm_volume_attached_check_tries=10
vm_volume_attached_check_delay=10

function cleanup {
  echo "cleaning up..."
  [ -n "$instance_id" ] && [ -n "$floatingip" ] && nova floating-ip-disassociate $instance_id $floatingip
  [ -n "$floatingip_id" ] && neutron floatingip-delete $floatingip_id
  [ -n "$instance_id" ] && [ -n "$secgroup_id" ] && nova remove-secgroup $instance_id $secgroup_id
  [ -n "$instance_id" ] && nova delete $instance_id
  [ -n "$secgroup_id" ] && neutron security-group-delete $secgroup_id
  [ -n "$router_id" ] && [ -n "$subnet_id" ] && neutron router-interface-delete $router_id $subnet_id
  [ -n "$router_id" ] && neutron router-delete $router_id
  [ -n "$subnet_id" ] && neutron subnet-delete $subnet_id
  [ -n "$net_id" ] && neutron net-delete $net_id
  [ -n "$keypair_name" ] && nova keypair-delete $keypair_name
  [ -f "spt-temporary-keypair" ] && rm "spt-temporary-keypair"
  [ -n "$volume_id" ] && cinder delete $volume_id
}

function check_code {
  # arguments:
  # $1 - exit code
  # $2 - error message
  # $3 - command output to print
  if [ "$1" -ne "0" ]
  then
    echo "$2:"
    echo "$3"
    cleanup
    exit 1
  fi
}

source $OPENRC

# create keypair
result="$(nova keypair-add "spt-temporary-keypair" >"spt-temporary-keypair" 2>&1)"
code=$?
[ "$code" -eq "0" ] && keypair_name="spt-temporary-keypair"
check_code $? "failed to create keypair" "$result"
chmod 600 "spt-temporary-keypair"

# create network
result="$(neutron net-create "spt-temporary-net" 2>&1)"
check_code $? "failed to create network" "$result"
net_id=$(echo "$result" | grep "^| id " | awk '{print $4}')

# create subnet
result="$(neutron subnet-create --name "spt-temporary-subnet" $net_id 10.20.30.0/24 2>&1)"
check_code $? "failed to create subnet" "$result"
subnet_id=$(echo "$result" | grep "^| id " | awk '{print $4}')

# create router
result="$(neutron router-create "spt-temporary-router" 2>&1)"
check_code $? "failed to create router" "$result"
router_id=$(echo "$result" | grep "^| id " | awk '{print $4}')

# add router interface
result="$(neutron router-interface-add $router_id $subnet_id 2>&1)"
check_code $? "failed to add router interface to subnet" "$result"

# set router gateway
result="$(neutron router-gateway-set $router_id $SPT_FLOATING_NET 2>&1)"
check_code $? "failed to set router gateway" "$result"

# create security group
result="$(neutron security-group-create "spt-temporary-security-group" 2>&1)"
check_code $? "failed to create security group" "$result"
secgroup_id=$(echo "$result" | grep "^| id " | awk '{print $4}')

# create security group rule
result="$(neutron security-group-rule-create $secgroup_id --protocol TCP 2>&1)"
check_code $? "failed to create security group rule" "$result"

# create floating ip
result="$(neutron floatingip-create $SPT_FLOATING_NET 2>&1)"
check_code $? "failed to create floatingip" "$result"
floatingip=$(echo "$result" | grep "^| floating_ip_address " | awk '{print $4}')
floatingip_id=$(echo "$result" | grep "^| id " | awk '{print $4}')

# boot VM
result="$(nova boot --image $SPT_IMAGE --flavor $SPT_FLAVOR --nic net-id=$net_id --key-name "spt-temporary-keypair" --security-groups $secgroup_id "spt-temporary-vm" 2>&1)"
check_code $? "failed to boot VM" "$result"
instance_id=$(echo "$result" | grep "^| id " | awk '{print $4}')

# wait for instance to become active
for i in $(seq 1 $vm_active_check_tries)
do
  result="$(nova show $instance_id 2>&1)"
  vm_status=$(echo "$result" | grep "^| *status" | awk '{printf $4}')
  [ "$vm_status" == "ACTIVE" ] && break
  [ $i -lt $vm_active_check_tries ] && sleep $vm_active_check_delay
done
! [ "$vm_status" == "ACTIVE" ] && check_code 1 "timeout waiting for VM to become active" "$result"

# associate floatingip
result="$(nova floating-ip-associate $instance_id $floatingip 2>&1)"
check_code $? "failed to associate floatingip" "$result"

# create volume
result="$(cinder create --name "spt-temporary-volume" 4 2>&1)"
check_code $? "failed to create volume" "$result"
volume_id=$(echo "$result" | grep "^| *id " | awk '{print $4}')

# wait for volume to become available
for i in $(seq 1 $vm_volume_available_check_tries)
do
  result="$(cinder show $volume_id 2>&1)"
  volume_status=$(echo "$result" | grep "^| *status" | awk '{printf $4}')
  [ "$volume_status" == "available" ] && break
  [ $i -lt $vm_volume_available_check_tries ] && sleep $vm_volume_available_check_delay
done
! [ "$volume_status" == "available" ] && check_code 1 "timeout waiting for volume to become available" "$result"

# test connection to VM
for i in $(seq 1 $vm_boot_check_tries)
do
  result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip "uptime" 2>&1)"
  code=$?
  [ $code -eq 0 ] && break
  [ $i -lt $vm_boot_check_tries ] && sleep $vm_boot_check_delay
done
check_code $code "failed to connect to VM" "$result"

# due to unreliable cinder attachment procedure, first get the list of current drives
vm_drives="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip "find /dev/vd*" 2>&1)"
check_code $? "failed to find /dev/vd* in VM" "$result"

# attach volume
result="$(nova volume-attach $instance_id $volume_id 2>&1)"
check_code $? "failed to attach volume" "$result"

# wait for volume to appear in VM
for i in $(seq 1 $vm_volume_attached_check_tries)
do
  vm_drives_2="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip "find /dev/vd*" 2>&1)"
  new_drive="$((echo "$vm_drives"; echo "$vm_drives_2") | sort | uniq -u)"
  [ -n "$new_drive" ] && break
  if [ $i -lt $vm_volume_attached_check_tries ]
  then
    nova volume-attach $instance_id $volume_id &> /dev/null # retry attaching since it is known to fail silently sometimes
    sleep $vm_volume_attached_check_delay
  fi
done
! [ -n "$new_drive" ] && check_code 1 "timeout waiting for volume to appear in VM" "$vm_drives_2"

# mkfs in VM
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip "sudo -i mkfs.ext4 -m 0 $new_drive" 2>&1)"
check_code $? "failed to create ext4 filesystem on VM" "$result"

# mount volume in VM
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip "sudo -i mount $new_drive /mnt && sudo -i chown $SPT_VM_USER /mnt" 2>&1)"
check_code $? "failed to mount ext4 filesystem on VM" "$result"

# cooldown to allow VM to finish init activities
sleep $SPT_VM_COOLDOWN

# give 10 seconds to dd to run, then getting intermediate stats, waiting 1 second and killing. Need to wait before killing, otherwise intermediate stats may not be printed
timelimit_cmd="pid=\$!; sleep $DD_TIMEOUT; kill -USR1 \$pid; sleep 1; kill \$pid"

# run dd write tests
echo "running dd write test - writing 1GB with bs=4k"
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip "dd if=/dev/zero of=/mnt/spt-write-test $DD_OPTIONS bs=4k count=262144 &:; $timelimit_cmd" 2>&1)"
echo "$result" | xargs -I@ echo "DD_TEST_1: @"

echo "running dd write test - writing 1GB with bs=1M"
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip "dd if=/dev/zero of=/mnt/spt-write-test-2 $DD_OPTIONS bs=1M count=1024 &:; $timelimit_cmd" 2>&1)"
echo "$result" | xargs -I@ echo "DD_TEST_2: @"

echo "running dd write test - writing 1GB with bs=1G"
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip "dd if=/dev/zero of=/mnt/spt-write-test-3 $DD_OPTIONS bs=1G count=1" 2>&1)" # no time limit here because it's a single block operation, no intermediate results available
echo "$result" | xargs -I@ echo "DD_TEST_3: @"

cleanup
