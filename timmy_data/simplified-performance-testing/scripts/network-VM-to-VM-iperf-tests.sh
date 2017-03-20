#!/bin/bash

set -x

# this test requires sudo in VM
# this test requires iperf in VM (or available for installation)
# this test expects iptables in VM to accept connections, it does not manipulate iptables inside VM

SPT_DNS=${SPT_DNS:-"8.8.8.8"}
SPT_FLOATING_NET=${SPT_FLOATING_NET:-"admin_floating_net"}
SPT_FLAVOR=${SPT_FLAVOR:-"m1.small"}
SPT_IMAGE=${SPT_IMAGE:-"xenial"}
SPT_VM_USER=${SPT_VM_USER:-"ubuntu"}
SPT_VM_COOLDOWN=${SPT_VM_COOLDOWN:-"120"}
SPT_VM_INSTALL_COMMAND=${SPT_VM_INSTALL_COMMAND:-"apt-get"}
SPT_IPERF_PORT=${SPT_IPERF_PORT:-"65432"}
SPT_AVAILABILITY_ZONE=${SPT_AVAILABILITY_ZONE:-"nova"}
SSH_OPTS="-q -n -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -l $SPT_VM_USER"
VM_BOOT_TIMEOUT_MINUTES=${VM_BOOT_TIMEOUT_MINUTES:-"5"}

vm_boot_check_tries=$(($VM_BOOT_TIMEOUT_MINUTES*2))
vm_boot_check_delay=30
vm_active_check_tries=10
vm_active_check_delay=10

function partial_cleanup_2 {
  [ -n "$instance_2_id" ] && [ -n "$floatingip_2" ] && nova floating-ip-disassociate $instance_2_id $floatingip_2
  [ -n "$instance_2_id" ] && [ -n "$secgroup_id" ] && nova remove-secgroup $instance_2_id $secgroup_id
  [ -n "$instance_2_id" ] && nova delete $instance_2_id
}

function cleanup {
  echo "cleaning up..."
  partial_cleanup_2
  [ -n "$floatingip_2_id" ] && neutron floatingip-delete $floatingip_2_id
  [ -n "$instance_id" ] && [ -n "$floatingip" ] && nova floating-ip-disassociate $instance_id $floatingip
  [ -n "$floatingip_id" ] && neutron floatingip-delete $floatingip_id
  [ -n "$instance_id" ] && [ -n "$secgroup_id" ] && nova remove-secgroup $instance_id $secgroup_id
  [ -n "$instance_id" ] && nova delete $instance_id
  [ -n "$secgroup_id" ] && neutron security-group-delete $secgroup_id
  [ -n "$router_id" ] && [ -n "$subnet_id" ] && neutron router-interface-delete $router_id $subnet_id
  [ -n "$router_id" ] && [ -n "$subnet_2_id" ] && neutron router-interface-delete $router_id $subnet_2_id
  [ -n "$router_id" ] && neutron router-delete $router_id
  [ -n "$subnet_id" ] && neutron subnet-delete $subnet_id
  [ -n "$subnet_2_id" ] && neutron subnet-delete $subnet_2_id
  [ -n "$net_id" ] && neutron net-delete $net_id
  [ -n "$net_2_id" ] && neutron net-delete $net_2_id
  [ -n "$keypair_name" ] && nova keypair-delete $keypair_name
  [ -f "spt-temporary-keypair" ] && rm "spt-temporary-keypair"
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
result="$(neutron subnet-create --name "spt-temporary-subnet" --dns-nameserver $SPT_DNS $net_id 10.20.30.0/24 2>&1)"
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
result="$(nova boot --image $SPT_IMAGE --flavor $SPT_FLAVOR --nic net-id=$net_id --key-name "spt-temporary-keypair" --security-groups $secgroup_id --availability-zone $SPT_AVAILABILITY_ZONE "spt-temporary-vm" 2>&1)"
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

# get fixed ip
result="$(neutron floatingip-show $floatingip_id 2>&1)"
check_code $? "failed to show floatingip info" "$result"
fixedip=$(echo "$result" | grep "^| fixed_ip_address " | awk '{print $4}')

# test connection to VM
for i in $(seq 1 $vm_boot_check_tries)
do
  result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip "uptime" 2>&1)"
  code=$?
  [ $code -eq 0 ] && break
  [ $i -lt $vm_boot_check_tries ] && sleep $vm_boot_check_delay
done
check_code $code "failed to connect to VM" "$result"

# install iperf
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip "sudo $SPT_VM_INSTALL_COMMAND install iperf" 2>&1)"
check_code $? "failed to install iperf" "$result"

# start server
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip '
outfile=$(mktemp)
iperf -s -p '$SPT_IPERF_PORT'&> $outfile &
pid=$!
if ! [ $(pgrep iperf) ]
then
  echo "iperf did not start"
  cat $outfile
  rm -f $outfile
  exit 1
fi
echo $pid
echo $outfile' 2>&1)"
check_code $? "failed to start iperf server" "$result"
read -d'\n' server_pid server_output <<< "$result"

##########################################################
### stage 1 - test with another VM on the same compute ###
##########################################################

# find location of the first VM

host=$(mysql -s -N -D nova -e "select host from instances where uuid='$instance_id'" 2>&1)
check_code $? "failed to get host of VM $instance_id" "$host"

# allocate second floating IP
result="$(neutron floatingip-create $SPT_FLOATING_NET 2>&1)"
check_code $? "failed to create second floatingip" "$result"
floatingip_2=$(echo "$result" | grep "^| floating_ip_address " | awk '{print $4}')
floatingip_2_id=$(echo "$result" | grep "^| id " | awk '{print $4}')

# boot second VM on the same host
result="$(nova boot --image $SPT_IMAGE --flavor $SPT_FLAVOR --nic net-id=$net_id --key-name "spt-temporary-keypair" --security-groups $secgroup_id --availability-zone $SPT_AVAILABILITY_ZONE:$host "spt-temporary-vm-2" 2>&1)"
check_code $? "failed to boot second VM on the same host" "$result"
instance_2_id=$(echo "$result" | grep "^| id " | awk '{print $4}')

# wait for instance to become active
for i in $(seq 1 $vm_active_check_tries)
do
  result="$(nova show $instance_2_id 2>&1)"
  vm_status=$(echo "$result" | grep "^| *status" | awk '{printf $4}')
  [ "$vm_status" == "ACTIVE" ] && break
  [ $i -lt $vm_active_check_tries ] && sleep $vm_active_check_delay
done
! [ "$vm_status" == "ACTIVE" ] && check_code 1 "timeout waiting for second VM to become active" "$result"

# associate floatingip
result="$(nova floating-ip-associate $instance_2_id $floatingip_2 2>&1)"
check_code $? "failed to associate floatingip_2" "$result"

# test connection to VM
for i in $(seq 1 $vm_boot_check_tries)
do
  result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip_2 "uptime" 2>&1)"
  code=$?
  [ $code -eq 0 ] && break
  [ $i -lt $vm_boot_check_tries ] && sleep $vm_boot_check_delay
done
check_code $code "failed to connect to second VM" "$result"

# install iperf on second VM
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip_2 "sudo $SPT_VM_INSTALL_COMMAND install iperf" 2>&1)"
check_code $? "failed to install iperf on second VM" "$result"

# run VM to VM test via internal IPs
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip_2 "iperf -c $fixedip -p $SPT_IPERF_PORT" 2>&1)"
echo "VM to VM, same host, internal IP, 1 connection:"
echo "$result"

# removing second VM
partial_cleanup_2

#####################################################
### stage 2 - test with VMs on different computes ###
#####################################################

#find current AZ id
az_id=$(mysql -s -N -D nova -e "select aggregate_id from aggregate_hosts where host='$host' and deleted = 0" 2>&1)

# find another host
if [ -z "$az_id" ]
then
  # no AZ defined - all hosts in the default "nova" AZ
  host_2=$(mysql -s -N -D nova -e "select host from compute_nodes where host <> '$host' and deleted = 0 limit 1" 2>&1)
else
  host_2=$(mysql -s -N -D nova -e "select host from aggregate_hosts where aggregate_id = $az_id and host <> '$host' and deleted = 0 limit 1" 2>&1)
fi
check_code $? "failed to get a different host for a new VM" "$host"

# boot second VM on a different host
result="$(nova boot --image $SPT_IMAGE --flavor $SPT_FLAVOR --nic net-id=$net_id --key-name "spt-temporary-keypair" --security-groups $secgroup_id --availability-zone $SPT_AVAILABILITY_ZONE:$host_2 "spt-temporary-vm-2" 2>&1)"
check_code $? "failed to boot second VM on a different host" "$result"
instance_2_id=$(echo "$result" | grep "^| id " | awk '{print $4}')

# wait for instance to become active
for i in $(seq 1 $vm_active_check_tries)
do
  result="$(nova show $instance_2_id 2>&1)"
  vm_status=$(echo "$result" | grep "^| *status" | awk '{printf $4}')
  [ "$vm_status" == "ACTIVE" ] && break
  [ $i -lt $vm_active_check_tries ] && sleep $vm_active_check_delay
done
! [ "$vm_status" == "ACTIVE" ] && check_code 1 "timeout waiting for second VM to become active" "$result"

# associate floatingip
result="$(nova floating-ip-associate $instance_2_id $floatingip_2 2>&1)"
check_code $? "failed to associate floatingip_2" "$result"

# test connection to VM
for i in $(seq 1 $vm_boot_check_tries)
do
  result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip_2 "uptime" 2>&1)"
  code=$?
  [ $code -eq 0 ] && break
  [ $i -lt $vm_boot_check_tries ] && sleep $vm_boot_check_delay
done
check_code $code "failed to connect to second VM" "$result"

# install iperf on second VM
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip_2 "sudo $SPT_VM_INSTALL_COMMAND install iperf" 2>&1)"
check_code $? "failed to install iperf on second VM" "$result"

# run VM to VM test via internal IPs
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip_2 "iperf -c $fixedip -p $SPT_IPERF_PORT" 2>&1)"
echo "VM to VM, different hosts, internal IP, 1 connection:"
echo "$result"

# run VM to VM test via internal IPs, 10 connections
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip_2 "iperf -c $fixedip -p $SPT_IPERF_PORT -P10" 2>&1)"
echo "VM to VM, different hosts, internal IP, 10 connections:"
echo "$result"

# run VM to VM test via floating IPs
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip_2 "iperf -c $floatingip -p $SPT_IPERF_PORT" 2>&1)"
echo "VM to VM, different hosts, floating IP, 1 connection:"
echo "$result"

# removing second VM
partial_cleanup_2

#####################################################################################################################
### stage 3 - test with VMs on different hosts and connected to different networks, networks connected via router ###
#####################################################################################################################

# create second network
result="$(neutron net-create "spt-temporary-net-2" 2>&1)"
check_code $? "failed to create second network" "$result"
net_2_id=$(echo "$result" | grep "^| id " | awk '{print $4}')

# create second subnet
result="$(neutron subnet-create --name "spt-temporary-subnet-2" --dns-nameserver $SPT_DNS $net_2_id 10.20.40.0/24 2>&1)"
check_code $? "failed to create second subnet" "$result"
subnet_2_id=$(echo "$result" | grep "^| id " | awk '{print $4}')

# join subnets via router
result="$(neutron router-interface-add $router_id $subnet_2_id 2>&1)"
check_code $? "failed to add router interface to second subnet" "$result"

# boot second VM in second network
result="$(nova boot --image $SPT_IMAGE --flavor $SPT_FLAVOR --nic net-id=$net_2_id --key-name "spt-temporary-keypair" --security-groups $secgroup_id --availability-zone $SPT_AVAILABILITY_ZONE:$host_2 "spt-temporary-vm-2" 2>&1)"
check_code $? "failed to boot second VM" "$result"
instance_2_id=$(echo "$result" | grep "^| id " | awk '{print $4}')

# wait for instance to become active
for i in $(seq 1 $vm_active_check_tries)
do
  result="$(nova show $instance_2_id 2>&1)"
  vm_status=$(echo "$result" | grep "^| *status" | awk '{printf $4}')
  [ "$vm_status" == "ACTIVE" ] && break
  [ $i -lt $vm_active_check_tries ] && sleep $vm_active_check_delay
done
! [ "$vm_status" == "ACTIVE" ] && check_code 1 "timeout waiting for second VM to become active" "$result"

# associate floatingip
result="$(nova floating-ip-associate $instance_2_id $floatingip_2 2>&1)"
check_code $? "failed to associate floatingip_2" "$result"

# test connection to VM
for i in $(seq 1 $vm_boot_check_tries)
do
  result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip_2 "uptime" 2>&1)"
  code=$?
  [ $code -eq 0 ] && break
  [ $i -lt $vm_boot_check_tries ] && sleep $vm_boot_check_delay 
done
check_code $code "failed to connect to second VM" "$result"

# install iperf on second VM
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip_2 "sudo $SPT_VM_INSTALL_COMMAND install iperf" 2>&1)"
check_code $? "failed to install iperf on second VM" "$result"

# run VM to VM test via internal IPs
result="$(ssh $SSH_OPTS -i spt-temporary-keypair $floatingip_2 "iperf -c $fixedip -p $SPT_IPERF_PORT" 2>&1)"
echo "VM to VM, different hosts, different networks, internal IP, 1 connection:"
echo "$result"

cleanup

