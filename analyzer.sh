#!/usr/bin/env bash

######################################################################################################################
# Script to get in parallel:                                                                                         #
#  - conntrack logs (on host and inside specified pod)                                                               #
#  - tcpdumps (all non-veth host interfaces (included br0) + host veth interface of specified pod + eth0 inside pod) #
# NOTE This script is intended to be used only on OCP clusters with OpenShiftSDN CNI                                 # 
######################################################################################################################

#### FUNCTIONS ####

function usage() {
  echo
  echo "@@ USAGE:"
  echo 
  echo "$(basename $0) <pod-name> <ocp-project-of-pod>"
  echo "  CTRL+C to end the capture"
  exit 1
}

function cleanup() {
  echo
  echo "@@ CLEANUP..."
  kill_jobs
  unmirror_br0
  echo
  echo "@@ FINISHED"
}

# exit all background processes
function kill_jobs() {
  running_jobs=()
  running_jobs+="$(jobs -p)"
  if [ -n "$running_jobs" ]; then
    echo
    echo "    @@ KILLING CAPTURING JOBS..."
    for j in ${running_jobs[@]}; do
      kill $j
    done
  fi
  sleep 5 
}

# check that all required tools are installed
function check_tools() {
  echo
  echo "@@ CHECKING REQUIRED TOOLS..."
  chroot /host command -v conntrack
  command -v tcpdump  # NOTE No chroot needed here
}

# set br0 mirror so it can be dumped. See https://access.redhat.com/solutions/3128381
function mirror_br0() {
  echo
  echo "@@ SETTING br0 MIRROR..."
  set -x
  ip link add name br0-snooper0 type dummy
  ip link set dev br0-snooper0 up
  set +x
  chroot /host ovs-vsctl --verbose=INFO add-port br0 br0-snooper0
  chroot /host ovs-vsctl --verbose=INFO -- set Bridge br0 mirrors=@m  \
    -- --id=@br0-snooper0 get Port br0-snooper0 \
    -- --id=@br0 get Port br0 \
    -- --id=@m create Mirror name=br0mirror \
    select-dst-port=@br0 \
    select-src-port=@br0 \
    output-port=@br0-snooper0 \
    select_all=1
  chroot /host ovs-vsctl --verbose=INFO list mirror br0mirror
}

# clean up port mirror and remove snooper interface. See https://access.redhat.com/solutions/3128381
function unmirror_br0() {
  if [ -n "$(ip link | grep br0-snooper0)" ]; then
    echo
    echo "    @@ UN-SETTING br0 MIRROR..."
    chroot /host ovs-vsctl --verbose=INFO clear bridge br0 mirrors
    chroot /host ovs-vsctl --verbose=INFO del-port br0 br0-snooper0
    set -x
    ip link delete br0-snooper0
    set +x
  fi
}

# get linux namespace of container of pod. See https://access.redhat.com/solutions/4569211
function get_container_namespace() {
  echo
  echo "@@ GETTING NET NS OF POD \"$PODNAME\" ..."

  pod_id=$(chroot /host crictl pods --namespace ${PODNAMESPACE} --name ${PODNAME} -q)
  if [ -z "$pod_id" ]; then
    echo "ERROR: Cannot find pod \"${PODNAME}\" in project \"${PODNAMESPACE}\" on this host"
    exit 3
  else
    ns_path="/host/$(chroot /host bash -c "crictl inspectp $pod_id | jq '.info.runtimeSpec.linux.namespaces[]|select(.type==\"network\").path' -r")"
    nsenter_parameters="--net=${ns_path}"
    echo "$nsenter_parameters"
  fi
}

# get host veth interface corresponding to the pod. See https://access.redhat.com/solutions/4569211
function get_veth_if() {
  echo
  echo "@@ GETTING HOST VETH INTERFACE RELATED TO POD \"$PODNAME\" ..."

  pair_n=$(nsenter $nsenter_parameters -- ip -o link show | awk -F':' '{print $2}' | grep eth0 | sed 's/ eth0@if//g')
  veth_if=$(ip -o link show | grep -E "^$pair_n:" | awk -F':' '{print $2}' | sed -E 's/^ //; s/@if[0-9]+//')
  echo $veth_if | tee $DESTINATION_FOLDER/${PODNAME}_$(date +%d_%m_%Y-%H_%M_%S-%Z)-veth.txt
}

# CUSTOMIZATION
function get_pod() {
  echo
  echo "@@ GETTING YAML OF POD \"$PODNAME\" ..."
  chroot /host oc get pod --kubeconfig /var/lib/kubelet/kubeconfig -n $2 $1 -o yaml | tee $DESTINATION_FOLDER/${PODNAME}_$(date +%d_%m_%Y-%H_%M_%S-%Z).yaml
}
# end of CUSTOMIZATION

#### MAIN ####

# when this script exits, run the cleanup function
trap cleanup EXIT

# parameters
[ $# -lt 2 ] && usage
PODNAME=$1
PODNAMESPACE=$2
TCPDUMP_FILTER=''
DESTINATION_FOLDER="/host/var/tmp/DUMP"

# CUSTOMIZATION
# dump pod yaml
get_pod $PODNAME $PODNAMESPACE
# end of CUSTOMIZATION

# check that all required tools are installed
check_tools

# get linux namespace of container of pod
get_container_namespace 

# get host veth interface related to pod
get_veth_if

# by default br0 can't be dumped; create mirror interface "br0-snooper0" to do so
mirror_br0

# the list of host interfaces to tcpdump
echo
echo "@@ CREATING HOST INTERFACES LIST..."
declare -a host_interfaces
host_interfaces+=$(ip -o link show | grep -v "veth" | awk -F':' '{print $2}' | sed 's/^ //g' | grep -E -v '^(lo|ovs-system|br0)$')
host_interfaces+=($veth_if)
echo "${host_interfaces[@]}" | sed -E 's/ /\n/g' | sort

# the list of pod interfaces to tcpdump
echo
echo "@@ CREATING POD INTERFACES LIST..."
declare -a pod_interfaces
pod_interfaces+=("eth0")
echo "${pod_interfaces[@]}" | sed -E 's/ /\n/g' | sort

# start data collecting
echo
echo "@@ STARTING PARALLEL CONNTRACKS AND TCPDUMPS . Use CTRL+C to end the capture"

echo
echo "    @@ STARTING HOST CONNTRACK"   
chroot /host conntrack -E -o timestamp > $DESTINATION_FOLDER/conntrack_host_${HOSTNAME}_$(date +%d_%m_%Y-%H_%M_%S-%Z).txt &

echo
echo "    @@ STARTING POD CONNTRACK"   
bash -c "nsenter $nsenter_parameters -- chroot /host conntrack -E -o timestamp > $DESTINATION_FOLDER/conntrack_pod_${PODNAME}_$(date +%d_%m_%Y-%H_%M_%S-%Z).txt" &

# create one tcpdump output per interface
echo
echo "    @@ STARTING HOST TCPDUMPS" 
for i in ${host_interfaces[@]}; do
  tcpdump -nn -i ${i} -v -C 1000 -W 10 -Z root -w $DESTINATION_FOLDER/tcpdump_host_${HOSTNAME}_${i}_$(date +%d_%m_%Y-%H_%M_%S-%Z).pcap $TCPDUMP_FILTER & 
done

# create one tcpdump output per interface
echo
echo "    @@ STARTING POD TCPDUMPS"   
for i in ${pod_interfaces[@]}; do
  # See https://access.redhat.com/solutions/4569211
  bash -c "nsenter $nsenter_parameters -- tcpdump -nn -i ${i} -v -C 1000 -W 10 -Z root -w $DESTINATION_FOLDER/tcpdump_pod_${PODNAME}_${i}_$(date +%d_%m_%Y-%H_%M_%S-%Z).pcap $TCPDUMP_FILTER" &
done

######################################################################################################################
# monitor.sh begins here
# License: Creative Commons Zero - https://creativecommons.org/publicdomain/zero/1.0/
######################################################################################################################

## defaults

VERSION=47

DELAY=5
ITERATIONS=-1
DEF_SS_OPTS="-noemitaup"
DEF_SS_OPTS_NOP="-noemitau"

## option parsing

REAL_SS_OPTS=${SS_OPTS:-$DEF_SS_OPTS}

#
# Removed default addition of -S for ss options due to
# https://bugzilla.redhat.com/show_bug.cgi?id=1982804
# which causes ss coredump in RHEL8.0 - RHEL8.4. when there
# are active SCTP associations
# 
#if [ -z "$SS_OPTS" ] ; then
#    if ! ss -S 2>&1 | grep -q "invalid option"; then
#        REAL_SS_OPTS+="S"
#    fi
#fi

## reporting

if [ "$ITERATIONS" -gt 0 ]; then
    echo "Running network monitoring with $DELAY second delay for $ITERATIONS iterations."
else
    echo "Running network monitoring with $DELAY second delay. Press Ctrl+c to stop..."
fi

## one-time commands

MQDEVS=( $(chroot /host tc qdisc show | awk '/^qdisc mq/{print $(NF-1)}') )

# CUSTOMIZATION - add fileslist for further dump
netfilter_files_list=()
for f in /proc/sys/net/netfilter/*; do
if [ -f $f ] ; then
    netfilter_files_list+=($(basename $f))
fi
done
# end of CUSTOMIZATION

## data collection loop
while [ "$ITERATIONS" != 0 ]; do

    #start timer in background
    sleep "$DELAY"

    now=$(date +%Y_%m_%d_%H)
    mkdir -p "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now"
    mkdir -p "$DESTINATION_FOLDER/$PODNAME-network_stats_$now"

    if ! [ -e "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/version.txt" ]; then
        echo "===== $(date +"%F %T.%N%:z (%Z)") =====" > "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/version.txt"
        echo "This output created with monitor.sh version $VERSION" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/version.txt"
        echo "See https://access.redhat.com/articles/1311173" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/version.txt"
        echo "Delay: $DELAY" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/version.txt"
        echo "Iterations: $ITERATIONS" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/version.txt"
    echo "SS_OPTS: $REAL_SS_OPTS" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/version.txt"
    fi
    if ! [ -e "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sysctl.txt" ]; then
        echo "===== $(date +"%F %T.%N%:z (%Z)") =====" > "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sysctl.txt"
        sysctl -a 2>/dev/null >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sysctl.txt"
    fi  
    if ! [ -e "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ip-address.txt" ]; then
        echo "===== $(date +"%F %T.%N%:z (%Z)") =====" > "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ip-address.txt"
        ip address list >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ip-address.txt"
    fi
    if ! [ -e "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ip-route.txt" ]; then
        echo "===== $(date +"%F %T.%N%:z (%Z)") =====" > "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ip-route.txt"
        ip route show table all >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ip-route.txt"
    fi
    if ! [ -e "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/uname.txt" ]; then
        echo "===== $(date +"%F %T.%N%:z (%Z)") =====" > "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/uname.txt"
        uname -a >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/uname.txt"
    fi
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ip_neigh"
    ip neigh show >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ip_neigh"
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/tc_qdisc"
    chroot /host tc -s qdisc >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/tc_qdisc"
    if [ "${#MQDEVS[@]}" -gt 0 ]; then
        for MQDEV in "${MQDEVS[@]}"; do
            echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/tc_class_$MQDEV"
            chroot /host tc -s class show dev "$MQDEV" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/tc_class_$MQDEV"
        done
    fi
    # CUSTOMIZATION - using nstat instead of netstat, since no netstat installed in toolbox
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/nstat"
    nstat -s >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/nstat"
    # end of CUSTOMIZATION
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/nstat"
    nstat -az >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/nstat"
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ss"
    eval "ss $REAL_SS_OPTS" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ss"
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/interrupts"
    cat /proc/interrupts >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/interrupts"
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/softnet_stat"
    cat /proc/net/softnet_stat >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/softnet_stat"
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/vmstat"
    cat /proc/vmstat >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/vmstat"
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ps"
    ps -alfe >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ps"
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/mpstat"
    eval mpstat -A "$DELAY" 1 2>/dev/null >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/mpstat" &
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/top"
    top -c -b -n1 >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/top"
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/numastat"
    numastat 2>/dev/null >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/numastat"
    if [ -e /proc/softirqs ]; then
        echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/softirqs"
        cat /proc/softirqs >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/softirqs"
    fi
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sockstat"
    cat /proc/net/sockstat >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sockstat"
    if [ -e /proc/net/sockstat6 ]; then
        echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sockstat6"
        cat /proc/net/sockstat6 >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sockstat6"
    fi
    echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/netdev"
    cat /proc/net/dev >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/netdev"
    for DEV in $(ip a l | grep mtu | awk '{print $2}' | awk -F ":" '{print $1}'); do echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ethtool_$DEV"; ethtool -S "$DEV" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/ethtool_$DEV" 2>/dev/null; done
    for DEV in $(ip a l | grep mtu | awk '{print $2}' | awk -F ":" '{print $1}'); do echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sys_statistics_$DEV"; find /sys/devices/ -type f | grep "/net/$DEV/statistics" | xargs grep . | awk -F "/" '{print $NF}' >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sys_statistics_$DEV"; done
    if [ -e /proc/net/sctp ]; then
        echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sctp-assocs"
        cat /proc/net/sctp/assocs >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sctp-assocs"
        echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sctp-snmp"
        cat /proc/net/sctp/snmp >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/sctp-snmp"
    fi

    # CUSTOMIZATION - dump iteratively all netfilter files
    for f in ${netfilter_files_list[@]}; do
        # on node
        if [ ! -e $DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/$f ]; then
            echo "===== $(date +"%F %T.%N%:z (%Z)") =====" > "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/$f" 
        else
            echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/$f"
        fi
        cat /proc/sys/net/netfilter/$f >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/$f"

        # on pod
        if [ ! -e $DESTINATION_FOLDER/$PODNAME-network_stats_$now/$f ]; then
            echo "===== $(date +"%F %T.%N%:z (%Z)") =====" > "$DESTINATION_FOLDER/$PODNAME-network_stats_$now/$f" 
        else
            echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$PODNAME-network_stats_$now/$f"
        fi
        bash -c "nsenter $nsenter_parameters -- chroot /host cat /proc/sys/net/netfilter/$f >> $DESTINATION_FOLDER/$PODNAME-network_stats_$now/$f" &

    done
    # CUSTOMIZATION - dump all iptables
    # we collect less iterations here (one each 10 seconds), because the dump locks iptables
    if [[ $(( $(date +%-S) % 10 )) == 0 ]]; then
      for t in filter nat mangle raw security; do
          # on node
          if [ ! -e $DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/iptables-$t ]; then
              echo "===== $(date +"%F %T.%N%:z (%Z)") =====" > "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/iptables-$t"
          else
              echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/iptables-$t"
          fi
          chroot /host iptables -v -L -t $t >> "$DESTINATION_FOLDER/$HOSTNAME-network_stats_$now/iptables-$t"

          # on pod
          if [ ! -e $DESTINATION_FOLDER/$PODNAME-network_stats_$now/iptables-$t ]; then
              echo "===== $(date +"%F %T.%N%:z (%Z)") =====" > "$DESTINATION_FOLDER/$PODNAME-network_stats_$now/iptables-$t"
          else
              echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> "$DESTINATION_FOLDER/$PODNAME-network_stats_$now/iptables-$t"
          fi
          bash -c "nsenter $nsenter_parameters -- chroot /host iptables -v -L -t $t >> $DESTINATION_FOLDER/$PODNAME-network_stats_$now/iptables-$t" &
      done
    fi
    # end of CUSTOMIZATION
    if [ "$ITERATIONS" -gt 0 ]; then let ITERATIONS-=1; fi
done

# wait until CTRL+C
wait
