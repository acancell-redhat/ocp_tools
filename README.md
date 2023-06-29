The following was created by merging:
- https://github.com/acancell-redhat/ocp_tools/blob/alt-params/parallel_conntrack_tcpdump/INSTRUCTIONS.txt
- https://gitlab.cee.redhat.com/palonsor/monitorsh-image/-/blob/main/monitor.sh
- extra checks (see "CUSTOMIZATION" comments inside the script)
  - pod yaml
  - pod veth name
  - netfilter files on both node and pod
  - iptable on both node and pod

Requirements:

The node must contain a copy of container image `registry.redhat.io/rhel8/support-tools`

Usage:
~~~
oc debug node/<node-name>
chroot /host podman rm 'toolbox-root'
chroot /host toolbox
mkdir /host/var/tmp/DUMP && cd /host/var/tmp/DUMP
vi analyzer.sh # and copy inside this file the script in this repo
chmod +x analyzer.sh
${DESTINATION_FOLDER:-/host/var/tmp/DUMP}/analyzer.sh POD NAMESPACE
~~~

Note:

The error `cat: /proc/sys/net/netfilter/nf_log_all_netns: No such file or directory` can be ignored