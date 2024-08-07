#!/bin/sh

## Wait for the daemons to start
sleep 2
#
## Check for linux routing suites
#if command -v bird || command -v /usr/lib/frr/zebra || command -v holod; then
#    # Setup interfaces
#    ifup -a
#
#    if command -v holod; then
#    	# Load Holo startup configuration
#        holo-cli --file /etc/holo.startup
#    elif command -v /usr/lib/frr/zebra; then
#    	# Load FRR startup configuration
#        vtysh -f /etc/frr/frr.startup
#    fi
#fi
VRF=$(ip link | grep vrf | cut -d "-" -f 3 | cut -d "@" -f 1 )

for i in $VRF
  do
  	sleep 1
        VRF_INT=$(ifconfig | grep vrf-${i} | awk '{print $1}')
  	TABLE=$(echo $i | sha256sum | sed 's/[^1-9]*//g')
  	ip link add $i type vrf table ${TABLE:0:4}
  	ip link set $i up
        for x in $VRF_INT
          do
	     ip link set dev $x vrf $i
             ip link set dev $x up
             echo "interface vrf: $i $x"
	     echo "ip link set dev $x vrf $i"
          done
	echo "vrf : $i"
  done
