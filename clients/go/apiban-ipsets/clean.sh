#!/bin/bash

CHAIN=$1
#CHAIN="BLOCKER"
#CHAIN="NAZDAR"
IPSETNAME=$2

ipset flush blacklist
iptables -D INPUT -j $CHAIN
iptables -D FORWARD -j $CHAIN
iptables -D $CHAIN -m set --match-set $IPSETNAME src -j DROP
iptables -X $CHAIN
ipset destroy $IPSETNAME
