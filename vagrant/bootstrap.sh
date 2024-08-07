#!/bin/sh

# install packages
dnf install -y kernel-modules-$(uname -r) git zsh

# install containerlab
if ! command -v containerlab &> /dev/null 
  then	
     (curl -sL https://containerlab.dev/setup | sudo bash -s "all")
fi

if [ ! -d "/home/vagrant/clab" ]; then
  git clone https://github.com/sbng/clab.git
fi

! (lsmod | grep mpls > /dev/null ) &&  
	modprobe mpls_router &&
	modprobe mpls_gso &&
	modprobe mpls_iptunnel 

exit 0
