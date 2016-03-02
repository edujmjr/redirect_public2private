# redirect_public2private
Script that helps when you have few public adresses but you require ssh connection to multiple VMs (cloud or clusters)

# Operation of the script

This script makes an entire cluster or cloud accessible through only one public address, by redirecting ports.

When you already knows the vm or droplets ips, the private network they will use, you can automate the port redirect so the users can access his virtual machines directly using ssh.

The script knowing the private network, he generate several rules at iptables for each address in the private network until the max octet to map.

# Example

supposing if you have the public ip address 200.200.50.10 and inside your cloud/cluster you have the private network 10.2.0.0/16

One client have launched the vm with ip 10.2.0.20, using this script, anywhere in the world he can access his vm using ssh to 200.200.50.10 on port 20020.
because the script get the last 3 octets and combine them to create a port and associates to the private ip of the vm.

other examples:
10.2.8.20 -> port 28020
10.2.9.140 -> port 29140
10.2.10.100 -> port 30100
10.2.12.200 -> port 32200

