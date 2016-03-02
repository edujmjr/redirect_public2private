##
#
# 	FIREWALL SSH Redirect 1 public IP to several private IPs
#	
#	
##


ANY=0.0.0.0/0
LAN=X.X.X.X/X
BAD_BAD_IPS="/root/bad_bad_ips.lst"
FW_IP=Y.Y.Y.Y

###
### Flushing tables
###
iptables -F
iptables -X

iptables -F -t nat
iptables -X -t nat


fwStatus() {
	echo ===
	echo === INPUT ===
	echo ===
	iptables -L INPUT -n
	echo ===
	echo === FORWARD ===
	echo ===
	iptables -L FORWARD -n
	echo ===============
}



case $1 in
	start)
		flag=start
		;;
	stop)
		flag=stop
		;;
	status)
		fwStatus
		exit 0
		;;
	*)
		fwStatus
		exit 0
esac

###
##	CLEANING FILTERS
#

iptables -F INPUT
iptables -F FORWARD
iptables -F OUTPUT

iptables -X

iptables -F -t nat
iptables -X -t nat

[ $flag = stop ]  &&  echo "Stopping firewall..."  &&  exit 0

echo "Starting firewall public2private..."



## BLOCKING ATTACKERS

for ip in `cat $BAD_BAD_IPS | grep ^[^#]`
do
       
        iptables -A FORWARD -p tcp -s $ip -d $LAN --dport 1:65535 -j REJECT
        iptables -A FORWARD -p udp -s $ip -d $LAN --dport 1:65535 -j REJECT
        iptables -A INPUT -p udp -s $ip -d $LAN --dport 1:65535 -j REJECT
        iptables -A INPUT -p tcp -s $ip -d $LAN --dport 1:65535 -j REJECT
done

      #Redirecting ips with iptables, example: if i want to connect ssh to a vm with an ip address 10.2.2.200, i can use a ssh to the FW_IP (public address) using the port 22200, and i will arrive directly to the vm, the sense here is to get the last 3 octets of the ip and combine to get the port number for the vm with private address, another example: i need to ssh one vm with 10.2.5.120, so i can use ssh FW_IP using the port 25120.

# cluster vms' ips are: 10.2.oct2.oct3
max_oct2_to_map="18"

for oct2 in $(seq 0 $max_oct2_to_map); do
  for oct3 in $(seq 0 255); do
    if [[ $oct2 = "0" ]] && [[ $oct3 = "0" ]]; then
      # Skip the first address of the network 10.2.0.0
      continue
    fi
    #Skip the last address of the network 10.2.255.255? Do we want tcp broadcasts?

    addr="10.2.${oct2}.${oct3}"                       
    port="$((20 + ${oct2}))$(printf '%03d' ${oct3})"  # 10.2.0.35 -> 20035; 10.2.12.35 -> 32035

    # check that the port has the format [1-9]\d[0-2]\d\d, e.g. 22035
    if [[ ! $port =~ ^[1-9][0-9][0-2][0-9][0-9]$ ]]; then
      echo "Assertion error! oct2=${oct2} oct3=${oct3} port=${port}"
      exit -1
    fi

    iptables -t nat -A PREROUTING -d $FW_IP -p tcp --dport ${port} -j DNAT --to-destination ${addr}:22
  done
done

# the entries of the nat/PREROUTING will change before the packet pass through filter/FORWARD
iptables -t filter -A FORWARD -d 10.2.0.0/16 -p tcp --dport 22 -j ACCEPT

# ...e antes de chegar no nat/POSTROUTING
iptables -t nat -A POSTROUTING -d 10.2.0.0/16 -p tcp --dport 22 -j SNAT --to-source $FW_IP:20000-65535


      #END of Redirect IPs



####
##	Reject everything else
####

iptables -P FORWARD -j DROP

##
#
##
