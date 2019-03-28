#! /bin/bash

iptables -t filter -F
iptables -t filter -X
iptables -t nat -F
iptables -t nat -X
echo All rules and chains removed

# Create a new chain for the filter table
# masqerade all output
iptables -t nat -A POSTROUTING -j MASQUERADE

# block connections from ip in IPs
IPs=("123.123.123.123" "233.233.233.233")
for x in ${IPs[@]} 
do
    iptables -A INPUT -s $x -j REJECT
    echo Reject connection from $x
done

# block from being pinged
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
echo No pinging allowed

# get ip of this machine
ip=$(hostname -I | sed 's/ //g')

# ssh forwarding
iptables -t nat -A PREROUTING -d $ip -p tcp\
    --dport 2333 -j DNAT --to-destination $ip:22
echo SSH port forwarding set up

# only accept ssh from engineering.purdue.edu
iptables -A INPUT -p tcp -s 128.46.0.0 --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 22 -j DROP
echo Allow for SSH only from engineering.purdue.edu

iptables -A INPUT -p tcp -s 233.233.233.233 --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 80 -j DROP
echo Only 233.233.233.233 can access this machine through HTTP

iptables -A INPUT -p tcp --dport 113 -j ACCEPT
echo Permit Auth/Ident \(port 113\)
