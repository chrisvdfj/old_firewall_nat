#!/bin/sh

echo "1" > /proc/sys/net/ipv4/ip_forward

iptables -F
iptables -F -t nat
iptables -X
iptables -X -t nat
iptables -Z
iptables -Z -t nat

######## sysctl ##########
#Disabling IP Spoofing attacks.
#echo 2 > /proc/sys/net/ipv4/conf/all/rp_filter
#Don't respond to broadcast pings (Smurf-Amplifier-Protection)
#echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
#Block source routing
#echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
#Kill timestamps
#echo 0 > /proc/sys/net/ipv4/tcp_timestamps
#Enable SYN Cookies
#echo 1 > /proc/sys/net/ipv4/tcp_syncookies
#Kill redirects
#echo 1 > /proc/sys/net/ipv4/conf/all/accept_redirects
#echo 1 > /proc/sys/net/ipv4/conf/all/accept_source_route
#Enable bad error message protection
#echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses


######### nat ############
iptables -F FORWARD
iptables -A FORWARD -j ACCEPT -i eth0 -o eth1 -d 200.120.216.0/24
iptables -A FORWARD -j ACCEPT -i eth1 -o eth0 -s 192.168.0.0/24

# vpn
#iptables -A PREROUTING -t nat -p gre -d 164.77.230.20 -j DNAT --to-destination 192.168.0.249
#iptables -A PREROUTING -t nat -p tcp --dport 1723 -d 164.77.230.20 -j DNAT --to-destination 192.168.0.249:1723
#iptables -A PREROUTING -t nat -p udp --dport 1723 -d 164.77.230.20 -j DNAT --to-destination 192.168.0.249:1723


##### Forwarding ######
#iptables -A FORWARD -i 164.77.230.20 -o 192.168.0.249 -p udp --dport 137 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#iptables -A PREROUTING -t nat -p udp -d 164.77.230.20 --dport 137 -j DNAT --to 192.168.0.249:137
#iptables -A FORWARD -i 164.77.230.20 -o 192.168.0.249 -p udp --dport 138 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#iptables -A PREROUTING -t nat -p udp -d 164.77.230.20 --dport 138 -j DNAT --to 192.168.0.249:138


#iptables -A FORWARD -i 164.77.230.20 -o 192.168.0.249 -p tcp --dport 139 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#iptables -A PREROUTING -t nat -p tcp -d 164.77.230.20 --dport 139 -j DNAT --to 192.168.0.249:139
########################



#################################
##### deny/allow ext to int #####
################################

# ACCEPT
#iptables -A INPUT -i eth0 -p tcp -s 192.168.1.106/32 --dport 137 -j ACCEPT
#iptables -A INPUT -i eth0 -p udp -s 192.168.1.106/32 --dport 137 -j ACCEPT
#iptables -A INPUT -i eth0 -p tcp -s 192.168.1.106/32 --dport 138 -j ACCEPT
#iptables -A INPUT -i eth0 -p udp -s 192.168.1.106/32 --dport 138 -j ACCEPT
#iptables -A INPUT -i eth0 -p tcp -s 192.168.1.106/32 --dport 139 -j ACCEPT
#iptables -A INPUT -i eth0 -p udp -s 192.168.1.106/32 --dport 139 -j ACCEPT

# DROP
#iptables -A INPUT -i eth0 -p tcp -s 0.0.0.0/0 --dport 137 -j DROP
#iptables -A INPUT -i eth0 -p udp -s 0.0.0.0/0 --dport 137 -j DROP
#iptables -A INPUT -i eth0 -p tcp -s 0.0.0.0/0 --dport 138 -j DROP
#iptables -A INPUT -i eth0 -p udp -s 0.0.0.0/0 --dport 138 -j DROP
#iptables -A INPUT -i eth0 -p tcp -s 0.0.0.0/0 --dport 139 -j DROP
#iptables -A INPUT -i eth0 -p udp -s 0.0.0.0/0 --dport 139 -j DROP

##########################
##########################
iptables -t nat -F POSTROUTING
iptables -t nat -A POSTROUTING -j MASQUERADE -o eth1
##########################





#### LOOP traffic accept #
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
##########################

########## syn ###########

#iptables -N syn-flood
#iptables -A INPUT -i eth0 -p tcp --syn -j syn-flood
#iptables -A INPUT -i eth1 -p tcp --syn -j syn-flood
#iptables -A syn-flood -m limit --limit 1/s --limit-burst 4 -j RETURN
#iptables -A syn-flood -j DROP

####### fragments ########

#iptables -A INPUT -i eth0 -f -j DROP
#iptables -A INPUT -i eth1 -f -j DROP

######## loop/broadcast ##

#iptables -A INPUT  -i eth0 -d 127.0.0.1 -j DROP
#iptables -A INPUT  -i eth1 -d 127.0.0.1 -j DROP
#iptables -A INPUT -i eth0 -d BROADCAST -j DROP
#iptables -A INPUT -i eth1 -d BROADCAST -j DROP

#iptables -A INPUT -i eth0 -p icmp -j DROP
#iptables -A OUTPUT -o eth1 -p icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

######### redir #######

#/sbin/redir --lport=80 --laddr=164.77.230.20 --cport=80 --caddr=192.168.0.249 --syslog &
#/sbin/redir --lport=25 --laddr=164.77.230.20 --cport=25 --caddr=192.168.0.249 --syslog &
#/sbin/redir --lport=110 --laddr=164.77.230.20 --cport=110 --caddr=192.168.0.249 --syslog &
#/sbin/redir --lport=5900 --laddr=164.77.230.20 --cport=5900 --caddr=192.168.0.249 --syslog &
#/sbin/redir --lport=3389 --laddr=164.77.230.20 --cport=3389 --caddr=192.168.0.249 --syslog &

