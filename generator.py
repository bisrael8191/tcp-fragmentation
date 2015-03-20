from scapy.all import *
import StringIO
import math

# Use scapy to generate a DNS packet
def gen_dns_packet(dns_server, address):
    return IP(dst=dns_server)/UDP()/DNS(id=1,qd=DNSQR(qname=address))

# Use scapy to generate an ARP packet
def gen_arp_packet():
    return Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="10.0.0.1")

# Use scapy to generate an ICMP ping packet
def gen_icmp_packet(address):
    return IP(dst=address)/ICMP()

# Use scapy to generate a generic TCP packet with a
# custom sized payload
def gen_tcp_packet(payload_size, fragsize=1460):
    payload = []
    num_frags = int(math.ceil(payload_size/float(fragsize))) - 1
    for i in range(0, num_frags):
        payload.append(str(i)*fragsize)

    payload.append(str(num_frags) * (payload_size - (fragsize * num_frags)))
    return IP()/TCP(flags="")/(''.join(payload))