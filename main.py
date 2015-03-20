import binascii
import logging

from generator import *
from packet_decoder import *
from PcapWriter import PcapWriter

# Log packets to a PCAP file.
# When viewing in wireshark, make sure to enable IP/TCP/UDP checksum validation.
pktdump = PcapWriter("output.pcap", PcapWriter.LinkType.LINKTYPE_RAW)

def validate_packet(original, decode_pkt):
    decode_str = decode_pkt.encode()
    if original == decode_str:
        print("Packets match")
    else:
        print("Packets are not equal")
        print("ORIG: %s" % binascii.hexlify(original))
        print("DECD: %s" % binascii.hexlify(decode_str))

if __name__ == "__main__":
    FORMAT = '%(asctime)-15s - %(message)s'
    logging.basicConfig(format=FORMAT)

    # Generate a DNS query, decode then encode it to make 
    # sure the packets are equal
    pkt_str = str(gen_dns_packet("8.8.8.8", "bisrael8191.com"))
    decode_pkt = PacketDecoder(pkt_str)
    validate_packet(pkt_str, decode_pkt)
    decode_pkt.fix_checksum()
    pktdump.write_packet(decode_pkt.encode())

    # Generate an ICMP ping, decode then encode it to make 
    # sure the packets are equal
    pkt_str = str(gen_icmp_packet("8.8.8.8"))
    decode_pkt = PacketDecoder(pkt_str)
    validate_packet(pkt_str, decode_pkt)
    decode_pkt.fix_checksum()
    pktdump.write_packet(decode_pkt.encode())
    
    # Generate an ARP packet and make sure it doesn't decode (not supported)
    try:
        pkt_str = str(gen_arp_packet())
        decode_pkt = PacketDecoder(pkt_str)
    except:
        # This is a negative test, should throw an exception
        pass
    
    # Generate a large packet, run it through the decoder, re-encode
    # it and make sure the packets are equal.
    pkt_str = str(gen_tcp_packet(7300))
    decode_pkt = PacketDecoder(pkt_str)
    validate_packet(pkt_str, decode_pkt)

    # Fragment the large packet and log it to a pcap file
    # to verify that wireshark assembles it properly.
    for frag in decode_pkt.fragment():
        frag.fix_checksum()
        pktdump.write_packet(frag.encode())