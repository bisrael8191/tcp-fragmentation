import math
import socket
from collections import defaultdict
import struct
import array
import logging


class IpHeader(object):
    """ IP Header block

        RFC 791
        http://en.wikipedia.org/wiki/IPv4#Header
    """

    IP_HEADER_FMT = struct.Struct('!BBHHHBBH4s4s')

    IP_PROTOCOL = {'TCP': 6, 'UDP': 17, 'ICMP': 1}

    def __init__(self, ip_frame):
        self.ip_frame = ip_frame

        self.version = 4
        self.header_length = 5
        self.type_of_service = 0
        self.total_length = 0
        self.identification = 0
        self.flags = 0
        self.fragment_offset = 0
        self.ttl = 0
        self.protocol = 0
        self.checksum = 0
        self.src = ""
        self.dst = ""
        self.options = []

        self._decode()

    def _decode(self):
        header = self.IP_HEADER_FMT.unpack(self.ip_frame[:self.IP_HEADER_FMT.size])

        self.version = header[0] >> 4
        self.header_length = header[0] & 0xF
        self.type_of_service = header[1]
        self.total_length = header[2]
        self.identification = header[3]
        self.flags = header[4] >> 3
        self.fragment_offset = header[4] & 0xF
        self.ttl = header[5]

        proto = header[6]
        if proto == self.IP_PROTOCOL['TCP']:
            self.protocol = 'TCP'
        elif proto == self.IP_PROTOCOL['UDP']:
            self.protocol = 'UDP'
        elif proto == self.IP_PROTOCOL['ICMP']:
            self.protocol = 'ICMP'
        else:
            self.protocol = proto

        self.checksum = header[7]
        self.src = socket.inet_ntoa(str(header[8]))
        self.dst = socket.inet_ntoa(str(header[9]))

        # Decode additional options (header length is greater than 5)
        if self.header_length > 5:
            num_options = self.header_length - 5
            num_options_bytes = num_options * 4
            self.options = struct.unpack("!%dL" % num_options, self.ip_frame[self.IP_HEADER_FMT.size:self.IP_HEADER_FMT.size + num_options_bytes])

    def encode(self):
        proto = self.protocol if self.protocol not in self.IP_PROTOCOL else self.IP_PROTOCOL[self.protocol]
        header = self.IP_HEADER_FMT.pack(
            (self.version << 4) + self.header_length,
            self.type_of_service,
            self.total_length,
            self.identification,
            (self.flags << 3) + self.fragment_offset,
            self.ttl,
            proto,
            self.checksum,
            socket.inet_aton(self.src),
            socket.inet_aton(self.dst)
        )

        opts = ""
        if len(self.options) > 0:
            opts = struct.pack("!%dL" % len(self.options), *self.options)

        return header + opts


class TcpHeader(object):
    """ TDP Header block

        RFC 793
        http://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    """

    TCP_HEADER_FMT = struct.Struct('!HHLLBBHHH')

    # Maximum sequence number (numbers rollover back to zero when they reach this point)
    MAX_SEQUENCE = 4294967296

    def __init__(self, ip_frame, ip_header_size):
        self.ip_frame = ip_frame
        self.ip_header_size = ip_header_size

        self.sport = 0
        self.dport = 0
        self.seq = 0
        self.ack = 0
        self.data_offset = 0
        self.reserved = 0

        # Flags
        self.tcp_fin = 0
        self.tcp_syn = 0
        self.tcp_rst = 0
        self.tcp_psh = 0
        self.tcp_ack = 0
        self.tcp_urg = 0
        self.tcp_ece = 0
        self.tcp_cwr = 0

        self.window = 0
        self.checksum = 0
        self.urgent_pointer = 0
        self.options = []

        self._decode()

    def _decode(self):
        header = self.TCP_HEADER_FMT.unpack(self.ip_frame[self.ip_header_size:self.ip_header_size + self.TCP_HEADER_FMT.size])
        self.sport = header[0]
        self.dport = header[1]
        self.seq = header[2]
        self.ack = header[3]
        self.data_offset = header[4] >> 4
        self.reserved = header[4] & 0xF

        # Parse out each flag bit
        self.tcp_fin = self._is_bit_set(header[5], 0)
        self.tcp_syn = self._is_bit_set(header[5], 1)
        self.tcp_rst = self._is_bit_set(header[5], 2)
        self.tcp_psh = self._is_bit_set(header[5], 3)
        self.tcp_ack = self._is_bit_set(header[5], 4)
        self.tcp_urg = self._is_bit_set(header[5], 5)
        self.tcp_ece = self._is_bit_set(header[5], 6)
        self.tcp_cwr = self._is_bit_set(header[5], 7)

        self.window = socket.ntohs(header[6])
        self.checksum = header[7]
        self.urgent_pointer = header[8]

        # Decode additional options (data offset is greater than 5)
        if self.data_offset > 5:
            num_options = self.data_offset - 5
            num_options_bytes = num_options * 4
            self.options = struct.unpack("!%dL" % num_options, self.ip_frame[self.ip_header_size + self.TCP_HEADER_FMT.size:self.ip_header_size + self.TCP_HEADER_FMT.size + num_options_bytes])


    def _is_bit_set(self, field, offset):
        return 1 if ((field & (1 << offset)) > 0) else 0

    def encode(self):
        flags = self.tcp_fin + (self.tcp_syn << 1) + (self.tcp_rst << 2) + (self.tcp_psh <<3) + (self.tcp_ack << 4) + (self.tcp_urg << 5) + (self.tcp_ece << 6) + (self.tcp_cwr << 7)
        header = self.TCP_HEADER_FMT.pack(
            self.sport,
            self.dport,
            self.seq,
            self.ack,
            (self.data_offset << 4) + self.reserved,
            flags,
            socket.htons(self.window),
            self.checksum,
            self.urgent_pointer
        )

        opts = ""
        if len(self.options) > 0:
            opts = struct.pack("!%dL" % len(self.options), *self.options)

        return header + opts


class UdpHeader(object):
    """ UDP Header block

        RFC 768
        http://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure
    """

    UDP_HEADER_FMT = struct.Struct('!HHHH')

    def __init__(self, ip_frame, ip_header_size):
        self.ip_frame = ip_frame
        self.ip_header_size = ip_header_size

        self.sport = 0
        self.dport = 0
        self.length = 0
        self.checksum = 0

        self._decode()

    def _decode(self):
        header = self.UDP_HEADER_FMT.unpack(self.ip_frame[self.ip_header_size:self.ip_header_size + self.UDP_HEADER_FMT.size])
        self.sport = header[0]
        self.dport = header[1]
        self.length = header[2]
        self.checksum = header[3]

    def encode(self):
        header = self.UDP_HEADER_FMT.pack(
            self.sport,
            self.dport,
            self.length,
            self.checksum
        )

        return header


class IcmpHeader(object):
    """ ICMP Header block

        RFC 792
        http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
    """

    ICMP_HEADER_FMT = struct.Struct('!BBH')

    def __init__(self, ip_frame, ip_header_size):
        self.ip_frame = ip_frame
        self.ip_header_size = ip_header_size

        self.type = 0
        self.code = 0
        self.checksum = 0

        self._decode()

    def _decode(self):
        header = self.ICMP_HEADER_FMT.unpack(self.ip_frame[self.ip_header_size:self.ip_header_size + self.ICMP_HEADER_FMT.size])

        self.type = header[0]
        self.code = header[1]
        self.checksum = header[2]

    def encode(self):
        header = self.ICMP_HEADER_FMT.pack(
            self.type,
            self.code,
            self.checksum
        )

        return header


class Payload(object):
    def __init__(self, payload):
        self.payload_str = payload
        self.length = len(self.payload_str)

    def encode(self):
        return self.payload_str


class PacketDecoder(object):
    # Layer Enum
    IP, TCP, UDP, ICMP, PAYLOAD = range(0, 5)

    def __init__(self, ip_frame):
        self.ip_frame = ip_frame

        # Class logger
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.getLogger().getEffectiveLevel())

        # Packet layer map (return None if layer doesn't exist)
        self.layer = defaultdict(lambda: None)

        self._decode()

    def _decode(self):
        try:
            ip = IpHeader(self.ip_frame)
            self.layer[self.IP] = ip

            payload_start = ip.header_length * 4

            if ip.protocol == 'TCP':
                tcp = TcpHeader(self.ip_frame, ip.header_length*4)
                self.layer[self.TCP] = tcp
                payload_start += tcp.data_offset * 4
            elif ip.protocol == 'UDP':
                udp = UdpHeader(self.ip_frame, ip.header_length*4)
                self.layer[self.UDP] = udp
                payload_start += UdpHeader.UDP_HEADER_FMT.size
            elif ip.protocol == 'ICMP':
                icmp = IcmpHeader(self.ip_frame, ip.header_length*4)
                self.layer[self.ICMP] = icmp
                payload_start += IcmpHeader.ICMP_HEADER_FMT.size
            else:
                self.logger.warning("Unsupported IP protocol: %s" % ip.protocol)


            payload = Payload(self.ip_frame[payload_start:])
            self.layer[self.PAYLOAD] = payload

        except Exception as ex:
            self.logger.warning("Failed to decode packet: %s" % ex)

    def encode(self):
        """ Re-encode the packet with any changes """
        pkt_str = self.layer[self.IP].encode()

        tcp = self.layer[self.TCP]
        if tcp is not None:
            pkt_str += tcp.encode()

        udp = self.layer[self.UDP]
        if udp is not None:
            pkt_str += udp.encode()

        icmp = self.layer[self.ICMP]
        if icmp is not None:
            pkt_str += icmp.encode()

        payload = self.layer[self.PAYLOAD]
        if payload is not None:
            pkt_str += payload.encode()

        return pkt_str

    def fragment(self, fragment_size=1334):
        """ Fragment an oversized packet into smaller segments.
            
            The maximum allowed fragment_size is 1460 (with IP/TCP headers it becomes 1500 bytes),
            but packets in the real world tend to choose 1334 bytes for the payload,
            so we followed that.
        """
        pkt_lst = []

        payload = self.layer[self.PAYLOAD]
        if payload is None:
            pkt_lst.append(self)
        elif payload.length <= fragment_size:
            pkt_lst.append(self)
        elif self.layer[self.IP].protocol != 'TCP':
            self.logger.info("Fragmentation not supported for protocol: %s" % self.layer[self.IP].protocol)
            pkt_lst.append(self)
        else:
            num_fragments = int(math.ceil(payload.length/float(fragment_size)))
            for i in range(0, num_fragments):
                # Deep copy the total packet
                frag = PacketDecoder(self.ip_frame)

                # Slice the payload
                start_index = i * fragment_size
                end_index = start_index + fragment_size
                if end_index > payload.length:
                    end_index = payload.length

                frag.layer[self.PAYLOAD].payload_str = payload.payload_str[start_index:end_index]
                frag.layer[self.PAYLOAD].length = len(frag.layer[self.PAYLOAD].payload_str)

                # Set the IP header length to the new fragment size
                frag.layer[self.IP].total_length = (frag.layer[self.IP].header_length * 4) + (frag.layer[self.TCP].data_offset * 4) + frag.layer[self.PAYLOAD].length

                # Segment the TCP sequence number
                frag.layer[self.TCP].seq += i * fragment_size

                # Set the TCP flags correctly (SYN shouldn't be set but if it is never change it).
                # Also, the ACK flag should always be set and the ack number should be left alone,
                # if it's not set the ack number should be 0.
                if i == 0:
                    # First fragment can only have URG or ACK flags, set all other flags to 0
                    frag.layer[self.TCP].tcp_fin = 0
                    frag.layer[self.TCP].tcp_rst = 0
                    frag.layer[self.TCP].tcp_psh = 0
                    frag.layer[self.TCP].tcp_ece = 0
                    frag.layer[self.TCP].tcp_cwr = 0
                elif i == num_fragments-1:
                    # Last fragment can have PSH, RST, or FIN flags, all other flags are 0
                    #frag.layer[self.TCP].tcp_ack = 0
                    frag.layer[self.TCP].tcp_urg = 0
                    frag.layer[self.TCP].tcp_ece = 0
                    frag.layer[self.TCP].tcp_cwr = 0
                    #frag.layer[self.TCP].ack = 0
                else:
                    # Middle fragments have all flags set to 0
                    frag.layer[self.TCP].tcp_fin = 0
                    frag.layer[self.TCP].tcp_rst = 0
                    frag.layer[self.TCP].tcp_psh = 0
                    #frag.layer[self.TCP].tcp_ack = 0
                    frag.layer[self.TCP].tcp_urg = 0
                    frag.layer[self.TCP].tcp_ece = 0
                    frag.layer[self.TCP].tcp_cwr = 0
                    #frag.layer[self.TCP].ack = 0

                # Regenerate the IP frame string
                frag.ip_frame = frag.encode()

                pkt_lst.append(frag)

        return pkt_lst

    def fix_checksum(self):
        """ Recalculate the protocol layer checksum """
        correct_chksum = self._protocol_checksum()

        if self.layer[self.TCP] is not None:
            self.layer[self.TCP].checksum = correct_chksum
        elif self.layer[self.UDP] is not None:
            self.layer[self.UDP].checksum = correct_chksum
        elif self.layer[self.ICMP] is not None:
            self.layer[self.ICMP].checksum = correct_chksum
            
        """ Recalculate the IP header checksum """
        if self.layer[self.IP] is not None:
            self.layer[self.IP].checksum = self._ip_checksum()
            
    def _ip_checksum(self):
        """ IP header checksum calculator """
        # Get just the existing IP header (20-60 bytes)
        frame = bytearray(self.ip_frame[:self.layer[self.IP].header_length*4])
        
        # Reset the TCP/UDP checksum to 0
        mv = memoryview(frame)
        mv[10:12] = struct.pack("!H", 0)
        
        return self._checksum(str(frame))

    def _protocol_checksum(self):
        """ Protocol specific checksum calculator """
        ip_layer = self.layer[self.IP]

        if ip_layer is None:
            return 0

        # Get the frame as a string, used for any protocl that is not TCP or UDP
        frame = str(self.ip_frame)
        
        if ip_layer.protocol == 'TCP' or ip_layer.protocol == 'UDP':
            # TCP/UDP use a pseudo header that is a subset of the IP header + the TCP/UDP header

            # Strip off the existing IP header (20-60 bytes)
            frame = bytearray(self.ip_frame[ip_layer.header_length*4:])

            # Reset the TCP/UDP checksum to 0
            mv = memoryview(frame)
            if ip_layer.protocol == 'TCP':
                mv[16:18] = struct.pack("!H", 0)
            elif ip_layer.protocol == 'UDP':
                mv[6:8] = struct.pack("!H", 0)

            # Create the pseudo header as defined in either:
            #   http://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_checksum_for_IPv4
            #   http://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv4_Pseudo_Header
            pseudo_hdr = struct.pack(
                "!4s4sBBH",
                 socket.inet_aton(ip_layer.src),
                 socket.inet_aton(ip_layer.dst),
                 0,
                 IpHeader.IP_PROTOCOL[ip_layer.protocol],
                 len(frame))

            frame = pseudo_hdr + str(frame)
            
        return self._checksum(frame)
    
    def _checksum(self, frame):
        """ Calculate checksum over an array of bytes """
        if len(frame) % 2 == 1:
            frame += "\0"
        s = sum(array.array("H", frame))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s>>8)&0xff)|s<<8) & 0xffff