import time
import struct
import logging


class PcapWriter(object):
    """ Create a PCAP file and write raw data packets to it.

    This class supports writing default ethernet frames,
    Raw IP frames (no ethernet information), and GPRS LLC.
    See the spec for more information:

        http://wiki.wireshark.org/Development/LibpcapFileFormat

    Helpful note: The PCAP file can be opened in wireshark while
        new packets are being written to it using the command:

        wireshark -k -i <(cat FILENAME)

    """

    # Headers in struct format
    GLOBAL_HEADER_FMT = "IHHIIII"
    PACKET_HEADER_FMT = "IIII"


    class LinkType(object):
        """ Supported link layer types """

        LINKTYPE_ETHERNET = 1
        LINKTYPE_RAW = 101

    def __init__(self, filename, link_type, append=False):
        self.filename = filename
        self.link_type = link_type
        self.append = append

        # Class logger
        self.logger = logging.getLogger(self.__class__.__name__)

        # Pcap file handle
        self.file = None

        # Generate global header
        # Pcap format: http://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header
        self.global_header = struct.pack(self.GLOBAL_HEADER_FMT, 0xa1b2c3d4, 2, 4, 0, 0, 65535, self.link_type)

        # Start file
        self._open_file()

    def _open_file(self):
        # Make sure file is closed
        self.close()

        flag = 'a' if self.append else 'w'
        self.file = open(self.filename, flag)

        self.logger.debug("Opened pcap file %s, append=%s" % (self.filename, self.append))

        self.file.write(self.global_header)
        self.file.flush()

    def close(self):
        if self.file is not None:
            self.file.close()
            self.logger.debug("Closed pcap file %s" % self.filename)

        self.file = None

    def write_packet(self, packet_bytes):
        if self.file is not None:
            # Pcap format: http://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header
            timestamp = int(time.time())
            length = len(packet_bytes)
            header = struct.pack(self.PACKET_HEADER_FMT, timestamp, 0, length, length)

            self.file.write(header)
            self.file.write(packet_bytes)
            self.file.flush()
