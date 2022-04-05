import struct
from random import randint
import socket
from helper import checksum


# A handler for IP protocol with two raw scokets send/recv data.
class IpHandler(object):
    # initialize raw sockets and fetch local/remote IP address.
    def __init__(self, destIp) -> None:
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.src = IpHandler.fetch_ip()
        self.dst = destIp

    # sending packets including fragamentation.
    def send(self, destIp, destPort, data) -> None:
        packet = IPacket()
        packet.destinationAddress = destIp

        while len(data) > 1480:
            packet.data = data[:1480]
            data = data[1480:]
            packet.flags_df = 0
            packet.flags_mf = 1
            self.sender.sendto(packet.encode(), (destIp, destPort))

        packet.flags_mf = 0
        packet.data = data
        self.sender.sendto(packet.encode(), (destIp, destPort))

    # receiving data.
    def recv(self) -> bytes:
        packet = IPacket()

        while True:
            raw_data = self.receiver.recv(65535)
            if packet.decode(raw_data) == b'':
                continue
            if packet.sourceAddress == self.dst and packet.destinationAddress == self.src \
                    and packet.Protocol == socket.IPPROTO_TCP:
                return packet.data

    # static method used to fecth local IP address
    @staticmethod
    def fetch_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        return local_ip

# For building IP headers.
class IPacket:
    """
    RFC 791: https://datatracker.ietf.org/doc/html/rfc791#section-3.1

    IP Header Format:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           data                                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    version: int = 4
    ihl: int = 5
    typeOfService: int = 0
    totalLength: int = 0
    identification: int = 0
    flags: int = 0
    flags_df: int = 0
    flags_mf: int = 0
    fragmentOffset: int = 0
    timeToLive: int = 255
    Protocol: int = socket.IPPROTO_TCP
    headerChecksum: int = 0
    sourceAddress: str
    destinationAddress: str
    options: int = None
    data: bytes = None

    def __init__(self) -> None:
        self.sourceAddress = IpHandler.fetch_ip()

    # Building IP headers and wrap it around the TCP header and data.
    def encode(self) -> bytes:
        self.identification = randint(0, 65535)
        self.totalLength = self.ihl * 4 + len(self.data)

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                (self.version << 4) + self.ihl,
                                self.typeOfService,
                                self.totalLength,
                                self.identification,
                                (((self.flags_df << 1) + self.flags_mf << 13) +
                                 self.fragmentOffset),
                                self.timeToLive,
                                self.Protocol,
                                self.headerChecksum,
                                socket.inet_aton(self.sourceAddress),
                                socket.inet_aton(self.destinationAddress))

        self.headerChecksum = checksum(ip_header)
        return ip_header[:10] + struct.pack('H', self.headerChecksum) + ip_header[12:] + self.data

    # Parsing  IP header of incoming packets to make sure it is a validated packet.
    def decode(self, raw) -> bytes:
        ver_inl, service, slen, id_header, offset, ttl, prot, csm, src, dst = struct.unpack('!BBHHHBBH4s4s', raw[:20])

        self.version = ver_inl >> 4
        self.ihl = ver_inl & 0x0f
        self.typeOfService = service
        self.totalLength = slen
        self.identification = id_header
        self.flags_df = offset >> 14
        self.flags_mf = offset >> 13
        self.fragmentOffset = offset & 0x1f
        self.timeToLive = ttl
        self.Protocol = prot
        self.headerChecksum = csm
        self.sourceAddress = socket.inet_ntoa(src)
        self.destinationAddress = socket.inet_ntoa(dst)

        ip_head = raw[:self.ihl * 4]
        # parse data.
        self.data = raw[self.ihl * 4:  self.totalLength]

        self.headerChecksum = 0
        # remove checksum from header.
        ip_header_no_sum = struct.pack('!BBHHHBBH4s4s',
                                       (self.version << 4) + self.ihl,
                                       self.typeOfService,
                                       self.totalLength,
                                       self.identification,
                                       (((self.flags_df << 1) + self.flags_mf << 13) + self.fragmentOffset),
                                       self.timeToLive,
                                       self.Protocol,
                                       self.headerChecksum,
                                       socket.inet_aton(self.sourceAddress),
                                       socket.inet_aton(self.destinationAddress))

        # checksum validation.
        if checksum(ip_head) != 0 and checksum(ip_head) != checksum(ip_header_no_sum):
            print('Ip checksum incorrect! Ignore this packet!')
            return b''

        return self.data
