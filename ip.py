import struct
from random import randint
from typing import NamedTuple
import socket

from helper import checksum


class Packet(NamedTuple):
    '''
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
    '''


class IpHandler(object):

    def __init__(self, destIp) -> None:
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.src = IpHandler.fetch_ip()
        self.dst = destIp

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

    def recv(self) -> bytes:
        packet = IPacket()

        while True:
            raw_data = self.receiver.recv(65535)
            packet.decode(raw_data)
            ip_header_raw = raw_data[:20]
            if packet.sourceAddress == self.dst and packet.destinationAddress == self.src:
                return packet.data

    @staticmethod
    def fetch_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


class IPacket:
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
                                socket.inet_aton(self.destinationAddress)
                                )

        self.headerChecksum = checksum(ip_header)

        ip_header = struct.pack('!BBHHHBB',
                                (self.version << 4) + self.ihl,
                                self.typeOfService,
                                self.totalLength,
                                self.identification,
                                (((self.flags_df << 1) + self.flags_mf << 13) +
                                 self.fragmentOffset),
                                self.timeToLive,
                                self.Protocol
                                ) + struct.pack('H', self.headerChecksum) + \
                    struct.pack('!4s4s', socket.inet_aton(self.sourceAddress),
                                socket.inet_aton(self.destinationAddress))

        packet = ip_header + self.data
        return packet

    def decode(self, raw) -> bytes:
        ver_inl, service, slen, id_header, offset, ttl, prot, csm, src, dst = struct.unpack('!BBHHHBBH4s4s', raw[:20])

        self.version = (ver_inl & 0xf0) >> 4
        self.ihl = ver_inl & 0x0f
        self.typeOfService = service
        self.totalLength = slen
        self.identification = id_header
        self.flags_df = (offset & 0x40) >> 14
        self.flags_mf = (offset & 0x20) >> 13
        self.fragmentOffset = offset & 0x1f
        self.timeToLive = ttl
        self.Protocol = prot
        self.headerChecksum = csm
        self.sourceAddress = socket.inet_ntoa(src)
        self.destinationAddress = socket.inet_ntoa(dst)

        ip_head = raw[:self.ihl * 4]

        self.data = raw[self.ihl * 4:  self.totalLength]
        if checksum(ip_head) != 0:
            print("ip checksum is not correct")

        return self.data
