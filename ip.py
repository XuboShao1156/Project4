import struct
from typing import NamedTuple
import socket

from numpy.random import randint

from tcp import checksum


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

    def __init__(self) -> None:
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    def send(self, destIp, data) -> None:
        packet = IPacket()
        packet.data = data
        packet.destinationAddress = destIp

        self.sender.send(IPacket.encode())

    def receive(self) -> bytes:
        packet = IPacket()

        raw_data = self.receiver.recv(65535)
        return packet.decode(raw_data)

    @staticmethod
    def fetch_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


class IPacket:
    version: int = 4
    ihl: int = 5
    typeOfService: int = 0
    totalLength: int = 0
    identification: int = 0
    flags: int = 0
    fragmentOffset: int = 0
    timeToLive: int = 255
    Protocol: int = 6
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
                                self.fragmentOffset,
                                self.timeToLive,
                                self.Protocol,
                                self.headerChecksum,
                                self.sourceAddress,
                                self.destinationAddress
                                )

        self.headerChecksum = checksum(ip_header)

        ip_header_checksum = struct.pack('!BBHHHBBH4s4s',
                                         (self.version << 4) + self.ihl,
                                         self.typeOfService,
                                         self.totalLength,
                                         self.identification,
                                         self.fragmentOffset,
                                         self.timeToLive,
                                         self.Protocol,
                                         self.headerChecksum,
                                         self.sourceAddress,
                                         self.destinationAddress
                                         )

        packet = ip_header_checksum + self.data
        return packet

    def decode(self, raw) -> bytes:
        ver_inl, service, slen, id_header, offset, ttl, prot, csm, src, dst = struct.unpack('!BBHHHBBH4s4s', raw[:20])

        self.version = (ver_inl & 0xf0) >> 4
        self.ihl = ver_inl & 0x0f
        self.typeOfService = service
        self.totalLength = slen
        self.identification = id_header
        self.flags = offset
        self.fragmentOffset = offset
        self.timeToLive = ttl
        self.Protocol = prot
        self.headerChecksum = csm
        self.sourceAddress = src
        self.destinationAddress = dst

        ip_head = raw[:self.ihl * 4]

        self.data = raw[self.ihl * 4:  self.totalLength]
        if checksum(ip_head) != 0:
            print("checksum is not correct")

        return self.data
