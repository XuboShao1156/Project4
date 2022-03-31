from typing import NamedTuple
import socket
import random
import struct
from ipmock import IpHandler
from iplayer import IPLayer

class TcpHandler(object):
    def __init__(self) -> None:
        # self.ipHandler = IpHandler()
        # self.ipHandler = IpHandler()
        self.ipHandler = IPLayer()
        self.srcPort = self.__initPort()
        self.seq = random.randint(0, 2**32)

        self.destIp = None
        self.destPort = None
        self.ack = None

    # find an available port
    def __initPort(self) -> int:
        sock = socket.socket()
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    # establish a connection
    def connect(self, destIp, destPort) -> None:
        self.destIp = destIp
        self.destPort = destPort

        # first handshake
        first = Packet(sourcePort=self.srcPort, destinationPort=destPort,
                       sequenceNumber=self.seq, syn=1, window=65535)
        self.__send(destIp, first)
        print("first handshake done!")

        # second handshake
        second = self.recv()
        if second is None:
            print("Invalid checksum!")
        self.ack = second.sequenceNumber + 1
        self.seq = second.acknowledgmentNumber
        print("second handshake done!")

        # third handshake
        third = Packet(sourcePort=self.srcPort, destinationPort=destPort,
                       sequenceNumber=self.seq, acknowledgmentNumber=self.ack, window=65535)
        self.__send(destIp, third)

    def send(self, dest_ip, packet) -> None:
        self.__send(dest_ip, packet)

    # wrap one packet with TCP header and sent to IP layer
    def __send(self, dest_ip, packet) -> None:
        print(len(encode(self.ipHandler.get_ip_address(), dest_ip, packet)))
        self.ipHandler.send(dest_ip, encode(self.ipHandler.get_ip_address(), dest_ip, packet))

    def recv(self):
        return decode(self.__recv())

    # receive one packet from IP layer
    def __recv(self) -> bytes:
        while True:
            data = self.ipHandler.recv()
            print('receive {} data: {}'.format(len(data), bytes.fromhex(data).decode('utf-8')))
            packet = decode(data)
            if packet.destinationPort == self.srcPort:
                return packet

    # close connection
    def close(self) -> None:
        # handle four-way close
        pass


class Packet(NamedTuple):
    '''
    RFC 793: https://datatracker.ietf.org/doc/html/rfc793#section-3.1

    TCP Header Format:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    # fields
    sourcePort:             int     = 0
    destinationPort:        int     = 0
    sequenceNumber:         int     = 0
    acknowledgmentNumber:   int     = 0
    dataOffset:             int     = 5
    reserved:               bytes   = 0
    urg:                    int     = 0
    ack:                    int     = 0
    psh:                    int     = 0
    rst:                    int     = 0
    syn:                    int     = 0
    fin:                    int     = 0
    window:                 int     = 0
    checksum:               bytes   = 0
    urgentPointer:          int     = 0
    options:                int     = 0
    data:                   bytes   = b''


HEADER_PACK_FORMAT = '!HHLLBBHHH'


def encode(src_ip, dest_ip, packet) -> bytes:
    # tcp header
    offset = packet.dataOffset << 4
    flags = packet.fin + (packet.syn << 1) + (packet.rst << 2) + (packet.psh << 3) + (packet.ack << 4) + (packet.urg << 5)
    tcp_header = struct.pack(HEADER_PACK_FORMAT, packet.sourcePort, packet.destinationPort,
                             packet.sequenceNumber, packet.acknowledgmentNumber,
                             offset, flags, packet.window, packet.checksum, packet.urgentPointer)

    # pseudo header
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dest_ip),
                                0, 6, len(tcp_header) + len(packet.data))

    # replace checksum
    csum = checksum(pseudo_header + tcp_header + packet.data)
    tcp_header = tcp_header[:16] + csum + tcp_header[18:]

    # print(packet)
    # print(tcp_header)
    return tcp_header + packet.data


def decode(raw) -> Packet:
    # tcp header
    source_port, destination_port, \
        sequence_number, acknowledgment_number, \
        offset, flags, window, csum, urgent_pointer = \
        struct.unpack(HEADER_PACK_FORMAT, raw)

    offset = (offset >> 4) * 4

    fin = flags & 0x01
    flags >>= 1
    syn = flags & 0x01
    flags >>= 1
    rst = flags & 0x01
    flags >>= 1
    psh = flags & 0x01
    flags >>= 1
    ack = flags & 0x01
    flags >>= 1
    urg = flags & 0x01

    # verify checksum
    csum = bytes()

    return Packet(source_port, destination_port, sequence_number, acknowledgment_number,
                  offset, bytes(), urg, ack, psh, rst, syn, fin, window, csum, urgent_pointer, 0, raw[offset:])


def checksum(data) -> bytes:
    s = 0
    for i in range(0, len(data), 2):
        s = s + ord(data[i:i+1]) + (ord(data[i+1:i+2]) << 8)

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s.to_bytes(2, 'big')

# hex = bytes.fromhex("A2 C5 00 50 BD 23 1E 08 00 00 00 00 50 02 FF FF A6 88 00 00")
handler = TcpHandler()
handler.connect("204.44.192.60", 80)