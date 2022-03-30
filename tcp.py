from typing import NamedTuple
import socket
import random
import struct
from ipmock import IpHandler


class TcpHandler(object):
    def __init__(self) -> None:
        # self.ipHanlder = IpHandler()
        self.ipHandler = IpHandler()
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
        print(port)
        return port

    # establish a connection
    def connect(self, destIp, destPort) -> None:
        self.destIp = destIp
        self.destPort = destPort

        # first handshake
        first = Packet(sourcePort=self.srcPort, destinationPort=destPort,
                       sequenceNumber=self.seq, syn=1, window=65535)
        self.__send(destIp, first)

        # second handshake
        second = self.recv()
        if second is None:
            print("Invalid checksum!")
        self.ack = second.sequenceNumber + 1
        self.seq = second.acknowledgmentNumber

        # thrid handshake
        third = Packet()
        third.sourcePort = self.srcPort
        third.destinationPort = destPort
        third.sequenceNumber = self.seq
        third.ack = 1
        third.window = 65535
        self.__send(encode(), destIp, destPort)

    def send(self, dest_ip, data) -> None:
        self.__send(dest_ip, data)

    # wrap one packet with TCP header and sent to IP layer
    def __send(self, dest_ip, packet) -> None:
        self.ipHandler.send(dest_ip, encode(self.ipHandler.get_ip_address(), dest_ip, packet))

    def recv(self):
        return decode(self.__recv())

    # receive one packet from IP layer
    def __recv(self) -> bytes:
        while True:
            data = self.ipHandler.recv()
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

    # offsets in bits
    SOURCE_PORT_OFFSET:         int = 0
    DESTINATION_PORT_OFFSET:    int = 16
    SEQUENCE_NUMBER_OFFSET:     int = 32 * 1
    ACKNOWLEDGMENT_OFFSET:      int = 32 * 2
    DATA_OFFSET:                int = 32 * 3
    RESERVERD_OFFSET:           int = 32 * 3 + 4
    URG_OFFSET:                 int = 32 * 3 + 10
    ACK_OFFSET:                 int = 32 * 3 + 11
    PSH_OFFSET:                 int = 32 * 3 + 12
    RST_OFFSET:                 int = 32 * 3 + 13
    SYN_OFFSET:                 int = 32 * 3 + 14
    FIN_OFFSET:                 int = 32 * 3 + 15
    WINDOW_OFFSET:              int = 32 * 3 + 16
    CHECKSUM_OFFSET:            int = 32 * 4
    URGENT_POINTER_OFFSET:      int = 32 * 4 + 16
    OPTIONS_OFFSET:             int = 32 * 5
    PADDING_OFFSET:             int = 32 * 5 + 24
    DATA_OFFSET:                int = 32 * 6


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

    print(packet)
    print(tcp_header)
    return tcp_header + packet.data


def decode(raw) -> Packet:
    # tcp header
    packet = Packet()
    packet.sourcePort, packet.destinationPort, \
        packet.sequenceNumber, packet.acknowledgmentNumber, \
        offset, flags, packet.window, packet.checksum, packet.urgentPointer = \
        struct.unpack(HEADER_PACK_FORMAT, raw)

    packet.dataOffset = offset >> 4
    packet.fin = (flags >> 1) & 0x01
    packet.syn = (flags >> 1) & 0x01
    packet.pst = (flags >> 1) & 0x01
    packet.psh = (flags >> 1) & 0x01
    packet.ack = (flags >> 1) & 0x01
    packet.urg = (flags >> 1) & 0x01

    # verify checksum
    # ...

    packet.data = raw[packet.dataOffset:]
    return packet


def checksum(data) -> bytes:
    s = 0
    for i in range(0, len(data), 2):
        w = ord(data[i:i+1]) + (ord(data[i+1:i+2]) << 8)
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s.to_bytes(2, 'big')


handler = TcpHandler()
handler.connect("204.44.192.60", 80)