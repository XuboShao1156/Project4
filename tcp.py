from ip import IpHandler
from urllib.parse import urlparse
from typing import NamedTuple

class TcpHandler(object):
    def __init__(self) -> None:
        self.ipHanlder = IpHandler()
        self.srcPort = self.__initPort()

        self.destIp = None
        self.destPort = None

    def __initPort(self) -> int:
        pass

    # establish a connection
    def connect(self, destIp, destPort) -> None:
        self.destIp = destIp
        self.destPort = destPort

        # handle three-way handshake
        pass

    def send(self, destIp, data) -> None:
        self.__send(destIp, data)

    # wrap one packet with TCP header and sent to IP layer
    def __send(self, destIp, data) -> None:
        self.sender.sendto(destIp, wrap(data))

    def recv(self, bufsize) -> bytes:
        pass

    # receive one packet from IP layer
    def __recv(self) -> bytes:
        while True:
            data = self.ipHanlder.receive()
            packet = parse(data)
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
    sourcePort:             int
    destinationPort:        int
    seuqenceNumber:         int
    acknowledgmentNumber:   int
    dataOffset:             int
    reserved:               int
    URG:                    int
    ACK:                    int
    PSH:                    int
    RST:                    int
    SYN:                    int
    FIN:                    int
    window:                 int
    checksum:               int
    urgentPointer:          int
    options:                int
    data:                   bytes

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

def wrap(data) -> bytes:
    pass
    
def parse(raw) -> Packet:
    pass