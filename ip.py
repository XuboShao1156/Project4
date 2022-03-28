from typing import NamedTuple
import socket

class IpHandler(object):
    def __init__(self) -> None:
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    def send(self, destIp, data) -> None:
        pass

    def receive(self) -> bytes:
        pass

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
    # fields ...
    version:            int
    ihl:                int
    typeOfService:      int
    totalLength:        int
    identification:     int
    flags:              int
    fragmentOffset:     int
    timeToLive:         int
    Protocol:           int
    headerChecksum:     int
    sourceAddress:      str
    destinationAddress: str
    options:            int
    data:               bytes

    # offsets ...

def wrap(data) -> bytes:
    pass
    
def parse(raw) -> Packet:
    # handle incorrect checksum: raise exception?
    pass