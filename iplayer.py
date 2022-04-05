import socket
from struct import *

SRC_IP = '172.16.112.130'
DEST_IP = '204.44.192.60'

class IPLayer:
    rc = None
    ss = None

    src = None

    def __init__(self):
        self.rc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.ss.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True)
        self.src = IPLayer.fetch_ip()

    def send(self, dst, data):
        pkt = IPPacket()
        pkt.SRC = socket.inet_aton(self.src)
        pkt.Dest = socket.inet_aton(dst)
        pkt.Data = data

        self.ss.sendto(pkt.toHexString(), (dst, 0))

    def recv(self):
        raw_data, addr = self.rc.recvfrom(65565)
        # print(addr)
        # print(len(raw_data))
        ippkt = IPPacket()
        ippkt.fromData(raw_data)
        return ippkt.Data

    @staticmethod
    def fetch_ip():
        return SRC_IP

class IPPacket:
    #Packet Fields
    Version = 4
    Hlen = 5
    Service = 0
    Len = 0
    Identification = 54321
    Flags = 0
    FragmentOfset = 0
    TTL = 255
    ULP = 6
    CheckSum = 0
    SRC = socket.inet_aton(SRC_IP)
    Dest = socket.inet_aton(DEST_IP)
    Opt = None
    Data = None

    def __init__(self):
        pass

    def toHexString(self):
        ip_ver_hlen = (self.Version << 4) + self.Hlen
        hex= pack('!BBHHHBBH4s4s',
             ip_ver_hlen,
             self.Service,
             self.Len,
             self.Identification,
             self.FragmentOfset,
             self.TTL,
             self.ULP,
             self.CheckSum,
             self.SRC,
             self.Dest) + self.Data
        # print("sent: " + str(hex))
        return hex

    def fromData(self, data):
        ver_hlen, service, dlen, id, frag_offset, ttl, proto, chksum, src, dst = unpack('!BBHHHBBH4s4s',
                                                                                               data[:20])
        # self.Version = (ord(data[0:1]) >> 4)
        # self.Hlen = (ord(data[0:1]) & 15) * 4
        self.Service = service
        self.Len = dlen
        self.Identification = id
        self.Flags = frag_offset
        self.FragmentOfset = frag_offset
        self.TTL = ttl
        self.ULP = proto
        self.CheckSum = chksum
        self.SRC = src
        self.Dest = dst
        self.Data = data[20:]
        # print("ip data len:" + str(len(self.Data)))

    def __str__(self):
        s = "\n"
        s += "IPv4 Packet:\n"
        s += "\t Version: {}, Header Length: {}, TTL: {}\n".format(self.Version, self.Hlen, self.TTL)
        s += "\t Protocol: {}, Source: {}, Destination: {}\n".format(self.ULP, socket.inet_ntoa(self.SRC), socket.inet_ntoa(self.Dest))
        return s