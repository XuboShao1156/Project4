import socket


class IpHandler:
    def __init__(self):
        self.rc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        # self.ss.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True)
        self.src = '72.74.225.130'

    def send(self, dst, data):
        self.ss.sendto(data, (dst, 0))

    def recv(self):
        data, addr = self.rc.recvfrom(65565)
        return data

    @staticmethod
    def get_ip_address():
        return '72.74.225.130'