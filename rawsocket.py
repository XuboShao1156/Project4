import tcp
import ip
import socket
from urllib.parse import urlparse

class RawSocket(object):
    def __init__(self) -> None:
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.receiver.setblocking(0)

        self.ip = None
        self.port = None

    def connect(self, url, port) -> None:
        urlobj = urlparse(url)
        self.ip = self.__dns(urlobj.hostname)
        self.port = port

        # handle three-way handshake
        pass

    def sendall(self, rawReq) -> None:
        self.__send(rawReq)

    # wrap one packet with TCP and IP header and send
    def __send(self, rawReq) -> None:
        self.sender.sendto(ip.wrap(tcp.wrap(rawReq)), self.ip)

    def recv(self, bufsize) -> bytes:
        return self.__recv(bufsize)

    # receive and filter one packet with IP address and port
    def __recv(self, bufsize) -> bytes:
        while True:
            data, addr = self.receiver.recvfrom(bufsize)
            if not data:
                return data
        
            ipHeader = ip.parse(data)
            tcpHeader = tcp.parse(data[20:])

            if True: # filter data and return
                return b''

    def __dns(self, hostname) -> str:
        pass
