from tcp import TcpHandler
from urllib.parse import urlparse

HTTP_PORT = 80


class HttpRequester(object):
    def __init__(self) -> None:
        self.tcpHandler = TcpHandler()

    def get(self, url) -> (int, bytes):
        url_obj = urlparse(url)

        # dns query
        host_ip = self.__dns(url_obj.hostname)
        if host_ip == "":
            raise Exception("dns query for host ip failed!")

        # connect host
        self.tcpHandler.connect(host_ip, HTTP_PORT)

        # send http request
        request = "GET {} HTTP/1.0\r\nHost: {}\r\n\r\n".format(url_obj.path, url_obj.hostname)
        self.tcpHandler.send(request.encode('utf-8'))

        # receive http response
        rawResp = self.tcpHandler.recvall()
        self.tcpHandler.close()

        # parse response for content and return
        return self.__parse(rawResp)

    @staticmethod
    def __parse(rawResp) -> (int, bytes):
        offset = rawResp.find(b'\r\n\r\n')
        if offset != -1:
            offset += 4
        else:
            offset = rawResp.find('\n\n') + 2

        return int(rawResp.split(b' ', 2)[1]), rawResp[offset:]

    @staticmethod
    def __dns(host) -> str:
        import socket
        return socket.gethostbyname(host)
