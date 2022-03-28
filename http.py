from tcp import TcpHandler
from urllib.parse import urlparse

HTTP_PORT = 80

class HttpHandler(object):
    def __init__(self) -> None:
        self.tcpHandler = TcpHandler()

    def get(self, url) -> str:
        urlobj = urlparse(url)

        # connect host
        self.socket.connect(self.__dns(urlobj.hostname), HTTP_PORT)

        # send http request
        request = "GET {} HTTP/1.0\r\nHost: {}\r\n\r\n".format(urlobj.path, urlobj.hostname)
        self.socket.sendall(request.encode('utf-8'))

        # receive http response
        rawResp = self.socket.recv(32768) # TODO: chagne to loop

        # parse response for content and return
        return self.__parse(rawResp)
    
    def __parse(self, rawResp) -> str:
        pass

    def __dns(self, host) -> str:
        pass

